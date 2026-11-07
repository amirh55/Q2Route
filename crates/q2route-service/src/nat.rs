//! TCP NAT redirect using the WinDivert "streamdump" reflection technique
//! (IPv4/TCP and IPv6/TCP).
//!
//! * App packet `A:pa -> D:pd` (outbound, NAT entry for `pa`): rewritten to
//!   `D:pa -> A:relay_port` and reinjected inbound, so the relay listener
//!   sees a connection from peer `D:pa`.
//! * Relay packet `A:relay_port -> D:pa` (outbound): rewritten to
//!   `D:pd -> A:pa` and reinjected inbound, so the app sees `D:pd`.
//!
//! Entries are keyed by the address family and the app's source port `pa`
//! (an IPv4 and an IPv6 flow may share a port number). The engine inserts the
//! entry before calling [`redirect_outbound`] for a flow it routes to the
//! relay. An RST in either direction removes the entry immediately; once a
//! FIN has been seen in both directions the entry lingers for
//! [`CLOSE_LINGER`] so the final ACK (and FIN retransmits) are still
//! redirected, then [`NatTable::sweep`] removes it. The engine should call
//! `sweep` periodically.
//!
//! **The relay owns an entry's lifetime** once its connection has looked it
//! up ([`NatTable::attach`]): such an entry is never idle-expired, however
//! long the connection is quiet, and [`NatTable::release`] (called when the
//! relay connection ends) starts the [`CLOSE_LINGER`]. Only entries no relay
//! connection ever attached (e.g. a SYN that never reached the relay) expire
//! after [`IDLE_TIMEOUT`].
//!
//! IPv6 is rewritten only when the TCP header directly follows the fixed
//! 40-byte header; a packet of a redirected flow that carries extension
//! headers is dropped (fail closed) rather than escaping un-rewritten.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::windivert::{calc_checksums_addr, Address};

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const CLOSE_LINGER: Duration = Duration::from_secs(10);

/// The address family of a NAT entry (part of its key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(a: &SocketAddr) -> Family {
        match a {
            SocketAddr::V4(_) => Family::V4,
            SocketAddr::V6(_) => Family::V6,
        }
    }
}

type Key = (Family, u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalDst {
    pub dst: SocketAddr,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not ours: reinject unchanged.
    Pass,
    /// Must not leave un-restored: drop.
    Drop,
    /// Rewritten in place (addr now inbound): reinject.
    Rewritten,
}

struct Entry {
    o: OriginalDst,
    /// Identifies this entry across port reuse (see [`NatTable::release`]).
    token: u64,
    /// A live relay connection holds this entry.
    attached: bool,
    last_seen: Instant,
    fin_from_app: bool,
    fin_from_relay: bool,
    closed_at: Option<Instant>,
}

/// Thread-safe; all methods take `&self`.
#[derive(Default)]
pub struct NatTable {
    map: Mutex<HashMap<Key, Entry>>,
    next_token: std::sync::atomic::AtomicU64,
}

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

impl NatTable {
    fn lock(&self) -> MutexGuard<'_, HashMap<Key, Entry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Inserts (or replaces, e.g. on port reuse) the entry for `app_port`.
    pub fn insert(&self, fam: Family, app_port: u16, o: OriginalDst) {
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let e = Entry {
            o,
            token,
            attached: false,
            last_seen: Instant::now(),
            fin_from_app: false,
            fin_from_relay: false,
            closed_at: None,
        };
        self.lock().insert((fam, app_port), e);
    }

    pub fn get(&self, fam: Family, app_port: u16) -> Option<OriginalDst> {
        self.lock().get(&(fam, app_port)).map(|e| e.o)
    }

    pub fn remove(&self, fam: Family, app_port: u16) {
        self.lock().remove(&(fam, app_port));
    }

    /// The relay accepted the connection from peer `ip:app_port`: returns
    /// the original destination and a token for [`NatTable::release`], and
    /// marks the entry as held by a live relay connection (never idle-swept).
    pub fn attach(&self, fam: Family, app_port: u16, ip: IpAddr) -> Option<(OriginalDst, u64)> {
        let mut g = self.lock();
        let e = g.get_mut(&(fam, app_port)).filter(|e| e.o.dst.ip() == ip)?;
        e.attached = true;
        Some((e.o, e.token))
    }

    /// The relay connection that attached `token` ended: the entry lingers
    /// for [`CLOSE_LINGER`] (final ACK / FIN retransmits), then is swept. A
    /// stale token (the port was reused by a newer flow) is ignored.
    pub fn release(&self, fam: Family, app_port: u16, token: u64) {
        let mut g = self.lock();
        if let Some(e) = g.get_mut(&(fam, app_port)).filter(|e| e.token == token) {
            e.attached = false;
            e.closed_at.get_or_insert_with(Instant::now);
        }
    }

    /// Removes closed entries older than [`CLOSE_LINGER`], and entries no
    /// relay connection holds that were idle longer than [`IDLE_TIMEOUT`].
    pub fn sweep(&self, now: Instant) {
        self.lock().retain(|_, e| {
            (e.attached || now.saturating_duration_since(e.last_seen) <= IDLE_TIMEOUT)
                && e.closed_at
                    .is_none_or(|c| now.saturating_duration_since(c) <= CLOSE_LINGER)
        });
    }

    /// Looks up `key`; if present and `accept` holds, records activity and
    /// TCP close state, and returns the entry.
    fn observe(
        &self,
        key: Key,
        tcp_flags: u8,
        from_app: bool,
        accept: impl FnOnce(&OriginalDst) -> bool,
    ) -> Option<OriginalDst> {
        let mut g = self.lock();
        let e = g.get_mut(&key)?;
        if !accept(&e.o) {
            return None;
        }
        let o = e.o;
        let now = Instant::now();
        e.last_seen = now;
        if tcp_flags & TCP_RST != 0 {
            g.remove(&key);
            return Some(o);
        }
        if tcp_flags & TCP_FIN != 0 {
            if from_app {
                e.fin_from_app = true;
            } else {
                e.fin_from_relay = true;
            }
            if e.fin_from_app && e.fin_from_relay && e.closed_at.is_none() {
                e.closed_at = Some(now);
            }
        }
        Some(o)
    }
}

/// A bounds-checked view of an IPv4/TCP or IPv6/TCP packet's fields we
/// touch.
struct Tcp {
    fam: Family,
    /// Offset of the TCP header.
    l4: usize,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    flags: u8,
    /// IPv6 only: the TCP header does not directly follow the fixed header
    /// (extension headers). Such a packet is never rewritten.
    ext: bool,
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

/// Returns `None` for anything that is not a complete, first-fragment
/// IPv4/TCP or IPv6/TCP packet.
fn parse(p: &[u8]) -> Option<Tcp> {
    match p.first()? >> 4 {
        4 => parse4(p),
        6 => parse6(p),
        _ => None,
    }
}

fn parse4(p: &[u8]) -> Option<Tcp> {
    if p.len() < 20 || p[9] != 6 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2));
    let frag_offset = be16(p, 6) & 0x1fff;
    if ihl < 20 || frag_offset != 0 || total < ihl + 20 || total > p.len() {
        return None;
    }
    let tcp_hdr_len = usize::from(p[ihl + 12] >> 4) * 4;
    if tcp_hdr_len < 20 || ihl + tcp_hdr_len > total {
        return None;
    }
    Some(Tcp {
        fam: Family::V4,
        l4: ihl,
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]).into(),
        sport: be16(p, ihl),
        dport: be16(p, ihl + 2),
        flags: p[ihl + 13],
        ext: false,
    })
}

const IPV6_HDR: usize = 40;
const NH_HOP_BY_HOP: u8 = 0;
const NH_TCP: u8 = 6;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_AH: u8 = 51;
const NH_DEST_OPTS: u8 = 60;

fn parse6(p: &[u8]) -> Option<Tcp> {
    if p.len() < IPV6_HDR {
        return None;
    }
    let total = IPV6_HDR + usize::from(be16(p, 4));
    if total > p.len() {
        return None;
    }
    // Walk any extension headers to the TCP header, only to learn the ports
    // of a packet that will then not be rewritten.
    let mut next = p[6];
    let mut at = IPV6_HDR;
    while next != NH_TCP {
        if at + 8 > total {
            return None;
        }
        let len = match next {
            NH_HOP_BY_HOP | NH_ROUTING | NH_DEST_OPTS => (usize::from(p[at + 1]) + 1) * 8,
            NH_FRAGMENT => {
                if be16(p, at + 2) & 0xfff8 != 0 {
                    return None; // not the first fragment
                }
                8
            }
            NH_AH => (usize::from(p[at + 1]) + 2) * 4,
            _ => return None,
        };
        next = p[at];
        at += len;
    }
    if at + 20 > total {
        return None;
    }
    let tcp_hdr_len = usize::from(p[at + 12] >> 4) * 4;
    if tcp_hdr_len < 20 || at + tcp_hdr_len > total {
        return None;
    }
    let dst: [u8; 16] = p[24..40].try_into().ok()?;
    Some(Tcp {
        fam: Family::V6,
        l4: at,
        dst: Ipv6Addr::from(dst).into(),
        sport: be16(p, at),
        dport: be16(p, at + 2),
        flags: p[at + 13],
        ext: at != IPV6_HDR,
    })
}

/// Swaps the source and destination addresses (the TTL / hop limit and
/// everything else is kept).
fn swap_ips(p: &mut [u8], fam: Family) {
    let (src, dst) = match fam {
        Family::V4 => p[12..20].split_at_mut(4),
        Family::V6 => p[8..40].split_at_mut(16),
    };
    src.swap_with_slice(dst);
}

/// Reinjects the rewritten packet as inbound with fresh checksums.
fn finish(p: &mut [u8], addr: &mut Address) -> Verdict {
    addr.set_outbound(false);
    calc_checksums_addr(p, addr);
    Verdict::Rewritten
}

/// App -> D:pd (outbound) with a NAT entry for the app's source port whose
/// destination matches: reflected to `D:pa -> A:relay_port`, inbound. Such
/// a packet that cannot be rewritten (IPv6 extension headers) is dropped.
/// Anything else passes untouched.
pub fn redirect_outbound(
    pkt: &mut [u8],
    addr: &mut Address,
    relay_port: u16,
    nat: &NatTable,
) -> Verdict {
    if !addr.outbound() {
        return Verdict::Pass;
    }
    let Some(t) = parse(pkt) else {
        return Verdict::Pass;
    };
    if t.sport == relay_port {
        return Verdict::Pass;
    }
    let dst = SocketAddr::new(t.dst, t.dport);
    if t.ext {
        let redirected = nat.get(t.fam, t.sport).is_some_and(|o| o.dst == dst);
        return if redirected {
            Verdict::Drop
        } else {
            Verdict::Pass
        };
    }
    if nat
        .observe((t.fam, t.sport), t.flags, true, |o| o.dst == dst)
        .is_none()
    {
        return Verdict::Pass;
    }
    swap_ips(pkt, t.fam);
    pkt[t.l4 + 2..t.l4 + 4].copy_from_slice(&relay_port.to_be_bytes());
    finish(pkt, addr)
}

/// Relay `A:relay_port -> D:pa` (outbound): restored to `D:pd -> A:pa`,
/// inbound. Dropped if there is no NAT entry for `pa` (or it is for another
/// destination) or it cannot be rewritten (IPv6 extension headers); packets
/// not from `relay_port` pass untouched.
pub fn restore_inbound(
    pkt: &mut [u8],
    addr: &mut Address,
    relay_port: u16,
    nat: &NatTable,
) -> Verdict {
    if !addr.outbound() {
        return Verdict::Pass;
    }
    let Some(t) = parse(pkt) else {
        return Verdict::Pass;
    };
    if t.sport != relay_port {
        return Verdict::Pass;
    }
    if t.ext {
        return Verdict::Drop;
    }
    let Some(o) = nat.observe((t.fam, t.dport), t.flags, false, |o| o.dst.ip() == t.dst) else {
        return Verdict::Drop;
    };
    swap_ips(pkt, t.fam);
    pkt[t.l4..t.l4 + 2].copy_from_slice(&o.dst.port().to_be_bytes());
    finish(pkt, addr)
}
