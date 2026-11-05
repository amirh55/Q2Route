//! TCP NAT redirect using the WinDivert "streamdump" reflection technique
//! (IPv4/TCP only in M1).
//!
//! * App packet `A:pa -> D:pd` (outbound, NAT entry for `pa`): rewritten to
//!   `D:pa -> A:relay_port` and reinjected inbound, so the relay listener
//!   sees a connection from peer `D:pa`.
//! * Relay packet `A:relay_port -> D:pa` (outbound): rewritten to
//!   `D:pd -> A:pa` and reinjected inbound, so the app sees `D:pd`.
//!
//! Entries are keyed by the app's source port `pa`. The engine inserts the
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

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::windivert::{calc_checksums_addr, Address};

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const CLOSE_LINGER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalDst {
    pub dst: SocketAddrV4,
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
    map: Mutex<HashMap<u16, Entry>>,
    next_token: std::sync::atomic::AtomicU64,
}

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

impl NatTable {
    fn lock(&self) -> MutexGuard<'_, HashMap<u16, Entry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Inserts (or replaces, e.g. on port reuse) the entry for `app_port`.
    pub fn insert(&self, app_port: u16, o: OriginalDst) {
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
        self.lock().insert(app_port, e);
    }

    pub fn get(&self, app_port: u16) -> Option<OriginalDst> {
        self.lock().get(&app_port).map(|e| e.o)
    }

    pub fn remove(&self, app_port: u16) {
        self.lock().remove(&app_port);
    }

    /// The relay accepted the connection from peer `ip:app_port`: returns
    /// the original destination and a token for [`NatTable::release`], and
    /// marks the entry as held by a live relay connection (never idle-swept).
    pub fn attach(&self, app_port: u16, ip: Ipv4Addr) -> Option<(OriginalDst, u64)> {
        let mut g = self.lock();
        let e = g.get_mut(&app_port).filter(|e| *e.o.dst.ip() == ip)?;
        e.attached = true;
        Some((e.o, e.token))
    }

    /// The relay connection that attached `token` ended: the entry lingers
    /// for [`CLOSE_LINGER`] (final ACK / FIN retransmits), then is swept. A
    /// stale token (the port was reused by a newer flow) is ignored.
    pub fn release(&self, app_port: u16, token: u64) {
        let mut g = self.lock();
        if let Some(e) = g.get_mut(&app_port).filter(|e| e.token == token) {
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

    /// Looks up `app_port`; if present and `accept` holds, records activity
    /// and TCP close state, and returns the entry.
    fn observe(
        &self,
        app_port: u16,
        tcp_flags: u8,
        from_app: bool,
        accept: impl FnOnce(&OriginalDst) -> bool,
    ) -> Option<OriginalDst> {
        let mut g = self.lock();
        let e = g.get_mut(&app_port)?;
        if !accept(&e.o) {
            return None;
        }
        let o = e.o;
        let now = Instant::now();
        e.last_seen = now;
        if tcp_flags & TCP_RST != 0 {
            g.remove(&app_port);
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

/// A bounds-checked view of an IPv4/TCP packet's fields we touch.
struct Tcp4 {
    ihl: usize,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

/// Returns `None` for anything that is not a complete, first-fragment
/// IPv4/TCP packet.
fn parse(p: &[u8]) -> Option<Tcp4> {
    if p.len() < 20 || p[0] >> 4 != 4 || p[9] != 6 {
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
    Some(Tcp4 {
        ihl,
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        sport: be16(p, ihl),
        dport: be16(p, ihl + 2),
        flags: p[ihl + 13],
    })
}

fn swap_ips(p: &mut [u8]) {
    let (src, dst) = p[12..20].split_at_mut(4);
    src.swap_with_slice(dst);
}

/// Reinjects the rewritten packet as inbound with fresh checksums.
fn finish(p: &mut [u8], addr: &mut Address) -> Verdict {
    addr.set_outbound(false);
    calc_checksums_addr(p, addr);
    Verdict::Rewritten
}

/// App -> D:pd (outbound) with a NAT entry for the app's source port whose
/// destination matches: reflected to `D:pa -> A:relay_port`, inbound.
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
    let dst = SocketAddrV4::new(t.dst, t.dport);
    if nat
        .observe(t.sport, t.flags, true, |o| o.dst == dst)
        .is_none()
    {
        return Verdict::Pass;
    }
    swap_ips(pkt);
    pkt[t.ihl + 2..t.ihl + 4].copy_from_slice(&relay_port.to_be_bytes());
    finish(pkt, addr)
}

/// Relay `A:relay_port -> D:pa` (outbound): restored to `D:pd -> A:pa`,
/// inbound. Dropped if there is no NAT entry for `pa` (or it is for another
/// destination); packets not from `relay_port` pass untouched.
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
    let Some(o) = nat.observe(t.dport, t.flags, false, |o| *o.dst.ip() == t.dst) else {
        return Verdict::Drop;
    };
    swap_ips(pkt);
    pkt[t.ihl..t.ihl + 2].copy_from_slice(&o.dst.port().to_be_bytes());
    finish(pkt, addr)
}
