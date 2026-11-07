//! Pure per-packet routing for outbound Network-layer packets (Ruling R12):
//! a per-flow decision cache makes sure no packet of a non-Direct flow is
//! ever passed, including after its NAT entry was swept or reset and for
//! flows that predate Q2Route.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use q2route_core::config::{GroupId, ProfileId};
use q2route_core::decide::{Decision, Route};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Cached TCP decisions expire after this long without packets.
pub const TCP_CACHE_IDLE: Duration = Duration::from_secs(60 * 60);
/// Cached UDP decisions expire after this long without packets.
pub const UDP_CACHE_IDLE: Duration = Duration::from_secs(5 * 60);

/// A transport flow seen from the local host: `local` is the packet's
/// source (outbound), `remote` its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub proto: u8,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PktMeta {
    pub flow: FlowId,
    /// TCP SYN without ACK (a connection attempt).
    pub syn: bool,
    /// TCP RST.
    pub rst: bool,
    /// TCP SYN+ACK (a local server answering an inbound connection).
    pub syn_ack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Reinject unchanged (Direct).
    Pass,
    /// Never send.
    Drop,
    /// Never send; instead inject an RST toward the app (see
    /// [`build_rst_to_app`]) so a non-Direct TCP flow that lost its NAT
    /// entry fails fast instead of hanging. Nothing goes to the remote.
    Reset,
    /// The flow has a NAT entry: reflect it to the relay (drop if that fails).
    Redirect,
    /// Insert a NAT entry for this new flow owned by `pid`, then redirect.
    NewRedirect { pid: u32 },
    /// IPv4 UDP of a proxied flow: relay it through the SOCKS5 profile.
    /// `pid` is the owning pid (from the decision, also on a cache hit).
    UdpProxy {
        pid: u32,
        profile: ProfileId,
        group_id: Option<GroupId>,
    },
}

/// A cached per-flow routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cached {
    Direct,
    /// Block, or a proxied TCP flow (handled by the TCP relay).
    Other,
    /// Proxied UDP flow: profile, group, owning pid.
    UdpProxy(ProfileId, Option<GroupId>, u32),
}

struct CacheEntry {
    cached: Cached,
    last_seen: Instant,
    /// Rules generation the decision was made under.
    generation: u64,
}

/// Per-flow route cache. Thread-safe.
#[derive(Default)]
pub struct FlowCache {
    map: Mutex<HashMap<FlowId, CacheEntry>>,
    /// Bumped by [`FlowCache::on_rules_changed`].
    generation: AtomicU64,
}

impl FlowCache {
    fn lock(&self) -> MutexGuard<'_, HashMap<FlowId, CacheEntry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current rules generation. Read it *before* loading the rules for a
    /// decision and store the decision with [`FlowCache::put_at`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Cached decision; refreshes the entry's idle timer.
    /// A decision made under older rules counts as uncached, except a
    /// non-Direct TCP one (such a flow must never continue direct).
    pub fn get(&self, id: &FlowId) -> Option<Cached> {
        let current = self.generation();
        let mut g = self.lock();
        let e = g.get_mut(id)?;
        if e.generation != current && (id.proto != PROTO_TCP || e.cached == Cached::Direct) {
            g.remove(id);
            return None;
        }
        e.last_seen = Instant::now();
        Some(e.cached.clone())
    }

    /// Stores a decision made under the current rules generation.
    pub fn put(&self, id: FlowId, cached: Cached) {
        self.put_at(id, cached, self.generation());
    }

    /// Stores a decision made under rules generation `generation`.
    pub fn put_at(&self, id: FlowId, cached: Cached, generation: u64) {
        self.lock().insert(
            id,
            CacheEntry {
                cached,
                last_seen: Instant::now(),
                generation,
            },
        );
    }

    /// A Socket-layer CLOSE for `local` (an unspecified ip matches any local
    /// ip with that port): forgets its UDP decisions and its Direct TCP
    /// decisions, so a new socket reusing the port is decided afresh.
    /// Non-Direct TCP decisions stay, so the closed flow's stray packets
    /// (FIN retransmits, final ACK) are still never sent direct.
    pub fn on_socket_closed(&self, proto: u8, local: SocketAddr) {
        let same_local = |l: &SocketAddr| {
            l.port() == local.port() && (local.ip().is_unspecified() || l.ip() == local.ip())
        };
        self.lock().retain(|id, e| {
            !(id.proto == proto
                && same_local(&id.local)
                && (proto != PROTO_TCP || e.cached == Cached::Direct))
        });
    }

    /// A Socket-layer ACCEPT: a local server accepted `remote`. The flow is
    /// Direct: the remote connected to the real IP, so replying from it
    /// reveals nothing (otherwise the SYN-ACK would be decided as an
    /// outgoing flow and dropped by a proxied catch-all).
    pub fn on_accept(&self, local: SocketAddr, remote: SocketAddr) {
        let id = FlowId {
            proto: PROTO_TCP,
            local,
            remote,
        };
        self.put(id, Cached::Direct);
    }

    /// Drops entries idle past [`TCP_CACHE_IDLE`] / [`UDP_CACHE_IDLE`].
    pub fn sweep(&self, now: Instant) {
        self.lock().retain(|id, e| {
            let idle = if id.proto == PROTO_TCP {
                TCP_CACHE_IDLE
            } else {
                UDP_CACHE_IDLE
            };
            now.saturating_duration_since(e.last_seen) <= idle
        });
    }

    /// After a rule change: forgets every Direct decision and every UDP
    /// decision, so those flows are re-decided on their next packet (a
    /// direct flow whose group is now proxied is dropped, not leaked). Only
    /// non-Direct TCP decisions are kept: such a flow went to the relay and
    /// must never continue direct.
    pub fn on_rules_changed(&self) {
        // Bump first: a decision still being made under the old rules is
        // stored with the old generation and so ignored by `get`.
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.lock()
            .retain(|id, e| id.proto == PROTO_TCP && e.cached != Cached::Direct);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Routes one outbound packet.
///
/// * `own_port`: the local port is one of the relay's own direct upstream
///   sockets (always passed).
/// * `own_pid`: the service's pid; its flows are always Direct (Ruling R13).
/// * `nat_has`: a NAT entry exists for this flow (same local port and
///   destination).
/// * `decide`: looks up the owning pid and decides the flow; only called
///   when the cache cannot answer.
///
/// Invariant: `Pass` is only returned for a flow whose (cached or fresh)
/// decision is Direct, or for the service's own sockets. A proxied UDP flow
/// is never passed: it is `UdpProxy` (IPv4 only) or `Drop`.
pub fn classify(
    m: &PktMeta,
    own_port: bool,
    own_pid: u32,
    cache: &FlowCache,
    nat_has: bool,
    decide: impl FnOnce() -> (u32, Decision),
) -> Action {
    if own_port {
        return Action::Pass;
    }
    let id = m.flow;
    // Read before `decide` loads the rules (the engine swaps rules, then
    // bumps the generation), so an old-rules decision is never trusted.
    let generation = cache.generation();
    // Decides now and remembers the outcome; returns (pid, decision).
    let decide_now = |decide: &mut dyn FnMut() -> (u32, Decision)| -> (u32, Cached) {
        let (pid, d) = decide();
        let cached = if pid == own_pid {
            Cached::Direct
        } else {
            match d {
                Decision::Final(Route::Direct, _) => Cached::Direct,
                // Only IPv4 UDP is relayed; proxied TCP is `Other` here.
                Decision::Final(Route::Proxy(p), info)
                    if id.proto == PROTO_UDP && id.remote.is_ipv4() =>
                {
                    Cached::UdpProxy(p, info.group_id, pid)
                }
                _ => Cached::Other,
            }
        };
        cache.put_at(id, cached.clone(), generation);
        (pid, cached)
    };
    // Every path below calls `decide` at most once.
    let mut decide = Some(decide);
    let mut call = || decide.take().map_or((0, Decision::NeedDomain), |f| f());
    match id.proto {
        PROTO_TCP if m.syn => {
            // A connection attempt is always (re)decided.
            let (pid, cached) = decide_now(&mut call);
            if cached == Cached::Direct {
                Action::Pass
            } else if id.remote.is_ipv4() {
                Action::NewRedirect { pid }
            } else {
                // No IPv6 relay in M1: never let a non-Direct IPv6 flow out.
                Action::Drop
            }
        }
        PROTO_TCP => {
            // A non-Direct flow without a NAT entry is never sent; the app
            // gets an RST so it fails fast. An RST is never answered, and a
            // SYN-ACK whose ACCEPT event has not arrived yet is only dropped
            // (its retransmit passes once the accept is cached as Direct).
            let stop = if m.rst || m.syn_ack {
                Action::Drop
            } else {
                Action::Reset
            };
            match cache.get(&id) {
                Some(Cached::Direct) => Action::Pass,
                Some(_) if nat_has => Action::Redirect,
                Some(_) => stop,
                None if nat_has => {
                    cache.put(id, Cached::Other);
                    Action::Redirect
                }
                // A flow that predates Q2Route: only a Direct flow may continue.
                None => match decide_now(&mut call) {
                    (_, Cached::Direct) => Action::Pass,
                    (_, _) => stop,
                },
            }
        }
        PROTO_UDP => {
            let cached = match cache.get(&id) {
                Some(c) => c,
                None => decide_now(&mut call).1,
            };
            match cached {
                Cached::Direct => Action::Pass,
                Cached::UdpProxy(profile, group_id, pid) if id.remote.is_ipv4() => {
                    Action::UdpProxy {
                        pid,
                        profile,
                        group_id,
                    }
                }
                _ => Action::Drop,
            }
        }
        _ => Action::Drop,
    }
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

/// Parses an IPv4/IPv6 TCP or UDP packet (first fragment only). IPv6
/// hop-by-hop, routing, destination-options and fragment headers are
/// skipped. Returns `None` for anything else.
pub fn parse(p: &[u8]) -> Option<PktMeta> {
    let (src, dst, proto, l4) = match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let ihl = usize::from(p[0] & 0x0f) * 4;
            let total = usize::from(be16(p, 2));
            if ihl < 20 || total < ihl || total > p.len() || be16(p, 6) & 0x1fff != 0 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
            (src, dst, p[9], &p[ihl..total])
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let total = (40 + usize::from(be16(p, 4))).min(p.len());
            let octets = |at: usize| -> [u8; 16] { p[at..at + 16].try_into().expect("16 bytes") };
            let src = IpAddr::V6(Ipv6Addr::from(octets(8)));
            let dst = IpAddr::V6(Ipv6Addr::from(octets(24)));
            let (mut next, mut at) = (p[6], 40);
            loop {
                match next {
                    // hop-by-hop, routing, destination options
                    0 | 43 | 60 => {
                        if at + 8 > total {
                            return None;
                        }
                        next = p[at];
                        at += (usize::from(p[at + 1]) + 1) * 8;
                    }
                    // fragment: only the first fragment carries ports
                    44 => {
                        if at + 8 > total || be16(p, at + 2) & 0xfff8 != 0 {
                            return None;
                        }
                        next = p[at];
                        at += 8;
                    }
                    _ => break,
                }
            }
            if at > total {
                return None;
            }
            (src, dst, next, &p[at..total])
        }
        _ => return None,
    };
    let min = match proto {
        PROTO_TCP => 20,
        PROTO_UDP => 8,
        _ => return None,
    };
    if l4.len() < min {
        return None;
    }
    let flags = if proto == PROTO_TCP { l4[13] } else { 0 };
    Some(PktMeta {
        flow: FlowId {
            proto,
            local: SocketAddr::new(src, be16(l4, 0)),
            remote: SocketAddr::new(dst, be16(l4, 2)),
        },
        syn: flags & TCP_SYN != 0 && flags & TCP_ACK == 0,
        rst: flags & TCP_RST != 0,
        syn_ack: flags & TCP_SYN != 0 && flags & TCP_ACK != 0,
    })
}

fn be32(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

/// Builds the RST an outbound TCP packet `A:pa -> D:pd` would get from
/// `D:pd` (RFC 793 reset generation): `seq = SEG.ACK` if the packet has ACK,
/// else `seq = 0, ack = SEG.SEQ + SEG.LEN` with RST|ACK. The result is
/// addressed `D:pd -> A:pa`, to be injected **inbound** to the app, with
/// checksums still to be computed. `None` for SYN, RST, non-TCP, IP
/// fragments, IPv6 extension headers or malformed packets.
pub fn build_rst_to_app(p: &[u8]) -> Option<Vec<u8>> {
    let (ip_len, l4_end) = match p.first()? >> 4 {
        4 => {
            if p.len() < 20 || p[9] != PROTO_TCP || be16(p, 6) & 0x3fff != 0 {
                return None;
            }
            (usize::from(p[0] & 0x0f) * 4, usize::from(be16(p, 2)))
        }
        6 => {
            if p.len() < 40 || p[6] != PROTO_TCP {
                return None;
            }
            (40, 40 + usize::from(be16(p, 4)))
        }
        _ => return None,
    };
    if ip_len < 20 || l4_end > p.len() || l4_end < ip_len + 20 {
        return None;
    }
    let t = &p[ip_len..l4_end];
    let hdr = usize::from(t[12] >> 4) * 4;
    let flags = t[13];
    if hdr < 20 || hdr > t.len() || flags & (TCP_SYN | TCP_RST) != 0 {
        return None;
    }
    let (seq, ack, out_flags) = if flags & TCP_ACK != 0 {
        (be32(t, 8), 0, TCP_RST)
    } else {
        let seg_len = (t.len() - hdr) as u32 + u32::from(flags & TCP_FIN != 0);
        (0, be32(t, 4).wrapping_add(seg_len), TCP_RST | TCP_ACK)
    };
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&t[2..4]); // from the original dst port
    tcp[2..4].copy_from_slice(&t[0..2]); // to the app's port
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = out_flags;
    let mut out = Vec::with_capacity(60);
    if p[0] >> 4 == 4 {
        out.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, PROTO_TCP, 0, 0]);
        out.extend_from_slice(&p[16..20]); // src = original dst
        out.extend_from_slice(&p[12..16]); // dst = the app
    } else {
        out.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
        out.extend_from_slice(&p[24..40]);
        out.extend_from_slice(&p[8..24]);
    }
    out.extend_from_slice(&tcp);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::decide::{MatchInfo, MatchReason};
    use std::cell::Cell;

    const APP_PID: u32 = 4242;
    const OWN_PID: u32 = 7;

    fn info() -> MatchInfo {
        MatchInfo {
            group_id: Some("g".into()),
            reason: MatchReason::CatchAll,
        }
    }
    fn direct() -> Decision {
        Decision::Final(Route::Direct, info())
    }
    fn proxy() -> Decision {
        Decision::Final(Route::Proxy("v2ray".into()), info())
    }
    fn block() -> Decision {
        Decision::Final(Route::Block, info())
    }

    fn meta(proto: u8, local: &str, remote: &str, syn: bool) -> PktMeta {
        PktMeta {
            flow: FlowId {
                proto,
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
            },
            syn,
            rst: false,
            syn_ack: false,
        }
    }
    fn tcp(syn: bool) -> PktMeta {
        meta(PROTO_TCP, "192.168.1.5:50000", "1.2.3.4:443", syn)
    }

    /// Runs classify with a decide fn that records how often it was called.
    fn run(
        m: &PktMeta,
        cache: &FlowCache,
        nat_has: bool,
        pid: u32,
        d: Decision,
        calls: &Cell<u32>,
    ) -> Action {
        classify(m, false, OWN_PID, cache, nat_has, || {
            calls.set(calls.get() + 1);
            (pid, d)
        })
    }

    #[test]
    fn syn_direct_passes_and_caches() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(true), &c, false, APP_PID, direct(), &n),
            Action::Pass
        );
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, proxy(), &n),
            Action::Pass
        );
        assert_eq!(n.get(), 1, "non-SYN answered from cache");
    }

    #[test]
    fn syn_proxied_redirects() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(true), &c, false, APP_PID, proxy(), &n),
            Action::NewRedirect { pid: APP_PID }
        );
        assert_eq!(
            run(&tcp(false), &c, true, APP_PID, proxy(), &n),
            Action::Redirect
        );
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn syn_need_domain_or_block_redirects_to_relay() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(true), &c, false, 1, Decision::NeedDomain, &n),
            Action::NewRedirect { pid: 1 }
        );
        assert_eq!(
            run(&tcp(true), &c, false, 2, block(), &n),
            Action::NewRedirect { pid: 2 }
        );
    }

    #[test]
    fn non_syn_of_proxied_flow_after_nat_removed_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        run(&tcp(true), &c, false, APP_PID, proxy(), &n);
        // NAT entry swept / reset: the packet must not leave direct, even
        // if the rules now say Direct; the app gets an RST so it fails fast.
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Reset
        );
        assert_eq!(n.get(), 1);
        // An RST of that flow is only dropped (never answer an RST).
        let rst = PktMeta {
            rst: true,
            ..tcp(false)
        };
        assert_eq!(run(&rst, &c, false, APP_PID, direct(), &n), Action::Drop);
    }

    #[test]
    fn non_syn_unknown_flow_proxied_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, proxy(), &n),
            Action::Reset
        );
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, proxy(), &n),
            Action::Reset
        );
        assert_eq!(n.get(), 1, "cached after the first decision");
        let c = FlowCache::default();
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, Decision::NeedDomain, &n),
            Action::Reset
        );
    }

    #[test]
    fn non_syn_unknown_flow_direct_passes() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Pass
        );
    }

    #[test]
    fn non_syn_with_nat_entry_redirects_without_deciding() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(false), &c, true, APP_PID, direct(), &n),
            Action::Redirect
        );
        assert_eq!(n.get(), 0);
        // and is remembered as non-Direct once the entry goes away
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Reset
        );
    }

    #[test]
    fn direct_cached_flow_ignores_stale_nat_entry() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        run(&tcp(true), &c, true, APP_PID, direct(), &n);
        assert_eq!(
            run(&tcp(false), &c, true, APP_PID, direct(), &n),
            Action::Pass
        );
    }

    #[test]
    fn retransmitted_syn_is_redecided() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        run(&tcp(true), &c, false, APP_PID, direct(), &n);
        assert_eq!(
            run(&tcp(true), &c, false, APP_PID, proxy(), &n),
            Action::NewRedirect { pid: APP_PID }
        );
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Reset
        );
    }

    #[test]
    fn own_pid_passes() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(true), &c, false, OWN_PID, proxy(), &n),
            Action::Pass
        );
        assert_eq!(
            run(&tcp(false), &c, false, OWN_PID, proxy(), &n),
            Action::Pass
        );
        let c = FlowCache::default();
        assert_eq!(
            run(&tcp(false), &c, false, OWN_PID, proxy(), &n),
            Action::Pass
        );
        let u = meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false);
        assert_eq!(
            run(&u, &FlowCache::default(), false, OWN_PID, block(), &n),
            Action::Pass
        );
    }

    #[test]
    fn own_port_passes_without_deciding() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let a = classify(&tcp(true), true, OWN_PID, &c, false, || {
            n.set(1);
            (APP_PID, proxy())
        });
        assert_eq!(a, Action::Pass);
        assert_eq!(n.get(), 0);
    }

    #[test]
    fn ipv6_proxied_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let syn = meta(PROTO_TCP, "[2001:db8::5]:50000", "[2001:db8::1]:443", true);
        let ack = PktMeta { syn: false, ..syn };
        // decide() maps proxied IPv6 to Block; even a Proxy answer must not pass.
        assert_eq!(run(&syn, &c, false, APP_PID, proxy(), &n), Action::Drop);
        assert_eq!(run(&ack, &c, false, APP_PID, direct(), &n), Action::Reset);
        assert_eq!(run(&syn, &c, false, APP_PID, block(), &n), Action::Drop);
        let c = FlowCache::default();
        assert_eq!(
            run(&syn, &c, false, APP_PID, Decision::NeedDomain, &n),
            Action::Drop
        );
        assert_eq!(run(&syn, &c, false, APP_PID, direct(), &n), Action::Pass);
        assert_eq!(run(&ack, &c, false, APP_PID, proxy(), &n), Action::Pass);
    }

    #[test]
    fn udp_proxied_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let u = meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false);
        assert_eq!(run(&u, &c, false, APP_PID, block(), &n), Action::Drop);
        assert_eq!(run(&u, &c, false, APP_PID, direct(), &n), Action::Drop);
        assert_eq!(n.get(), 1);
        let c = FlowCache::default();
        let u6 = meta(PROTO_UDP, "[2001:db8::5]:5000", "[2001:db8::1]:443", false);
        assert_eq!(run(&u6, &c, false, APP_PID, block(), &n), Action::Drop);
    }

    fn udp_stun() -> PktMeta {
        meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:3478", false)
    }

    #[test]
    fn udp_proxy_decision_returns_udp_proxy() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let want = Action::UdpProxy {
            pid: APP_PID,
            profile: "v2ray".into(),
            group_id: Some("g".into()),
        };
        assert_eq!(run(&udp_stun(), &c, false, APP_PID, proxy(), &n), want);
        // A cache hit returns the same action, pid included.
        assert_eq!(run(&udp_stun(), &c, false, APP_PID, proxy(), &n), want);
        assert_eq!(n.get(), 1, "second packet from cache");
    }

    #[test]
    fn udp_block_still_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&udp_stun(), &c, false, APP_PID, block(), &n),
            Action::Drop
        );
        assert_eq!(
            run(&udp_stun(), &c, false, APP_PID, direct(), &n),
            Action::Drop
        );
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn udp_direct_still_passes() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&udp_stun(), &c, false, APP_PID, direct(), &n),
            Action::Pass
        );
        assert_eq!(
            run(&udp_stun(), &c, false, APP_PID, block(), &n),
            Action::Pass
        );
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn udp_ipv6_proxy_never_udp_proxy() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let u6 = meta(PROTO_UDP, "[2001:db8::5]:5000", "[2001:db8::1]:3478", false);
        assert_eq!(run(&u6, &c, false, APP_PID, proxy(), &n), Action::Drop);
        assert_eq!(run(&u6, &c, false, APP_PID, proxy(), &n), Action::Drop);
    }

    #[test]
    fn rules_change_redecides_udp_proxy() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let is_proxy = |a: &Action| matches!(a, Action::UdpProxy { .. });
        assert!(is_proxy(&run(&udp_stun(), &c, false, APP_PID, proxy(), &n)));
        c.on_rules_changed();
        assert_eq!(
            run(&udp_stun(), &c, false, APP_PID, block(), &n),
            Action::Drop
        );
        assert_eq!(n.get(), 2, "decided again under the new rules");
    }

    #[test]
    fn rule_change_rechecks_direct_and_udp_but_keeps_proxied_tcp() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let u = meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false);
        let direct_tcp = meta(PROTO_TCP, "192.168.1.5:50001", "5.6.7.8:443", false);
        assert_eq!(run(&u, &c, false, APP_PID, direct(), &n), Action::Pass);
        assert_eq!(
            run(&direct_tcp, &c, false, APP_PID, direct(), &n),
            Action::Pass
        );
        run(&tcp(true), &c, false, APP_PID, proxy(), &n);
        c.on_rules_changed();
        assert_eq!(c.len(), 1, "only the proxied TCP decision is kept");
        // The group is now proxied: established direct flows stop, not leak.
        assert_eq!(run(&u, &c, false, APP_PID, block(), &n), Action::Drop);
        assert_eq!(
            run(&direct_tcp, &c, false, APP_PID, proxy(), &n),
            Action::Reset
        );
        // The proxied flow stays non-Direct even if the rules now say Direct.
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Reset
        );
    }

    #[test]
    fn socket_close_forgets_udp_decision_for_reused_port() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let u = meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false);
        assert_eq!(run(&u, &c, false, APP_PID, direct(), &n), Action::Pass);
        // The socket closes; a proxied app reuses the port for the same remote.
        c.on_socket_closed(PROTO_UDP, "10.0.0.2:5000".parse().unwrap());
        assert_eq!(run(&u, &c, false, APP_PID + 1, block(), &n), Action::Drop);
        // A wildcard-bound close also matches the concrete local address.
        assert_eq!(run(&u, &c, false, APP_PID, block(), &n), Action::Drop);
        c.put(u.flow, Cached::Direct);
        c.on_socket_closed(PROTO_UDP, "0.0.0.0:5000".parse().unwrap());
        assert!(c.is_empty());
    }

    #[test]
    fn socket_close_keeps_proxied_tcp_but_forgets_direct_tcp() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let d = meta(PROTO_TCP, "192.168.1.5:50001", "5.6.7.8:443", false);
        run(&tcp(true), &c, false, APP_PID, proxy(), &n);
        run(&d, &c, false, APP_PID, direct(), &n);
        c.on_socket_closed(PROTO_TCP, tcp(true).flow.local);
        c.on_socket_closed(PROTO_TCP, d.flow.local);
        // Stray packets of the closed proxied flow still never leave direct.
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Reset
        );
        assert_eq!(run(&d, &c, false, APP_PID, proxy(), &n), Action::Reset);
    }

    #[test]
    fn decision_made_with_old_rules_is_not_trusted_after_rule_change() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let u = meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false);
        // A packet thread is mid-decision (old rules: Direct) while the
        // rules are swapped and the cache is invalidated.
        let a = classify(&u, false, OWN_PID, &c, false, || {
            c.on_rules_changed();
            (APP_PID, direct())
        });
        assert_eq!(
            a,
            Action::Pass,
            "that one packet was decided under the old rules"
        );
        assert_eq!(run(&u, &c, false, APP_PID, block(), &n), Action::Drop);
        assert_eq!(n.get(), 1, "re-decided under the new rules");
    }

    #[test]
    fn accepted_inbound_flow_is_direct() {
        // A local server accepted 8.8.8.8:40000 -> 192.168.1.5:8080; its
        // replies (SYN-ACK, data) go direct: the remote already knows the IP.
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let local = "192.168.1.5:8080".parse().unwrap();
        let remote = "8.8.8.8:40000".parse().unwrap();
        c.on_accept(local, remote);
        let syn_ack = PktMeta {
            syn_ack: true,
            ..meta(PROTO_TCP, "192.168.1.5:8080", "8.8.8.8:40000", false)
        };
        assert_eq!(run(&syn_ack, &c, false, APP_PID, proxy(), &n), Action::Pass);
        let data = meta(PROTO_TCP, "192.168.1.5:8080", "8.8.8.8:40000", false);
        assert_eq!(run(&data, &c, false, APP_PID, proxy(), &n), Action::Pass);
        assert_eq!(n.get(), 0, "never decided as an outgoing flow");
    }

    #[test]
    fn syn_ack_before_accept_event_is_dropped_not_reset() {
        // The Socket-layer ACCEPT event can lag the SYN-ACK: drop it (it is
        // retransmitted) rather than RST the server's new connection.
        let (c, n) = (FlowCache::default(), Cell::new(0));
        let syn_ack = PktMeta {
            syn_ack: true,
            ..meta(PROTO_TCP, "192.168.1.5:8080", "8.8.8.8:40000", false)
        };
        assert_eq!(run(&syn_ack, &c, false, APP_PID, proxy(), &n), Action::Drop);
        c.on_accept(syn_ack.flow.local, syn_ack.flow.remote);
        assert_eq!(run(&syn_ack, &c, false, APP_PID, proxy(), &n), Action::Pass);
    }

    #[test]
    fn parse_sets_syn_ack() {
        assert!(parse(&build_v4_tcp(true, true)).unwrap().syn_ack);
        assert!(!parse(&build_v4_tcp(true, false)).unwrap().syn_ack);
        assert!(!parse(&build_v4_tcp(false, true)).unwrap().syn_ack);
    }

    #[test]
    fn cache_sweep_expires_idle_entries() {
        let c = FlowCache::default();
        c.put(tcp(true).flow, Cached::Other);
        c.put(
            meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false).flow,
            Cached::Direct,
        );
        c.sweep(Instant::now());
        assert_eq!(c.len(), 2);
        c.sweep(Instant::now() + UDP_CACHE_IDLE + Duration::from_secs(1));
        assert_eq!(c.len(), 1);
        c.sweep(Instant::now() + TCP_CACHE_IDLE + Duration::from_secs(1));
        assert!(c.is_empty());
    }

    fn build_v4_tcp(syn: bool, ack: bool) -> Vec<u8> {
        let mut b = etherparse::PacketBuilder::ipv4([192, 168, 1, 5], [1, 2, 3, 4], 64)
            .tcp(50000, 443, 1, 65535);
        if syn {
            b = b.syn();
        }
        if ack {
            b = b.ack(9);
        }
        let mut out = Vec::new();
        b.write(&mut out, b"hi").unwrap();
        out
    }

    #[test]
    fn parse_sets_rst() {
        let mut out = Vec::new();
        etherparse::PacketBuilder::ipv4([192, 168, 1, 5], [1, 2, 3, 4], 64)
            .tcp(50000, 443, 1, 65535)
            .rst()
            .write(&mut out, b"")
            .unwrap();
        let m = parse(&out).unwrap();
        assert!(m.rst && !m.syn);
        assert!(!parse(&build_v4_tcp(false, true)).unwrap().rst);
    }

    #[test]
    fn rst_to_app_v4_with_ack() {
        // App A:50000 -> D:443, seq 1, ack 9, payload "hi".
        let pkt = build_v4_tcp(false, true);
        let rst = build_rst_to_app(&pkt).unwrap();
        let s = etherparse::SlicedPacket::from_ip(&rst).unwrap();
        let Some(etherparse::NetSlice::Ipv4(ip)) = s.net else {
            panic!("not ipv4")
        };
        assert_eq!(ip.header().source(), [1, 2, 3, 4], "from the original dst");
        assert_eq!(ip.header().destination(), [192, 168, 1, 5]);
        let Some(etherparse::TransportSlice::Tcp(t)) = s.transport else {
            panic!("not tcp")
        };
        assert_eq!((t.source_port(), t.destination_port()), (443, 50000));
        assert!(t.rst() && !t.syn() && !t.fin());
        assert!(!t.ack(), "RST answering an ACK carries no ACK");
        assert_eq!(t.sequence_number(), 9, "seq = the dropped packet's ack");
        assert!(t.payload().is_empty());
    }

    #[test]
    fn rst_to_app_v4_without_ack() {
        // A non-SYN segment without ACK: RST|ACK, ack = seq + len.
        let mut out = Vec::new();
        etherparse::PacketBuilder::ipv4([192, 168, 1, 5], [1, 2, 3, 4], 64)
            .tcp(50000, 443, 100, 65535)
            .fin()
            .write(&mut out, b"abc")
            .unwrap();
        let rst = build_rst_to_app(&out).unwrap();
        let s = etherparse::SlicedPacket::from_ip(&rst).unwrap();
        let Some(etherparse::TransportSlice::Tcp(t)) = s.transport else {
            panic!("not tcp")
        };
        assert!(t.rst() && t.ack());
        assert_eq!(t.sequence_number(), 0);
        assert_eq!(t.acknowledgment_number(), 100 + 3 + 1, "data + FIN");
    }

    #[test]
    fn rst_to_app_v6() {
        let src: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut out = Vec::new();
        etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
            .tcp(50000, 443, 1, 65535)
            .ack(77)
            .write(&mut out, b"x")
            .unwrap();
        let rst = build_rst_to_app(&out).unwrap();
        let s = etherparse::SlicedPacket::from_ip(&rst).unwrap();
        let Some(etherparse::NetSlice::Ipv6(ip)) = s.net else {
            panic!("not ipv6")
        };
        assert_eq!(ip.header().source_addr(), dst);
        assert_eq!(ip.header().destination_addr(), src);
        let Some(etherparse::TransportSlice::Tcp(t)) = s.transport else {
            panic!("not tcp")
        };
        assert_eq!((t.source_port(), t.destination_port()), (443, 50000));
        assert!(t.rst());
        assert_eq!(t.sequence_number(), 77);
    }

    #[test]
    fn rst_never_built_for_rst_syn_or_udp() {
        let mut out = Vec::new();
        etherparse::PacketBuilder::ipv4([192, 168, 1, 5], [1, 2, 3, 4], 64)
            .tcp(50000, 443, 1, 65535)
            .rst()
            .write(&mut out, b"")
            .unwrap();
        assert!(build_rst_to_app(&out).is_none());
        assert!(build_rst_to_app(&build_v4_tcp(true, false)).is_none());
        let mut u = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [8, 8, 4, 4], 64)
            .udp(5000, 443)
            .write(&mut u, b"q")
            .unwrap();
        assert!(build_rst_to_app(&u).is_none());
        assert!(build_rst_to_app(&[0x45, 0, 0]).is_none());
    }

    #[test]
    fn parse_ipv4_tcp() {
        let m = parse(&build_v4_tcp(true, false)).unwrap();
        assert_eq!(m, tcp(true));
        assert!(
            !parse(&build_v4_tcp(true, true)).unwrap().syn,
            "SYN-ACK is not a connection attempt"
        );
        assert!(!parse(&build_v4_tcp(false, true)).unwrap().syn);
    }

    #[test]
    fn parse_ipv6_udp_and_rejects_garbage() {
        let src: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b = etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(5000, 443);
        let mut out = Vec::new();
        b.write(&mut out, b"q").unwrap();
        let m = parse(&out).unwrap();
        assert_eq!(
            m,
            meta(PROTO_UDP, "[2001:db8::5]:5000", "[2001:db8::1]:443", false)
        );
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&out[..30]), None);
        let mut v4 = build_v4_tcp(false, true);
        v4[6] = 0x00;
        v4[7] = 0x10; // fragment offset != 0
        assert_eq!(parse(&v4), None);
    }
}
