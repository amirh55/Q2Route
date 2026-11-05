//! Pure per-packet routing for outbound Network-layer packets (Ruling R12):
//! a per-flow decision cache makes sure no packet of a non-Direct flow is
//! ever passed, including after its NAT entry was swept or reset and for
//! flows that predate Q2Route.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use q2route_core::decide::{Decision, Route};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const TCP_SYN: u8 = 0x02;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Reinject unchanged (Direct).
    Pass,
    /// Never send.
    Drop,
    /// The flow has a NAT entry: reflect it to the relay (drop if that fails).
    Redirect,
    /// Insert a NAT entry for this new flow owned by `pid`, then redirect.
    NewRedirect { pid: u32 },
}

struct CacheEntry {
    direct: bool,
    last_seen: Instant,
}

/// Per-flow route cache: `true` = Direct. Thread-safe.
#[derive(Default)]
pub struct FlowCache {
    map: Mutex<HashMap<FlowId, CacheEntry>>,
}

impl FlowCache {
    fn lock(&self) -> MutexGuard<'_, HashMap<FlowId, CacheEntry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Cached decision (`true` = Direct); refreshes the entry's idle timer.
    pub fn get(&self, id: &FlowId) -> Option<bool> {
        let mut g = self.lock();
        let e = g.get_mut(id)?;
        e.last_seen = Instant::now();
        Some(e.direct)
    }

    pub fn put(&self, id: FlowId, direct: bool) {
        self.lock().insert(
            id,
            CacheEntry {
                direct,
                last_seen: Instant::now(),
            },
        );
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
        self.lock()
            .retain(|id, e| id.proto == PROTO_TCP && !e.direct);
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
/// decision is Direct, or for the service's own sockets.
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
    // Decides now and remembers the outcome; returns (pid, is_direct).
    let decide_now = |decide: &mut dyn FnMut() -> (u32, Decision)| -> (u32, bool) {
        let (pid, d) = decide();
        let direct = pid == own_pid || matches!(d, Decision::Final(Route::Direct, _));
        cache.put(id, direct);
        (pid, direct)
    };
    // Every path below calls `decide` at most once.
    let mut decide = Some(decide);
    let mut call = || decide.take().map_or((0, Decision::NeedDomain), |f| f());
    match id.proto {
        PROTO_TCP if m.syn => {
            // A connection attempt is always (re)decided.
            let (pid, direct) = decide_now(&mut call);
            if direct {
                Action::Pass
            } else if id.remote.is_ipv4() {
                Action::NewRedirect { pid }
            } else {
                // No IPv6 relay in M1: never let a non-Direct IPv6 flow out.
                Action::Drop
            }
        }
        PROTO_TCP => match cache.get(&id) {
            Some(true) => Action::Pass,
            Some(false) if nat_has => Action::Redirect,
            Some(false) => Action::Drop,
            None if nat_has => {
                cache.put(id, false);
                Action::Redirect
            }
            // A flow that predates Q2Route: only a Direct flow may continue.
            None => match decide_now(&mut call) {
                (_, true) => Action::Pass,
                (_, false) => Action::Drop,
            },
        },
        PROTO_UDP => {
            let direct = match cache.get(&id) {
                Some(d) => d,
                None => decide_now(&mut call).1,
            };
            if direct {
                Action::Pass
            } else {
                Action::Drop
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
    })
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
        // if the rules now say Direct.
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Drop
        );
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn non_syn_unknown_flow_proxied_drops() {
        let (c, n) = (FlowCache::default(), Cell::new(0));
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, proxy(), &n),
            Action::Drop
        );
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, proxy(), &n),
            Action::Drop
        );
        assert_eq!(n.get(), 1, "cached after the first decision");
        let c = FlowCache::default();
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, Decision::NeedDomain, &n),
            Action::Drop
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
            Action::Drop
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
            Action::Drop
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
        assert_eq!(run(&ack, &c, false, APP_PID, direct(), &n), Action::Drop);
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
        assert_eq!(run(&u, &c, false, APP_PID, proxy(), &n), Action::Drop);
        let u6 = meta(PROTO_UDP, "[2001:db8::5]:5000", "[2001:db8::1]:443", false);
        assert_eq!(run(&u6, &c, false, APP_PID, block(), &n), Action::Drop);
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
            Action::Drop
        );
        // The proxied flow stays non-Direct even if the rules now say Direct.
        assert_eq!(
            run(&tcp(false), &c, false, APP_PID, direct(), &n),
            Action::Drop
        );
    }

    #[test]
    fn cache_sweep_expires_idle_entries() {
        let c = FlowCache::default();
        c.put(tcp(true).flow, false);
        c.put(
            meta(PROTO_UDP, "10.0.0.2:5000", "8.8.4.4:443", false).flow,
            true,
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
