//! WinDivert capture loops (dedicated OS threads, blocking recv).
//!
//! * Socket layer (sniff): CONNECT / BIND / CLOSE events feed the TCP and UDP
//!   flow tables (pid lookup); TCP ACCEPT events mark inbound connections to
//!   local servers Direct.
//! * Network layer: every outbound, non-loopback TCP/UDP packet. Relay
//!   replies (`A:relay_port -> D:pa`) are restored to the app; everything else
//!   goes through [`classify`], which only ever passes Direct flows.
//!   Outbound ICMPv4 destination-unreachable is captured too: one quoting a
//!   UDP packet to a port the UDP relay serves (the stack answering an
//!   injected reply from the real IP) is dropped; any other passes as before.
//!   UDP/53 queries are routed by the queried name ([`dns_verdict`]):
//!   passed, answered REFUSED, or handed to the [`DnsProxy`] and dropped; a
//!   UDP/53 payload that is not a DNS query is an ordinary UDP flow.
//!   IPv4 TCP/53 is redirected to the relay, which routes it by name; IPv6
//!   TCP/53 is passed untouched (M4 gap). The proxy program's own port-53
//!   traffic is always passed (spec 5.6).
//! * DNS answers (sniff only): inbound UDP from port 53 that answers a query
//!   this loop passed ([`DnsPending`]) feeds the IP -> names map that lets
//!   domain rules decide flows without a peek.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use q2route_core::config::{Config, ProfileId, Protocol};
use q2route_core::decide::{
    decide_dns, decide_mapped, Decision, FlowInfo, MatchInfo, MatchReason, Route,
};
use q2route_core::dns::{answers, parse_query, refused, response_id, Query};
use q2route_core::domain_map::DomainMap;
use q2route_core::process_tree::ProcessTree;
use q2route_core::ruleset::RuleSet;
use q2route_core::suggest::reason_text;

use crate::classify::{
    build_rst_to_app, classify, parse, Action, FlowCache, FlowId, PROTO_TCP, PROTO_UDP,
};
use crate::conns::{ConnLog, NewConn};
use crate::dns_proxy::{bootstrap_direct, DnsProxy, DnsQuery};
use crate::flows::{FlowKey, FlowTable};
use crate::nat::{redirect_outbound, restore_inbound, NatTable, OriginalDst, Verdict};
use crate::proxy_servers::ServerCache;
use crate::relay::{describe, exe_name, proxy_program, OrigDstLookup, RelayCtx};
use crate::udp_packet::{build_inbound_udp, build_inbound_udp6};
use crate::udp_relay::{Datagram, InboundSink, UdpRelay};
use crate::winapi;
use crate::windivert::{
    calc_checksums_addr, Address, Handle, EVENT_SOCKET_ACCEPT, EVENT_SOCKET_BIND,
    EVENT_SOCKET_CLOSE, EVENT_SOCKET_CONNECT,
};

pub const SOCKET_FILTER: &str = "((tcp or udp) and (event == CONNECT or event == CLOSE)) \
     or (udp and event == BIND) or (tcp and event == ACCEPT)";
pub const NETWORK_FILTER: &str =
    "outbound and !loopback and ((tcp or udp) or (icmp and icmp.Type == 3))";
/// Sniff-only handle: DNS answers arriving from the network.
pub const DNS_SNIFF_FILTER: &str = "inbound and !loopback and udp.SrcPort == 53";
/// Threads receiving from the Network-layer handle.
pub const NETWORK_THREADS: usize = 4;
/// Ancestors refreshed on demand for an unknown pid (Ruling R5).
const MAX_ON_DEMAND: usize = 8;
const MAX_PACKET: usize = 0xffff;
/// How long a passed UDP/53 query waits for its answer to be learned.
const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
/// Passed UDP/53 queries remembered at most (oldest evicted).
const DNS_PENDING_MAX: usize = 4096;

/// (app local address, server address, DNS id) of a passed query.
type PendingKey = (SocketAddr, SocketAddr, u16);

/// UDP/53 queries passed to their server, so the sniffer learns only the
/// answers to them (an unsolicited or injected answer is never learned).
/// Bounded ([`DNS_PENDING_MAX`], oldest evicted) and short-lived
/// ([`DNS_PENDING_TTL`]); the lock is held only for a map operation.
#[derive(Default)]
pub struct DnsPending {
    inner: Mutex<PendingInner>,
}

#[derive(Default)]
struct PendingInner {
    /// key -> (lowercase question name, recorded at, serial).
    map: HashMap<PendingKey, (String, Instant, u64)>,
    /// (key, serial), oldest first; entries whose serial no longer matches
    /// the map are stale and skipped.
    order: VecDeque<(PendingKey, u64)>,
    serial: u64,
}

impl DnsPending {
    fn lock(&self) -> std::sync::MutexGuard<'_, PendingInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records a query for `name` with `id` from `app` to `server`.
    pub fn record(&self, app: SocketAddr, server: SocketAddr, id: u16, name: &str, now: Instant) {
        let mut g = self.lock();
        let g = &mut *g;
        // Drop stale and expired entries, then the oldest while full.
        while let Some(&(k, serial)) = g.order.front() {
            let live = g.map.get(&k).filter(|e| e.2 == serial);
            let expired = live.is_none_or(|e| now.duration_since(e.1) >= DNS_PENDING_TTL);
            if !expired && g.map.len() < DNS_PENDING_MAX {
                break;
            }
            g.order.pop_front();
            if live.is_some() {
                g.map.remove(&k);
            }
        }
        g.serial += 1;
        let key = (app, server, id);
        g.map.insert(key, (name.to_string(), now, g.serial));
        g.order.push_back((key, g.serial));
    }

    /// Whether an answer from `server` to `app` with `id` for `name` answers
    /// a recorded, unexpired query for that same name. On a match the query
    /// is forgotten (one answer is learned per query).
    pub fn take(
        &self,
        app: SocketAddr,
        server: SocketAddr,
        id: u16,
        name: &str,
        now: Instant,
    ) -> bool {
        let mut g = self.lock();
        let key = (app, server, id);
        let hit = g
            .map
            .get(&key)
            .is_some_and(|e| e.0 == name && now.duration_since(e.1) < DNS_PENDING_TTL);
        if hit {
            g.map.remove(&key);
        }
        hit
    }

    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// State shared by the packet loop, the relay and the engine for the
/// engine's lifetime.
pub struct Shared {
    pub relay: Arc<RelayCtx>,
    /// Resolved `host:port` of every configured proxy: always Direct, so the
    /// relay's upstream connections can never loop back into the relay.
    pub proxy_endpoints: ArcSwap<HashSet<SocketAddr>>,
    pub own_pid: u32,
    /// Engine-only: proxy client config files already read
    /// ([`crate::proxy_servers`]); never touched on the packet path.
    pub server_cache: Arc<Mutex<ServerCache>>,
}

/// State of one Start..Stop run.
pub struct RunState {
    pub relay_port: u16,
    pub nat: Arc<NatTable>,
    pub cache: FlowCache,
    pub tcp_flows: FlowTable,
    pub udp_flows: FlowTable,
    /// UDP/53 queries passed direct, awaiting their (sniffed) answers.
    pub dns_pending: DnsPending,
    /// Set before the handles are shut down, so recv errors end the loops.
    pub stopping: AtomicBool,
}

impl RunState {
    pub fn new(relay_port: u16) -> RunState {
        RunState {
            relay_port,
            nat: Arc::default(),
            cache: FlowCache::default(),
            tcp_flows: FlowTable::default(),
            udp_flows: FlowTable::default(),
            dns_pending: DnsPending::default(),
            stopping: AtomicBool::new(false),
        }
    }
}

/// The relay's view of the NAT: peer `D:pa` -> original destination.
pub struct NatLookup(pub Arc<NatTable>);

impl OrigDstLookup for NatLookup {
    fn attach(&self, peer: SocketAddr) -> Option<(OriginalDst, u64)> {
        let SocketAddr::V4(peer) = peer else {
            return None;
        };
        self.0.attach(peer.port(), *peer.ip())
    }
    fn release(&self, peer: SocketAddr, token: u64) {
        self.0.release(peer.port(), token);
    }
}

/// Logs a recv error (unless stopping) and reports whether to keep going.
fn keep_going(run: &RunState, layer: &str, e: &std::io::Error) -> bool {
    if run.stopping.load(Ordering::SeqCst) {
        return false;
    }
    tracing::warn!("{layer} recv failed: {e}");
    // A persistent error must not spin; a stalled loop fails closed (the
    // driver drops packets it cannot queue).
    std::thread::sleep(Duration::from_millis(10));
    true
}

/// Injects the UDP relay's rebuilt reply packets toward apps through the
/// Network-layer handle. A WinDivert send is a short non-blocking driver
/// call (safe concurrently with the packet threads), so it runs directly on
/// the calling tokio task.
pub struct NetworkSink(pub Arc<Handle>);

impl InboundSink for NetworkSink {
    fn inject(&self, mut pkt: Vec<u8>, addr: &Address) {
        let mut a = *addr;
        a.set_outbound(false);
        calc_checksums_addr(&mut pkt, &mut a);
        if let Err(e) = self.0.send(&pkt, &a) {
            tracing::debug!("udp reply inject failed: {e}");
        }
    }
}

/// A Socket-layer local address as the UDP relay keys it: IPv4 or
/// v4-mapped as is, the IPv6 wildcard as `0.0.0.0` (same port); `None` for
/// other IPv6 (never relayed).
fn relay_local(a: SocketAddr) -> Option<SocketAddrV4> {
    match a {
        SocketAddr::V4(a) => Some(a),
        SocketAddr::V6(a) if a.ip().is_unspecified() => {
            Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, a.port()))
        }
        SocketAddr::V6(a) => a
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddrV4::new(ip, a.port())),
    }
}

pub fn socket_loop(h: Arc<Handle>, run: Arc<RunState>, conns: Arc<ConnLog>, udp: Arc<UdpRelay>) {
    loop {
        let addr = match h.recv(&mut []) {
            Ok((_, addr)) => addr,
            Err(e) if keep_going(&run, "socket layer", &e) => continue,
            Err(_) => return,
        };
        let Some(s) = addr.socket() else { continue };
        let table = match s.protocol {
            PROTO_TCP => &run.tcp_flows,
            PROTO_UDP => &run.udp_flows,
            _ => continue,
        };
        match addr.event() {
            EVENT_SOCKET_CONNECT | EVENT_SOCKET_BIND => table.on_connect(&s),
            // Inbound connection to a local server: the remote already
            // knows the real IP, so its replies go direct.
            EVENT_SOCKET_ACCEPT if s.protocol == PROTO_TCP => {
                table.on_connect(&s);
                run.cache.on_accept(s.local, s.remote);
            }
            EVENT_SOCKET_CLOSE => {
                table.on_close(&s);
                let proto = if s.protocol == PROTO_TCP {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                };
                conns.close_local(proto, s.local);
                if s.protocol == PROTO_UDP {
                    if let Some(l) = relay_local(s.local) {
                        udp.close(l);
                    }
                }
                // A new socket reusing this local port must not inherit
                // the old socket's decision.
                run.cache.on_socket_closed(s.protocol, s.local);
            }
            _ => {}
        }
    }
}

pub fn network_loop(
    h: Arc<Handle>,
    shared: Arc<Shared>,
    run: Arc<RunState>,
    udp: Arc<UdpRelay>,
    dns: Arc<DnsProxy>,
) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (n, mut addr) = match h.recv(&mut buf) {
            Ok(r) => r,
            Err(e) if keep_going(&run, "network layer", &e) => continue,
            Err(_) => return,
        };
        let pkt = &mut buf[..n];
        match route_packet(pkt, &mut addr, &shared, &run, &udp, &dns) {
            Out::Send => {
                if let Err(e) = h.send(pkt, &addr) {
                    tracing::debug!("reinject failed: {e}");
                }
            }
            Out::Drop => {}
            Out::ResetApp => {
                // The packet itself is dropped; only an RST from the
                // original destination goes back *inbound* to the app.
                let Some(mut rst) = build_rst_to_app(pkt) else {
                    continue;
                };
                let mut a = addr;
                a.set_outbound(false);
                calc_checksums_addr(&mut rst, &mut a);
                if let Err(e) = h.send(&rst, &a) {
                    tracing::debug!("rst inject failed: {e}");
                }
            }
            // The packet is dropped; the reply goes inbound to the app.
            Out::Inject(reply) => NetworkSink(h.clone()).inject(reply, &addr),
        }
    }
}

/// What to do with a captured packet.
#[derive(Debug, PartialEq, Eq)]
enum Out {
    /// (Re)inject it (possibly rewritten).
    Send,
    Drop,
    /// Drop it and inject an RST toward the app.
    ResetApp,
    /// Drop it and inject this (complete) packet inbound toward the app.
    Inject(Vec<u8>),
}

impl From<bool> for Out {
    fn from(send: bool) -> Out {
        if send {
            Out::Send
        } else {
            Out::Drop
        }
    }
}

/// Decides one captured packet; may rewrite it (NAT). Every `Send` comes
/// from: an inbound packet (never captured by the filter), a restored relay
/// reply, a NAT-rewritten packet, or `classify` returning `Pass` (Direct
/// flow / own socket), or a UDP/53 query whose name decides Direct (or the
/// service's / proxy program's own). A UDP/53 payload that is not a DNS
/// query carries no name and is classified like any other UDP flow.
/// `ResetApp` / `Inject` never send the packet itself.
fn route_packet(
    pkt: &mut [u8],
    addr: &mut Address,
    shared: &Shared,
    run: &RunState,
    udp: &UdpRelay,
    dns: &DnsProxy,
) -> Out {
    if !addr.outbound() {
        return Out::Send;
    }
    // ICMPv4 (the filter captures only type 3): never a proxied flow; only
    // the stack's answer to an injected relay reply is held back.
    if pkt.first().is_some_and(|b| b >> 4 == 4) && pkt.get(9) == Some(&PROTO_ICMP) {
        return match icmp_quoted_udp_dst_port(pkt) {
            Some(port) if udp.serves_port(port) => Out::Drop,
            _ => Out::Send,
        };
    }
    // Captured but not understood (e.g. odd IPv6 extension headers): drop
    // rather than risk passing a non-Direct flow.
    let Some(m) = parse(pkt) else {
        return Out::Drop;
    };
    let f = m.flow;
    if f.proto == PROTO_UDP && f.remote.port() == 53 {
        if let Some(out) = dns_packet(pkt, addr, &f, shared, run, dns) {
            return out;
        }
    }
    // M4 gap (no IPv6 relay until M6): IPv6 TCP/53 is passed untouched.
    if ipv6_tcp_dns(&f) {
        return Out::Send;
    }
    let tcp4 = f.proto == PROTO_TCP && f.local.is_ipv4();
    if tcp4 && f.local.port() == run.relay_port {
        return (restore_inbound(pkt, addr, run.relay_port, &run.nat) == Verdict::Rewritten).into();
    }
    // The relay's direct upstream sockets are IPv4 TCP only.
    let own_port = tcp4 && shared.relay.own_ports.contains(&f.local.port());
    let nat_has = tcp4
        && run
            .nat
            .get(f.local.port())
            .is_some_and(|o| SocketAddr::V4(o.dst) == f.remote);
    // IPv4 TCP/53 is decided by the queried name in the relay.
    let tcp_dns = tcp4 && f.remote.port() == 53;
    let action = classify(&m, own_port, shared.own_pid, &run.cache, nat_has, || {
        if tcp_dns {
            let pid = lookup_pid(run, &f);
            let own = if pid == shared.own_pid || shared.proxy_endpoints.load().contains(&f.remote)
            {
                Some(MatchReason::ExcludedPid)
            } else {
                is_proxy_program(shared, pid).then_some(MatchReason::BootstrapName)
            };
            tcp_dns_decision(pid, own)
        } else {
            decide_flow(shared, run, &f)
        }
    });
    match action {
        Action::Pass => Out::Send,
        Action::Drop => Out::Drop,
        Action::Reset => {
            tracing::debug!(
                "non-direct flow {} -> {} has no NAT entry: RST to app",
                f.local,
                f.remote
            );
            Out::ResetApp
        }
        Action::NewRedirect { pid } => {
            let SocketAddr::V4(dst) = f.remote else {
                return Out::Drop;
            };
            run.nat.insert(f.local.port(), OriginalDst { dst, pid });
            (redirect_outbound(pkt, addr, run.relay_port, &run.nat) == Verdict::Rewritten).into()
        }
        // Handed to the UDP relay; the packet itself never leaves.
        Action::UdpProxy {
            pid,
            profile,
            group_id,
        } => {
            let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (f.local, f.remote) else {
                return Out::Drop;
            };
            if let Some(payload) = udp4_payload(pkt) {
                udp.submit(Datagram {
                    pid,
                    profile,
                    group_id,
                    local,
                    remote,
                    payload: payload.to_vec(),
                    addr: *addr,
                });
            }
            Out::Drop
        }
        Action::Redirect => {
            (redirect_outbound(pkt, addr, run.relay_port, &run.nat) == Verdict::Rewritten).into()
        }
    }
}

const PROTO_ICMP: u8 = 1;

/// IPv6 TCP to port 53: always Direct in M4 (documented gap; there is no
/// IPv6 relay to route it by name).
fn ipv6_tcp_dns(f: &FlowId) -> bool {
    f.proto == PROTO_TCP && f.remote.port() == 53 && f.remote.is_ipv6()
}

/// The decision for an IPv4 TCP/53 flow: the service's own sockets, proxy
/// endpoints and the proxy program (`own`: why) are Direct; every other
/// flow is NeedDomain, so its SYN is redirected to the relay (cached
/// non-Direct, like a proxied flow), which routes it by the queried name
/// ([`crate::relay`]).
fn tcp_dns_decision(pid: u32, own: Option<MatchReason>) -> (u32, Decision) {
    match own {
        Some(reason) => (pid, direct(reason)),
        None => (pid, Decision::NeedDomain),
    }
}

/// Whether `pid` is the proxy program ([`proxy_program`]), after making
/// sure it is in the process tree.
fn is_proxy_program(shared: &Shared, pid: u32) -> bool {
    ensure_process(&shared.relay.tree, pid);
    let tree = shared.relay.tree.read().unwrap_or_else(|e| e.into_inner());
    let rules = shared.relay.rules.load();
    proxy_program(&rules, &tree, &shared.relay.excluded.load(), pid).is_some()
}

/// For an IPv4 ICMP destination unreachable (type 3) quoting an IPv4/UDP
/// packet: the quoted UDP destination port (the local port the triggering
/// inbound packet was addressed to). `None` for anything else or anything
/// malformed / truncated.
fn icmp_quoted_udp_dst_port(p: &[u8]) -> Option<u16> {
    let be16 = |b: &[u8], at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
    };
    if p.len() < 20 || p[0] >> 4 != 4 || p[9] != PROTO_ICMP || be16(p, 6)? & 0x1fff != 0 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2)?).min(p.len());
    if ihl < 20 {
        return None;
    }
    let icmp = p.get(ihl..total)?;
    if *icmp.first()? != 3 {
        return None;
    }
    // ICMP header (8 bytes), then the quoted IP header + 8 bytes.
    let q = icmp.get(8..)?;
    if q.len() < 20 || q[0] >> 4 != 4 || q[9] != PROTO_UDP || be16(q, 6)? & 0x1fff != 0 {
        return None;
    }
    let qihl = usize::from(q[0] & 0x0f) * 4;
    if qihl < 20 {
        return None;
    }
    be16(q, qihl + 2)
}

/// UDP payload of an IPv4/UDP packet (bounded by the UDP and IP lengths);
/// `None` if the lengths are inconsistent (e.g. a truncated fragment).
fn udp4_payload(p: &[u8]) -> Option<&[u8]> {
    let ihl = usize::from(*p.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
    let udp_len = usize::from(u16::from_be_bytes([*p.get(ihl + 4)?, *p.get(ihl + 5)?]));
    if udp_len < 8 || ihl + udp_len > total.min(p.len()) {
        return None;
    }
    p.get(ihl + 8..ihl + udp_len)
}

/// UDP payload of an IPv4 or IPv6 UDP packet. IPv6 with extension headers
/// is not parsed (`None`: treated as malformed by the DNS path).
fn udp_payload(p: &[u8]) -> Option<&[u8]> {
    match *p.first()? >> 4 {
        4 if p.get(9) == Some(&PROTO_UDP) => udp4_payload(p),
        6 if p.get(6) == Some(&PROTO_UDP) => {
            let total = 40 + usize::from(u16::from_be_bytes([*p.get(4)?, *p.get(5)?]));
            let udp_len = usize::from(u16::from_be_bytes([*p.get(44)?, *p.get(45)?]));
            if udp_len < 8 || 40 + udp_len > total.min(p.len()) {
                return None;
            }
            p.get(48..40 + udp_len)
        }
        _ => None,
    }
}

/// What the DNS rules do with a UDP/53 query.
#[derive(Debug, PartialEq, Eq)]
enum DnsVerdict {
    /// Send it to the server the app asked.
    Pass,
    /// A bootstrap name ([`bootstrap_direct`], the label says which
    /// source): always sent direct.
    Bootstrap(&'static str),
    /// Answer REFUSED.
    Refuse,
    /// Resolve through this profile's proxy ([`DnsProxy`]).
    Proxy(ProfileId),
}

/// Routes a UDP/53 query by its name: a bootstrap name ([`bootstrap_direct`]:
/// proxy hosts, `direct_names`, the detected proxy servers in `auto`)
/// passes, anything else by [`decide_dns`].
fn dns_verdict(rules: &RuleSet, cfg: &Config, auto: &[String], q: &Query) -> DnsVerdict {
    if let Some(why) = bootstrap_direct(cfg, auto, &q.name) {
        return DnsVerdict::Bootstrap(why);
    }
    match decide_dns(rules, &q.name).0 {
        Route::Direct => DnsVerdict::Pass,
        Route::Block => DnsVerdict::Refuse,
        Route::Proxy(id) => DnsVerdict::Proxy(id),
    }
}

/// An outbound UDP/53 packet: the service's own (and anything to a proxy
/// endpoint) passes, and so does the proxy program's ([`proxy_program`]);
/// a DNS query is routed by the queried name only. `None`: the payload is
/// not a DNS query (it carries no name to leak), so the caller classifies
/// it as an ordinary UDP flow (e.g. a VPN on port 53).
fn dns_packet(
    pkt: &[u8],
    addr: &Address,
    f: &FlowId,
    shared: &Shared,
    run: &RunState,
    dns: &DnsProxy,
) -> Option<Out> {
    if shared.proxy_endpoints.load().contains(&f.remote) {
        return Some(Out::Send);
    }
    let pid = lookup_pid(run, f);
    if pid == shared.own_pid {
        return Some(Out::Send);
    }
    let q = udp_payload(pkt).and_then(parse_query);
    if is_proxy_program(shared, pid) {
        match &q {
            Some(q) => tracing::debug!(
                "dns name={} type={} pid={pid} via=direct (proxy program)",
                q.name,
                q.qtype
            ),
            None => tracing::debug!(
                "dns {} -> {} pid={pid} via=direct (proxy program)",
                f.local,
                f.remote
            ),
        }
        return Some(Out::Send);
    }
    let Some(q) = q else {
        tracing::debug!(
            "udp {} -> {} pid={pid}: not a DNS query; routed as a flow",
            f.local,
            f.remote
        );
        return None;
    };
    let v = dns_verdict(
        &shared.relay.rules.load(),
        &shared.relay.cfg.load(),
        &shared.relay.proxy_servers.load(),
        &q,
    );
    let via = match &v {
        DnsVerdict::Pass => "direct".to_string(),
        DnsVerdict::Bootstrap(why) => format!("direct ({why})"),
        DnsVerdict::Refuse => "block".to_string(),
        DnsVerdict::Proxy(id) => format!("proxy '{id}'"),
    };
    tracing::debug!("dns name={} type={} via={via}", q.name, q.qtype);
    let msg = q.raw;
    Some(match v {
        DnsVerdict::Pass | DnsVerdict::Bootstrap(_) => {
            // Only the answer to this very query may be learned (sniffer).
            run.dns_pending
                .record(f.local, f.remote, q.id, &q.name, Instant::now());
            Out::Send
        }
        DnsVerdict::Refuse => {
            let reply = refused(msg).and_then(|r| match (f.remote, f.local) {
                (SocketAddr::V4(s), SocketAddr::V4(a)) => build_inbound_udp(s, a, &r).ok(),
                (SocketAddr::V6(s), SocketAddr::V6(a)) => build_inbound_udp6(s, a, &r).ok(),
                _ => None,
            });
            reply.map_or(Out::Drop, Out::Inject)
        }
        DnsVerdict::Proxy(profile) => {
            dns.submit(DnsQuery {
                profile,
                app: f.local,
                server: f.remote,
                msg: msg.to_vec(),
                addr: *addr,
            });
            Out::Drop
        }
    })
}

/// Learns names from one sniffed inbound DNS answer packet, only if it
/// answers a query passed to that server from that app socket with the
/// same id and name ([`DnsPending`]): an injected or unsolicited answer
/// could otherwise map a proxied site's IP to a Direct name.
fn learn_answers(domains: &DomainMap, pending: &DnsPending, pkt: &[u8], now: Instant) {
    let Some(m) = parse(pkt) else { return };
    // Inbound: the packet's source is the server, its destination the app.
    let (server, app) = (m.flow.local, m.flow.remote);
    let Some(msg) = udp_payload(pkt) else { return };
    let (Some(name), ips) = answers(msg) else {
        return;
    };
    let Some(id) = response_id(msg) else { return };
    if !pending.take(app, server, id, &name, now) {
        tracing::debug!("dns answer {server} -> {app} for {name}: no matching query; not learned");
        return;
    }
    for (ip, ttl) in ips {
        domains.insert(ip, &name, ttl, now);
    }
}

/// Sniff-only loop over inbound DNS answers (never reinjects: the handle is
/// `FLAG_SNIFF | FLAG_RECV_ONLY`). Ends when the handle shuts down on stop.
pub fn dns_sniff_loop(h: Arc<Handle>, domains: Arc<DomainMap>, run: Arc<RunState>) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let n = match h.recv(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if keep_going(&run, "dns sniff", &e) => continue,
            Err(_) => return,
        };
        learn_answers(&domains, &run.dns_pending, &buf[..n], Instant::now());
    }
}

/// Ruling R14: FlowTable by (local, remote) -> by local -> OS socket table
/// by local port -> 0 (no app rule matches pid 0: catch-all, the safe side).
fn lookup_pid(run: &RunState, f: &FlowId) -> u32 {
    let table = if f.proto == PROTO_TCP {
        &run.tcp_flows
    } else {
        &run.udp_flows
    };
    table
        .pid_for(&FlowKey {
            local: f.local,
            remote: f.remote,
        })
        .or_else(|| table.pid_for_local(f.local))
        .or_else(|| winapi::owner_pid(f.proto, f.local, f.remote))
        .unwrap_or(0)
}

/// Ruling R5: makes sure `pid` (and its missing ancestors) are in the tree.
fn ensure_process(tree: &std::sync::RwLock<ProcessTree>, pid: u32) {
    let mut cur = pid;
    for _ in 0..MAX_ON_DEMAND {
        if cur == 0 || cur == 4 {
            return;
        }
        if tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(cur)
            .is_some()
        {
            return;
        }
        let Some(info) = winapi::process_info(cur) else {
            return;
        };
        let parent = info.parent;
        tree.write().unwrap_or_else(|e| e.into_inner()).insert(info);
        cur = parent;
    }
}

fn direct(reason: MatchReason) -> Decision {
    Decision::Final(
        Route::Direct,
        MatchInfo {
            group_id: None,
            reason,
        },
    )
}

fn decide_flow(shared: &Shared, run: &RunState, f: &FlowId) -> (u32, Decision) {
    let pid = lookup_pid(run, f);
    if pid == shared.own_pid || shared.proxy_endpoints.load().contains(&f.remote) {
        return (pid, direct(MatchReason::ExcludedPid));
    }
    ensure_process(&shared.relay.tree, pid);
    let proto = if f.proto == PROTO_TCP {
        Protocol::Tcp
    } else {
        Protocol::Udp
    };
    let info = FlowInfo {
        proto,
        pid,
        dst: f.remote,
        domain: None,
    };
    // Names DNS answered for this destination (the flow itself carries none
    // at the packet layer); taken before the tree lock.
    let names = shared.relay.domains.names(f.remote.ip(), Instant::now());
    let rules = shared.relay.rules.load();
    let excluded = shared.relay.excluded.load();
    let tree = shared.relay.tree.read().unwrap_or_else(|e| e.into_inner());
    let d = decide_mapped(&rules, &tree, &excluded, &info, &names);
    // One line per decided flow (decide_flow runs only when the flow cache
    // cannot answer). LAN / DNS / NTP flows are frequent and uninteresting.
    let proto_name = if proto == Protocol::Tcp { "tcp" } else { "udp" };
    let exe = exe_name(&tree, pid);
    let what = describe(&d);
    if matches!(&d, Decision::Final(_, i) if i.reason == MatchReason::AlwaysDirectDst) {
        tracing::debug!(
            "flow {proto_name} pid={pid} exe={exe} dst={} {what}",
            f.remote
        );
    } else {
        tracing::info!(
            "flow {proto_name} pid={pid} exe={exe} dst={} {what}",
            f.remote
        );
    }
    // Direct / Block flows are never relayed, so record them here; Proxy and
    // NeedDomain flows are redirected and recorded by the relay.
    if let Decision::Final(route @ (Route::Direct | Route::Block), i) = &d {
        if i.reason != MatchReason::AlwaysDirectDst {
            shared.relay.conns.open(
                NewConn {
                    proto,
                    pid,
                    exe,
                    local: f.local,
                    dst: f.remote,
                    domain: None,
                    route: route.clone(),
                    group_id: i.group_id.clone(),
                    reason: reason_text(&i.reason, &tree),
                },
                None,
            );
        }
    }
    (pid, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Cached;
    use crate::windivert::{check_filter, Layer};

    #[test]
    fn udp4_payload_slices_after_header() {
        let src = "10.0.0.2:5000".parse().unwrap();
        let dst = "8.8.4.4:3478".parse().unwrap();
        let p = crate::udp_packet::build_inbound_udp(src, dst, b"hello").unwrap();
        assert_eq!(udp4_payload(&p), Some(&b"hello"[..]));
        let mut bad = p.clone();
        bad[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(udp4_payload(&bad), None, "UDP length past the packet");
        assert_eq!(udp4_payload(&p[..25]), None, "truncated");
    }

    #[test]
    fn relay_local_maps_socket_addresses() {
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let v4 = |s: &str| Some(s.parse::<SocketAddrV4>().unwrap());
        assert_eq!(relay_local(p("10.0.0.2:5000")), v4("10.0.0.2:5000"));
        assert_eq!(
            relay_local(p("[::ffff:10.0.0.2]:5000")),
            v4("10.0.0.2:5000")
        );
        assert_eq!(relay_local(p("[::]:5000")), v4("0.0.0.0:5000"));
        assert_eq!(relay_local(p("[2001:db8::1]:5000")), None);
    }

    /// IPv4 ICMP `ty`/code 3 quoting the first 28 bytes of `quoted`.
    fn icmp4(ty: u8, quoted: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 128, PROTO_ICMP, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2, 8, 8, 4, 4]);
        p.extend_from_slice(&[ty, 3, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&quoted[..28.min(quoted.len())]);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    #[test]
    fn icmp_quoted_udp_dst_port_parses_port_unreachable() {
        // The triggering inbound packet: remote -> app's local port 5000.
        let src = "8.8.4.4:3478".parse().unwrap();
        let dst = "10.0.0.2:5000".parse().unwrap();
        let udp = crate::udp_packet::build_inbound_udp(src, dst, b"reply").unwrap();
        assert_eq!(icmp_quoted_udp_dst_port(&icmp4(3, &udp)), Some(5000));
        let mut tcp = udp.clone();
        tcp[9] = PROTO_TCP;
        assert_eq!(
            icmp_quoted_udp_dst_port(&icmp4(3, &tcp)),
            None,
            "quotes TCP"
        );
        assert_eq!(icmp_quoted_udp_dst_port(&icmp4(8, &udp)), None, "echo");
        let full = icmp4(3, &udp);
        for n in [0, 10, 20, 27, 36, 48, 51] {
            assert_eq!(
                icmp_quoted_udp_dst_port(&full[..n]),
                None,
                "truncated to {n}"
            );
        }
        // The outer packet itself is UDP, not ICMP.
        assert_eq!(icmp_quoted_udp_dst_port(&udp), None);
    }

    fn seed_rules() -> RuleSet {
        RuleSet::compile(&Config::seed()).unwrap()
    }

    /// A standard query (RD) for `name`, type A.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    /// `dns_verdict` for a query for `name`.
    fn verdict(rules: &RuleSet, cfg: &Config, auto: &[String], name: &str) -> DnsVerdict {
        let q = dns_query(name);
        dns_verdict(rules, cfg, auto, &parse_query(&q).unwrap())
    }

    #[test]
    fn dns_query_routed_by_name() {
        let rules = seed_rules();
        let seed = Config::seed();
        assert_eq!(
            verdict(&rules, &seed, &[], "example.com"),
            DnsVerdict::Proxy("v2ray".into())
        );
        assert_eq!(
            verdict(&rules, &seed, &[], "www.digikala.ir"),
            DnsVerdict::Pass
        );
        let mut cfg = Config::seed();
        for g in cfg.groups.iter_mut().filter(|g| g.catch_all) {
            g.action = q2route_core::config::Action::Block;
        }
        let block = RuleSet::compile(&cfg).unwrap();
        assert_eq!(
            verdict(&block, &cfg, &[], "example.com"),
            DnsVerdict::Refuse
        );
    }

    #[test]
    fn proxy_host_query_goes_direct() {
        let mut cfg = Config::seed();
        cfg.proxies[0].host = "Proxy.Example.net".into();
        let rules = RuleSet::compile(&cfg).unwrap();
        for name in ["proxy.example.net", "PROXY.example.NET"] {
            assert_eq!(
                verdict(&rules, &cfg, &[], name),
                DnsVerdict::Bootstrap("proxy host")
            );
        }
        assert_eq!(
            verdict(&rules, &cfg, &[], "other.example.net"),
            DnsVerdict::Proxy("v2ray".into())
        );
    }

    #[test]
    fn bootstrap_names_go_direct() {
        let mut cfg = Config::seed();
        cfg.settings.dns.direct_names = vec!["*.manual.example".into()];
        let rules = RuleSet::compile(&cfg).unwrap();
        let auto = vec!["vpn.example.com".to_string()];
        let v = |n: &str| verdict(&rules, &cfg, &auto, n);
        assert_eq!(v("vpn.example.com"), DnsVerdict::Bootstrap("proxy server"));
        assert_eq!(v("a.manual.example"), DnsVerdict::Bootstrap("direct name"));
        // Everything else still decides by the rules (catch-all Proxy).
        assert_eq!(v("x.vpn.example.com"), DnsVerdict::Proxy("v2ray".into()));
        assert_eq!(v("example.com"), DnsVerdict::Proxy("v2ray".into()));
    }

    #[test]
    fn udp_payload_v4_and_v6() {
        let p4 = crate::udp_packet::build_inbound_udp(
            "10.0.0.2:5000".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            b"q4",
        )
        .unwrap();
        assert_eq!(udp_payload(&p4), Some(&b"q4"[..]));
        let p6 = crate::udp_packet::build_inbound_udp6(
            "[2001:db8::2]:5000".parse().unwrap(),
            "[2001:db8::53]:53".parse().unwrap(),
            b"q6",
        )
        .unwrap();
        assert_eq!(udp_payload(&p6), Some(&b"q6"[..]));
        assert_eq!(udp_payload(&p6[..45]), None, "truncated");
        let mut ext = p6.clone();
        ext[6] = 0; // hop-by-hop header: not parsed here
        assert_eq!(udp_payload(&ext), None);
    }

    #[test]
    fn sniffed_answer_learns_names() {
        let mut ans = dns_query("example.com");
        ans[2] |= 0x80;
        ans[3] = 0x80;
        ans[6..8].copy_from_slice(&[0, 1]);
        ans.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 9, 9, 9, 9]);
        let pkt = crate::udp_packet::build_inbound_udp(
            "8.8.8.8:53".parse().unwrap(),
            "10.0.0.2:5000".parse().unwrap(),
            &ans,
        )
        .unwrap();
        let map = DomainMap::new();
        let pending = DnsPending::default();
        let now = std::time::Instant::now();
        let (app, server) = (sa("10.0.0.2:5000"), sa("8.8.8.8:53"));
        pending.record(app, server, 0x1234, "example.com", now);
        learn_answers(&map, &pending, &pkt, now);
        assert_eq!(
            map.names("9.9.9.9".parse().unwrap(), now),
            vec!["example.com".to_string()]
        );
        assert!(pending.is_empty(), "matched query forgotten");
        learn_answers(&map, &pending, &pkt[..30], now);
        assert_eq!(map.len(), 1);
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// An A answer (9.9.9.9) for `name` with `id`, as an inbound packet
    /// from `server` to `app`.
    fn answer_pkt(name: &str, id: u16, server: &str, app: &str) -> Vec<u8> {
        let mut ans = dns_query(name);
        ans[..2].copy_from_slice(&id.to_be_bytes());
        ans[2] |= 0x80;
        ans[3] = 0x80;
        ans[6..8].copy_from_slice(&[0, 1]);
        ans.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 9, 9, 9, 9]);
        crate::udp_packet::build_inbound_udp(server.parse().unwrap(), app.parse().unwrap(), &ans)
            .unwrap()
    }

    #[test]
    fn sniffed_answer_needs_a_matching_query() {
        let nine = "9.9.9.9".parse().unwrap();
        let now = std::time::Instant::now();
        let (app, server) = ("10.0.0.2:5000", "8.8.8.8:53");
        // Unsolicited (no query recorded): not learned.
        let map = DomainMap::new();
        let pending = DnsPending::default();
        learn_answers(&map, &pending, &answer_pkt("x.ir", 7, server, app), now);
        assert!(map.names(nine, now).is_empty());
        // Recorded query; answers that differ in name, id, server or app
        // socket are not learned and leave the query in place.
        pending.record(sa(app), sa(server), 7, "x.ir", now);
        for pkt in [
            answer_pkt("y.ir", 7, server, app),
            answer_pkt("x.ir", 8, server, app),
            answer_pkt("x.ir", 7, "1.1.1.1:53", app),
            answer_pkt("x.ir", 7, server, "10.0.0.2:5001"),
        ] {
            learn_answers(&map, &pending, &pkt, now);
        }
        assert!(map.names(nine, now).is_empty());
        assert_eq!(pending.len(), 1);
        // Expired: not learned.
        let late = now + DNS_PENDING_TTL;
        learn_answers(&map, &pending, &answer_pkt("x.ir", 7, server, app), late);
        assert!(map.names(nine, late).is_empty());
        // The matching answer: learned once.
        learn_answers(&map, &pending, &answer_pkt("x.ir", 7, server, app), now);
        assert_eq!(map.names(nine, now), vec!["x.ir".to_string()]);
        assert!(pending.is_empty());
    }

    #[test]
    fn dns_pending_is_bounded_and_expires() {
        let p = DnsPending::default();
        let now = std::time::Instant::now();
        let server = sa("8.8.8.8:53");
        for i in 0..(DNS_PENDING_MAX + 10) {
            let app = SocketAddr::new("10.0.0.2".parse().unwrap(), 1000 + i as u16);
            p.record(app, server, 1, "a.ir", now);
        }
        assert_eq!(p.len(), DNS_PENDING_MAX);
        // The oldest were evicted, the newest kept.
        assert!(!p.take(sa("10.0.0.2:1000"), server, 1, "a.ir", now));
        let newest = SocketAddr::new(
            "10.0.0.2".parse().unwrap(),
            1000 + DNS_PENDING_MAX as u16 + 9,
        );
        assert!(p.take(newest, server, 1, "a.ir", now));
        // Expired entries are dropped on the next record.
        p.record(sa("10.0.0.3:1"), server, 1, "a.ir", now + DNS_PENDING_TTL);
        assert_eq!(p.len(), 1);
    }

    fn tcp_meta(remote: &str, syn: bool) -> crate::classify::PktMeta {
        crate::classify::PktMeta {
            flow: FlowId {
                proto: PROTO_TCP,
                local: if remote.starts_with('[') {
                    "[2001:db8::2]:50000".parse().unwrap()
                } else {
                    "10.0.0.2:50000".parse().unwrap()
                },
                remote: remote.parse().unwrap(),
            },
            syn,
            rst: false,
            syn_ack: false,
        }
    }

    #[test]
    fn tcp_dns_v4_syn_goes_to_relay_and_stays_there() {
        const OWN: u32 = 7;
        let cache = FlowCache::default();
        let syn = tcp_meta("8.8.8.8:53", true);
        let a = classify(&syn, false, OWN, &cache, false, || {
            tcp_dns_decision(4242, None)
        });
        assert_eq!(a, Action::NewRedirect { pid: 4242 });
        assert_eq!(cache.get(&syn.flow), Some(Cached::Other));
        // Later packets of the flow follow the NAT entry, never direct.
        let data = tcp_meta("8.8.8.8:53", false);
        let never = || -> (u32, Decision) { panic!("re-decided") };
        assert_eq!(
            classify(&data, false, OWN, &cache, true, never),
            Action::Redirect
        );
        assert_eq!(
            classify(&data, false, OWN, &cache, false, never),
            Action::Reset
        );
        // A flow that predates Q2Route (no SYN seen): reset, not passed.
        let old = FlowCache::default();
        assert_eq!(
            classify(&data, false, OWN, &old, false, || tcp_dns_decision(1, None)),
            Action::Reset
        );
        // The service's own (and proxy endpoints) and the proxy program:
        // Direct.
        for (pid, why) in [
            (OWN, MatchReason::ExcludedPid),
            (4242, MatchReason::BootstrapName),
        ] {
            let own = FlowCache::default();
            assert_eq!(
                classify(&syn, false, OWN, &own, false, || tcp_dns_decision(
                    pid,
                    Some(why)
                )),
                Action::Pass
            );
        }
    }

    // ---- route_packet: the port-53 wiring ----

    use crate::test_util::{ctx, profile, ChanSink};
    use crate::windivert::SocketData;
    use q2route_core::config::{Action as GroupAction, Group, ProxyKind, Rule};
    use q2route_core::process_tree::ProcInfo;
    use tokio_util::sync::CancellationToken;

    const OWN_PID: u32 = 7;
    const DIRECT_APP: u32 = 100;
    const BROWSER: u32 = 200;
    const XRAY: u32 = 300;
    const EXCLUDED: u32 = 400;

    struct Harness {
        shared: Shared,
        run: RunState,
        udp: Arc<UdpRelay>,
        dns: Arc<DnsProxy>,
        cancel: CancellationToken,
    }

    /// `direct.exe` Direct, `*.ir` Direct, catch-all Proxy("mock");
    /// xray.exe always direct; pid 400 excluded (a proxy listener).
    fn harness() -> Harness {
        let mut cfg = crate::test_util::config(profile(ProxyKind::Socks5, 1));
        let group = |id: &str, action, rule: Option<Rule>, catch_all| Group {
            id: id.into(),
            name: id.into(),
            enabled: true,
            action,
            rules: rule.into_iter().collect(),
            catch_all,
        };
        cfg.groups = vec![
            group(
                "apps",
                GroupAction::Direct,
                Some(Rule {
                    apps: vec!["direct.exe".into()],
                    ..Rule::default()
                }),
                false,
            ),
            group(
                "ir",
                GroupAction::Direct,
                Some(Rule {
                    domains: vec!["*.ir".into()],
                    ..Rule::default()
                }),
                false,
            ),
            group("rest", GroupAction::Proxy("mock".into()), None, true),
        ];
        cfg.always_direct = vec!["xray.exe".into()];
        let relay = ctx(cfg);
        {
            let mut t = relay.tree.write().unwrap();
            for (pid, exe) in [
                (DIRECT_APP, r"C:\Apps\direct.exe"),
                (BROWSER, r"C:\Apps\browser.exe"),
                (XRAY, r"C:\v2rayN\bin\xray\xray.exe"),
                (EXCLUDED, r"C:\Tools\client.exe"),
            ] {
                t.insert(ProcInfo {
                    pid,
                    parent: 1,
                    exe: exe.into(),
                    start_time: 0,
                });
            }
        }
        relay.excluded.store(Arc::new(HashSet::from([EXCLUDED])));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: Arc<dyn InboundSink> = Arc::new(ChanSink(tx));
        let cancel = CancellationToken::new();
        let udp = UdpRelay::new(relay.clone(), sink.clone(), cancel.clone());
        let dns = DnsProxy::new(
            relay.clone(),
            sink,
            cancel.clone(),
            crate::dns_proxy::DnsProxyConfig::default(),
        );
        Harness {
            shared: Shared {
                relay,
                proxy_endpoints: ArcSwap::from_pointee(HashSet::new()),
                own_pid: OWN_PID,
                server_cache: Arc::default(),
            },
            run: RunState::new(1),
            udp,
            dns,
            cancel,
        }
    }

    impl Harness {
        /// Routes `pkt` (outbound) from `pid`'s socket `local` -> `remote`.
        fn route(&self, pid: u32, proto: u8, local: &str, remote: &str, mut pkt: Vec<u8>) -> Out {
            let table = if proto == PROTO_TCP {
                &self.run.tcp_flows
            } else {
                &self.run.udp_flows
            };
            table.on_connect(&SocketData {
                pid,
                local: sa(local),
                remote: sa(remote),
                protocol: proto,
            });
            let mut addr = Address::default();
            addr.set_outbound(true);
            route_packet(
                &mut pkt,
                &mut addr,
                &self.shared,
                &self.run,
                &self.udp,
                &self.dns,
            )
        }

        fn cached(&self, proto: u8, local: &str, remote: &str) -> Option<Cached> {
            self.run.cache.get(&FlowId {
                proto,
                local: sa(local),
                remote: sa(remote),
            })
        }
    }

    fn udp_pkt(local: &str, remote: &str, payload: &[u8]) -> Vec<u8> {
        crate::udp_packet::build_inbound_udp(
            local.parse().unwrap(),
            remote.parse().unwrap(),
            payload,
        )
        .unwrap()
    }

    fn tcp_syn(local: &str, remote: &str) -> Vec<u8> {
        let (l, r) = (sa(local), sa(remote));
        let ip = |a: SocketAddr| match a {
            SocketAddr::V4(a) => a.ip().octets(),
            SocketAddr::V6(_) => panic!("v4 only"),
        };
        let mut out = Vec::new();
        etherparse::PacketBuilder::ipv4(ip(l), ip(r), 64)
            .tcp(l.port(), r.port(), 1, 65535)
            .syn()
            .write(&mut out, b"")
            .unwrap();
        out
    }

    /// Finding 1: the proxy program's own TCP/53 (e.g. a v2ray server on
    /// port 53) is passed, never redirected into the DNS relay.
    #[tokio::test]
    async fn tcp_dns_from_proxy_program_passes() {
        let h = harness();
        for (pid, port) in [(EXCLUDED, 40001), (XRAY, 40002)] {
            let local = format!("10.0.0.2:{port}");
            let out = h.route(
                pid,
                PROTO_TCP,
                &local,
                "203.0.113.5:53",
                tcp_syn(&local, "203.0.113.5:53"),
            );
            assert_eq!(out, Out::Send, "pid {pid}");
            assert_eq!(
                h.cached(PROTO_TCP, &local, "203.0.113.5:53"),
                Some(Cached::Direct)
            );
            assert!(h.run.nat.get(port).is_none(), "pid {pid} redirected");
        }
        // Any other app's TCP/53 goes to the relay (NAT entry, not Direct).
        let local = "10.0.0.2:40003";
        let out = h.route(
            BROWSER,
            PROTO_TCP,
            local,
            "203.0.113.5:53",
            tcp_syn(local, "203.0.113.5:53"),
        );
        assert_eq!(out, Out::Send, "rewritten toward the relay");
        assert_eq!(
            h.cached(PROTO_TCP, local, "203.0.113.5:53"),
            Some(Cached::Other)
        );
        assert!(h.run.nat.get(40003).is_some());
        // The service itself: passed.
        let local = "10.0.0.2:40004";
        let out = h.route(
            OWN_PID,
            PROTO_TCP,
            local,
            "203.0.113.5:53",
            tcp_syn(local, "203.0.113.5:53"),
        );
        assert_eq!(out, Out::Send);
        assert!(h.run.nat.get(40004).is_none());
        h.cancel.cancel();
    }

    /// Finding 5: a UDP/53 payload that is not a DNS query is an ordinary
    /// flow (WireGuard / OpenVPN on port 53), routed by the app's rules.
    #[tokio::test]
    async fn udp_53_non_dns_follows_the_app_rules() {
        let h = harness();
        let (a, b, dst) = ("10.0.0.2:41001", "10.0.0.2:41002", "203.0.113.5:53");
        let out = h.route(
            DIRECT_APP,
            PROTO_UDP,
            a,
            dst,
            udp_pkt(a, dst, b"\x01\x00\x00\x00wireguard"),
        );
        assert_eq!(out, Out::Send, "Direct app: passed");
        assert_eq!(h.cached(PROTO_UDP, a, dst), Some(Cached::Direct));
        let out = h.route(BROWSER, PROTO_UDP, b, dst, udp_pkt(b, dst, b"garbage"));
        assert_eq!(out, Out::Drop, "proxied app: never passed");
        assert!(
            matches!(h.cached(PROTO_UDP, b, dst), Some(Cached::UdpProxy(..))),
            "handed to the UDP relay"
        );
        h.cancel.cancel();
    }

    /// DNS queries on port 53 are still routed by name, whatever the app;
    /// a passed query is recorded for the answer sniffer.
    #[tokio::test]
    async fn udp_53_queries_still_routed_by_name() {
        let h = harness();
        let dst = "203.0.113.5:53";
        let a = "10.0.0.2:42001";
        let out = h.route(
            DIRECT_APP,
            PROTO_UDP,
            a,
            dst,
            udp_pkt(a, dst, &dns_query("example.com")),
        );
        assert_eq!(
            out,
            Out::Drop,
            "proxied name from a Direct app: via the proxy"
        );
        assert!(h.run.dns_pending.is_empty());
        let b = "10.0.0.2:42002";
        let out = h.route(
            BROWSER,
            PROTO_UDP,
            b,
            dst,
            udp_pkt(b, dst, &dns_query("x.ir")),
        );
        assert_eq!(out, Out::Send, "Direct name passed");
        assert_eq!(h.run.dns_pending.len(), 1);
        assert!(h
            .run
            .dns_pending
            .take(sa(b), sa(dst), 0x1234, "x.ir", Instant::now()));
        h.cancel.cancel();
    }

    #[test]
    fn tcp_dns_ipv6_stays_direct_m4_gap() {
        // M4 gap (M6 adds an IPv6 relay): IPv6 TCP/53 is passed untouched.
        assert!(ipv6_tcp_dns(&tcp_meta("[2001:db8::53]:53", true).flow));
        assert!(!ipv6_tcp_dns(&tcp_meta("8.8.8.8:53", true).flow));
        assert!(!ipv6_tcp_dns(&tcp_meta("[2001:db8::53]:443", true).flow));
        let mut udp = tcp_meta("[2001:db8::53]:53", false).flow;
        udp.proto = PROTO_UDP;
        assert!(!ipv6_tcp_dns(&udp));
    }

    #[test]
    fn filters_compile() {
        check_filter(SOCKET_FILTER, Layer::Socket).unwrap();
        check_filter(NETWORK_FILTER, Layer::Network).unwrap();
        check_filter(DNS_SNIFF_FILTER, Layer::Network).unwrap();
        check_filter(
            "outbound and !loopback and icmp and icmp.Type == 3",
            Layer::Network,
        )
        .unwrap();
        assert!(NETWORK_FILTER.contains("icmp and icmp.Type == 3"));
        assert!(check_filter("tcp and event == NOPE", Layer::Socket).is_err());
    }
}
