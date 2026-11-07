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
//!   passed, answered REFUSED, or handed to the [`DnsProxy`] and dropped.
//! * DNS answers (sniff only): inbound UDP from port 53 feeds the IP -> names
//!   map that lets domain rules decide flows without a peek.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use q2route_core::config::{Action as GroupAction, ProfileId, Protocol};
use q2route_core::decide::{
    decide_dns, decide_mapped, Decision, FlowInfo, MatchInfo, MatchReason, Route,
};
use q2route_core::dns::{answers, parse_query, refused, Query};
use q2route_core::domain_map::DomainMap;
use q2route_core::process_tree::ProcessTree;
use q2route_core::ruleset::RuleSet;
use q2route_core::suggest::reason_text;

use crate::classify::{
    build_rst_to_app, classify, parse, Action, FlowCache, FlowId, PROTO_TCP, PROTO_UDP,
};
use crate::conns::{ConnLog, NewConn};
use crate::dns_proxy::{DnsProxy, DnsQuery};
use crate::flows::{FlowKey, FlowTable};
use crate::nat::{redirect_outbound, restore_inbound, NatTable, OriginalDst, Verdict};
use crate::relay::{describe, exe_name, OrigDstLookup, RelayCtx};
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

/// State shared by the packet loop, the relay and the engine for the
/// engine's lifetime.
pub struct Shared {
    pub relay: Arc<RelayCtx>,
    /// Resolved `host:port` of every configured proxy: always Direct, so the
    /// relay's upstream connections can never loop back into the relay.
    pub proxy_endpoints: ArcSwap<HashSet<SocketAddr>>,
    pub own_pid: u32,
}

/// State of one Start..Stop run.
pub struct RunState {
    pub relay_port: u16,
    pub nat: Arc<NatTable>,
    pub cache: FlowCache,
    pub tcp_flows: FlowTable,
    pub udp_flows: FlowTable,
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
/// service's own). `ResetApp` / `Inject` never send the packet itself.
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
        return dns_packet(pkt, addr, &f, shared, run, dns);
    }
    // M4 Task 4 replaces this: until then TCP/53 behaves exactly as before
    // (passed through untouched).
    if f.proto == PROTO_TCP && f.remote.port() == 53 {
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
    let action = classify(&m, own_port, shared.own_pid, &run.cache, nat_has, || {
        decide_flow(shared, run, &f)
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
    Drop,
    /// Answer REFUSED.
    Refuse,
    /// Resolve through this profile's proxy ([`DnsProxy`]).
    Proxy(ProfileId),
}

/// Routes a UDP/53 payload by its queried name ([`decide_dns`]). A payload
/// that is not a single-question query only passes when the catch-all is
/// Direct (it could carry a proxied name), else it is dropped.
fn dns_verdict<'a>(rules: &RuleSet, msg: Option<&'a [u8]>) -> (DnsVerdict, Option<Query<'a>>) {
    let Some(q) = msg.and_then(parse_query) else {
        let direct = rules
            .groups
            .iter()
            .find(|g| g.catch_all)
            .is_some_and(|g| g.action == GroupAction::Direct);
        let v = if direct {
            DnsVerdict::Pass
        } else {
            DnsVerdict::Drop
        };
        return (v, None);
    };
    let v = match decide_dns(rules, &q.name).0 {
        Route::Direct => DnsVerdict::Pass,
        Route::Block => DnsVerdict::Refuse,
        Route::Proxy(id) => DnsVerdict::Proxy(id),
    };
    (v, Some(q))
}

/// An outbound UDP/53 packet: the service's own (and anything to a proxy
/// endpoint) passes; everything else is routed by the queried name only.
fn dns_packet(
    pkt: &[u8],
    addr: &Address,
    f: &FlowId,
    shared: &Shared,
    run: &RunState,
    dns: &DnsProxy,
) -> Out {
    if shared.proxy_endpoints.load().contains(&f.remote) || lookup_pid(run, f) == shared.own_pid {
        return Out::Send;
    }
    let msg = udp_payload(pkt);
    let (v, q) = dns_verdict(&shared.relay.rules.load(), msg);
    let via = match &v {
        DnsVerdict::Pass => "direct".to_string(),
        DnsVerdict::Drop => "drop".to_string(),
        DnsVerdict::Refuse => "block".to_string(),
        DnsVerdict::Proxy(id) => format!("proxy '{id}'"),
    };
    match &q {
        Some(q) => tracing::debug!("dns name={} type={} via={via}", q.name, q.qtype),
        None => tracing::debug!("dns malformed query {} -> {} via={via}", f.local, f.remote),
    }
    let msg = msg.unwrap_or_default();
    match v {
        DnsVerdict::Pass => Out::Send,
        DnsVerdict::Drop => Out::Drop,
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
    }
}

/// Learns names from one sniffed inbound DNS answer packet.
fn learn_answers(domains: &DomainMap, pkt: &[u8], now: Instant) {
    let Some(msg) = udp_payload(pkt) else { return };
    let (Some(name), ips) = answers(msg) else {
        return;
    };
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
        learn_answers(&domains, &buf[..n], Instant::now());
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
    use crate::windivert::{check_filter, Layer};
    use q2route_core::config::Config;

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

    #[test]
    fn malformed_query_dropped_when_catch_all_proxied() {
        let rules = seed_rules();
        assert_eq!(dns_verdict(&rules, Some(b"garbage")).0, DnsVerdict::Drop);
        assert_eq!(dns_verdict(&rules, None).0, DnsVerdict::Drop);
        let mut cfg = Config::seed();
        for g in cfg.groups.iter_mut().filter(|g| g.catch_all) {
            g.action = q2route_core::config::Action::Direct;
        }
        let direct = RuleSet::compile(&cfg).unwrap();
        assert_eq!(dns_verdict(&direct, Some(b"garbage")).0, DnsVerdict::Pass);
    }

    #[test]
    fn dns_query_routed_by_name() {
        let rules = seed_rules();
        let q = dns_query("example.com");
        let (v, parsed) = dns_verdict(&rules, Some(&q));
        assert_eq!(v, DnsVerdict::Proxy("v2ray".into()));
        assert_eq!(parsed.unwrap().name, "example.com");
        let q = dns_query("www.digikala.ir");
        assert_eq!(dns_verdict(&rules, Some(&q)).0, DnsVerdict::Pass);
        let mut cfg = Config::seed();
        for g in cfg.groups.iter_mut().filter(|g| g.catch_all) {
            g.action = q2route_core::config::Action::Block;
        }
        let block = RuleSet::compile(&cfg).unwrap();
        let q = dns_query("example.com");
        assert_eq!(dns_verdict(&block, Some(&q)).0, DnsVerdict::Refuse);
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
        let now = std::time::Instant::now();
        learn_answers(&map, &pkt, now);
        assert_eq!(
            map.names("9.9.9.9".parse().unwrap(), now),
            vec!["example.com".to_string()]
        );
        learn_answers(&map, &pkt[..30], now);
        assert_eq!(map.len(), 1);
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
