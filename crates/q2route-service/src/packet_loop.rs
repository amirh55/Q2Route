//! WinDivert capture loops (dedicated OS threads, blocking recv).
//!
//! * Socket layer (sniff): CONNECT / BIND / CLOSE events feed the TCP and UDP
//!   flow tables (pid lookup); TCP ACCEPT events mark inbound connections to
//!   local servers Direct.
//! * Network layer: every outbound, non-loopback TCP/UDP packet. Relay
//!   replies (`A:relay_port -> D:pa`) are restored to the app; everything else
//!   goes through [`classify`], which only ever passes Direct flows.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use q2route_core::config::Protocol;
use q2route_core::decide::{decide, Decision, FlowInfo, MatchInfo, MatchReason, Route};
use q2route_core::process_tree::ProcessTree;

use crate::classify::{
    build_rst_to_app, classify, parse, Action, FlowCache, FlowId, PROTO_TCP, PROTO_UDP,
};
use crate::flows::{FlowKey, FlowTable};
use crate::nat::{redirect_outbound, restore_inbound, NatTable, OriginalDst, Verdict};
use crate::relay::{describe, exe_name, OrigDstLookup, RelayCtx};
use crate::winapi;
use crate::windivert::{
    calc_checksums_addr, Address, Handle, EVENT_SOCKET_ACCEPT, EVENT_SOCKET_BIND,
    EVENT_SOCKET_CLOSE, EVENT_SOCKET_CONNECT,
};

pub const SOCKET_FILTER: &str = "((tcp or udp) and (event == CONNECT or event == CLOSE)) \
     or (udp and event == BIND) or (tcp and event == ACCEPT)";
pub const NETWORK_FILTER: &str = "outbound and !loopback and (tcp or udp)";
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

pub fn socket_loop(h: Arc<Handle>, run: Arc<RunState>) {
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
                // A new socket reusing this local port must not inherit
                // the old socket's decision.
                run.cache.on_socket_closed(s.protocol, s.local);
            }
            _ => {}
        }
    }
}

pub fn network_loop(h: Arc<Handle>, shared: Arc<Shared>, run: Arc<RunState>) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (n, mut addr) = match h.recv(&mut buf) {
            Ok(r) => r,
            Err(e) if keep_going(&run, "network layer", &e) => continue,
            Err(_) => return,
        };
        let pkt = &mut buf[..n];
        match route_packet(pkt, &mut addr, &shared, &run) {
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
/// flow / own socket). `ResetApp` never sends the packet itself.
fn route_packet(pkt: &mut [u8], addr: &mut Address, shared: &Shared, run: &RunState) -> Out {
    if !addr.outbound() {
        return Out::Send;
    }
    // Captured but not understood (e.g. odd IPv6 extension headers): drop
    // rather than risk passing a non-Direct flow.
    let Some(m) = parse(pkt) else {
        return Out::Drop;
    };
    let f = m.flow;
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
        Action::Redirect => {
            (redirect_outbound(pkt, addr, run.relay_port, &run.nat) == Verdict::Rewritten).into()
        }
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
    let rules = shared.relay.rules.load();
    let excluded = shared.relay.excluded.load();
    let tree = shared.relay.tree.read().unwrap_or_else(|e| e.into_inner());
    let d = decide(&rules, &tree, &excluded, &info);
    // One line per decided flow (decide_flow runs only when the flow cache
    // cannot answer). LAN / DNS / NTP flows are frequent and uninteresting.
    let proto = if proto == Protocol::Tcp { "tcp" } else { "udp" };
    let exe = exe_name(&tree, pid);
    let what = describe(&d);
    if matches!(&d, Decision::Final(_, i) if i.reason == MatchReason::AlwaysDirectDst) {
        tracing::debug!("flow {proto} pid={pid} exe={exe} dst={} {what}", f.remote);
    } else {
        tracing::info!("flow {proto} pid={pid} exe={exe} dst={} {what}", f.remote);
    }
    (pid, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windivert::{check_filter, Layer};

    #[test]
    fn filters_compile() {
        check_filter(SOCKET_FILTER, Layer::Socket).unwrap();
        check_filter(NETWORK_FILTER, Layer::Network).unwrap();
        assert!(check_filter("tcp and event == NOPE", Layer::Socket).is_err());
    }
}
