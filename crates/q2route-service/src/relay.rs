//! Transparent TCP relay. Accepts connections redirected by the NAT, looks
//! up their original destination, peeks the SNI / HTTP Host when the rules
//! need a domain, decides a route and relays bytes. TCP/53 is routed by the
//! queried DNS name instead (`handle_dns`), unless it is not DNS at all.
//!
//! **Fail closed:** a flow routed to a proxy is only ever connected through
//! that proxy. If the profile is unknown or the proxy fails, the client is
//! closed; there is no direct fallback. `Event::ProxyDown` is emitted only
//! when the proxy itself is unreachable or silent, and `Event::ProxyUp` on
//! the first successful connect after that.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Config, ProfileId, Protocol};
use q2route_core::decide::{
    decide, decide_dns, decide_mapped_no_peek, Decision, FlowInfo, MatchInfo, MatchReason, Route,
};
use q2route_core::dns::{answers, parse_query, response_id};
use q2route_core::domain_map::DomainMap;
use q2route_core::ipc::Event;
use q2route_core::peek::{peek_host, PeekResult};
use q2route_core::process_tree::ProcessTree;
use q2route_core::proxy::{connect_via, Target};
use q2route_core::ruleset::RuleSet;
use q2route_core::suggest::reason_text;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::conns::{ConnBytes, ConnLog, NewConn};
use crate::dns_proxy::bootstrap_direct;
use crate::nat::OriginalDst;
use crate::stats::Stats;

/// Maximum client bytes buffered while looking for a domain.
const PEEK_MAX: usize = 4096;
const PROXY_TIMEOUT: Duration = Duration::from_secs(5);
const COPY_BUF: usize = 16 * 1024;
/// Stats group for flows whose decision names no group.
pub(crate) const NO_GROUP: &str = "(none)";

/// Maps an accepted peer address back to the flow's original destination.
/// The relay owns the NAT entry while its connection lives: it attaches the
/// entry on accept and releases it when the connection ends, so a quiet
/// connection is never black-holed by the NAT's idle sweep.
pub trait OrigDstLookup: Send + Sync {
    /// Original destination for `peer` plus a token for [`Self::release`].
    fn attach(&self, peer: SocketAddr) -> Option<(OriginalDst, u64)>;
    /// The relay connection that attached `token` has ended.
    fn release(&self, peer: SocketAddr, token: u64);
}

/// Releases the NAT entry when the relay connection ends (also on cancel).
struct Hold<'a> {
    lookup: &'a dyn OrigDstLookup,
    peer: SocketAddr,
    token: u64,
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        self.lookup.release(self.peer, self.token);
    }
}

/// Marks the connection ended when the relay connection ends (also on cancel).
struct ConnGuard<'a> {
    log: &'a ConnLog,
    id: u64,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.log.close(self.id);
    }
}

pub struct RelayCtx {
    pub rules: ArcSwap<RuleSet>,
    pub cfg: ArcSwap<Config>,
    pub tree: Arc<RwLock<ProcessTree>>,
    pub excluded: ArcSwap<HashSet<u32>>,
    pub stats: Arc<Stats>,
    pub conns: Arc<ConnLog>,
    /// Local ports of the relay's direct upstream sockets; capture skips them.
    pub own_ports: Arc<DashSet<u16>>,
    pub events: broadcast::Sender<Event>,
    /// A relayed connection with no bytes in either direction for this long
    /// is closed ([`RELAY_IDLE_TIMEOUT`] in production).
    pub idle_timeout: Duration,
    /// Profiles the relay last saw down (unreachable / silent); the first
    /// successful connect through one emits `Event::ProxyUp`.
    pub proxy_down: DashSet<ProfileId>,
    /// IP -> names learned from DNS answers (sniffed and proxied), so
    /// domain rules can decide flows that carry no SNI / Host.
    pub domains: Arc<DomainMap>,
    /// Server names detected from the running proxy client's config
    /// (refreshed by the engine): their DNS queries are resolved directly.
    pub proxy_servers: ArcSwap<Vec<String>>,
    /// Test hook: maps an original destination to the address a direct
    /// connect actually dials (mock servers on 127.0.0.1). `None` in
    /// production.
    pub direct_dial_override: Option<DialOverride>,
}

/// See [`RelayCtx::direct_dial_override`].
pub type DialOverride = Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>;

/// Production idle timeout of a relayed connection.
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
/// TCP keepalive on both relay sockets, so dead peers are noticed long
/// before the idle timeout (the Windows default first probe is after 2 h).
const KEEPALIVE_TIME: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Turns on SO_KEEPALIVE (with [`KEEPALIVE_TIME`] / [`KEEPALIVE_INTERVAL`]).
fn set_keepalive(s: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL);
    if let Err(e) = socket2::SockRef::from(s).set_tcp_keepalive(&ka) {
        tracing::debug!("cannot set keepalive: {e}");
    }
}

/// Accepts until `cancel` fires, then closes every in-flight connection and
/// returns once they are all gone.
pub async fn run_relay(
    listener: TcpListener,
    lookup: Arc<dyn OrigDstLookup>,
    ctx: Arc<RelayCtx>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let tracker = TaskTracker::new();
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        match accepted {
            Ok((client, peer)) => {
                let (lookup, ctx, cancel) = (lookup.clone(), ctx.clone(), cancel.clone());
                tracker.spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = handle(client, peer, &*lookup, &ctx) => {}
                    }
                });
            }
            Err(e) => {
                // Per-connection accept errors (e.g. reset before accept) are
                // transient; back off briefly so a persistent error cannot spin.
                tracing::warn!("relay accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    tracker.close();
    tracker.wait().await;
    Ok(())
}

/// `::ffff:a.b.c.d` (dual-stack listener) becomes `a.b.c.d`.
fn normalize_peer(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::V4(SocketAddrV4::new(ip, a.port())),
            None => peer,
        },
        v4 => v4,
    }
}

fn decide_flow(ctx: &RelayCtx, orig: &OriginalDst, domain: Option<&str>) -> Decision {
    let rules = ctx.rules.load();
    let excluded = ctx.excluded.load();
    let f = FlowInfo {
        proto: Protocol::Tcp,
        pid: orig.pid,
        dst: orig.dst,
        domain,
    };
    let tree = ctx.tree.read().unwrap_or_else(|e| e.into_inner());
    decide(&rules, &tree, &excluded, &f)
}

/// After a peek that found no host: decide by the names DNS answered for
/// the destination; disagreeing names give the most protective route
/// (Proxy > Block > Direct). No names: a domain-less flow (`Some("")`), as
/// before the DNS map existed.
fn decide_after_empty_peek(ctx: &RelayCtx, orig: &OriginalDst) -> Decision {
    let names = ctx.domains.names(orig.dst.ip(), std::time::Instant::now());
    let rules = ctx.rules.load();
    let excluded = ctx.excluded.load();
    let f = FlowInfo {
        proto: Protocol::Tcp,
        pid: orig.pid,
        dst: orig.dst,
        domain: None,
    };
    let tree = ctx.tree.read().unwrap_or_else(|e| e.into_inner());
    decide_mapped_no_peek(&rules, &tree, &excluded, &f, &names)
}

/// Reads client bytes until a host is found, the input is not TLS/HTTP, the
/// buffer cap is reached, the client stops sending, or `limit` passes.
async fn peek(client: &mut TcpStream, buf: &mut Vec<u8>, limit: Duration) -> Option<String> {
    let deadline = Instant::now() + limit;
    let mut chunk = [0u8; PEEK_MAX];
    while buf.len() < PEEK_MAX {
        let room = PEEK_MAX - buf.len();
        match timeout_at(deadline, client.read(&mut chunk[..room])).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
        match peek_host(buf) {
            PeekResult::Host(h) => return Some(h),
            PeekResult::NotFound => return None,
            PeekResult::NeedMore => {}
        }
    }
    None
}

async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    lookup: &dyn OrigDstLookup,
    ctx: &RelayCtx,
) {
    let peer = normalize_peer(peer);
    let Some((orig, token)) = lookup.attach(peer) else {
        tracing::debug!("no original destination for {peer}; closing");
        return;
    };
    let _hold = Hold {
        lookup,
        peer,
        token,
    };
    set_keepalive(&client);
    if orig.dst.port() == 53 {
        return handle_dns(client, peer, &orig, ctx).await;
    }
    let mut buf = Vec::new();
    let mut domain = String::new();
    let mut decision = decide_flow(ctx, &orig, None);
    if decision == Decision::NeedDomain {
        let limit = Duration::from_millis(ctx.cfg.load().settings.peek_timeout_ms);
        domain = peek(&mut client, &mut buf, limit).await.unwrap_or_default();
        decision = if domain.is_empty() {
            decide_after_empty_peek(ctx, &orig)
        } else {
            // A domain is set, so this cannot be NeedDomain again.
            decide_flow(ctx, &orig, Some(&domain))
        };
    }
    relay_flow(client, peer, &orig, ctx, &buf, domain, decision).await
}

/// Carries out `decision` for a relayed flow: `buf` (client bytes already
/// read) is sent upstream first; `domain` (may be empty) is the peeked host.
async fn relay_flow(
    client: TcpStream,
    peer: SocketAddr,
    orig: &OriginalDst,
    ctx: &RelayCtx,
    buf: &[u8],
    domain: String,
    decision: Decision,
) {
    let (route, info) = match decision {
        Decision::Final(route, info) => (route, info),
        Decision::NeedDomain => {
            tracing::warn!("undecidable flow to {}; closing", orig.dst);
            return;
        }
    };
    let group = group_of(&info);
    // One line per relayed flow: the decision plus how it turned out.
    let what = describe(&Decision::Final(route.clone(), info.clone()));
    let exe = exe_name(
        &ctx.tree.read().unwrap_or_else(|e| e.into_inner()),
        orig.pid,
    );
    let bytes = Arc::new(ConnBytes::default());
    let _conn = ConnGuard {
        log: &ctx.conns,
        id: ctx.conns.open(
            NewConn {
                proto: Protocol::Tcp,
                pid: orig.pid,
                exe: exe.clone(),
                local: peer,
                dst: orig.dst,
                domain: (!domain.is_empty()).then(|| domain.clone()),
                route: route.clone(),
                group_id: info.group_id.clone(),
                reason: reason_text(
                    &info.reason,
                    &ctx.tree.read().unwrap_or_else(|e| e.into_inner()),
                ),
            },
            Some(bytes.clone()),
        ),
    };
    let shown_domain = if domain.is_empty() {
        "-".to_string()
    } else {
        domain.clone()
    };
    let log = |outcome: &str| {
        tracing::info!(
            "relay pid={} exe={exe} dst={} domain={shown_domain} {what}: {outcome}",
            orig.pid,
            orig.dst
        )
    };
    match route {
        Route::Block => log("blocked"),
        Route::Proxy(id) => {
            let target = if domain.is_empty() {
                Target::Ip(orig.dst)
            } else {
                Target::Domain(domain, orig.dst.port())
            };
            match connect_proxy(ctx, &id, &target).await {
                Ok(up) => {
                    log(&format!("proxied via '{id}'"));
                    pump(client, up, buf, ctx, group, &bytes).await
                }
                // Fail closed: drop the client, never connect direct.
                Err(e) => log(&format!("proxy failed: {e} (closed, no direct fallback)")),
            }
        }
        Route::Direct => match connect_direct(ctx, orig.dst).await {
            Ok((up, _own)) => {
                log("direct");
                pump(client, up, buf, ctx, group, &bytes).await
            }
            Err(e) => log(&format!("direct connect failed: {e}")),
        },
    }
}

/// Connects to `target` through profile `id`. Emits `Event::ProxyDown` when
/// the proxy itself is unreachable / silent, and `Event::ProxyUp` on the
/// first success after that. The caller must fail closed on `Err`.
async fn connect_proxy(
    ctx: &RelayCtx,
    id: &ProfileId,
    target: &Target,
) -> Result<TcpStream, String> {
    let profile = ctx.cfg.load().proxies.iter().find(|p| &p.id == id).cloned();
    let upstream = match profile {
        Some(p) => connect_via(&p, target, PROXY_TIMEOUT)
            .await
            .map_err(|e| (e.is_proxy_down(), e.to_string())),
        None => Err((false, "unknown proxy profile".to_string())),
    };
    match upstream {
        Ok(up) => {
            // First success since the relay saw it down: it is back.
            if ctx.proxy_down.remove(id).is_some() {
                let _ = ctx.events.send(Event::ProxyUp { id: id.clone() });
            }
            Ok(up)
        }
        Err((down, e)) => {
            // Only an unreachable / silent proxy is "down"; a refused target
            // or auth/protocol error is not a banner alarm.
            if down {
                ctx.proxy_down.insert(id.clone());
                let _ = ctx.events.send(Event::ProxyDown { id: id.clone() });
            }
            Err(e)
        }
    }
}

/// Connects directly to `dst` from a port registered in `own_ports` (so
/// capture skips it) for as long as the returned guard lives.
/// IPv4 only (the capture skips own ports for IPv4 TCP only).
async fn connect_direct(ctx: &RelayCtx, dst: SocketAddr) -> io::Result<(TcpStream, OwnPort<'_>)> {
    if !dst.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 direct connect",
        ));
    }
    let sock = TcpSocket::new_v4()?;
    // Bind first so the local port is known (and skipped by capture) before
    // the SYN leaves.
    sock.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let port = sock.local_addr()?.port();
    ctx.own_ports.insert(port);
    let own = OwnPort {
        ports: &ctx.own_ports,
        port,
    };
    let dst = ctx.direct_dial_override.as_ref().map_or(dst, |f| f(dst));
    let up = sock.connect(dst).await?;
    Ok((up, own))
}

/// Longest first DNS-over-TCP query accepted, and how long it may take.
const DNS_FIRST_MAX: usize = 4096;
const DNS_FIRST_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `pid` is the proxy program itself: a pid listening on a
/// configured proxy endpoint (`excluded`) or a process whose OWN exe is
/// always-direct (Ruling R8; children are not). Its DNS is always Direct.
pub fn proxy_program(
    rules: &RuleSet,
    tree: &ProcessTree,
    excluded: &HashSet<u32>,
    pid: u32,
) -> Option<MatchReason> {
    if excluded.contains(&pid) {
        return Some(MatchReason::ExcludedPid);
    }
    tree.get(pid)
        .is_some_and(|p| rules.always_direct.iter().any(|m| m.matches(&p.exe)))
        .then_some(MatchReason::AlwaysDirectApp)
}

/// Route of a DNS query for `name` from `pid`: the proxy program's own
/// queries ([`proxy_program`]) and bootstrap names ([`bootstrap_direct`])
/// are Direct, anything else by [`decide_dns`] (the queried name only).
fn dns_route(ctx: &RelayCtx, pid: u32, name: &str) -> (Route, MatchInfo) {
    let bootstrap = MatchInfo {
        group_id: None,
        reason: MatchReason::BootstrapName,
    };
    let program = {
        let tree = ctx.tree.read().unwrap_or_else(|e| e.into_inner());
        proxy_program(&ctx.rules.load(), &tree, &ctx.excluded.load(), pid).is_some()
    };
    if program {
        tracing::debug!("dns name={name} pid={pid} via=direct (proxy program)");
        return (Route::Direct, bootstrap);
    }
    if let Some(why) = bootstrap_direct(&ctx.cfg.load(), &ctx.proxy_servers.load(), name) {
        tracing::debug!("dns name={name} pid={pid} via=direct ({why})");
        return (Route::Direct, bootstrap);
    }
    decide_dns(&ctx.rules.load(), name)
}

/// What the first bytes of a relayed TCP/53 connection turned out to be.
enum FirstMsg {
    /// One complete length-prefixed DNS query (with its prefix).
    Query(Vec<u8>),
    /// Not DNS (bytes read so far, possibly none): a frame longer than a
    /// query may be, a complete frame that is not a query, or a client
    /// that sent nothing within the limit (DNS clients speak first).
    Other(Vec<u8>),
    /// The client closed without sending anything, or a frame that could
    /// be a query never completed: closed (fail closed).
    Close,
}

/// Reads the first length-prefixed message of a TCP/53 connection, never
/// past its end (later bytes stay in the socket).
async fn read_first_msg(client: &mut TcpStream, max: usize, limit: Duration) -> FirstMsg {
    let deadline = Instant::now() + limit;
    let mut buf = Vec::new();
    let mut need = 2;
    let mut chunk = [0u8; 2048];
    loop {
        while buf.len() < need {
            let room = (need - buf.len()).min(chunk.len());
            match timeout_at(deadline, client.read(&mut chunk[..room])).await {
                Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                // Silent client: not a DNS client.
                Err(_) if buf.is_empty() => return FirstMsg::Other(buf),
                // EOF / error / a partial frame: nothing safe to relay.
                _ => return FirstMsg::Close,
            }
        }
        if need > 2 {
            return if parse_query(&buf[2..]).is_some() {
                FirstMsg::Query(buf)
            } else {
                FirstMsg::Other(buf)
            };
        }
        let n = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if n > max || n == 0 {
            return FirstMsg::Other(buf);
        }
        need = 2 + n;
    }
}

/// Reads one length-prefixed DNS message of at most `max` bytes and returns
/// it with its 2-byte prefix. `Ok(None)`: the stream ended cleanly at a
/// message boundary. The buffer is bounded by the prefix (<= 65535 + 2).
async fn read_dns_msg<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    if r.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..]).await?;
    let n = usize::from(u16::from_be_bytes(len));
    if n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns message too long",
        ));
    }
    let mut m = vec![0u8; n + 2];
    m[..2].copy_from_slice(&len);
    r.read_exact(&mut m[2..]).await?;
    Ok(Some(m))
}

/// Queries forwarded on one DNS-over-TCP connection and not yet answered:
/// id -> lowercase name. At most [`TCP_DNS_PENDING_MAX`]; a query beyond
/// that is still forwarded, but its answer is not learned.
const TCP_DNS_PENDING_MAX: usize = 256;

type Asked = std::sync::Mutex<HashMap<u16, String>>;

fn ask(asked: &Asked, msg: &[u8]) {
    let Some(q) = parse_query(msg) else { return };
    let mut a = asked.lock().unwrap_or_else(|e| e.into_inner());
    if a.len() < TCP_DNS_PENDING_MAX || a.contains_key(&q.id) {
        a.insert(q.id, q.name);
    }
}

/// Feeds the IP -> name answers of one DNS response into the map, only if
/// it answers a query forwarded on this connection (same id and name).
fn learn_answers(domains: &DomainMap, asked: &Asked, msg: &[u8]) {
    let (Some(name), ips) = answers(msg) else {
        return;
    };
    let Some(id) = response_id(msg) else { return };
    {
        let mut a = asked.lock().unwrap_or_else(|e| e.into_inner());
        if a.get(&id) != Some(&name) {
            tracing::debug!("tcp dns answer for {name} (id {id}) matches no query; not learned");
            return;
        }
        a.remove(&id);
    }
    let now = std::time::Instant::now();
    for (ip, ttl) in ips {
        domains.insert(ip, &name, ttl, now);
    }
}

/// IPv4 TCP/53: routed by the first query's name only. Direct goes to the
/// original server from an own port, Proxy to `proxy_resolver` through the
/// profile (fail closed: any failure closes the client), Block closes.
/// Later queries on the connection must decide the same route, else the
/// connection is closed before that query is sent anywhere. A connection
/// that is not DNS at all (a VPN on port 53) carries no name: it is relayed
/// to its original destination by the ordinary flow decision.
async fn handle_dns(mut client: TcpStream, peer: SocketAddr, orig: &OriginalDst, ctx: &RelayCtx) {
    let first = match read_first_msg(&mut client, DNS_FIRST_MAX, DNS_FIRST_TIMEOUT).await {
        FirstMsg::Query(m) => m,
        FirstMsg::Other(buf) => {
            tracing::debug!(
                "tcp {peer} -> {}: not DNS; relayed as an ordinary flow",
                orig.dst
            );
            let decision = decide_flow(ctx, orig, None);
            return relay_flow(client, peer, orig, ctx, &buf, String::new(), decision).await;
        }
        FirstMsg::Close => {
            tracing::debug!("tcp dns {peer} -> {}: no query read; closing", orig.dst);
            return;
        }
    };
    let Some(q) = parse_query(&first[2..]) else {
        return;
    };
    let (name, qtype) = (q.name, q.qtype);
    let (route, info) = dns_route(ctx, orig.pid, &name);
    let group = group_of(&info);
    let what = describe(&Decision::Final(route.clone(), info.clone()));
    let (exe, reason) = {
        let tree = ctx.tree.read().unwrap_or_else(|e| e.into_inner());
        (exe_name(&tree, orig.pid), reason_text(&info.reason, &tree))
    };
    let bytes = Arc::new(ConnBytes::default());
    let _conn = ConnGuard {
        log: &ctx.conns,
        id: ctx.conns.open(
            NewConn {
                proto: Protocol::Tcp,
                pid: orig.pid,
                exe: exe.clone(),
                local: peer,
                dst: orig.dst,
                domain: Some(name.clone()),
                route: route.clone(),
                group_id: info.group_id.clone(),
                reason,
            },
            Some(bytes.clone()),
        ),
    };
    let log = |outcome: &str| {
        tracing::info!(
            "relay dns pid={} exe={exe} dst={} name={name} type={qtype} {what}: {outcome}",
            orig.pid,
            orig.dst
        )
    };
    let (up, _own) = match &route {
        Route::Block => return log("blocked"),
        Route::Direct => match connect_direct(ctx, orig.dst).await {
            Ok((up, own)) => (up, Some(own)),
            Err(e) => return log(&format!("direct connect failed: {e}")),
        },
        Route::Proxy(id) => {
            let resolver = ctx.cfg.load().settings.dns.proxy_resolver.clone();
            let Ok(resolver) = resolver.parse::<SocketAddr>() else {
                return log(&format!("resolver '{resolver}' is not ip:port (closed)"));
            };
            match connect_proxy(ctx, id, &Target::Ip(resolver)).await {
                Ok(up) => (up, None),
                // Fail closed: drop the client, never connect direct.
                Err(e) => return log(&format!("proxy failed: {e} (closed, no direct fallback)")),
            }
        }
    };
    log(match route {
        Route::Proxy(_) => "proxied to the resolver",
        _ => "direct",
    });
    let same_route = |n: &str| dns_route(ctx, orig.pid, n).0 == route;
    dns_pump(client, up, &first, same_route, ctx, group, &bytes).await
}

/// [`pump`] for DNS over TCP: relays whole length-prefixed messages. Each
/// client query is parsed and its name checked with `same_route` (decides
/// the first query's route) before it is sent (a query that does not parse or decides differently ends the
/// connection); each answer feeds `ctx.domains` on its way back.
async fn dns_pump(
    client: TcpStream,
    upstream: TcpStream,
    first: &[u8],
    same_route: impl Fn(&str) -> bool,
    ctx: &RelayCtx,
    group: &str,
    bytes: &ConnBytes,
) {
    set_keepalive(&upstream);
    let _active = ctx.stats.open(group);
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let asked = Asked::default();
    ask(&asked, &first[2..]);
    if uw.write_all(first).await.is_err() {
        return;
    }
    ctx.stats.add(group, first.len() as u64, 0);
    bytes.up.fetch_add(first.len() as u64, Ordering::Relaxed);
    let activity = Activity::new();
    let max = usize::from(u16::MAX);
    let up = async {
        while let Some(m) = read_dns_msg(&mut cr, max).await? {
            let same = parse_query(&m[2..]).is_some_and(|q| same_route(&q.name));
            if !same {
                tracing::debug!(
                    "tcp dns: a later query is malformed or routed differently; closing"
                );
                return Err(io::Error::other("dns query with another route"));
            }
            ask(&asked, &m[2..]);
            uw.write_all(&m).await?;
            activity.touch();
            bytes.up.fetch_add(m.len() as u64, Ordering::Relaxed);
            ctx.stats.add(group, m.len() as u64, 0);
        }
        uw.shutdown().await
    };
    let down = async {
        while let Some(m) = read_dns_msg(&mut ur, max).await? {
            learn_answers(&ctx.domains, &asked, &m[2..]);
            cw.write_all(&m).await?;
            activity.touch();
            bytes.down.fetch_add(m.len() as u64, Ordering::Relaxed);
            ctx.stats.add(group, 0, m.len() as u64);
        }
        cw.shutdown().await
    };
    drive(up, down, &activity, ctx.idle_timeout).await
}

fn group_of(info: &MatchInfo) -> &str {
    info.group_id.as_deref().unwrap_or(NO_GROUP)
}

/// `route=.. group=.. reason=..` for the one-line-per-flow decision log.
pub(crate) fn describe(d: &Decision) -> String {
    let Decision::Final(route, info) = d else {
        return "route=NeedDomain (peek)".into();
    };
    let route = match route {
        Route::Direct => "Direct".to_string(),
        Route::Block => "Block".to_string(),
        Route::Proxy(id) => format!("Proxy({id})"),
    };
    let reason = match &info.reason {
        MatchReason::Inherited { from_pid } => format!("Inherited(from_pid={from_pid})"),
        r => format!("{r:?}"),
    };
    format!("route={route} group={} reason={reason}", group_of(info))
}

/// The process's exe file name (e.g. `chrome.exe`), or `?` if unknown.
pub(crate) fn exe_name(tree: &ProcessTree, pid: u32) -> String {
    tree.get(pid)
        .and_then(|p| p.exe.file_name())
        .map_or_else(|| "?".into(), |n| n.to_string_lossy().into_owned())
}

/// Removes a port from `own_ports` when the direct upstream is gone.
struct OwnPort<'a> {
    ports: &'a DashSet<u16>,
    port: u16,
}

impl Drop for OwnPort<'_> {
    fn drop(&mut self) {
        self.ports.remove(&self.port);
    }
}

/// Time of the last byte relayed in either direction.
struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Activity {
        Activity {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }
    fn touch(&self) {
        let ms = self.base.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.base.elapsed().saturating_sub(last)
    }
}

/// Sends the peeked bytes upstream, then copies both ways until both
/// directions are closed (or either fails), or until no byte has moved in
/// either direction for `ctx.idle_timeout`.
async fn pump(
    client: TcpStream,
    upstream: TcpStream,
    peeked: &[u8],
    ctx: &RelayCtx,
    group: &str,
    bytes: &ConnBytes,
) {
    set_keepalive(&upstream);
    let _active = ctx.stats.open(group);
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    if !peeked.is_empty() {
        if uw.write_all(peeked).await.is_err() {
            return;
        }
        ctx.stats.add(group, peeked.len() as u64, 0);
        bytes.up.fetch_add(peeked.len() as u64, Ordering::Relaxed);
    }
    let activity = Activity::new();
    let up = copy(&mut cr, &mut uw, |n| {
        activity.touch();
        bytes.up.fetch_add(n, Ordering::Relaxed);
        ctx.stats.add(group, n, 0)
    });
    let down = copy(&mut ur, &mut cw, |n| {
        activity.touch();
        bytes.down.fetch_add(n, Ordering::Relaxed);
        ctx.stats.add(group, 0, n)
    });
    drive(up, down, &activity, ctx.idle_timeout).await
}

/// Runs both directions until both have ended cleanly (or either fails),
/// or until no byte has moved for `idle_timeout`.
async fn drive(
    up: impl Future<Output = io::Result<()>>,
    down: impl Future<Output = io::Result<()>>,
    activity: &Activity,
    idle_timeout: Duration,
) {
    tokio::pin!(up, down);
    let both = async {
        tokio::select! {
            r = &mut up => r.is_ok() && down.await.is_ok(),
            r = &mut down => r.is_ok() && up.await.is_ok(),
        }
    };
    let idle = async {
        loop {
            let quiet = activity.idle_for();
            if quiet >= idle_timeout {
                return;
            }
            tokio::time::sleep(idle_timeout - quiet).await;
        }
    };
    tokio::select! {
        ok = both => {
            if !ok {
                tracing::debug!("relay connection ended with an error");
            }
        }
        () = idle => tracing::debug!("relay connection idle for {idle_timeout:?}; closing"),
    }
}

/// Copies until EOF, then shuts down the write side (half-close).
async fn copy<R, W>(r: &mut R, w: &mut W, count: impl Fn(u64)) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return w.shutdown().await;
        }
        w.write_all(&buf[..n]).await?;
        count(n as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keepalive_is_enabled() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        assert!(!socket2::SockRef::from(&c).keepalive().unwrap());
        set_keepalive(&c);
        assert!(socket2::SockRef::from(&c).keepalive().unwrap());
    }

    #[test]
    fn decision_log_fields() {
        use q2route_core::decide::MatchReason;
        let d = Decision::Final(
            Route::Direct,
            MatchInfo {
                group_id: Some("steam".into()),
                reason: MatchReason::Inherited { from_pid: 10 },
            },
        );
        assert_eq!(
            describe(&d),
            "route=Direct group=steam reason=Inherited(from_pid=10)"
        );
        let d = Decision::Final(
            Route::Proxy("v2ray".into()),
            MatchInfo {
                group_id: Some("everything-else".into()),
                reason: MatchReason::CatchAll,
            },
        );
        assert_eq!(
            describe(&d),
            "route=Proxy(v2ray) group=everything-else reason=CatchAll"
        );
        let d = Decision::Final(
            Route::Block,
            MatchInfo {
                group_id: None,
                reason: MatchReason::NoMatch,
            },
        );
        assert_eq!(describe(&d), "route=Block group=(none) reason=NoMatch");
        assert_eq!(describe(&Decision::NeedDomain), "route=NeedDomain (peek)");
    }

    #[test]
    fn exe_name_is_file_name() {
        let mut t = ProcessTree::default();
        t.insert(q2route_core::process_tree::ProcInfo {
            pid: 5,
            parent: 0,
            exe: r"C:\Program Files\Steam\bin\steamwebhelper.exe".into(),
            start_time: 1,
        });
        assert_eq!(exe_name(&t, 5), "steamwebhelper.exe");
        assert_eq!(exe_name(&t, 6), "?");
    }

    #[test]
    fn mapped_peer_becomes_v4() {
        let p: SocketAddr = "[::ffff:5.6.7.8]:4000".parse().unwrap();
        assert_eq!(normalize_peer(p), "5.6.7.8:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        assert_eq!(normalize_peer(v6), v6);
        let v4: SocketAddr = "1.2.3.4:5".parse().unwrap();
        assert_eq!(normalize_peer(v4), v4);
    }
}
