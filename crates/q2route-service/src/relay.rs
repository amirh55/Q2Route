//! Transparent TCP relay. Accepts connections redirected by the NAT, looks
//! up their original destination, peeks the SNI / HTTP Host when the rules
//! need a domain, decides a route and relays bytes.
//!
//! **Fail closed:** a flow routed to a proxy is only ever connected through
//! that proxy. If the profile is unknown or the proxy fails, the client is
//! closed; there is no direct fallback. `Event::ProxyDown` is emitted only
//! when the proxy itself is unreachable or silent, and `Event::ProxyUp` on
//! the first successful connect after that.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Config, ProfileId, Protocol};
use q2route_core::decide::{decide, Decision, FlowInfo, MatchInfo, Route};
use q2route_core::ipc::Event;
use q2route_core::peek::{peek_host, PeekResult};
use q2route_core::process_tree::ProcessTree;
use q2route_core::proxy::{connect_via, Target};
use q2route_core::ruleset::RuleSet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::nat::OriginalDst;
use crate::stats::Stats;

/// Maximum client bytes buffered while looking for a domain.
const PEEK_MAX: usize = 4096;
const PROXY_TIMEOUT: Duration = Duration::from_secs(5);
const COPY_BUF: usize = 16 * 1024;
/// Stats group for flows whose decision names no group.
const NO_GROUP: &str = "(none)";

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

pub struct RelayCtx {
    pub rules: ArcSwap<RuleSet>,
    pub cfg: ArcSwap<Config>,
    pub tree: Arc<RwLock<ProcessTree>>,
    pub excluded: ArcSwap<HashSet<u32>>,
    pub stats: Arc<Stats>,
    /// Local ports of the relay's direct upstream sockets; capture skips them.
    pub own_ports: Arc<DashSet<u16>>,
    pub events: broadcast::Sender<Event>,
    /// A relayed connection with no bytes in either direction for this long
    /// is closed ([`RELAY_IDLE_TIMEOUT`] in production).
    pub idle_timeout: Duration,
    /// Profiles the relay last saw down (unreachable / silent); the first
    /// successful connect through one emits `Event::ProxyUp`.
    pub proxy_down: DashSet<ProfileId>,
}

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
        dst: SocketAddr::V4(orig.dst),
        domain,
    };
    let tree = ctx.tree.read().unwrap_or_else(|e| e.into_inner());
    decide(&rules, &tree, &excluded, &f)
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
    let mut buf = Vec::new();
    let mut domain = String::new();
    let mut decision = decide_flow(ctx, &orig, None);
    if decision == Decision::NeedDomain {
        let limit = Duration::from_millis(ctx.cfg.load().settings.peek_timeout_ms);
        domain = peek(&mut client, &mut buf, limit).await.unwrap_or_default();
        // An empty domain matches no domain rule, so this cannot be NeedDomain again.
        decision = decide_flow(ctx, &orig, Some(&domain));
    }
    let (route, info) = match decision {
        Decision::Final(route, info) => (route, info),
        Decision::NeedDomain => {
            tracing::warn!("undecidable flow to {}; closing", orig.dst);
            return;
        }
    };
    let group = group_of(&info);
    match route {
        Route::Block => {}
        Route::Proxy(id) => {
            let profile = ctx.cfg.load().proxies.iter().find(|p| p.id == id).cloned();
            let target = if domain.is_empty() {
                Target::Ip(SocketAddr::V4(orig.dst))
            } else {
                Target::Domain(domain, orig.dst.port())
            };
            let upstream = match profile {
                Some(p) => connect_via(&p, &target, PROXY_TIMEOUT)
                    .await
                    .map_err(|e| (e.is_proxy_down(), e.to_string())),
                None => Err((false, "unknown proxy profile".to_string())),
            };
            match upstream {
                Ok(up) => {
                    // First success since the relay saw it down: it is back.
                    if ctx.proxy_down.remove(&id).is_some() {
                        let _ = ctx.events.send(Event::ProxyUp { id: id.clone() });
                    }
                    pump(client, up, &buf, ctx, group).await
                }
                Err((down, e)) => {
                    // Fail closed: drop the client, never connect direct.
                    tracing::warn!("proxy '{id}' failed for {}: {e}", orig.dst);
                    drop(client);
                    // Only an unreachable / silent proxy is "down"; a refused
                    // target or auth/protocol error is not a banner alarm.
                    if down {
                        ctx.proxy_down.insert(id.clone());
                        let _ = ctx.events.send(Event::ProxyDown { id });
                    }
                }
            }
        }
        Route::Direct => {
            let Ok(sock) = TcpSocket::new_v4() else {
                return;
            };
            // Bind first so the local port is known (and skipped by capture)
            // before the SYN leaves.
            if sock
                .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                .is_err()
            {
                return;
            }
            let Ok(port) = sock.local_addr().map(|a| a.port()) else {
                return;
            };
            ctx.own_ports.insert(port);
            let _own = OwnPort {
                ports: &ctx.own_ports,
                port,
            };
            match sock.connect(SocketAddr::V4(orig.dst)).await {
                Ok(up) => pump(client, up, &buf, ctx, group).await,
                Err(e) => tracing::debug!("direct connect to {} failed: {e}", orig.dst),
            }
        }
    }
}

fn group_of(info: &MatchInfo) -> &str {
    info.group_id.as_deref().unwrap_or(NO_GROUP)
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
async fn pump(client: TcpStream, upstream: TcpStream, peeked: &[u8], ctx: &RelayCtx, group: &str) {
    set_keepalive(&upstream);
    let _active = ctx.stats.open(group);
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    if !peeked.is_empty() {
        if uw.write_all(peeked).await.is_err() {
            return;
        }
        ctx.stats.add(group, peeked.len() as u64, 0);
    }
    let activity = Activity::new();
    let up = copy(&mut cr, &mut uw, |n| {
        activity.touch();
        ctx.stats.add(group, n, 0)
    });
    let down = copy(&mut ur, &mut cw, |n| {
        activity.touch();
        ctx.stats.add(group, 0, n)
    });
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
            if quiet >= ctx.idle_timeout {
                return;
            }
            tokio::time::sleep(ctx.idle_timeout - quiet).await;
        }
    };
    tokio::select! {
        ok = both => {
            if !ok {
                tracing::debug!("relay connection ended with an error");
            }
        }
        () = idle => tracing::debug!("relay connection idle for {:?}; closing", ctx.idle_timeout),
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
    fn mapped_peer_becomes_v4() {
        let p: SocketAddr = "[::ffff:5.6.7.8]:4000".parse().unwrap();
        assert_eq!(normalize_peer(p), "5.6.7.8:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        assert_eq!(normalize_peer(v6), v6);
        let v4: SocketAddr = "1.2.3.4:5".parse().unwrap();
        assert_eq!(normalize_peer(v4), v4);
    }
}
