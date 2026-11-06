//! UDP relay: proxied IPv4 UDP flows go through a SOCKS5 UDP ASSOCIATE.
//!
//! Packet threads [`UdpRelay::submit`] captured datagrams (never blocking:
//! bounded channel, full = drop). One manager task owns the session map, one
//! session per app socket (local address). A session associates through its
//! profile, then relays app datagrams to the proxy's UDP relay and injects
//! the proxy's replies back to the app as inbound packets.
//!
//! **Fail closed:** nothing here ever sends an app datagram direct. A missing
//! or non-SOCKS5 profile, or a failed association, drops the datagrams (for
//! [`FAIL_BACKOFF`], then the next datagram retries).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use q2route_core::config::{GroupId, ProfileId, Protocol, ProxyKind};
use q2route_core::decide::Route;
use q2route_core::ipc::Event;
use q2route_core::proxy::{decode_udp, encode_udp, udp_associate, UdpAssociation};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

use crate::conns::{ConnBytes, NewConn};
use crate::relay::{exe_name, RelayCtx, NO_GROUP};
use crate::udp_packet::build_inbound_udp;
use crate::windivert::Address;

/// A session with no datagram in either direction for this long ends.
pub const SESSION_IDLE: Duration = Duration::from_secs(300);
/// Datagrams queued per session while it associates (more are dropped).
pub const PENDING_MAX: usize = 64;
/// ConnLog rows (one per remote) a session opens at most; further remotes
/// are still relayed and counted in the stats, but get no row.
pub const MAX_REMOTE_ROWS: usize = 32;
/// After a failed association (or an unusable profile) the session drops
/// its datagrams for this long; the next datagram after that retries.
pub const FAIL_BACKOFF: Duration = Duration::from_secs(10);
const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound of the packet threads -> manager channel.
const SUBMIT_QUEUE: usize = 4096;
const RECV_BUF: usize = 65536;

/// Delivers a rebuilt inbound packet to the app (production: WinDivert send
/// with the first outbound packet's Address, outbound=false, checksums
/// recalculated).
pub trait InboundSink: Send + Sync + 'static {
    fn inject(&self, pkt: Vec<u8>, addr: &Address);
}

/// One captured outbound datagram of a proxied UDP flow.
pub struct Datagram {
    pub pid: u32,
    pub profile: ProfileId,
    pub group_id: Option<GroupId>,
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub payload: Vec<u8>,
    pub addr: Address,
}

/// Timeouts of a [`UdpRelay`] (tests shorten them).
#[derive(Clone, Copy, Debug)]
pub struct UdpRelayConfig {
    pub idle: Duration,
    pub backoff: Duration,
}

impl Default for UdpRelayConfig {
    fn default() -> Self {
        UdpRelayConfig {
            idle: SESSION_IDLE,
            backoff: FAIL_BACKOFF,
        }
    }
}

enum Msg {
    Data(Datagram),
    Close(SocketAddrV4),
}

pub struct UdpRelay {
    tx: mpsc::Sender<Msg>,
    tracker: TaskTracker,
}

impl UdpRelay {
    pub fn new(
        ctx: Arc<RelayCtx>,
        sink: Arc<dyn InboundSink>,
        cancel: CancellationToken,
    ) -> Arc<UdpRelay> {
        Self::with_config(ctx, sink, cancel, UdpRelayConfig::default())
    }

    /// Like [`UdpRelay::new`] with explicit timeouts. Must be called inside
    /// a tokio runtime.
    pub fn with_config(
        ctx: Arc<RelayCtx>,
        sink: Arc<dyn InboundSink>,
        cancel: CancellationToken,
        cfg: UdpRelayConfig,
    ) -> Arc<UdpRelay> {
        let (tx, rx) = mpsc::channel(SUBMIT_QUEUE);
        let tracker = TaskTracker::new();
        let m = Manager {
            ctx,
            sink,
            cancel,
            cfg,
            tracker: tracker.clone(),
            sessions: HashMap::new(),
        };
        tracker.spawn(m.run(rx));
        // Closed now: `wait` returns once the manager and every session
        // (all spawned while the manager runs) have ended.
        tracker.close();
        Arc::new(UdpRelay { tx, tracker })
    }

    /// Called from packet threads; never blocks (bounded channel, try_send;
    /// full = drop).
    pub fn submit(&self, d: Datagram) {
        if self.tx.try_send(Msg::Data(d)).is_err() {
            tracing::debug!("udp relay queue full or stopped; datagram dropped");
        }
    }

    /// App socket closed: end its session now (an unspecified ip ends every
    /// session on that port).
    pub fn close(&self, local: SocketAddrV4) {
        if self.tx.try_send(Msg::Close(local)).is_err() {
            tracing::debug!("udp relay queue full or stopped; close for {local} dropped");
        }
    }

    /// Resolves once the relay was cancelled and every session has ended
    /// (control connections closed).
    pub async fn wait(&self) {
        self.tracker.wait().await;
    }
}

struct SessionHandle {
    profile: ProfileId,
    tx: mpsc::Sender<Datagram>,
    /// Ends the session when the handle is dropped.
    _stop: DropGuard,
}

struct Manager {
    ctx: Arc<RelayCtx>,
    sink: Arc<dyn InboundSink>,
    cancel: CancellationToken,
    cfg: UdpRelayConfig,
    tracker: TaskTracker,
    sessions: HashMap<SocketAddrV4, SessionHandle>,
}

/// Same port, and `close` is unspecified or the same ip.
fn same_local(entry: &SocketAddrV4, close: SocketAddrV4) -> bool {
    entry.port() == close.port() && (close.ip().is_unspecified() || entry.ip() == close.ip())
}

impl Manager {
    async fn run(mut self, mut rx: mpsc::Receiver<Msg>) {
        loop {
            let msg = tokio::select! {
                _ = self.cancel.cancelled() => break,
                m = rx.recv() => match m {
                    Some(m) => m,
                    None => break,
                },
            };
            match msg {
                Msg::Data(d) => self.data(d),
                Msg::Close(local) => self.sessions.retain(|l, _| !same_local(l, local)),
            }
        }
        // Dropping the handles cancels every session.
        self.sessions.clear();
    }

    fn data(&mut self, d: Datagram) {
        let d = match self.sessions.get(&d.local) {
            // A rules change moved the flow to another profile: start over.
            Some(s) if s.profile == d.profile => match s.tx.try_send(d) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => return,
                Err(mpsc::error::TrySendError::Closed(d)) => d,
            },
            _ => d,
        };
        // New sessions are rare next to datagrams: prune ended ones here.
        self.sessions.retain(|_, s| !s.tx.is_closed());
        let (tx, rx) = mpsc::channel(PENDING_MAX);
        let stop = self.cancel.child_token();
        let session = Session {
            ctx: self.ctx.clone(),
            sink: self.sink.clone(),
            cfg: self.cfg,
            pid: d.pid,
            profile: d.profile.clone(),
            group: d.group_id.clone(),
            local: d.local,
            first_remote: d.remote,
            addr: d.addr,
        };
        let local = d.local;
        let profile = d.profile.clone();
        // Fresh channel with room: cannot fail.
        let _ = tx.try_send(d);
        let st = stop.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                _ = st.cancelled() => {}
                _ = session.run(rx) => {}
            }
        });
        self.sessions.insert(
            local,
            SessionHandle {
                profile,
                tx,
                _stop: stop.drop_guard(),
            },
        );
    }
}

/// Ends the session's ConnLog entries when the session ends (also on cancel).
struct Entries<'a> {
    ctx: &'a RelayCtx,
    by_remote: HashMap<SocketAddrV4, (u64, Arc<ConnBytes>)>,
}

impl Drop for Entries<'_> {
    fn drop(&mut self) {
        for (id, _) in self.by_remote.values() {
            self.ctx.conns.close(*id);
        }
    }
}

struct Session {
    ctx: Arc<RelayCtx>,
    sink: Arc<dyn InboundSink>,
    cfg: UdpRelayConfig,
    pid: u32,
    profile: ProfileId,
    group: Option<GroupId>,
    local: SocketAddrV4,
    first_remote: SocketAddrV4,
    /// Address of the first outbound packet (interface for injection).
    addr: Address,
}

impl Session {
    fn exe(&self) -> String {
        exe_name(
            &self.ctx.tree.read().unwrap_or_else(|e| e.into_inner()),
            self.pid,
        )
    }

    fn log(&self, outcome: &str) {
        tracing::info!(
            "udp pid={} exe={} local={} dst={} {outcome}",
            self.pid,
            self.exe(),
            self.local,
            self.first_remote
        );
    }

    /// ConnLog entry (with live bytes) for `remote`, opened on its first
    /// datagram; `None` once the session has [`MAX_REMOTE_ROWS`] rows.
    fn entry<'e>(&self, e: &'e mut Entries<'_>, remote: SocketAddrV4) -> Option<&'e ConnBytes> {
        if !e.by_remote.contains_key(&remote) && e.by_remote.len() >= MAX_REMOTE_ROWS {
            return None;
        }
        Some(
            &e.by_remote
                .entry(remote)
                .or_insert_with(|| {
                    let bytes = Arc::new(ConnBytes::default());
                    let id = self.ctx.conns.open(
                        NewConn {
                            proto: Protocol::Udp,
                            pid: self.pid,
                            exe: self.exe(),
                            local: SocketAddr::V4(self.local),
                            dst: SocketAddr::V4(remote),
                            domain: None,
                            route: Route::Proxy(self.profile.clone()),
                            group_id: self.group.clone(),
                            reason: "udp relay".into(),
                        },
                        Some(bytes.clone()),
                    );
                    (id, bytes)
                })
                .1,
        )
    }

    /// Drops every datagram for the backoff, then ends (the next datagram
    /// starts a new session).
    async fn hold_dead(&self, rx: &mut mpsc::Receiver<Datagram>, entries: &mut Entries<'_>) {
        let until = Instant::now() + self.cfg.backoff;
        loop {
            tokio::select! {
                _ = sleep_until(until) => return,
                d = rx.recv() => match d {
                    Some(d) => {
                        self.entry(entries, d.remote);
                    }
                    None => return,
                },
            }
        }
    }

    async fn run(self, mut rx: mpsc::Receiver<Datagram>) {
        let ctx = self.ctx.clone();
        let mut entries = Entries {
            ctx: &ctx,
            by_remote: HashMap::new(),
        };
        self.entry(&mut entries, self.first_remote);
        let id = self.profile.clone();
        let found = ctx.cfg.load().proxies.iter().find(|p| p.id == id).cloned();
        let profile = match found {
            Some(p) if p.kind == ProxyKind::Socks5 => p,
            found => {
                let reason = match found {
                    None => "unknown proxy profile",
                    Some(_) => "UDP needs a SOCKS5 proxy",
                };
                self.log(&format!(
                    "profile={id}: dropped ({reason}, no direct fallback)"
                ));
                return self.hold_dead(&mut rx, &mut entries).await;
            }
        };
        let assoc = match udp_associate(&profile, ASSOCIATE_TIMEOUT).await {
            Ok(a) => a,
            Err(e) => {
                self.log(&format!(
                    "via '{id}': association failed: {e} (dropped, no direct fallback)"
                ));
                // Same rule as the TCP relay: only an unreachable / silent
                // proxy is "down".
                if e.is_proxy_down() {
                    ctx.proxy_down.insert(id.clone());
                    let _ = ctx.events.send(Event::ProxyDown { id });
                }
                return self.hold_dead(&mut rx, &mut entries).await;
            }
        };
        let sock = match bind_relay_socket(&assoc).await {
            Ok(s) => s,
            Err(e) => {
                self.log(&format!(
                    "via '{id}': association failed: {e} (dropped, no direct fallback)"
                ));
                return self.hold_dead(&mut rx, &mut entries).await;
            }
        };
        self.log(&format!("via '{id}': associated"));
        if ctx.proxy_down.remove(&id).is_some() {
            let _ = ctx.events.send(Event::ProxyUp { id: id.clone() });
        }
        self.pump(assoc, sock, &mut rx, &mut entries).await;
    }

    /// Relays until idle, control EOF / error, or the channel closes.
    async fn pump(
        &self,
        mut assoc: UdpAssociation,
        sock: UdpSocket,
        rx: &mut mpsc::Receiver<Datagram>,
        entries: &mut Entries<'_>,
    ) {
        let group = self.group.as_deref().unwrap_or(NO_GROUP);
        let _active = self.ctx.stats.open(group);
        let mut buf = vec![0u8; RECV_BUF];
        let mut ctl = [0u8; 64];
        let mut deadline = Instant::now() + self.cfg.idle;
        loop {
            tokio::select! {
                _ = sleep_until(deadline) => {
                    tracing::debug!("udp session {} idle; closing", self.local);
                    return;
                }
                r = assoc.control.read(&mut ctl) => match r {
                    Ok(0) | Err(_) => {
                        tracing::debug!("udp session {}: control connection closed", self.local);
                        return;
                    }
                    Ok(_) => {}
                },
                d = rx.recv() => {
                    let Some(d) = d else { return };
                    let n = d.payload.len() as u64;
                    let bytes = self.entry(entries, d.remote);
                    match sock.send(&encode_udp(SocketAddr::V4(d.remote), &d.payload)).await {
                        Ok(_) => {
                            if let Some(b) = bytes {
                                b.up.fetch_add(n, Ordering::Relaxed);
                            }
                            self.ctx.stats.add(group, n, 0);
                            deadline = Instant::now() + self.cfg.idle;
                        }
                        Err(e) => tracing::debug!("udp relay send failed: {e}"),
                    }
                }
                r = sock.recv(&mut buf) => {
                    let Ok(n) = r else { continue };
                    let Some((SocketAddr::V4(src), payload)) = decode_udp(&buf[..n]) else {
                        continue;
                    };
                    let Ok(pkt) = build_inbound_udp(src, self.local, payload) else {
                        continue;
                    };
                    let len = payload.len() as u64;
                    if let Some((_, b)) = entries.by_remote.get(&src) {
                        b.down.fetch_add(len, Ordering::Relaxed);
                    }
                    self.ctx.stats.add(group, 0, len);
                    self.sink.inject(pkt, &self.addr);
                    deadline = Instant::now() + self.cfg.idle;
                }
            }
        }
    }
}

/// UDP socket bound to 0.0.0.0:0 and connected to the proxy's relay, so
/// only datagrams from the relay are accepted.
async fn bind_relay_socket(a: &UdpAssociation) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    sock.connect(a.relay).await?;
    Ok(sock)
}

#[cfg(test)]
mod tests;
