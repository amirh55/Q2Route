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
//!
//! **ICMP guard:** replies are injected toward the app's socket; one arriving
//! after that socket closed makes Windows answer with an ICMP port
//! unreachable from the real IP. [`UdpRelay::serves_port`] (live sessions
//! plus [`ICMP_GUARD`] after they end) lets the packet loop drop those.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

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
/// A local port still counts as relay-served this long after its last
/// session ended (late replies may still be in flight / injected).
pub const ICMP_GUARD: Duration = Duration::from_secs(60);
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
    pub icmp_guard: Duration,
}

impl Default for UdpRelayConfig {
    fn default() -> Self {
        UdpRelayConfig {
            idle: SESSION_IDLE,
            backoff: FAIL_BACKOFF,
            icmp_guard: ICMP_GUARD,
        }
    }
}

/// Live sessions on a local port, and when the last one ended.
struct PortState {
    live: u32,
    ended: std::time::Instant,
}

type Ports = Arc<DashMap<u16, PortState>>;

/// Counts a session on its local port while alive (dropped when the
/// session task ends, also on cancel).
struct PortGuard {
    ports: Ports,
    port: u16,
}

impl PortGuard {
    fn new(ports: &Ports, port: u16) -> PortGuard {
        ports
            .entry(port)
            .and_modify(|e| e.live += 1)
            .or_insert(PortState {
                live: 1,
                ended: std::time::Instant::now(),
            });
        PortGuard {
            ports: ports.clone(),
            port,
        }
    }
}

impl Drop for PortGuard {
    fn drop(&mut self) {
        if let Some(mut e) = self.ports.get_mut(&self.port) {
            e.live = e.live.saturating_sub(1);
            e.ended = std::time::Instant::now();
        }
    }
}

/// Session -> manager.
enum Report {
    /// Association failed / unusable profile: back off this key.
    Failed(SocketAddrV4, ProfileId),
    /// Associated: the key works again.
    Associated(SocketAddrV4, ProfileId),
}

pub struct UdpRelay {
    /// Datagrams (bounded: full = drop), stamped with `seq`.
    tx: mpsc::Sender<(u64, Datagram)>,
    /// Socket closes: unbounded (OS-rate-limited Socket-layer events), so a
    /// close is never dropped while the manager runs.
    close_tx: mpsc::UnboundedSender<(u64, SocketAddrV4)>,
    /// Orders datagrams against closes across the two channels.
    seq: AtomicU64,
    ports: Ports,
    icmp_guard: Duration,
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
        let (close_tx, close_rx) = mpsc::unbounded_channel();
        let (report_tx, report_rx) = mpsc::unbounded_channel();
        let tracker = TaskTracker::new();
        let ports = Ports::default();
        let m = Manager {
            ctx,
            sink,
            cancel,
            cfg,
            tracker: tracker.clone(),
            sessions: HashMap::new(),
            ports: ports.clone(),
            report_tx,
            failed: HashMap::new(),
            closed: HashMap::new(),
        };
        tracker.spawn(m.run(rx, close_rx, report_rx));
        // Closed now: `wait` returns once the manager and every session
        // (all spawned while the manager runs) have ended.
        tracker.close();
        Arc::new(UdpRelay {
            tx,
            close_tx,
            seq: AtomicU64::new(0),
            ports,
            icmp_guard: cfg.icmp_guard,
            tracker,
        })
    }

    /// Called from packet threads; never blocks (bounded channel, try_send;
    /// full = drop).
    pub fn submit(&self, d: Datagram) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        if self.tx.try_send((seq, d)).is_err() {
            tracing::debug!("udp relay queue full or stopped; datagram dropped");
        }
    }

    /// App socket closed: end its session now (an unspecified ip ends every
    /// session on that port). Never blocks and is never dropped while the
    /// manager runs; datagrams captured before it never start a session.
    pub fn close(&self, local: SocketAddrV4) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        if self.close_tx.send((seq, local)).is_err() {
            tracing::debug!("udp relay stopped; close for {local} ignored");
        }
    }

    /// Whether a relay session serves local `port` now or did within the
    /// ICMP guard. Lock-light (one DashMap shard read), no allocation: safe
    /// per packet from packet threads.
    pub fn serves_port(&self, port: u16) -> bool {
        self.ports
            .get(&port)
            .is_some_and(|e| e.live > 0 || e.ended.elapsed() < self.icmp_guard)
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
    ports: Ports,
    report_tx: mpsc::UnboundedSender<Report>,
    /// Keys whose last attempt failed -> end of their backoff. Kept after
    /// the backoff (later failures log at debug) until the key associates
    /// or its socket closes.
    failed: HashMap<(SocketAddrV4, ProfileId), Instant>,
    /// Local port -> seq of its latest close; datagrams with a lower seq
    /// are from the closed socket. Cleared whenever the datagram queue is
    /// empty (nothing older can still be queued).
    closed: HashMap<u16, u64>,
}

/// Same port, and `close` is unspecified or the same ip.
fn same_local(entry: &SocketAddrV4, close: SocketAddrV4) -> bool {
    entry.port() == close.port() && (close.ip().is_unspecified() || entry.ip() == close.ip())
}

impl Manager {
    async fn run(
        mut self,
        mut rx: mpsc::Receiver<(u64, Datagram)>,
        mut close_rx: mpsc::UnboundedReceiver<(u64, SocketAddrV4)>,
        mut report_rx: mpsc::UnboundedReceiver<Report>,
    ) {
        loop {
            // Biased: reports and closes before datagrams.
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                r = report_rx.recv() => {
                    // Never None: the manager holds a sender.
                    if let Some(r) = r {
                        self.report(r);
                    }
                }
                c = close_rx.recv() => match c {
                    Some((seq, local)) => self.close(seq, local),
                    None => break,
                },
                m = rx.recv() => match m {
                    Some((seq, d)) => {
                        // A session that just ended reported before its
                        // channel closed: see its report first.
                        while let Ok(r) = report_rx.try_recv() {
                            self.report(r);
                        }
                        self.data(seq, d);
                    }
                    None => break,
                },
            }
            if !self.closed.is_empty() && rx.is_empty() {
                self.closed.clear();
            }
        }
        // Dropping the handles cancels every session.
        self.sessions.clear();
    }

    fn report(&mut self, r: Report) {
        match r {
            Report::Failed(local, profile) => {
                self.failed
                    .insert((local, profile), Instant::now() + self.cfg.backoff);
            }
            Report::Associated(local, profile) => {
                self.failed.remove(&(local, profile));
            }
        }
    }

    fn close(&mut self, seq: u64, local: SocketAddrV4) {
        let c = self.closed.entry(local.port()).or_insert(seq);
        *c = (*c).max(seq);
        self.sessions.retain(|l, _| !same_local(l, local));
        self.failed.retain(|(l, _), _| !same_local(l, local));
    }

    fn data(&mut self, seq: u64, d: Datagram) {
        // Captured before its socket's close: never (re)starts a session.
        if self.closed.get(&d.local.port()).is_some_and(|&c| seq < c) {
            return;
        }
        let d = match self.sessions.get(&d.local) {
            // A rules change moved the flow to another profile: start over.
            Some(s) if s.profile == d.profile => match s.tx.try_send(d) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => return,
                Err(mpsc::error::TrySendError::Closed(d)) => d,
            },
            _ => d,
        };
        // The handle (if any) has ended or is for another profile.
        self.sessions.remove(&d.local);
        let key = (d.local, d.profile.clone());
        let quiet = match self.failed.get(&key) {
            // Backing off: dropped here; no session, no row, no log.
            Some(until) if Instant::now() < *until => return,
            Some(_) => true,
            None => false,
        };
        // New sessions are rare next to datagrams: prune ended ones here.
        self.sessions.retain(|_, s| !s.tx.is_closed());
        let guard = self.cfg.icmp_guard;
        self.ports
            .retain(|_, e| e.live > 0 || e.ended.elapsed() < guard);
        let (tx, rx) = mpsc::channel(PENDING_MAX);
        let stop = self.cancel.child_token();
        let session = Session {
            ctx: self.ctx.clone(),
            sink: self.sink.clone(),
            report: self.report_tx.clone(),
            quiet,
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
        let port_guard = PortGuard::new(&self.ports, local.port());
        self.tracker.spawn(async move {
            let _port_guard = port_guard;
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
    report: mpsc::UnboundedSender<Report>,
    /// A failure of this key was already logged: log failures at debug.
    quiet: bool,
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

    /// Logs a failure (info the first time for this key, then debug) and
    /// reports it; the session then ends (its row with it) and the manager
    /// drops the key's datagrams for the backoff.
    fn fail(&self, outcome: &str) {
        if self.quiet {
            tracing::debug!(
                "udp pid={} local={} dst={} {outcome}",
                self.pid,
                self.local,
                self.first_remote
            );
        } else {
            self.log(outcome);
        }
        let _ = self
            .report
            .send(Report::Failed(self.local, self.profile.clone()));
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
                return self.fail(&format!(
                    "profile={id}: dropped ({reason}, no direct fallback)"
                ));
            }
        };
        let assoc = match udp_associate(&profile, ASSOCIATE_TIMEOUT).await {
            Ok(a) => a,
            Err(e) => {
                self.fail(&format!(
                    "via '{id}': association failed: {e} (dropped, no direct fallback)"
                ));
                // Same rule as the TCP relay: only an unreachable / silent
                // proxy is "down".
                if e.is_proxy_down() {
                    ctx.proxy_down.insert(id.clone());
                    let _ = ctx.events.send(Event::ProxyDown { id });
                }
                return;
            }
        };
        let sock = match bind_relay_socket(&assoc).await {
            Ok(s) => s,
            Err(e) => {
                return self.fail(&format!(
                    "via '{id}': association failed: {e} (dropped, no direct fallback)"
                ));
            }
        };
        self.log(&format!("via '{id}': associated"));
        let _ = self
            .report
            .send(Report::Associated(self.local, self.profile.clone()));
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

/// UDP socket bound to 0.0.0.0:0 (or [::]:0 for an IPv6 relay) and
/// connected to the proxy's relay, so only datagrams from the relay are
/// accepted.
pub(crate) async fn bind_relay_socket(a: &UdpAssociation) -> std::io::Result<UdpSocket> {
    let bind = if a.relay.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(a.relay).await?;
    Ok(sock)
}

#[cfg(test)]
mod tests;
