//! DNS through the proxy: UDP/53 queries whose name decides Proxy are sent
//! to `settings.dns.proxy_resolver` over the profile's SOCKS5 UDP
//! association, and the answers are injected back to the app as if the
//! original server had sent them.
//!
//! Packet threads [`DnsProxy::submit`] queries (never blocking: bounded
//! channel; full = REFUSED). One manager task hands them to one task per
//! profile, which owns that profile's association (opened lazily, reopened
//! after the control connection ends or the profile is edited, not retried
//! for `backoff` after a failure; the task ends when the profile is deleted)
//! and the in-flight queries (re-numbered, so ids from different
//! apps never collide; at most `max_inflight`; dropped after `timeout`).
//!
//! **Fail closed:** a query handed here is never sent to its original
//! server. Without an association (non-SOCKS5 profile, failure,
//! backoff) an IPv4 query gets an empty TC answer (the client retries over
//! TCP) and an IPv6 one REFUSED; a deleted profile and overload
//! (`max_inflight`, full queues)
//! gets REFUSED; a timeout gets nothing (the client retries).

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use q2route_core::config::{Config, ProfileId, ProxyKind, ProxyProfile};
use q2route_core::dns::{answers, parse_query, refused, response_id, truncated, with_id};
use q2route_core::ipc::Event;
use q2route_core::matchers::DomainPattern;
use q2route_core::proxy::{decode_udp, encode_udp, udp_associate};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::relay::RelayCtx;
use crate::udp_packet::{build_inbound_udp, build_inbound_udp6};
use crate::udp_relay::{bind_relay_socket, InboundSink};
use crate::windivert::Address;

pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub const DNS_MAX_INFLIGHT: usize = 1024;
pub const DNS_BACKOFF: Duration = Duration::from_secs(10);
const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound of the packet threads -> manager channel.
const SUBMIT_QUEUE: usize = 1024;
/// Bound of the manager -> profile task channel.
const PROFILE_QUEUE: usize = 256;
const RECV_BUF: usize = 65536;

/// One captured outbound UDP/53 query whose name decided Proxy.
pub struct DnsQuery {
    pub profile: ProfileId,
    /// The app's socket (the query's source).
    pub app: SocketAddr,
    /// The DNS server the app asked (the query's destination).
    pub server: SocketAddr,
    pub msg: Vec<u8>,
    /// Address of the captured packet (interface for injection).
    pub addr: Address,
}

/// Limits of a [`DnsProxy`] (tests shorten / shrink them).
#[derive(Clone, Copy, Debug)]
pub struct DnsProxyConfig {
    pub timeout: Duration,
    pub max_inflight: usize,
    pub backoff: Duration,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        DnsProxyConfig {
            timeout: DNS_TIMEOUT,
            max_inflight: DNS_MAX_INFLIGHT,
            backoff: DNS_BACKOFF,
        }
    }
}

pub struct DnsProxy {
    tx: mpsc::Sender<DnsQuery>,
    sink: Arc<dyn InboundSink>,
    tracker: TaskTracker,
}

impl DnsProxy {
    /// Must be called inside a tokio runtime.
    pub fn new(
        ctx: Arc<RelayCtx>,
        sink: Arc<dyn InboundSink>,
        cancel: CancellationToken,
        cfg: DnsProxyConfig,
    ) -> Arc<DnsProxy> {
        let (tx, rx) = mpsc::channel(SUBMIT_QUEUE);
        let tracker = TaskTracker::new();
        let m = Manager {
            ctx,
            sink: sink.clone(),
            cancel,
            cfg,
            tracker: tracker.clone(),
            profiles: HashMap::new(),
        };
        tracker.spawn(m.run(rx));
        // Closed now: `wait` returns once the manager and every profile task
        // (all spawned while the manager runs) have ended.
        tracker.close();
        Arc::new(DnsProxy { tx, sink, tracker })
    }

    /// Called from packet threads; never blocks. Full or stopped: the app
    /// gets REFUSED.
    pub fn submit(&self, q: DnsQuery) {
        if let Err(e) = self.tx.try_send(q) {
            let q = e.into_inner();
            tracing::debug!("dns proxy queue full or stopped; REFUSED to {}", q.app);
            answer(&*self.sink, &q, refused(&q.msg));
        }
    }

    /// Resolves once the proxy was cancelled and every task has ended
    /// (associations closed).
    pub fn wait(&self) -> impl Future<Output = ()> + 'static {
        let t = self.tracker.clone();
        async move { t.wait().await }
    }
}

/// Whether `name` is the host name (not an IP literal) of a configured
/// proxy profile: case-insensitive, trailing dots ignored. The DNS path
/// sends such names direct, since resolving the proxy cannot need the proxy.
pub fn is_proxy_host(cfg: &Config, name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty()
        && cfg.proxies.iter().any(|p| {
            let host = p.host.trim_end_matches('.');
            let literal = host.trim_start_matches('[').trim_end_matches(']');
            literal.parse::<IpAddr>().is_err() && host.eq_ignore_ascii_case(name)
        })
}

/// Names the DNS paths always resolve directly, checked before the rules
/// (the proxy cannot resolve the names it needs to come up). Returns the
/// reason label, or `None` (routed by name as usual):
/// - `"proxy host"`: a configured proxy's host name ([`is_proxy_host`]);
/// - `"direct name"`: matches an entry of `settings.dns.direct_names`
///   (invalid entries never match);
/// - `"proxy server"`: equals a name in `auto`, the servers detected from
///   the running proxy client's config ([`crate::proxy_servers`]).
pub fn bootstrap_direct(cfg: &Config, auto: &[String], name: &str) -> Option<&'static str> {
    if is_proxy_host(cfg, name) {
        return Some("proxy host");
    }
    let bare = name.trim_end_matches('.');
    if bare.is_empty() {
        return None;
    }
    let direct = cfg
        .settings
        .dns
        .direct_names
        .iter()
        .any(|n| DomainPattern::parse(n).is_ok_and(|p| p.matches(bare)));
    if direct {
        return Some("direct name");
    }
    auto.iter()
        .any(|a| {
            let a = a.trim_end_matches('.');
            !a.is_empty() && a.eq_ignore_ascii_case(bare)
        })
        .then_some("proxy server")
}

/// Injects `msg` (if any) to `app` as a UDP packet from `server`.
fn inject(sink: &dyn InboundSink, server: SocketAddr, app: SocketAddr, addr: &Address, msg: &[u8]) {
    let pkt = match (server, app) {
        (SocketAddr::V4(s), SocketAddr::V4(a)) => build_inbound_udp(s, a, msg),
        (SocketAddr::V6(s), SocketAddr::V6(a)) => build_inbound_udp6(s, a, msg),
        _ => return,
    };
    if let Ok(p) = pkt {
        sink.inject(p, addr);
    }
}

fn answer(sink: &dyn InboundSink, q: &DnsQuery, msg: Option<Vec<u8>>) {
    if let Some(m) = msg {
        inject(sink, q.server, q.app, &q.addr, &m);
    }
}

/// No association: TC over IPv4 (retry over TCP), REFUSED over IPv6.
fn unavailable(sink: &dyn InboundSink, q: &DnsQuery) {
    let msg = if q.app.is_ipv4() {
        truncated(&q.msg)
    } else {
        refused(&q.msg)
    };
    answer(sink, q, msg);
}

struct Manager {
    ctx: Arc<RelayCtx>,
    sink: Arc<dyn InboundSink>,
    cancel: CancellationToken,
    cfg: DnsProxyConfig,
    tracker: TaskTracker,
    profiles: HashMap<ProfileId, mpsc::Sender<DnsQuery>>,
}

impl Manager {
    async fn run(mut self, mut rx: mpsc::Receiver<DnsQuery>) {
        loop {
            let q = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                q = rx.recv() => match q {
                    Some(q) => q,
                    None => break,
                },
            };
            let tx = match self.profiles.get(&q.profile) {
                Some(tx) if !tx.is_closed() => tx,
                _ => {
                    let tx = self.spawn(q.profile.clone());
                    self.profiles.insert(q.profile.clone(), tx);
                    &self.profiles[&q.profile]
                }
            };
            if let Err(e) = tx.try_send(q) {
                let q = e.into_inner();
                tracing::debug!("dns proxy '{}' busy; REFUSED to {}", q.profile, q.app);
                answer(&*self.sink, &q, refused(&q.msg));
            }
        }
        // Dropping the senders ends every profile task.
    }

    fn spawn(&self, profile: ProfileId) -> mpsc::Sender<DnsQuery> {
        let (tx, rx) = mpsc::channel(PROFILE_QUEUE);
        let task = ProfileTask {
            ctx: self.ctx.clone(),
            sink: self.sink.clone(),
            cfg: self.cfg,
            profile,
            up: None,
            backoff_until: None,
            logged_up: None,
            tried: None,
            pending: HashMap::new(),
            order: BTreeMap::new(),
            next_id: 0,
            serial: 0,
        };
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = task.run(rx) => {}
            }
        });
        tx
    }
}

struct Upstream {
    control: tokio::net::TcpStream,
    sock: UdpSocket,
}

struct Pending {
    orig_id: u16,
    name: String,
    app: SocketAddr,
    server: SocketAddr,
    addr: Address,
    /// Key in `order`.
    due: (Instant, u64),
}

enum UpEvent {
    Reply(usize),
    Closed,
    Nothing,
}

/// Owns one profile's association and its in-flight queries.
struct ProfileTask {
    ctx: Arc<RelayCtx>,
    sink: Arc<dyn InboundSink>,
    cfg: DnsProxyConfig,
    profile: ProfileId,
    up: Option<Upstream>,
    backoff_until: Option<Instant>,
    /// State last logged at info: associated (true) or failed (false).
    logged_up: Option<bool>,
    /// The profile of the last association attempt (edits re-associate).
    tried: Option<ProxyProfile>,
    /// Proxy-side id -> query.
    pending: HashMap<u16, Pending>,
    /// (deadline, serial) -> proxy-side id, oldest first.
    order: BTreeMap<(Instant, u64), u16>,
    next_id: u16,
    serial: u64,
}

/// Waits for the association's next event; never resolves without one.
async fn next_up(up: &mut Option<Upstream>, buf: &mut [u8], ctl: &mut [u8]) -> UpEvent {
    let Some(u) = up else {
        return std::future::pending().await;
    };
    tokio::select! {
        r = u.control.read(ctl) => match r {
            Ok(0) | Err(_) => UpEvent::Closed,
            Ok(_) => UpEvent::Nothing,
        },
        r = u.sock.recv(buf) => match r {
            Ok(n) => UpEvent::Reply(n),
            Err(_) => UpEvent::Nothing,
        },
    }
}

impl ProfileTask {
    async fn run(mut self, mut rx: mpsc::Receiver<DnsQuery>) {
        let mut buf = vec![0u8; RECV_BUF];
        let mut ctl = [0u8; 64];
        loop {
            let due = self.order.keys().next().map(|k| k.0);
            tokio::select! {
                q = rx.recv() => match q {
                    Some(q) => {
                        if !self.query(q).await {
                            // Profile deleted: refuse what is queued and end
                            // (the manager starts a new task if it is re-added).
                            rx.close();
                            while let Ok(q) = rx.try_recv() {
                                answer(&*self.sink, &q, refused(&q.msg));
                            }
                            return;
                        }
                    }
                    None => return,
                },
                ev = next_up(&mut self.up, &mut buf, &mut ctl) => match ev {
                    UpEvent::Reply(n) => self.reply(&buf[..n]),
                    UpEvent::Closed => {
                        // Re-associated on the next query.
                        tracing::debug!("dns via '{}': association closed", self.profile);
                        self.drop_up();
                    }
                    UpEvent::Nothing => {}
                },
                _ = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                    self.expire();
                }
            }
        }
    }

    /// Logs at info when the association state changes, else at debug.
    fn state(&mut self, up: bool, msg: &str) {
        if self.logged_up == Some(up) {
            tracing::debug!("dns via '{}': {msg}", self.profile);
        } else {
            tracing::info!("dns via '{}': {msg}", self.profile);
        }
        self.logged_up = Some(up);
    }

    /// Opens the association through `p` unless backing off; false if
    /// there is none.
    async fn associate(&mut self, p: ProxyProfile) -> bool {
        if self.backoff_until.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        let id = self.profile.clone();
        self.tried = Some(p.clone());
        let up = if p.kind != ProxyKind::Socks5 {
            Err(("UDP needs a SOCKS5 proxy".to_string(), false))
        } else {
            match udp_associate(&p, ASSOCIATE_TIMEOUT).await {
                Ok(a) => match bind_relay_socket(&a).await {
                    Ok(sock) => Ok(Upstream {
                        control: a.control,
                        sock,
                    }),
                    Err(e) => Err((e.to_string(), false)),
                },
                Err(e) => Err((e.to_string(), e.is_proxy_down())),
            }
        };
        match up {
            Ok(u) => {
                self.up = Some(u);
                self.backoff_until = None;
                self.state(true, "associated");
                if self.ctx.proxy_down.remove(&id).is_some() {
                    let _ = self.ctx.events.send(Event::ProxyUp { id });
                }
                true
            }
            Err((e, down)) => {
                self.backoff_until = Some(Instant::now() + self.cfg.backoff);
                self.state(
                    false,
                    &format!("association failed: {e} (TC / REFUSED, no direct fallback)"),
                );
                // Same rule as the relays: only an unreachable / silent
                // proxy is "down".
                if down {
                    self.ctx.proxy_down.insert(id.clone());
                    let _ = self.ctx.events.send(Event::ProxyDown { id });
                }
                false
            }
        }
    }

    /// Ends the association; its in-flight answers cannot arrive any more
    /// (the clients retry).
    fn drop_up(&mut self) {
        self.up = None;
        self.pending.clear();
        self.order.clear();
    }

    /// Handles one query; false once the profile is gone from the config
    /// (the task then ends).
    async fn query(&mut self, q: DnsQuery) -> bool {
        // The packet loop only submits parsed queries; anything else is dropped.
        let Some(name) = parse_query(&q.msg).map(|p| p.name) else {
            return true;
        };
        let current = self
            .ctx
            .cfg
            .load()
            .proxies
            .iter()
            .find(|p| p.id == self.profile)
            .cloned();
        let Some(current) = current else {
            tracing::debug!("dns via '{}': profile gone; REFUSED", self.profile);
            self.drop_up();
            answer(&*self.sink, &q, refused(&q.msg));
            return false;
        };
        // Edited since the last association attempt: start over with it.
        if self.tried.as_ref().is_some_and(|t| *t != current) {
            tracing::debug!(
                "dns via '{}': profile changed; re-associating",
                self.profile
            );
            self.drop_up();
            self.backoff_until = None;
        }
        if self.pending.len() >= self.cfg.max_inflight.min(usize::from(u16::MAX)) {
            tracing::debug!(
                "dns via '{}': {} in flight; REFUSED",
                self.profile,
                self.pending.len()
            );
            answer(&*self.sink, &q, refused(&q.msg));
            return true;
        }
        if self.up.is_none() && !self.associate(current).await {
            unavailable(&*self.sink, &q);
            return true;
        }
        let resolver = self.ctx.cfg.load().settings.dns.proxy_resolver.clone();
        let Ok(resolver) = resolver.parse::<SocketAddr>() else {
            tracing::debug!("dns proxy resolver '{resolver}' is not ip:port");
            unavailable(&*self.sink, &q);
            return true;
        };
        let id = self.alloc_id();
        let Some(up) = &self.up else { return true };
        if let Err(e) = up
            .sock
            .send(&encode_udp(resolver, &with_id(&q.msg, id)))
            .await
        {
            tracing::debug!("dns via '{}': send failed: {e}", self.profile);
            unavailable(&*self.sink, &q);
            return true;
        }
        self.serial += 1;
        let due = (Instant::now() + self.cfg.timeout, self.serial);
        self.order.insert(due, id);
        self.pending.insert(
            id,
            Pending {
                orig_id: u16::from_be_bytes([q.msg[0], q.msg[1]]),
                name,
                app: q.app,
                server: q.server,
                addr: q.addr,
                due,
            },
        );
        true
    }

    /// A proxy-side id not in flight (there are fewer than 65535 in flight).
    fn alloc_id(&mut self) -> u16 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if !self.pending.contains_key(&self.next_id) {
                return self.next_id;
            }
        }
    }

    fn reply(&mut self, d: &[u8]) {
        let Some((_, msg)) = decode_udp(d) else {
            return;
        };
        let Some(p) = response_id(msg).and_then(|id| self.pending.remove(&id)) else {
            tracing::debug!("dns via '{}': unknown or late reply dropped", self.profile);
            return;
        };
        self.order.remove(&p.due);
        let msg = with_id(msg, p.orig_id);
        let (name, ips) = answers(&msg);
        match name {
            Some(n) if n != p.name => {
                tracing::debug!(
                    "dns via '{}': answer for {n}, asked {}",
                    self.profile,
                    p.name
                );
                return;
            }
            Some(_) => {
                let now = std::time::Instant::now();
                for (ip, ttl) in ips {
                    self.ctx.domains.insert(ip, &p.name, ttl, now);
                }
            }
            None => {}
        }
        inject(&*self.sink, p.server, p.app, &p.addr, &msg);
    }

    /// Drops every query past its deadline (no answer: the client retries).
    fn expire(&mut self) {
        let now = Instant::now();
        while let Some(entry) = self.order.first_entry() {
            if entry.key().0 > now {
                break;
            }
            let id = entry.remove();
            self.pending.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests;
