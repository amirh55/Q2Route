//! The engine: owns the config, wires WinDivert capture, classification, NAT
//! and the relay together, and answers IPC requests ([`Control`]).
//!
//! Start: load config, compile rules, snapshot processes (polled every 1 s),
//! compute the always-Direct proxy listeners/endpoints (every 5 s), open the
//! Socket and Network layers, flush DNS, run the relay. Stop: cancel the
//! relay (closes proxied connections), close the handles (all traffic
//! direct), flush DNS.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Config, ConfigError, ProfileId};
use q2route_core::domain_map::DomainMap;
use q2route_core::ipc::{Event, ProcEntry, Request, Response, StateSnapshot};
use q2route_core::process_tree::ProcessTree;
use q2route_core::proxy::test_proxy;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::conns::ConnLog;
use crate::dns_proxy::{DnsProxy, DnsProxyConfig};
use crate::geo::GeoCache;
use crate::ipc_server::{BoxFuture, Control};
use crate::packet_loop::{
    dns_sniff_loop, network_loop, socket_loop, NatLookup, NetworkSink, RunState, Shared,
    DNS_SNIFF_FILTER, NETWORK_FILTER, NETWORK_THREADS, SOCKET_FILTER,
};
use crate::proxy_servers::{self, ServerCache};
use crate::relay::{run_relay, RelayCtx, RELAY_IDLE_TIMEOUT};
use crate::stats::Stats;
use crate::udp_relay::UdpRelay;
use crate::winapi;
use crate::windivert::{Handle, Layer, FLAG_RECV_ONLY, FLAG_SNIFF};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

const PROCESS_POLL: Duration = Duration::from_secs(1);
const EXCLUSION_POLL: Duration = Duration::from_secs(5);
const SWEEP_EVERY: Duration = Duration::from_secs(5);
const SNAPSHOT_EVERY: Duration = Duration::from_millis(250);
/// Time for the relay's FIN/RST to reach apps before the handles close.
const STOP_DRAIN: Duration = Duration::from_millis(200);

pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    config_path: PathBuf,
    geo: GeoCache,
    shared: Arc<Shared>,
    running: AtomicBool,
    run: tokio::sync::Mutex<Option<Running>>,
    /// The current run (its flow decisions are re-checked on rule changes).
    current: Mutex<Option<Arc<RunState>>>,
    /// Serialises config mutations (read-modify-save-swap).
    cfg_lock: tokio::sync::Mutex<()>,
    proxy_up: Mutex<HashMap<ProfileId, bool>>,
    background: AtomicBool,
}

struct Running {
    state: Arc<RunState>,
    cancel: CancellationToken,
    sock: Arc<Handle>,
    net: Arc<Handle>,
    threads: Vec<std::thread::JoinHandle<()>>,
    relay: JoinHandle<std::io::Result<()>>,
    udp: Arc<UdpRelay>,
    dns: Arc<DnsProxy>,
    /// Sniff-only DNS answer handle.
    sniff: Arc<Handle>,
}

impl Engine {
    /// Loads (or seeds) the config at `config_path` and compiles it. Nothing
    /// is captured until [`Engine::start`].
    pub fn new(config_path: PathBuf) -> Result<Engine> {
        let cfg = Config::load(&config_path)?;
        let dir = config_path.parent().map(PathBuf::from).unwrap_or_default();
        let geo = GeoCache::new(dir);
        geo.reload(&winapi::list_processes());
        let rules = geo.compile(&cfg)?;
        let (events, _) = broadcast::channel(64);
        let relay = Arc::new(RelayCtx {
            rules: ArcSwap::from_pointee(rules),
            cfg: ArcSwap::from_pointee(cfg),
            tree: Arc::new(RwLock::new(ProcessTree::default())),
            excluded: ArcSwap::from_pointee(HashSet::new()),
            stats: Arc::new(Stats::default()),
            conns: Arc::new(ConnLog::default()),
            own_ports: Arc::new(DashSet::new()),
            events,
            idle_timeout: RELAY_IDLE_TIMEOUT,
            proxy_down: DashSet::new(),
            domains: Arc::new(DomainMap::new()),
            proxy_servers: ArcSwap::from_pointee(Vec::new()),
            direct_dial_override: None,
        });
        let shared = Arc::new(Shared {
            relay,
            proxy_endpoints: ArcSwap::from_pointee(HashSet::new()),
            own_pid: std::process::id(),
            server_cache: Arc::new(Mutex::new(ServerCache::default())),
        });
        Ok(Engine {
            inner: Arc::new(Inner {
                config_path,
                geo,
                shared,
                running: AtomicBool::new(false),
                run: tokio::sync::Mutex::new(None),
                current: Mutex::new(None),
                cfg_lock: tokio::sync::Mutex::new(()),
                proxy_up: Mutex::new(HashMap::new()),
                background: AtomicBool::new(false),
            }),
        })
    }

    /// `settings.last_running`: whether to start routing on service boot.
    pub fn last_running(&self) -> bool {
        self.inner.shared.relay.cfg.load().settings.last_running
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    /// Starts routing (no-op if already running) and persists
    /// `last_running = true`. Must be called inside a multi-thread runtime.
    pub async fn start(&self) -> Result<()> {
        self.inner.ensure_background();
        self.inner.start().await?;
        self.inner.persist_last_running(true).await
    }

    /// Stops routing (all traffic direct) and persists `last_running = false`.
    pub async fn stop(&self) -> Result<()> {
        self.inner.stop().await?;
        self.inner.persist_last_running(false).await
    }

    /// Stops routing without touching `last_running` (service shutdown), so
    /// the next boot restores the current state.
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.stop().await
    }

    pub fn snapshot(&self) -> StateSnapshot {
        self.inner.snapshot()
    }
}

fn mutex<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    fn relay(&self) -> &Arc<RelayCtx> {
        &self.shared.relay
    }

    async fn start(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        if run.is_some() {
            return Ok(());
        }
        let _g = self.cfg_lock.lock().await;
        let path = self.config_path.clone();
        let cfg = tokio::task::spawn_blocking(move || Config::load(&path)).await??;
        // Pick up a geoip.dat that v2rayN updated since the last start.
        let procs = tokio::task::spawn_blocking(winapi::list_processes).await?;
        self.geo.reload(&procs);
        let rules = self.geo.compile(&cfg)?;
        self.relay().rules.store(Arc::new(rules));
        self.relay().cfg.store(Arc::new(cfg));
        drop(_g);

        refresh_processes(self.relay()).await;
        refresh_exclusions(&self.shared).await;

        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
        let relay_port = listener.local_addr()?.port();
        let state = Arc::new(RunState::new(relay_port));

        // Socket layer first so the flow tables fill before packets are held;
        // the DNS answer sniffer after the Network layer.
        let (sock, net, sniff) = tokio::task::spawn_blocking(|| -> std::io::Result<_> {
            let sock = Handle::open(SOCKET_FILTER, Layer::Socket, 0, FLAG_SNIFF | FLAG_RECV_ONLY)?;
            let net = Handle::open(NETWORK_FILTER, Layer::Network, 0, 0)?;
            let sniff = Handle::open(
                DNS_SNIFF_FILTER,
                Layer::Network,
                0,
                FLAG_SNIFF | FLAG_RECV_ONLY,
            )?;
            Ok((Arc::new(sock), Arc::new(net), Arc::new(sniff)))
        })
        .await??;

        let cancel = CancellationToken::new();
        let sink = Arc::new(NetworkSink(net.clone()));
        let udp = UdpRelay::new(self.relay().clone(), sink.clone(), cancel.clone());
        let dns = DnsProxy::new(
            self.relay().clone(),
            sink,
            cancel.clone(),
            DnsProxyConfig::default(),
        );
        let mut threads = Vec::new();
        let spawn = |name: String, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new().name(name).spawn(f)
        };
        let (h, s, conns, u) = (
            sock.clone(),
            state.clone(),
            self.relay().conns.clone(),
            udp.clone(),
        );
        let mut spawned = spawn(
            "q2r-socket".into(),
            Box::new(move || socket_loop(h, s, conns, u)),
        )
        .map(|t| threads.push(t));
        for i in 0..NETWORK_THREADS {
            let (h, sh, s, u, d) = (
                net.clone(),
                self.shared.clone(),
                state.clone(),
                udp.clone(),
                dns.clone(),
            );
            spawned = spawned.and_then(|()| {
                spawn(
                    format!("q2r-net-{i}"),
                    Box::new(move || network_loop(h, sh, s, u, d)),
                )
                .map(|t| threads.push(t))
            });
        }
        let (h, m, s) = (sniff.clone(), self.relay().domains.clone(), state.clone());
        spawned = spawned.and_then(|()| {
            spawn(
                "q2r-dns-sniff".into(),
                Box::new(move || dns_sniff_loop(h, m, s)),
            )
            .map(|t| threads.push(t))
        });
        if let Err(e) = spawned {
            // Unwind: the threads already running exit once the handles shut down.
            state.stopping.store(true, Ordering::SeqCst);
            cancel.cancel();
            udp.wait().await;
            dns.wait().await;
            sniff.shutdown();
            net.shutdown();
            sock.shutdown();
            return Err(e.into());
        }

        let _ = tokio::task::spawn_blocking(winapi::flush_dns_cache).await;

        let relay = tokio::spawn(run_relay(
            listener,
            Arc::new(NatLookup(state.nat.clone())),
            self.relay().clone(),
            cancel.clone(),
        ));
        spawn_periodic(self.shared.clone(), state.clone(), cancel.clone());

        *mutex(&self.current) = Some(state.clone());
        *run = Some(Running {
            state,
            cancel,
            sock,
            net,
            threads,
            relay,
            udp,
            dns,
            sniff,
        });
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("routing started (relay port {relay_port})");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut run = self.run.lock().await;
        let Some(r) = run.take() else { return Ok(()) };
        // 1. Close every proxied connection (the relay's FIN/RST is still
        //    restored to the apps while capture is up) and every UDP
        //    session and DNS association (control connections closed).
        r.cancel.cancel();
        match r.relay.await {
            Ok(Err(e)) => tracing::warn!("relay ended with error: {e}"),
            Err(e) => tracing::warn!("relay task failed: {e}"),
            Ok(Ok(())) => {}
        }
        r.udp.wait().await;
        r.dns.wait().await;
        tokio::time::sleep(STOP_DRAIN).await;
        // 2. Close capture: from here on everything is direct.
        r.state.stopping.store(true, Ordering::SeqCst);
        r.sniff.shutdown();
        r.net.shutdown();
        r.sock.shutdown();
        let threads = r.threads;
        let joined = tokio::task::spawn_blocking(move || {
            for t in threads {
                let _ = t.join();
            }
        });
        let _ = joined.await;
        drop((r.sniff, r.net, r.sock));
        *mutex(&self.current) = None;
        let _ = tokio::task::spawn_blocking(winapi::flush_dns_cache).await;
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("routing stopped: all traffic direct");
        Ok(())
    }

    async fn persist_last_running(&self, on: bool) -> Result<()> {
        if self.relay().cfg.load().settings.last_running == on {
            return Ok(());
        }
        self.mutate(|c| {
            c.settings.last_running = on;
            Ok(())
        })
        .await
    }

    /// Applies `f` to a copy of the config, compiles and saves it, then swaps
    /// it in. Any failure leaves the running config untouched.
    async fn mutate(
        &self,
        f: impl FnOnce(&mut Config) -> std::result::Result<(), ConfigError>,
    ) -> Result<()> {
        let _g = self.cfg_lock.lock().await;
        let mut next = Config::clone(&self.relay().cfg.load());
        f(&mut next)?;
        next.validate()?;
        let rules = self.geo.compile(&next)?;
        let path = self.config_path.clone();
        let next = tokio::task::spawn_blocking(move || next.save(&path).map(|()| next)).await??;
        self.relay().rules.store(Arc::new(rules));
        self.relay().cfg.store(Arc::new(next));
        if let Some(s) = mutex(&self.current).as_ref() {
            s.cache.on_rules_changed();
        }
        Ok(())
    }

    /// Config change requests: mutate, then refresh the proxy exclusions.
    async fn apply(
        &self,
        f: impl FnOnce(&mut Config) -> std::result::Result<(), ConfigError>,
    ) -> Response {
        match self.mutate(f).await {
            Ok(()) => {
                refresh_exclusions(&self.shared).await;
                Response::Ok
            }
            Err(e) => Response::Error(e.to_string()),
        }
    }

    fn snapshot(&self) -> StateSnapshot {
        let (groups, total_up_bps, total_down_bps) = self.relay().stats.snapshot();
        StateSnapshot {
            running: self.running.load(Ordering::SeqCst),
            config: Config::clone(&self.relay().cfg.load()),
            groups,
            proxy_up: mutex(&self.proxy_up).clone(),
            total_up_bps,
            total_down_bps,
            proxy_servers: Vec::clone(&self.relay().proxy_servers.load()),
        }
    }

    async fn handle(self: &Arc<Inner>, r: Request) -> Response {
        self.ensure_background();
        let result = |r: Result<()>| match r {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error(e.to_string()),
        };
        match r {
            Request::GetState => Response::State(self.snapshot()),
            Request::Start => {
                let r = match self.start().await {
                    Ok(()) => self.persist_last_running(true).await,
                    Err(e) => Err(e),
                };
                result(r)
            }
            Request::Stop => {
                let r = match self.stop().await {
                    Ok(()) => self.persist_last_running(false).await,
                    Err(e) => Err(e),
                };
                result(r)
            }
            Request::SetGroupAction { group_id, action } => {
                self.apply(|c| c.set_group_action(&group_id, action)).await
            }
            Request::SetGroupEnabled { group_id, enabled } => {
                self.apply(|c| c.set_group_enabled(&group_id, enabled))
                    .await
            }
            Request::AddGroup { name, action } => {
                self.apply(|c| c.add_group(&name, action).map(|_| ())).await
            }
            Request::RenameGroup { group_id, name } => {
                self.apply(|c| c.rename_group(&group_id, &name)).await
            }
            Request::DeleteGroup { group_id } => self.apply(|c| c.delete_group(&group_id)).await,
            Request::MoveGroup { group_id, to } => {
                self.apply(|c| c.move_group(&group_id, to)).await
            }
            Request::SetGroupRules { group_id, rules } => {
                self.apply(|c| c.set_group_rules(&group_id, rules)).await
            }
            // Adding a rule that already exists is not an error.
            Request::AddRule { group_id, rule } => {
                self.apply(|c| c.add_rule(&group_id, rule).map(|_| ()))
                    .await
            }
            Request::GetConnections => Response::Connections(self.relay().conns.list()),
            Request::ListProcesses => Response::Processes(
                tokio::task::spawn_blocking(process_entries)
                    .await
                    .unwrap_or_default(),
            ),
            Request::UpsertProxy(p) => self.apply(|c| c.upsert_proxy(p)).await,
            Request::DeleteProxy { id } => self.apply(|c| c.delete_proxy(&id)).await,
            Request::TestProxy { id } => {
                let profile = self
                    .relay()
                    .cfg
                    .load()
                    .proxies
                    .iter()
                    .find(|p| p.id == id)
                    .cloned();
                let Some(p) = profile else {
                    return Response::Error(format!("unknown proxy '{id}'"));
                };
                let res = test_proxy(&p).await;
                let ev = if res.tcp_ok {
                    Event::ProxyUp { id: id.clone() }
                } else {
                    Event::ProxyDown { id: id.clone() }
                };
                // Keep the relay's view in step, so the relay's next success
                // after a failed test clears the banner (ProxyUp).
                if res.tcp_ok {
                    self.relay().proxy_down.remove(&id);
                } else {
                    self.relay().proxy_down.insert(id.clone());
                }
                mutex(&self.proxy_up).insert(id, res.tcp_ok);
                let _ = self.relay().events.send(ev);
                Response::ProxyTest(res)
            }
            Request::SetDns(d) => {
                let r = self.apply(|c| c.set_dns(d)).await;
                if matches!(r, Response::Ok) {
                    // Cached answers came from the old resolver setup.
                    let _ = tokio::task::spawn_blocking(winapi::flush_dns_cache).await;
                }
                r
            }
            Request::FlushDns => {
                let _ = tokio::task::spawn_blocking(winapi::flush_dns_cache).await;
                Response::Ok
            }
            // The pipe server answers Subscribe itself (via `subscribe`).
            Request::Subscribe => Response::Ok,
        }
    }

    /// Starts the engine-lifetime tasks once: 4 Hz snapshots to subscribers
    /// and proxy up/down tracking from relay events.
    fn ensure_background(self: &Arc<Inner>) {
        if self.background.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = Arc::downgrade(self);
        let mut rx = self.relay().events.subscribe();
        let watcher = me.clone();
        tokio::spawn(async move {
            loop {
                let ev = match rx.recv().await {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some(inner) = watcher.upgrade() else {
                    return;
                };
                match ev {
                    Event::ProxyDown { id } => {
                        mutex(&inner.proxy_up).insert(id, false);
                    }
                    Event::ProxyUp { id } => {
                        let was = mutex(&inner.proxy_up).insert(id, true);
                        // Lookups failed while the proxy was down are cached
                        // as failures: flush on the way back up.
                        if was != Some(true) {
                            tokio::task::spawn_blocking(winapi::flush_dns_cache);
                        }
                    }
                    Event::Snapshot(_) => {}
                }
            }
        });
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SNAPSHOT_EVERY);
            loop {
                tick.tick().await;
                let Some(inner) = me.upgrade() else { return };
                let tx = &inner.relay().events;
                // The proxy watcher is always subscribed; only snapshot for UIs.
                if tx.receiver_count() > 1 {
                    let _ = tx.send(Event::Snapshot(Box::new(inner.snapshot())));
                }
            }
        });
    }
}

impl Control for Engine {
    fn handle(&self, r: Request) -> BoxFuture<'_, Response> {
        Box::pin(self.inner.handle(r))
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.ensure_background();
        self.inner.relay().events.subscribe()
    }
}

/// Replaces the process tree with a fresh snapshot.
/// Running processes with a known absolute exe path, by name, one per path.
fn process_entries() -> Vec<ProcEntry> {
    let mut seen = HashSet::new();
    let mut out: Vec<ProcEntry> = winapi::list_processes()
        .into_iter()
        .filter(|p| p.exe.is_absolute())
        .filter_map(|p| {
            let name = p.exe.file_name()?.to_string_lossy().into_owned();
            let path = p.exe.to_string_lossy().into_owned();
            seen.insert(path.to_lowercase()).then_some(ProcEntry {
                pid: p.pid,
                name,
                path,
            })
        })
        .collect();
    out.sort_by_cached_key(|e| e.name.to_lowercase());
    out
}

async fn refresh_processes(relay: &RelayCtx) {
    let Ok(procs) = tokio::task::spawn_blocking(winapi::list_processes).await else {
        return;
    };
    let mut tree = ProcessTree::default();
    for p in procs {
        tree.insert(p);
    }
    *relay.tree.write().unwrap_or_else(|e| e.into_inner()) = tree;
}

/// Resolves every proxy's `host:port` (always Direct) and finds the pid
/// listening on it (excluded: always Direct), plus the service itself.
/// Then refreshes the proxy server names from those listeners' configs
/// ([`crate::proxy_servers`]; files are re-read only when changed; the last
/// list is kept while no config is found).
async fn refresh_exclusions(shared: &Shared) {
    let proxies: Vec<(String, u16)> = shared
        .relay
        .cfg
        .load()
        .proxies
        .iter()
        .map(|p| (p.host.clone(), p.port))
        .collect();
    let mut endpoints = HashSet::new();
    for (host, port) in proxies {
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => endpoints.extend(addrs),
            Err(e) => tracing::debug!("cannot resolve proxy {host}:{port}: {e}"),
        }
    }
    let eps: Vec<SocketAddr> = endpoints.iter().copied().collect();
    let own = shared.own_pid;
    let excluded = tokio::task::spawn_blocking(move || {
        let mut set: HashSet<u32> = eps
            .iter()
            .filter_map(|a| winapi::listener_pid(a.port(), a.ip()))
            .collect();
        set.insert(own);
        set
    })
    .await
    .unwrap_or_else(|_| HashSet::from([own]));
    let exes: Vec<PathBuf> = {
        let tree = shared.relay.tree.read().unwrap_or_else(|e| e.into_inner());
        excluded
            .iter()
            .filter(|&&pid| pid != own)
            .filter_map(|&pid| tree.get(pid).map(|p| p.exe.clone()))
            .collect()
    };
    shared.relay.excluded.store(Arc::new(excluded));
    shared.proxy_endpoints.store(Arc::new(endpoints));
    let cache = shared.server_cache.clone();
    let servers = tokio::task::spawn_blocking(move || {
        mutex(&cache).refresh(&proxy_servers::find_configs(&exes))
    })
    .await;
    // `None`: no proxy client config right now (e.g. it is restarting):
    // keep the last list, so its servers still resolve directly.
    if let Ok(Some(servers)) = servers {
        if *shared.relay.proxy_servers.load_full() != servers {
            let names = if servers.is_empty() {
                "none".to_string()
            } else {
                servers.join(", ")
            };
            tracing::info!("proxy servers resolved directly: {names}");
            shared.relay.proxy_servers.store(Arc::new(servers));
            // A lookup of a new server name made before it was detected
            // went through the (not yet connected) proxy and may have been
            // cached as a failure: start over.
            let _ = tokio::task::spawn_blocking(winapi::flush_dns_cache).await;
        }
    }
}

/// Per-run upkeep: process tree (1 s), exclusions (5 s), NAT and flow-cache
/// sweeps (5 s). All end when `cancel` fires.
fn spawn_periodic(shared: Arc<Shared>, state: Arc<RunState>, cancel: CancellationToken) {
    let (sh, c) = (shared.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PROCESS_POLL);
        loop {
            tokio::select! {
                _ = c.cancelled() => return,
                _ = tick.tick() => refresh_processes(&sh.relay).await,
            }
        }
    });
    let (sh, c) = (shared, cancel.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EXCLUSION_POLL);
        loop {
            tokio::select! {
                _ = c.cancelled() => return,
                _ = tick.tick() => refresh_exclusions(&sh).await,
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => {
                    let now = std::time::Instant::now();
                    state.nat.sweep(now);
                    state.cache.sweep(now);
                }
            }
        }
    });
}
