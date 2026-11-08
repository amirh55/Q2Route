//! Relay tests: localhost mocks, with `RuleSet::lan_direct = false` so that
//! loopback destinations are routed by the rules under test.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Action, Config, Group, ProxyKind, ProxyProfile, Rule, Settings};
use q2route_core::domain_map::DomainMap;
use q2route_core::ipc::Event;
use q2route_core::process_tree::{ProcInfo, ProcessTree};
use q2route_core::ruleset::RuleSet;
use q2route_service::nat::{Family, OriginalDst};
use q2route_service::relay::{
    bind_relay, bind_relay_with, run_relay, OrigDstLookup, RelayCtx, RELAY_BIND_ATTEMPTS,
};
use q2route_service::stats::Stats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct FixedLookup(SocketAddrV4);

impl OrigDstLookup for FixedLookup {
    fn attach(&self, _peer: SocketAddr) -> Option<(OriginalDst, u64)> {
        Some((
            OriginalDst {
                dst: self.0.into(),
                pid: 4242,
            },
            1,
        ))
    }
    fn release(&self, _peer: SocketAddr, _token: u64) {}
}

/// Like `FixedLookup`, but reports every release.
struct RecordingLookup(SocketAddrV4, mpsc::UnboundedSender<u64>);

impl OrigDstLookup for RecordingLookup {
    fn attach(&self, _peer: SocketAddr) -> Option<(OriginalDst, u64)> {
        Some((
            OriginalDst {
                dst: self.0.into(),
                pid: 4242,
            },
            77,
        ))
    }
    fn release(&self, _peer: SocketAddr, token: u64) {
        let _ = self.1.send(token);
    }
}

fn fixture() -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../q2route-core/tests/data/clienthello.bin");
    std::fs::read(p).unwrap()
}

fn v4(a: SocketAddr) -> SocketAddrV4 {
    match a {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => panic!("expected v4"),
    }
}

fn group(id: &str, action: Action, domains: &[&str], catch_all: bool) -> Group {
    let rules = if domains.is_empty() {
        vec![]
    } else {
        vec![Rule {
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ..Rule::default()
        }]
    };
    Group {
        id: id.into(),
        name: id.into(),
        enabled: true,
        action,
        rules,
        catch_all,
    }
}

fn socks_profile(port: u16) -> ProxyProfile {
    ProxyProfile {
        id: "mock".into(),
        name: "Mock".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port,
        username: None,
        password: None,
    }
}

fn config(proxies: Vec<ProxyProfile>, groups: Vec<Group>) -> Config {
    Config {
        seed_version: q2route_core::SEED_VERSION,
        proxies,
        groups,
        always_direct: vec![],
        default_proxy: "mock".into(),
        settings: Settings::default(),
    }
}

/// Original destination -> the mock server's real address. The relay's
/// direct connects (in every test `ctx`) dial through this map, so a NAT
/// entry can name e.g. `127.53.0.2:53` (keeping the port-53 DNS branch)
/// while the mock listens on `127.0.0.1:<ephemeral>`: connects to loopback
/// addresses other than 127.0.0.1 are not reliable on every machine.
static DIALS: LazyLock<Mutex<HashMap<SocketAddr, SocketAddr>>> = LazyLock::new(Default::default);

/// Binds a mock server on 127.0.0.1 standing in for `orig` (`ip:53`).
async fn bind_as(ip: &str) -> (SocketAddrV4, TcpListener) {
    let orig: SocketAddrV4 = format!("{ip}:53").parse().unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    DIALS
        .lock()
        .unwrap()
        .insert(orig.into(), l.local_addr().unwrap());
    (orig, l)
}

fn dial(dst: SocketAddr) -> SocketAddr {
    DIALS.lock().unwrap().get(&dst).copied().unwrap_or(dst)
}

fn ctx(cfg: Config) -> Arc<RelayCtx> {
    let mut rules = RuleSet::compile(&cfg).unwrap();
    rules.lan_direct = false;
    let (events, _) = broadcast::channel(16);
    Arc::new(RelayCtx {
        rules: ArcSwap::from_pointee(rules),
        cfg: ArcSwap::from_pointee(cfg),
        tree: Arc::new(RwLock::new(ProcessTree::default())),
        excluded: ArcSwap::from_pointee(HashSet::new()),
        stats: Arc::new(Stats::default()),
        conns: Arc::new(Default::default()),
        own_ports: Arc::new(DashSet::new()),
        events,
        idle_timeout: Duration::from_secs(7200),
        proxy_down: DashSet::new(),
        domains: Arc::new(DomainMap::new()),
        proxy_servers: ArcSwap::from_pointee(vec![]),
        direct_dial_override: Some(Arc::new(dial)),
    })
}

struct Relay {
    addr: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

async fn start(dst: SocketAddrV4, c: Arc<RelayCtx>) -> Relay {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_relay(
        vec![l],
        Arc::new(FixedLookup(dst)),
        c,
        cancel.clone(),
    ));
    Relay { addr, cancel, task }
}

struct SocksReq {
    atyp: u8,
    host: Vec<u8>,
    port: u16,
    first: Vec<u8>,
    at: Instant,
}

/// One-shot mock SOCKS5 (no auth): reports the CONNECT request and the first
/// `want` tunnelled bytes.
async fn mock_socks(want: usize) -> (u16, mpsc::Receiver<SocksReq>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 1, 0]);
        s.write_all(&[5, 0]).await.unwrap();
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await.unwrap();
        let at = Instant::now();
        let host = match h[3] {
            1 => {
                let mut a = vec![0u8; 4];
                s.read_exact(&mut a).await.unwrap();
                a
            }
            3 => {
                let mut n = [0u8; 1];
                s.read_exact(&mut n).await.unwrap();
                let mut a = vec![0u8; n[0] as usize];
                s.read_exact(&mut a).await.unwrap();
                a
            }
            4 => {
                let mut a = vec![0u8; 16];
                s.read_exact(&mut a).await.unwrap();
                a
            }
            x => panic!("unexpected atyp {x}"),
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut first = vec![0u8; want];
        s.read_exact(&mut first).await.unwrap();
        tx.send(SocksReq {
            atyp: h[3],
            host,
            port: u16::from_be_bytes(p),
            first,
            at,
        })
        .await
        .unwrap();
        // Keep the tunnel open until the relay closes it.
        let mut sink = [0u8; 64];
        while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    (port, rx)
}

/// Mock origin: counts accepts, reports each peer's port, echoes until EOF.
async fn mock_origin() -> (SocketAddr, Arc<AtomicUsize>, mpsc::UnboundedReceiver<u16>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, peer) = l.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(peer.port());
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, count, rx)
}

/// Waits for the peer to close: read returns 0 or an error.
async fn assert_closed(c: &mut TcpStream, within: Duration) {
    let mut b = [0u8; 64];
    let r = tokio::time::timeout(within, async {
        loop {
            match c.read(&mut b).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(r.is_ok(), "client socket was not closed");
}

#[tokio::test]
async fn proxied_via_socks_with_domain() {
    let hello = fixture();
    let (sport, mut reqs) = mock_socks(hello.len()).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![
            group("ir", Action::Proxy("mock".into()), &["*.ir"], false),
            group("rest", Action::Block, &[], true),
        ],
    );
    let r = start("5.5.5.5:443".parse().unwrap(), ctx(cfg)).await;
    let mut c = TcpStream::connect(r.addr).await.unwrap();
    c.write_all(&hello).await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(req.atyp, 3);
    assert_eq!(req.host, b"www.digikala.ir");
    assert_eq!(req.port, 443);
    assert_eq!(req.first, hello);
    r.cancel.cancel();
}

#[tokio::test]
async fn direct_records_own_port() {
    let (origin, _, mut peers) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let c = ctx(cfg);
    let r = start(v4(origin), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    client.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    let upstream_port = peers.recv().await.unwrap();
    assert!(
        c.own_ports.contains(&(Family::V4, upstream_port)),
        "own_ports missing upstream port"
    );
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(3);
    while c.own_ports.contains(&(Family::V4, upstream_port)) {
        assert!(
            Instant::now() < deadline,
            "own_ports not cleared after close"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    r.cancel.cancel();
}

#[tokio::test]
async fn proxy_down_fails_closed() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let (origin, accepts, _) = mock_origin().await;
    let cfg = config(
        vec![socks_profile(dead_port)],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    );
    let c = ctx(cfg);
    let mut events = c.events.subscribe();
    let r = start(v4(origin), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let _ = client.write_all(b"hello").await;
    assert_closed(&mut client, Duration::from_secs(6)).await;
    let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev, Event::ProxyDown { id: "mock".into() });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "fell back to a direct connection"
    );
    r.cancel.cancel();
}

#[tokio::test]
async fn server_first_timeout() {
    let (sport, mut reqs) = mock_socks(0).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![
            group("ir", Action::Direct, &["*.ir"], false),
            group("rest", Action::Proxy("mock".into()), &[], true),
        ],
    );
    let r = start("5.5.5.5:443".parse().unwrap(), ctx(cfg)).await;
    let t0 = Instant::now();
    let _client = TcpStream::connect(r.addr).await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(3), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    let waited = req.at - t0;
    assert!(
        waited >= Duration::from_millis(250),
        "decided too early: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(2),
        "decided too late: {waited:?}"
    );
    assert_eq!(req.atyp, 1);
    assert_eq!(req.host, [5, 5, 5, 5]);
    assert_eq!(req.port, 443);
    r.cancel.cancel();
}

#[tokio::test]
async fn stats_counted() {
    let (origin, _, _) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let c = ctx(cfg);
    let r = start(v4(origin), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let data: Vec<u8> = (0..10240u32).map(|i| i as u8).collect();
    client.write_all(&data).await.unwrap();
    let mut back = vec![0u8; data.len()];
    client.read_exact(&mut back).await.unwrap();
    assert_eq!(back, data);
    let (up, down) = c.stats.bytes("rest");
    assert!(up >= 10240, "up = {up}");
    assert!(down >= 10240, "down = {down}");
    let (groups, _, _) = c.stats.snapshot();
    assert_eq!(groups["rest"].active, 1);
    r.cancel.cancel();
}

#[tokio::test]
async fn cancel_closes_inflight() {
    let (origin, _, mut peers) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let r = start(v4(origin), ctx(cfg)).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    client.read_exact(&mut b).await.unwrap();
    peers.recv().await.unwrap();
    r.cancel.cancel();
    assert_closed(&mut client, Duration::from_secs(2)).await;
    let res = tokio::time::timeout(Duration::from_secs(2), r.task)
        .await
        .unwrap()
        .unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn connection_end_releases_nat_entry() {
    let (origin, _, mut peers) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, mut released) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    tokio::spawn(run_relay(
        vec![l],
        Arc::new(RecordingLookup(v4(origin), tx)),
        ctx(cfg),
        cancel.clone(),
    ));
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    client.read_exact(&mut b).await.unwrap();
    peers.recv().await.unwrap();
    assert!(released.try_recv().is_err(), "released while alive");
    drop(client);
    let token = tokio::time::timeout(Duration::from_secs(3), released.recv())
        .await
        .expect("release not called after close")
        .unwrap();
    assert_eq!(token, 77);
    cancel.cancel();
}

#[tokio::test]
async fn blocked_connection_releases_nat_entry() {
    let cfg = config(vec![], vec![group("rest", Action::Block, &[], true)]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, mut released) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    tokio::spawn(run_relay(
        vec![l],
        Arc::new(RecordingLookup("5.5.5.5:8000".parse().unwrap(), tx)),
        ctx(cfg),
        cancel.clone(),
    ));
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_closed(&mut client, Duration::from_secs(2)).await;
    let token = tokio::time::timeout(Duration::from_secs(2), released.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token, 77);
    cancel.cancel();
}

#[tokio::test]
async fn idle_connection_is_closed_after_idle_timeout() {
    let (origin, _, mut peers) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let c = ctx(cfg);
    // Same RelayCtx shape as production, with a short idle timeout.
    let c = Arc::new(RelayCtx {
        idle_timeout: Duration::from_millis(400),
        rules: ArcSwap::new(c.rules.load_full()),
        cfg: ArcSwap::new(c.cfg.load_full()),
        tree: c.tree.clone(),
        excluded: ArcSwap::new(c.excluded.load_full()),
        stats: c.stats.clone(),
        conns: c.conns.clone(),
        own_ports: c.own_ports.clone(),
        events: c.events.clone(),
        proxy_down: DashSet::new(),
        domains: Arc::new(DomainMap::new()),
        proxy_servers: ArcSwap::from_pointee(vec![]),
        direct_dial_override: c.direct_dial_override.clone(),
    });
    let r = start(v4(origin), c).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    // Activity keeps it open past one idle period.
    for i in 0..4 {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        client.write_all(b"k").await.unwrap();
        let mut b = [0u8; 1];
        client.read_exact(&mut b).await.unwrap();
    }
    let t0 = Instant::now();
    peers.recv().await.unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    assert!(
        t0.elapsed() >= Duration::from_millis(300),
        "closed too early"
    );
    r.cancel.cancel();
}

/// Multi-connection mock SOCKS5 (no auth) answering every CONNECT with
/// reply code `rep`; on success it holds the tunnel open until EOF.
async fn mock_socks_reply(rep: u8) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                s.read_exact(&mut g).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut h = [0u8; 10];
                s.read_exact(&mut h).await.unwrap(); // IPv4 CONNECT
                s.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut sink = [0u8; 64];
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    port
}

fn drain(rx: &mut broadcast::Receiver<Event>) -> Vec<Event> {
    let mut out = vec![];
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Opens one client connection through the relay and gives the relay time
/// to tunnel it (the connection is left open).
async fn one_flow(r: &Relay) {
    let mut c = TcpStream::connect(r.addr).await.unwrap();
    let _ = c.write_all(b"hello").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn proxy_up_emitted_once_after_recovery() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let groups = vec![group("rest", Action::Proxy("mock".into()), &[], true)];
    let c = ctx(config(vec![socks_profile(dead_port)], groups.clone()));
    let mut events = c.events.subscribe();
    let r = start("5.5.5.5:8000".parse().unwrap(), c.clone()).await;

    let mut dead_client = TcpStream::connect(r.addr).await.unwrap();
    let _ = dead_client.write_all(b"hello").await;
    // A refused loopback connect takes ~2 s on Windows.
    assert_closed(&mut dead_client, Duration::from_secs(6)).await;
    assert_eq!(drain(&mut events), [Event::ProxyDown { id: "mock".into() }]);

    // v2ray comes back (same profile id, now reachable).
    let live = mock_socks_reply(0).await;
    c.cfg
        .store(Arc::new(config(vec![socks_profile(live)], groups)));
    one_flow(&r).await;
    one_flow(&r).await;
    assert_eq!(
        drain(&mut events),
        [Event::ProxyUp { id: "mock".into() }],
        "exactly one ProxyUp for the down -> up transition"
    );
    r.cancel.cancel();
}

#[tokio::test]
async fn refused_target_is_not_proxy_down() {
    // The proxy is up but refuses this destination (SOCKS5 REP 5).
    let port = mock_socks_reply(5).await;
    let c = ctx(config(
        vec![socks_profile(port)],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    ));
    let mut events = c.events.subscribe();
    let r = start("5.5.5.5:8000".parse().unwrap(), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let _ = client.write_all(b"x").await;
    assert_closed(&mut client, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(drain(&mut events), [], "no false ProxyDown alarm");
    r.cancel.cancel();
}

#[tokio::test]
async fn relayed_connection_is_listed_with_bytes() {
    let hello = fixture();
    let (sport, mut reqs) = mock_socks(hello.len()).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![
            group("ir", Action::Proxy("mock".into()), &["*.ir"], false),
            group("rest", Action::Block, &[], true),
        ],
    );
    let c = ctx(cfg);
    let r = start("5.5.5.5:443".parse().unwrap(), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(&hello).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    let l = c.conns.list();
    assert_eq!(l.len(), 1);
    assert_eq!(
        l[0].route,
        q2route_core::decide::Route::Proxy("mock".into())
    );
    assert_eq!(l[0].domain.as_deref(), Some("www.digikala.ir"));
    assert_eq!(l[0].group_id.as_deref(), Some("ir"));
    assert_eq!(l[0].dst, "5.5.5.5:443".parse::<SocketAddr>().unwrap());
    assert!(l[0].up.unwrap() >= hello.len() as u64);
    assert!(l[0].ended_ms.is_none());
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let l = c.conns.list();
        if l[0].ended_ms.is_some() {
            assert_eq!(l.len(), 1);
            assert!(l[0].up.unwrap() > 0);
            break;
        }
        assert!(Instant::now() < deadline, "connection never ended");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    r.cancel.cancel();
}

#[tokio::test]
async fn empty_peek_uses_dns_mapped_names() {
    // 127.0.0.1:443 with lan_direct off: only the rules decide. Nothing in
    // the first bytes names a host, but DNS answered 127.0.0.1 for x.ir.
    let cfg = config(
        vec![],
        vec![
            group("ir", Action::Direct, &["*.ir"], false),
            group("rest", Action::Block, &[], true),
        ],
    );
    let c = ctx(cfg);
    c.domains.insert(
        "127.0.0.1".parse().unwrap(),
        "x.ir",
        300,
        std::time::Instant::now(),
    );
    let r = start("127.0.0.1:443".parse().unwrap(), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"not tls\r\n\r\n").await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let row = loop {
        if let Some(row) = c.conns.list().into_iter().next() {
            break row;
        }
        assert!(Instant::now() < deadline, "flow never decided");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(row.route, q2route_core::decide::Route::Direct);
    assert_eq!(row.group_id.as_deref(), Some("ir"));
    r.cancel.cancel();
}

#[tokio::test]
async fn empty_peek_disagreeing_names_most_protective() {
    // One mapped name proxied, one Direct, Direct catch-all: with nothing to
    // peek, the more protective route (Proxy) wins.
    let port = mock_socks_reply(0).await;
    let cfg = config(
        vec![socks_profile(port)],
        vec![
            group(
                "blocked",
                Action::Proxy("mock".into()),
                &["blocked.com"],
                false,
            ),
            group("ir", Action::Direct, &["*.ir"], false),
            group("rest", Action::Direct, &[], true),
        ],
    );
    let c = ctx(cfg);
    let now = std::time::Instant::now();
    c.domains
        .insert("127.0.0.1".parse().unwrap(), "x.ir", 300, now);
    c.domains
        .insert("127.0.0.1".parse().unwrap(), "blocked.com", 300, now);
    let r = start("127.0.0.1:443".parse().unwrap(), c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"not tls\r\n\r\n").await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let row = loop {
        if let Some(row) = c.conns.list().into_iter().next() {
            break row;
        }
        assert!(Instant::now() < deadline, "flow never decided");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(row.route, q2route_core::decide::Route::Proxy("mock".into()));
    assert_eq!(row.group_id.as_deref(), Some("blocked"));
    r.cancel.cancel();
}

// ---- DNS over TCP (port 53) through the relay ----

const NINE: [u8; 4] = [9, 9, 9, 9];

/// A standard query (RD) for `name`, type A.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

/// The answer to `q` (uncompressed question): one A record, 9.9.9.9.
fn dns_answer(q: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while q[end] != 0 {
        end += 1 + q[end] as usize;
    }
    end += 5;
    let mut r = q[..end].to_vec();
    r[2] |= 0x80;
    r[3] = 0x80;
    r[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
    r.extend_from_slice(&NINE);
    r
}

fn framed(m: &[u8]) -> Vec<u8> {
    let mut f = (m.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(m);
    f
}

async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut l = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut l))
        .await
        .expect("no reply")
        .unwrap();
    let mut m = vec![0u8; u16::from_be_bytes(l) as usize];
    s.read_exact(&mut m).await.unwrap();
    m
}

async fn recv_t<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out")
        .unwrap()
}

/// Answers every length-prefixed query on `s` with A 9.9.9.9; reports each
/// query.
async fn serve_dns(mut s: TcpStream, seen: mpsc::UnboundedSender<Vec<u8>>) {
    loop {
        let mut l = [0u8; 2];
        if s.read_exact(&mut l).await.is_err() {
            return;
        }
        let mut q = vec![0u8; u16::from_be_bytes(l) as usize];
        if s.read_exact(&mut q).await.is_err() {
            return;
        }
        let _ = seen.send(q.clone());
        if s.write_all(&framed(&dns_answer(&q))).await.is_err() {
            return;
        }
    }
}

type DnsServer = (
    SocketAddrV4,
    Arc<AtomicUsize>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);

/// Mock DNS-over-TCP server standing in for `ip:53` (a distinct ip per
/// test, see [`bind_as`]): counts accepts, reports queries.
async fn dns_server(ip: &str) -> DnsServer {
    let (addr, l) = bind_as(ip).await;
    let count = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    let c = count.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_dns(s, tx.clone()));
        }
    });
    (addr, count, rx)
}

fn http_profile(port: u16) -> ProxyProfile {
    ProxyProfile {
        kind: ProxyKind::Http,
        ..socks_profile(port)
    }
}

type ConnectDns = (
    u16,
    mpsc::UnboundedReceiver<String>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);

/// Mock HTTP CONNECT proxy that is itself a DNS-over-TCP resolver behind
/// the tunnel: reports each CONNECT target and each tunnelled query.
async fn mock_connect_dns() -> ConnectDns {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (ttx, targets) = mpsc::unbounded_channel();
    let (qtx, queries) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (ttx, qtx) = (ttx.clone(), qtx.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                let _ = ttx.send(target);
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                serve_dns(s, qtx).await;
            });
        }
    });
    (port, targets, queries)
}

/// `*.ir` Direct, `bad.example` Block, catch-all Proxy("mock").
fn dns_groups() -> Vec<Group> {
    vec![
        group("ir", Action::Direct, &["*.ir"], false),
        group("bad", Action::Block, &["bad.example"], false),
        group("rest", Action::Proxy("mock".into()), &[], true),
    ]
}

async fn wait_row(c: &RelayCtx) -> q2route_core::ipc::ConnInfo {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(row) = c.conns.list().into_iter().next() {
            return row;
        }
        assert!(Instant::now() < deadline, "flow never logged");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn names_of_nine(c: &RelayCtx) -> Vec<String> {
    c.domains
        .names("9.9.9.9".parse().unwrap(), std::time::Instant::now())
}

#[tokio::test]
async fn tcp_dns_proxied_name_goes_to_resolver_via_proxy() {
    let (orig, accepts, _) = dns_server("127.53.0.1").await;
    let (pport, mut targets, mut queries) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.settings.dns.proxy_resolver = "8.8.4.4:53".into();
    let c = ctx(cfg);
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(0x1234, "example.com");
    client.write_all(&framed(&q)).await.unwrap();
    let reply = read_frame(&mut client).await;
    assert_eq!(&reply[..2], &[0x12, 0x34], "original id");
    assert_eq!(reply, dns_answer(&q));
    assert_eq!(recv_t(&mut targets).await, "8.8.4.4:53");
    assert_eq!(recv_t(&mut queries).await, q);
    // A second query on the same connection, same route: also via the proxy.
    let q2 = dns_query(0x0042, "other.com");
    client.write_all(&framed(&q2)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q2));
    // Answers learned.
    let names = names_of_nine(&c);
    assert!(names.contains(&"example.com".to_string()), "{names:?}");
    assert!(names.contains(&"other.com".to_string()), "{names:?}");
    let row = wait_row(&c).await;
    assert_eq!(row.domain.as_deref(), Some("example.com"));
    assert_eq!(row.route, q2route_core::decide::Route::Proxy("mock".into()));
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "original server contacted"
    );
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_direct_name_goes_to_original_server() {
    let (orig, accepts, mut seen) = dns_server("127.53.0.2").await;
    let (pport, mut targets, _) = mock_connect_dns().await;
    let c = ctx(config(vec![http_profile(pport)], dns_groups()));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(0x0bad, "www.digikala.ir");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut seen).await, q);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert!(targets.try_recv().is_err(), "went through the proxy");
    let row = wait_row(&c).await;
    assert_eq!(row.domain.as_deref(), Some("www.digikala.ir"));
    assert_eq!(row.route, q2route_core::decide::Route::Direct);
    assert_eq!(row.group_id.as_deref(), Some("ir"));
    assert_eq!(names_of_nine(&c), vec!["www.digikala.ir".to_string()]);
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_blocked_name_closes() {
    let (orig, accepts, _) = dns_server("127.53.0.3").await;
    let (pport, mut targets, _) = mock_connect_dns().await;
    let c = ctx(config(vec![http_profile(pport)], dns_groups()));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client
        .write_all(&framed(&dns_query(1, "bad.example")))
        .await
        .unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    let row = wait_row(&c).await;
    assert_eq!(row.domain.as_deref(), Some("bad.example"));
    assert_eq!(row.route, q2route_core::decide::Route::Block);
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    assert!(targets.try_recv().is_err());
    r.cancel.cancel();
}

/// Echo server standing in for `ip:53` (a non-DNS service on port 53):
/// counts accepts.
async fn echo_53(ip: &str) -> (SocketAddrV4, Arc<AtomicUsize>) {
    let (addr, l) = bind_as(ip).await;
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, count)
}

/// Not DNS on TCP/53 from a Direct app (e.g. OpenVPN on port 53): relayed
/// directly to the original destination, the bytes already read replayed.
#[tokio::test]
async fn tcp_53_non_dns_from_direct_app_is_relayed_directly() {
    let (orig, accepts) = echo_53("127.53.0.5").await;
    let groups = vec![group("rest", Action::Direct, &[], true)];
    let c = ctx(config(vec![], groups));
    let r = start(orig, c.clone()).await;
    // A complete frame that is not a query.
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let msg = framed(b"not a dns query");
    client.write_all(&msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
        .await
        .expect("no echo")
        .unwrap();
    assert_eq!(back, msg, "bytes read by the relay were replayed");
    client.write_all(b"more").await.unwrap();
    let mut more = [0u8; 4];
    client.read_exact(&mut more).await.unwrap();
    assert_eq!(&more, b"more");
    let row = wait_row(&c).await;
    assert_eq!(row.route, q2route_core::decide::Route::Direct);
    assert_eq!(row.domain, None);
    // A frame longer than any query may be: not DNS either.
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let mut big = vec![0x20, 0x00];
    big.extend_from_slice(b"0123456789");
    client.write_all(&big).await.unwrap();
    let mut back = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
        .await
        .expect("no echo")
        .unwrap();
    assert_eq!(back, big);
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
    r.cancel.cancel();
}

/// Not DNS on TCP/53 from a proxied app: through the proxy to the original
/// destination, never direct.
#[tokio::test]
async fn tcp_53_non_dns_from_proxied_app_goes_via_proxy() {
    let (orig, accepts) = echo_53("127.53.0.14").await;
    let msg = framed(b"not a dns query");
    let (sport, mut reqs) = mock_socks(msg.len()).await;
    let c = ctx(config(vec![socks_profile(sport)], dns_groups()));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(&msg).await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(req.atyp, 1);
    assert_eq!(req.host, [127, 53, 0, 14]);
    assert_eq!(req.port, 53);
    assert_eq!(req.first, msg);
    assert_eq!(
        wait_row(&c).await.route,
        q2route_core::decide::Route::Proxy("mock".into())
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "connected direct");
    r.cancel.cancel();
}

/// A frame that could be a query but never completes: closed, never relayed.
#[tokio::test]
async fn tcp_dns_partial_frame_closes() {
    let (orig, accepts) = echo_53("127.53.0.15").await;
    let groups = vec![group("rest", Action::Direct, &[], true)];
    let r = start(orig, ctx(config(vec![], groups))).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(&[0, 50, 1, 2, 3]).await.unwrap();
    client.shutdown().await.unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    r.cancel.cancel();
}

/// Answers on a direct DNS-over-TCP connection are learned only for the
/// queries forwarded on it (same id and name).
#[tokio::test]
async fn tcp_dns_answers_for_names_never_asked_are_not_learned() {
    let (addr, l) = bind_as("127.53.0.16").await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.unwrap();
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut q).await.unwrap();
        let id = u16::from_be_bytes([q[0], q[1]]);
        // An answer with an id never asked, one for another name with the
        // asked id, then the real answer.
        for m in [
            dns_answer(&dns_query(id ^ 0xffff, "evil.ir")),
            dns_answer(&dns_query(id, "other.ir")),
            dns_answer(&q),
        ] {
            s.write_all(&framed(&m)).await.unwrap();
        }
        let mut sink = [0u8; 64];
        while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    let (pport, _, _) = mock_connect_dns().await;
    let c = ctx(config(vec![http_profile(pport)], dns_groups()));
    let r = start(addr, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(0x0101, "y.ir");
    client.write_all(&framed(&q)).await.unwrap();
    for _ in 0..3 {
        read_frame(&mut client).await;
    }
    assert_eq!(names_of_nine(&c), vec!["y.ir".to_string()]);
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_later_query_with_other_route_closes() {
    let (orig, _, mut seen) = dns_server("127.53.0.6").await;
    let (pport, mut targets, _) = mock_connect_dns().await;
    let c = ctx(config(vec![http_profile(pport)], dns_groups()));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(1, "x.ir");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut seen).await, q);
    // Same route (Direct): still served on this connection.
    let q2 = dns_query(2, "y.ir");
    client.write_all(&framed(&q2)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q2));
    assert_eq!(recv_t(&mut seen).await, q2);
    // Decides Proxy: must never reach the original server.
    client
        .write_all(&framed(&dns_query(3, "blocked.com")))
        .await
        .unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        seen.try_recv().is_err(),
        "proxied name sent to the original server"
    );
    assert!(targets.try_recv().is_err());
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_proxy_down_fails_closed() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let (orig, accepts, _) = dns_server("127.53.0.7").await;
    let c = ctx(config(vec![socks_profile(dead_port)], dns_groups()));
    let mut events = c.events.subscribe();
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client
        .write_all(&framed(&dns_query(1, "example.com")))
        .await
        .unwrap();
    assert_closed(&mut client, Duration::from_secs(6)).await;
    let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev, Event::ProxyDown { id: "mock".into() });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "fell back to direct");
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_proxy_host_name_goes_direct() {
    let (orig, accepts, mut seen) = dns_server("127.53.0.8").await;
    let (pport, mut targets, _) = mock_connect_dns().await;
    let mut p = http_profile(pport);
    p.host = "proxy.example.net".into();
    let c = ctx(config(vec![p], dns_groups()));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(7, "proxy.example.net");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut seen).await, q);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert!(targets.try_recv().is_err());
    assert_eq!(
        wait_row(&c).await.route,
        q2route_core::decide::Route::Direct
    );
    r.cancel.cancel();
}

/// Hands every injected packet to the test.
struct ChanSink(mpsc::UnboundedSender<Vec<u8>>);

impl q2route_service::udp_relay::InboundSink for ChanSink {
    fn inject(&self, pkt: Vec<u8>, _addr: &q2route_service::windivert::Address) {
        let _ = self.0.send(pkt);
    }
}

#[tokio::test]
async fn udp_unavailable_answers_tc_then_tcp_resolves_via_proxy() {
    use q2route_service::dns_proxy::{DnsProxy, DnsProxyConfig, DnsQuery};
    let (orig, accepts, _) = dns_server("127.53.0.4").await;
    let (pport, mut targets, mut queries) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.settings.dns.proxy_resolver = "8.8.4.4:53".into();
    let c = ctx(cfg);
    let (tx, mut injected) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let dns = DnsProxy::new(
        c.clone(),
        Arc::new(ChanSink(tx)),
        cancel.clone(),
        DnsProxyConfig::default(),
    );
    let q = dns_query(0x5151, "example.com");
    // UDP: an HTTP-only profile has no UDP association -> empty TC answer.
    dns.submit(DnsQuery {
        profile: "mock".into(),
        app: "10.0.0.5:50000".parse().unwrap(),
        server: SocketAddr::V4(orig),
        msg: q.clone(),
        addr: Default::default(),
    });
    let pkt = recv_t(&mut injected).await;
    let tc = &pkt[28..];
    assert_eq!(&tc[..2], &[0x51, 0x51]);
    assert_ne!(tc[2] & 0x02, 0, "TC bit set");
    // The client retries over TCP: resolved through the CONNECT proxy.
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut targets).await, "8.8.4.4:53");
    assert_eq!(recv_t(&mut queries).await, q);
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    r.cancel.cancel();
    cancel.cancel();
}

/// Sends one query for `name` through the relay and checks it reached the
/// original server directly and was logged Direct.
async fn assert_tcp_dns_direct(server_ip: &str, c: Arc<RelayCtx>, name: &str) {
    let (orig, accepts, mut seen) = dns_server(server_ip).await;
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(7, name);
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut seen).await, q);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    let row = wait_row(&c).await;
    assert_eq!(row.domain.as_deref(), Some(name));
    assert_eq!(row.route, q2route_core::decide::Route::Direct);
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_from_excluded_pid_goes_direct() {
    let (pport, mut targets, _) = mock_connect_dns().await;
    let c = ctx(config(vec![http_profile(pport)], dns_groups()));
    c.excluded.store(Arc::new(HashSet::from([4242])));
    assert_tcp_dns_direct("127.53.0.9", c, "example.com").await;
    assert!(targets.try_recv().is_err(), "went through the proxy");
}

#[tokio::test]
async fn tcp_dns_from_always_direct_exe_goes_direct() {
    let (pport, mut targets, _) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.always_direct = vec!["xray.exe".into()];
    let c = ctx(cfg);
    c.tree.write().unwrap().insert(ProcInfo {
        pid: 4242,
        parent: 1,
        exe: r"C:\v2rayN\bin\xray\xray.exe".into(),
        start_time: 0,
    });
    assert_tcp_dns_direct("127.53.0.10", c, "example.com").await;
    assert!(targets.try_recv().is_err(), "went through the proxy");
}

/// Own exe only (Ruling R8): an app started by an always-direct GUI is
/// still routed by name.
#[tokio::test]
async fn tcp_dns_child_of_always_direct_exe_is_routed() {
    let (orig, accepts, _) = dns_server("127.53.0.11").await;
    let (pport, mut targets, _) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.always_direct = vec!["v2rayn.exe".into()];
    let c = ctx(cfg);
    {
        let mut t = c.tree.write().unwrap();
        t.insert(ProcInfo {
            pid: 100,
            parent: 1,
            exe: r"C:\v2rayN\v2rayN.exe".into(),
            start_time: 0,
        });
        t.insert(ProcInfo {
            pid: 4242,
            parent: 100,
            exe: r"C:\Apps\browser.exe".into(),
            start_time: 0,
        });
    }
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(9, "example.com");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut targets).await, "1.1.1.1:53");
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    r.cancel.cancel();
}

#[tokio::test]
async fn tcp_dns_bootstrap_names_go_direct() {
    let (pport, mut targets, _) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.settings.dns.direct_names = vec!["*.manual.example".into()];
    let c = ctx(cfg.clone());
    c.proxy_servers
        .store(Arc::new(vec!["vpn.example.com".to_string()]));
    assert_tcp_dns_direct("127.53.0.12", c, "vpn.example.com").await;
    assert_tcp_dns_direct("127.53.0.13", ctx(cfg), "a.manual.example").await;
    assert!(targets.try_recv().is_err(), "went through the proxy");
}

// ---- M6: the dual-stack relay ----

/// Answers only for an IPv6 peer (as the NAT lookup does for an IPv6
/// redirected flow): the original destination is `dst`.
struct V6Lookup(SocketAddr);

impl OrigDstLookup for V6Lookup {
    fn attach(&self, peer: SocketAddr) -> Option<(OriginalDst, u64)> {
        peer.is_ipv6().then_some((
            OriginalDst {
                dst: self.0,
                pid: 4242,
            },
            1,
        ))
    }
    fn release(&self, _peer: SocketAddr, _token: u64) {}
}

/// Starts a relay on 127.0.0.1 + [::1] (same port). `None` (test skipped)
/// when this machine cannot bind the IPv6 loopback.
async fn start_dual(lookup: Arc<dyn OrigDstLookup>, c: Arc<RelayCtx>) -> Option<Relay> {
    let ls = bind_relay(Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST).unwrap();
    if ls.v6.is_none() {
        eprintln!("skipped: cannot bind [::1]");
        return None;
    }
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, ls.port()));
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_relay(ls.into_vec(), lookup, c, cancel.clone()));
    Some(Relay { addr, cancel, task })
}

#[tokio::test]
async fn relayed_ipv6_connection_via_proxy() {
    let (sport, mut reqs) = mock_socks(4).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    );
    let dst: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
    let Some(r) = start_dual(Arc::new(V6Lookup(dst)), ctx(cfg)).await else {
        return;
    };
    let mut c = TcpStream::connect(r.addr).await.unwrap();
    c.write_all(b"ping").await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(req.atyp, 4, "SOCKS5 ATYP IPv6");
    assert_eq!(
        req.host,
        "2606:4700::1"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    );
    assert_eq!(req.port, 443);
    assert_eq!(req.first, b"ping");
    r.cancel.cancel();
}

/// The SOCKS5 request for one proxied flow to `dst` (catch-all proxy, the
/// first bytes "ping"), with `name` mapped to `dst` by DNS when given;
/// `None` when the IPv6 relay cannot bind [::1].
async fn proxied_v6_request(dst: &str, name: Option<&str>) -> Option<SocksReq> {
    let (sport, mut reqs) = mock_socks(4).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    );
    let dst: SocketAddr = dst.parse().unwrap();
    let c = ctx(cfg);
    if let Some(n) = name {
        c.domains
            .insert(dst.ip(), n, 300, std::time::Instant::now());
    }
    let r = start_dual(Arc::new(V6Lookup(dst)), c).await?;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    r.cancel.cancel();
    Some(req)
}

/// A proxied IPv6 flow with no peeked host asks the proxy for the name DNS
/// answered for the destination (an IPv4-only proxy exit can still reach
/// it), both without a peek (port 22) and after an empty one (443).
#[tokio::test]
async fn proxied_ipv6_without_domain_uses_mapped_name() {
    for dst in ["[2606:4700::1]:22", "[2606:4700::1]:443"] {
        let Some(req) = proxied_v6_request(dst, Some("ssh.example.com")).await else {
            return;
        };
        assert_eq!(req.atyp, 3, "{dst}: SOCKS5 ATYP domain");
        assert_eq!(req.host, b"ssh.example.com", "{dst}");
        assert_eq!(req.first, b"ping");
    }
}

/// Without a mapped name the IPv6 address itself is asked for.
#[tokio::test]
async fn proxied_ipv6_without_name_uses_address() {
    let Some(req) = proxied_v6_request("[2606:4700::1]:22", None).await else {
        return;
    };
    assert_eq!(req.atyp, 4, "SOCKS5 ATYP IPv6");
    assert_eq!(req.port, 22);
}

/// IPv4 is unchanged: a mapped name is not used as the proxy target.
#[tokio::test]
async fn proxied_ipv4_without_domain_keeps_address() {
    let (sport, mut reqs) = mock_socks(4).await;
    let cfg = config(
        vec![socks_profile(sport)],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    );
    let dst: SocketAddrV4 = "203.0.113.7:22".parse().unwrap();
    let c = ctx(cfg);
    c.domains.insert(
        (*dst.ip()).into(),
        "ssh.example.com",
        300,
        std::time::Instant::now(),
    );
    let r = start(dst, c).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let req = tokio::time::timeout(Duration::from_secs(5), reqs.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(req.atyp, 1);
    assert_eq!(req.host, [203, 0, 113, 7]);
    r.cancel.cancel();
}

#[tokio::test]
async fn direct_ipv6_connection_from_relay() {
    let Ok(l) = TcpListener::bind("[::1]:0").await else {
        eprintln!("skipped: cannot bind [::1]");
        return;
    };
    let origin = l.local_addr().unwrap();
    let (tx, mut peers) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, peer)) = l.accept().await {
            let _ = tx.send(peer);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let c = ctx(cfg);
    let Some(r) = start_dual(Arc::new(V6Lookup(origin)), c.clone()).await else {
        return;
    };
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    client.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    let up = peers.recv().await.unwrap();
    assert!(up.is_ipv6(), "direct upstream is IPv6: {up}");
    assert!(
        c.own_ports.contains(&(Family::V6, up.port())),
        "own_ports keyed by family"
    );
    assert!(!c.own_ports.contains(&(Family::V4, up.port())));
    r.cancel.cancel();
}

#[tokio::test]
async fn socks4_ipv6_target_closes() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = proxy.local_addr().unwrap().port();
    let proxy_accepts = Arc::new(AtomicUsize::new(0));
    let pa = proxy_accepts.clone();
    tokio::spawn(async move {
        while proxy.accept().await.is_ok() {
            pa.fetch_add(1, Ordering::SeqCst);
        }
    });
    // A direct connect would be dialled to this origin: it must see nothing.
    let (origin, direct_accepts, _) = mock_origin().await;
    let dst: SocketAddr = "[2606:4700::1]:4434".parse().unwrap();
    DIALS.lock().unwrap().insert(dst, origin);
    let mut p = socks_profile(pport);
    p.kind = ProxyKind::Socks4;
    let cfg = config(
        vec![p],
        vec![group("rest", Action::Proxy("mock".into()), &[], true)],
    );
    let c = ctx(cfg);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cancel = CancellationToken::new();
    tokio::spawn(run_relay(
        vec![l],
        Arc::new(V6OrAnyLookup(dst)),
        c.clone(),
        cancel.clone(),
    ));
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        proxy_accepts.load(Ordering::SeqCst),
        0,
        "SOCKS4 never tried"
    );
    assert_eq!(
        direct_accepts.load(Ordering::SeqCst),
        0,
        "no direct fallback"
    );
    cancel.cancel();
}

/// Answers `dst` for any peer.
struct V6OrAnyLookup(SocketAddr);

impl OrigDstLookup for V6OrAnyLookup {
    fn attach(&self, _peer: SocketAddr) -> Option<(OriginalDst, u64)> {
        Some((
            OriginalDst {
                dst: self.0,
                pid: 4242,
            },
            1,
        ))
    }
    fn release(&self, _peer: SocketAddr, _token: u64) {}
}

#[tokio::test]
async fn relay_starts_ipv4_only_when_ipv6_bind_fails() {
    let mut tries = 0;
    let ls = bind_relay_with(Ipv4Addr::LOCALHOST, |_| {
        tries += 1;
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no IPv6",
        ))
    })
    .unwrap();
    assert!(ls.v6.is_none(), "IPv4 only");
    assert_eq!(tries, RELAY_BIND_ATTEMPTS);
    // The IPv4 side still relays.
    let (origin, _, _) = mock_origin().await;
    let cfg = config(vec![], vec![group("rest", Action::Direct, &[], true)]);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, ls.port()));
    let cancel = CancellationToken::new();
    tokio::spawn(run_relay(
        ls.into_vec(),
        Arc::new(FixedLookup(v4(origin))),
        ctx(cfg),
        cancel.clone(),
    ));
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    client.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    cancel.cancel();
}

#[tokio::test]
async fn relay_bind_retries_the_pair_for_ipv6() {
    let mut tries = 0;
    let ls = bind_relay_with(Ipv4Addr::LOCALHOST, |port| {
        tries += 1;
        if tries < 3 {
            return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "taken"));
        }
        let l = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, port))?;
        l.set_nonblocking(true)?;
        TcpListener::from_std(l)
    });
    let ls = ls.unwrap();
    if ls.v6.is_none() {
        eprintln!("skipped: cannot bind [::1]");
        return;
    }
    assert_eq!(tries, 3);
    let v6 = ls.v6.as_ref().unwrap().local_addr().unwrap();
    assert_eq!(v6.port(), ls.port(), "same port on both families");
}

/// IPv6 TCP/53 redirected into the dual-stack relay is routed by the
/// queried name like IPv4: a proxied name goes to the resolver via the
/// proxy, a Direct name to the original `[..]:53` server.
#[tokio::test]
async fn ipv6_tcp_dns_routed_by_name() {
    let orig: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    DIALS.lock().unwrap().insert(orig, l.local_addr().unwrap());
    let accepts = Arc::new(AtomicUsize::new(0));
    let (tx, mut seen) = mpsc::unbounded_channel();
    let a = accepts.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            a.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_dns(s, tx.clone()));
        }
    });
    let (pport, mut targets, mut queries) = mock_connect_dns().await;
    let mut cfg = config(vec![http_profile(pport)], dns_groups());
    cfg.settings.dns.proxy_resolver = "8.8.4.4:53".into();
    let c = ctx(cfg);
    let Some(r) = start_dual(Arc::new(V6Lookup(orig)), c.clone()).await else {
        return;
    };
    // Proxied name: via the proxy to the resolver, original server untouched.
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(0x1234, "example.com");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut targets).await, "8.8.4.4:53");
    assert_eq!(recv_t(&mut queries).await, q);
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "original server contacted"
    );
    // Direct name: to the original IPv6 server, not through the proxy.
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    let q = dns_query(0x0bad, "www.digikala.ir");
    client.write_all(&framed(&q)).await.unwrap();
    assert_eq!(read_frame(&mut client).await, dns_answer(&q));
    assert_eq!(recv_t(&mut seen).await, q);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert!(targets.try_recv().is_err(), "went through the proxy");
    r.cancel.cancel();
}
