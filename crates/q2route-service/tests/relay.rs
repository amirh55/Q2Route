//! Relay tests: localhost mocks, with `RuleSet::lan_direct = false` so that
//! loopback destinations are routed by the rules under test.

use std::collections::HashSet;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Action, Config, Group, ProxyKind, ProxyProfile, Rule, Settings};
use q2route_core::domain_map::DomainMap;
use q2route_core::ipc::Event;
use q2route_core::process_tree::ProcessTree;
use q2route_core::ruleset::RuleSet;
use q2route_service::nat::OriginalDst;
use q2route_service::relay::{run_relay, OrigDstLookup, RelayCtx};
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
                dst: self.0,
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
                dst: self.0,
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
    let task = tokio::spawn(run_relay(l, Arc::new(FixedLookup(dst)), c, cancel.clone()));
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
        c.own_ports.contains(&upstream_port),
        "own_ports missing upstream port"
    );
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(3);
    while c.own_ports.contains(&upstream_port) {
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
        l,
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
        l,
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

/// Mock DNS-over-TCP server on `ip:53` (a distinct loopback ip per test):
/// counts accepts, reports queries.
async fn dns_server(ip: &str) -> DnsServer {
    let addr: SocketAddrV4 = format!("{ip}:53").parse().unwrap();
    let l = TcpListener::bind(addr).await.expect("bind loopback :53");
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

#[tokio::test]
async fn tcp_dns_malformed_query_closes() {
    let (orig, accepts, _) = dns_server("127.53.0.5").await;
    let groups = vec![group("rest", Action::Direct, &[], true)];
    let c = ctx(config(vec![], groups));
    let r = start(orig, c.clone()).await;
    let mut client = TcpStream::connect(r.addr).await.unwrap();
    client.write_all(&framed(b"not a dns query")).await.unwrap();
    assert_closed(&mut client, Duration::from_secs(3)).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
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
