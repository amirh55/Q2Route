//! UDP relay tests: a mock SOCKS5 UDP proxy relaying to a local echo server,
//! and an `InboundSink` that hands injected packets to the test.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Config, ProxyKind, ProxyProfile, Settings};
use q2route_core::ipc::{ConnInfo, Event};
use q2route_core::process_tree::ProcessTree;
use q2route_core::proxy::{decode_udp, encode_udp};
use q2route_core::ruleset::RuleSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::relay::RelayCtx;
use crate::stats::Stats;
use crate::windivert::Address;

const WAIT: Duration = Duration::from_secs(5);
/// How long a negative assertion ("nothing arrives") waits.
const QUIET: Duration = Duration::from_millis(300);

fn local() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000)
}

fn v4(a: SocketAddr) -> SocketAddrV4 {
    match a {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => panic!("expected v4"),
    }
}

fn profile(kind: ProxyKind, port: u16) -> ProxyProfile {
    ProxyProfile {
        id: "mock".into(),
        name: "Mock".into(),
        kind,
        host: "127.0.0.1".into(),
        port,
        username: None,
        password: None,
    }
}

fn config(p: ProxyProfile) -> Config {
    Config {
        seed_version: q2route_core::SEED_VERSION,
        proxies: vec![p],
        groups: vec![],
        always_direct: vec![],
        default_proxy: "mock".into(),
        settings: Settings::default(),
    }
}

fn ctx(cfg: Config) -> Arc<RelayCtx> {
    let rules = RuleSet::compile(&cfg).unwrap();
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
    })
}

/// Hands every injected packet to the test.
struct ChanSink(mpsc::UnboundedSender<Vec<u8>>);

impl InboundSink for ChanSink {
    fn inject(&self, pkt: Vec<u8>, _addr: &Address) {
        let _ = self.0.send(pkt);
    }
}

/// (src, dst, payload) of an injected IPv4/UDP packet.
fn parse_inbound(p: &[u8]) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
    assert_eq!(p[0], 0x45);
    assert_eq!(p[9], 17);
    let ip = |at: usize| Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]);
    let port = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
    (
        SocketAddrV4::new(ip(12), port(20)),
        SocketAddrV4::new(ip(16), port(22)),
        p[28..].to_vec(),
    )
}

/// UDP echo server; reports every payload it receives.
async fn echo() -> (SocketAddrV4, mpsc::UnboundedReceiver<Vec<u8>>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = v4(s.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = tx.send(buf[..n].to_vec());
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    (addr, rx)
}

#[derive(Default)]
struct MockOpts {
    /// Delay before the ASSOCIATE reply.
    delay: Duration,
    /// REP code of the ASSOCIATE reply.
    rep: u8,
    /// After the first relayed datagram, also send one from this remote.
    unsolicited: Option<SocketAddrV4>,
}

struct Mock {
    port: u16,
    attempts: Arc<AtomicUsize>,
    /// Closes the current control connections.
    close_control: Arc<Notify>,
}

/// SOCKS5 proxy (no auth) that answers UDP ASSOCIATE and relays datagrams
/// through one shared UDP relay socket.
async fn mock(opts: MockOpts) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let outer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_port = relay.local_addr().unwrap().port();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let attempts = Arc::new(AtomicUsize::new(0));
    let close_control = Arc::new(Notify::new());

    // Client -> target.
    let (r, o, c) = (relay.clone(), outer.clone(), client.clone());
    let unsolicited = opts.unsolicited;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut first = true;
        while let Ok((n, from)) = r.recv_from(&mut buf).await {
            *c.lock().unwrap() = Some(from);
            let Some((dst, payload)) = decode_udp(&buf[..n]) else {
                continue;
            };
            let _ = o.send_to(payload, dst).await;
            if first {
                first = false;
                if let Some(u) = unsolicited {
                    let d = encode_udp(SocketAddr::V4(u), b"unsolicited");
                    let _ = r.send_to(&d, from).await;
                }
            }
        }
    });
    // Target -> client.
    let (r, o, c) = (relay.clone(), outer, client);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = o.recv_from(&mut buf).await {
            let to = *c.lock().unwrap();
            if let Some(to) = to {
                let _ = r.send_to(&encode_udp(from, &buf[..n]), to).await;
            }
        }
    });
    // Control connections.
    let (a, cc) = (attempts.clone(), close_control.clone());
    let (delay, rep) = (opts.delay, opts.rep);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (a, cc) = (a.clone(), cc.clone());
            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                s.read_exact(&mut greet).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 10];
                s.read_exact(&mut req).await.unwrap();
                assert_eq!(req[1], 3, "UDP ASSOCIATE");
                a.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                let mut reply = vec![5, rep, 0, 1, 127, 0, 0, 1];
                reply.extend_from_slice(&relay_port.to_be_bytes());
                s.write_all(&reply).await.unwrap();
                if rep != 0 {
                    return;
                }
                let mut b = [0u8; 1];
                tokio::select! {
                    _ = cc.notified() => {}
                    _ = s.read(&mut b) => {}
                }
            });
        }
    });
    Mock {
        port,
        attempts,
        close_control,
    }
}

fn dg(remote: SocketAddrV4, payload: &[u8]) -> Datagram {
    Datagram {
        pid: 4242,
        profile: "mock".into(),
        group_id: Some("g".into()),
        local: local(),
        remote,
        payload: payload.to_vec(),
        addr: Address::default(),
    }
}

struct Setup {
    ctx: Arc<RelayCtx>,
    relay: Arc<UdpRelay>,
    injected: mpsc::UnboundedReceiver<Vec<u8>>,
    _cancel: tokio_util::sync::DropGuard,
}

fn setup(cfg: Config, rc: UdpRelayConfig) -> Setup {
    let ctx = ctx(cfg);
    let (tx, injected) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let relay = UdpRelay::with_config(ctx.clone(), Arc::new(ChanSink(tx)), cancel.clone(), rc);
    Setup {
        ctx,
        relay,
        injected,
        _cancel: cancel.drop_guard(),
    }
}

async fn recv<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    timeout(WAIT, rx.recv()).await.expect("timed out").unwrap()
}

async fn quiet<T: std::fmt::Debug>(rx: &mut mpsc::UnboundedReceiver<T>) {
    if let Ok(Some(x)) = timeout(QUIET, rx.recv()).await {
        panic!("unexpected {x:?}");
    }
}

/// Waits until a UDP ConnLog entry satisfies `f`.
async fn conn_where(ctx: &RelayCtx, f: impl Fn(&ConnInfo) -> bool) -> ConnInfo {
    timeout(WAIT, async {
        loop {
            if let Some(c) = ctx.conns.list().into_iter().find(|c| f(c)) {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("conn entry timed out")
}

#[tokio::test]
async fn relays_datagram_and_injects_reply() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"ping"));
    assert_eq!(recv(&mut seen).await, b"ping");
    let (src, dst, payload) = parse_inbound(&recv(&mut s.injected).await);
    assert_eq!(
        (src, dst, payload.as_slice()),
        (echo_addr, local(), &b"ping"[..])
    );
    let c = conn_where(&s.ctx, |c| c.up == Some(4) && c.down == Some(4)).await;
    assert_eq!(c.proto, q2route_core::config::Protocol::Udp);
    assert_eq!(c.route, q2route_core::decide::Route::Proxy("mock".into()));
    assert_eq!(c.dst, SocketAddr::V4(echo_addr));
    assert_eq!(s.ctx.stats.bytes("g"), (4, 4));
    assert_eq!(m.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn queues_until_associated_then_flushes() {
    let m = mock(MockOpts {
        delay: Duration::from_millis(300),
        ..Default::default()
    })
    .await;
    let (echo_addr, mut seen) = echo().await;
    let s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    for i in 0..70u32 {
        s.relay.submit(dg(echo_addr, &i.to_be_bytes()));
    }
    for i in 0..PENDING_MAX as u32 {
        assert_eq!(recv(&mut seen).await, i.to_be_bytes(), "datagram {i}");
    }
    quiet(&mut seen).await;
}

#[tokio::test]
async fn reply_from_other_remote_is_delivered() {
    let other = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 999);
    let m = mock(MockOpts {
        unsolicited: Some(other),
        ..Default::default()
    })
    .await;
    let (echo_addr, _seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"ping"));
    let mut got = [
        parse_inbound(&recv(&mut s.injected).await),
        parse_inbound(&recv(&mut s.injected).await),
    ];
    got.sort_by_key(|(src, _, _)| *src == echo_addr);
    assert_eq!(got[0], (other, local(), b"unsolicited".to_vec()));
    assert_eq!(got[1], (echo_addr, local(), b"ping".to_vec()));
}

#[tokio::test]
async fn udp_association_refused_drops_and_logs() {
    let m = mock(MockOpts {
        rep: 7,
        ..Default::default()
    })
    .await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"one"));
    timeout(WAIT, async {
        while m.attempts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    s.relay.submit(dg(echo_addr, b"two"));
    quiet(&mut seen).await;
    quiet(&mut s.injected).await;
    assert_eq!(m.attempts.load(Ordering::SeqCst), 1);
    assert!(s.ctx.proxy_down.is_empty(), "a refusal is not proxy down");
}

#[tokio::test]
async fn non_socks5_profile_drops() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Http, port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"one"));
    s.relay.submit(dg(echo_addr, b"two"));
    assert!(timeout(QUIET, l.accept()).await.is_err(), "no connection");
    quiet(&mut seen).await;
    quiet(&mut s.injected).await;
}

#[tokio::test]
async fn control_close_tears_down_and_reassociates() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"one"));
    assert_eq!(recv(&mut seen).await, b"one");
    recv(&mut s.injected).await;
    m.close_control.notify_waiters();
    conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
    s.relay.submit(dg(echo_addr, b"two"));
    assert_eq!(recv(&mut seen).await, b"two");
    let (_, _, payload) = parse_inbound(&recv(&mut s.injected).await);
    assert_eq!(payload, b"two");
    assert_eq!(m.attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn close_ends_session() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"one"));
    assert_eq!(recv(&mut seen).await, b"one");
    recv(&mut s.injected).await;
    // An unspecified-ip CLOSE ends every session on that port.
    s.relay
        .close(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local().port()));
    let c = conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
    assert_eq!(c.local, SocketAddr::V4(local()));
    timeout(WAIT, async {
        while s.ctx.stats.snapshot().0.values().any(|g| g.active > 0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("stats guard dropped");
}

#[tokio::test]
async fn idle_session_ends() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig {
            idle: Duration::from_millis(200),
            ..Default::default()
        },
    );
    s.relay.submit(dg(echo_addr, b"one"));
    assert_eq!(recv(&mut seen).await, b"one");
    conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
}

#[tokio::test]
async fn proxy_unreachable_emits_proxy_down_then_up() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = closed.local_addr().unwrap().port();
    drop(closed);
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, dead_port)),
        UdpRelayConfig {
            backoff: Duration::from_millis(100),
            ..Default::default()
        },
    );
    let mut events = s.ctx.events.subscribe();
    s.relay.submit(dg(echo_addr, b"one"));
    let e = timeout(WAIT, events.recv()).await.unwrap().unwrap();
    assert!(
        matches!(e, Event::ProxyDown { ref id } if id == "mock"),
        "{e:?}"
    );
    assert!(s.ctx.proxy_down.contains("mock"));

    let m = mock(MockOpts::default()).await;
    s.ctx
        .cfg
        .store(Arc::new(config(profile(ProxyKind::Socks5, m.port))));
    // Datagrams inside the backoff are dropped; keep sending until one
    // starts a new association.
    let e = timeout(WAIT, async {
        loop {
            s.relay.submit(dg(echo_addr, b"two"));
            if let Ok(e) = timeout(Duration::from_millis(20), events.recv()).await {
                return e.unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert!(
        matches!(e, Event::ProxyUp { ref id } if id == "mock"),
        "{e:?}"
    );
    assert!(s.ctx.proxy_down.is_empty());
    assert_eq!(recv(&mut seen).await, b"two");
    let _ = recv(&mut s.injected).await;
}
