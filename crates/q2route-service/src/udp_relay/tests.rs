//! UDP relay tests: a mock SOCKS5 UDP proxy relaying to a local echo server
//! (see [`crate::test_util`]), and an `InboundSink` that hands injected
//! packets to the test.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use q2route_core::config::{Config, ProxyKind};
use q2route_core::ipc::{ConnInfo, Event};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::relay::RelayCtx;
use crate::test_util::*;
use crate::windivert::Address;

fn local() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000)
}

fn dg(remote: SocketAddrV4, payload: &[u8]) -> Datagram {
    dg_at(SocketAddr::V4(local()), SocketAddr::V4(remote), payload)
}

fn dg_at(local: SocketAddr, remote: SocketAddr, payload: &[u8]) -> Datagram {
    Datagram {
        pid: 4242,
        profile: "mock".into(),
        group_id: Some("g".into()),
        local,
        remote,
        payload: payload.to_vec(),
        addr: Address::default(),
    }
}

/// The app's IPv6 socket, on the same port as [`local`].
fn local6() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::2".parse().unwrap(),
        local().port(),
        0,
        0,
    ))
}

/// (src, dst, payload) of an injected IPv6/UDP packet; asserts the UDP
/// checksum is valid.
fn parse_inbound6(p: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};
    let s = SlicedPacket::from_ip(p).unwrap();
    let (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Udp(u))) = (s.net, s.transport) else {
        panic!("not ipv6/udp")
    };
    let h = ip.header().to_header();
    let want = u.to_header().calc_checksum_ipv6(&h, u.payload()).unwrap();
    assert_eq!(u.checksum(), want, "udp checksum");
    let a = |ip: [u8; 16], port| SocketAddr::from((Ipv6Addr::from(ip), port));
    (
        a(h.source, u.source_port()),
        a(h.destination, u.destination_port()),
        u.payload().to_vec(),
    )
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
    // Another remote inside the backoff: no new row either.
    let other = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 999);
    s.relay.submit(dg(other, b"three"));
    quiet(&mut seen).await;
    quiet(&mut s.injected).await;
    assert_eq!(m.attempts.load(Ordering::SeqCst), 1);
    assert!(s.ctx.proxy_down.is_empty(), "a refusal is not proxy down");
    assert_eq!(rows(&s.ctx).len(), 1, "one ConnLog row within the backoff");
}

/// ConnLog rows of the test's app socket.
fn rows(ctx: &RelayCtx) -> Vec<ConnInfo> {
    ctx.conns
        .list()
        .into_iter()
        .filter(|c| c.local == SocketAddr::V4(local()))
        .collect()
}

#[tokio::test]
async fn dead_proxy_retries_once_per_backoff() {
    let m = mock(MockOpts {
        rep: 7,
        ..Default::default()
    })
    .await;
    let (echo_addr, mut seen) = echo().await;
    let backoff = Duration::from_millis(400);
    let s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig {
            backoff,
            ..Default::default()
        },
    );
    let attempts = |n: usize| {
        let a = m.attempts.clone();
        async move {
            timeout(WAIT, async {
                while a.load(Ordering::SeqCst) < n {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
    };
    s.relay.submit(dg(echo_addr, b"one"));
    attempts(1).await;
    // Inside the backoff: dropped by the manager, no session.
    for _ in 0..10 {
        s.relay.submit(dg(echo_addr, b"x"));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(m.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(rows(&s.ctx).len(), 1);
    // After it: exactly one new attempt and one new row.
    tokio::time::sleep(backoff).await;
    s.relay.submit(dg(echo_addr, b"two"));
    s.relay.submit(dg(echo_addr, b"three"));
    attempts(2).await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(m.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(rows(&s.ctx).len(), 2);
    quiet(&mut seen).await;
}

#[tokio::test]
async fn close_is_not_dropped_when_queue_is_full() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"one"));
    assert_eq!(recv(&mut seen).await, b"one");
    recv(&mut s.injected).await;
    // Current-thread runtime: the manager cannot run while this loop fills
    // (and overflows) the datagram queue.
    for _ in 0..SUBMIT_QUEUE + 100 {
        s.relay.submit(dg(echo_addr, b"flood"));
    }
    s.relay.close(SocketAddr::V4(local()));
    let c = conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
    assert_eq!(c.local, SocketAddr::V4(local()));
    // The queued datagrams predate the close: none restarts a session.
    quiet(&mut seen).await;
    assert_eq!(m.attempts.load(Ordering::SeqCst), 1);
    assert!(rows(&s.ctx).iter().all(|c| c.ended_ms.is_some()));
    // A datagram after the close (new socket on the port) is relayed.
    s.relay.submit(dg(echo_addr, b"two"));
    assert_eq!(recv(&mut seen).await, b"two");
}

#[tokio::test]
async fn serves_port_during_session_and_guard() {
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let guard = Duration::from_millis(500);
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig {
            icmp_guard: guard,
            ..Default::default()
        },
    );
    let port = local().port();
    assert!(!s.relay.serves_port(Family::V4, port));
    s.relay.submit(dg(echo_addr, b"one"));
    assert_eq!(recv(&mut seen).await, b"one");
    recv(&mut s.injected).await;
    assert!(s.relay.serves_port(Family::V4, port));
    assert!(!s.relay.serves_port(Family::V4, port + 1));
    s.relay.close(SocketAddr::V4(local()));
    conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
    timeout(WAIT, async {
        while s.ctx.stats.snapshot().0.values().any(|g| g.active > 0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // Ended, still guarded.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        s.relay.serves_port(Family::V4, port),
        "guarded after the session ends"
    );
    tokio::time::sleep(guard + Duration::from_millis(100)).await;
    assert!(!s.relay.serves_port(Family::V4, port), "guard expired");
}

#[tokio::test]
async fn ipv6_relay_address_works() {
    let Some(m) = try_mock(MockOpts {
        v6: true,
        ..Default::default()
    })
    .await
    else {
        eprintln!("no IPv6 loopback; skipped");
        return;
    };
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg(echo_addr, b"ping6"));
    assert_eq!(recv(&mut seen).await, b"ping6");
    let (src, dst, payload) = parse_inbound(&recv(&mut s.injected).await);
    assert_eq!(
        (src, dst, payload.as_slice()),
        (echo_addr, local(), &b"ping6"[..])
    );
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
    s.relay.close(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        local().port(),
    )));
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

#[tokio::test]
async fn remote_rows_are_capped() {
    let m = mock(MockOpts::default()).await;
    // One echo server per remote (distinct ports), all reporting to `seen`.
    let total = MAX_REMOTE_ROWS + 10;
    let (tx, mut seen) = mpsc::unbounded_channel();
    let mut remotes = Vec::new();
    for _ in 0..total {
        let (addr, mut rx) = echo().await;
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                let _ = tx.send((addr, p));
            }
        });
        remotes.push(addr);
    }
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    for (i, r) in remotes.iter().enumerate() {
        s.relay.submit(dg(*r, &(i as u32).to_be_bytes()));
    }
    let mut got = HashSet::new();
    for _ in 0..total {
        got.insert(recv(&mut seen).await.0);
        recv(&mut s.injected).await;
    }
    assert_eq!(got.len(), total, "every remote is relayed");
    let rows: Vec<_> = s
        .ctx
        .conns
        .list()
        .into_iter()
        .filter(|c| c.local == SocketAddr::V4(local()))
        .collect();
    assert_eq!(rows.len(), MAX_REMOTE_ROWS);
    assert!(rows.iter().all(|c| c.ended_ms.is_none()));
    assert_eq!(s.ctx.stats.bytes("g"), (4 * total as u64, 4 * total as u64));
}

#[tokio::test]
async fn relays_ipv6_datagram_and_injects_ipv6_reply() {
    let Some((echo_addr, mut seen)) = echo6().await else {
        eprintln!("no IPv6 loopback; skipped");
        return;
    };
    let m = mock(MockOpts::default()).await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    s.relay.submit(dg_at(local6(), echo_addr, b"ping6"));
    assert_eq!(recv(&mut seen).await, b"ping6");
    let (src, dst, payload) = parse_inbound6(&recv(&mut s.injected).await);
    assert_eq!(
        (src, dst, payload.as_slice()),
        (echo_addr, local6(), &b"ping6"[..])
    );
    let c = conn_where(&s.ctx, |c| c.up == Some(5) && c.down == Some(5)).await;
    assert_eq!((c.local, c.dst), (local6(), echo_addr));
    assert!(s.relay.serves_port(Family::V6, local().port()));
    assert!(!s.relay.serves_port(Family::V4, local().port()));
}

/// An IPv4 and an IPv6 socket on the same local port are two sessions:
/// each is associated, answered, guarded and closed on its own.
#[tokio::test]
async fn v4_and_v6_sessions_on_same_port_are_separate() {
    let Some((echo6_addr, mut seen6)) = echo6().await else {
        eprintln!("no IPv6 loopback; skipped");
        return;
    };
    let m = mock(MockOpts::default()).await;
    let (echo_addr, mut seen) = echo().await;
    let mut s = setup(
        config(profile(ProxyKind::Socks5, m.port)),
        UdpRelayConfig::default(),
    );
    let port = local().port();
    s.relay.submit(dg(echo_addr, b"four"));
    assert_eq!(recv(&mut seen).await, b"four");
    assert_eq!(parse_inbound(&recv(&mut s.injected).await).1, local());
    assert!(s.relay.serves_port(Family::V4, port));
    assert!(!s.relay.serves_port(Family::V6, port), "only the v4 socket");
    s.relay.submit(dg_at(local6(), echo6_addr, b"six"));
    assert_eq!(recv(&mut seen6).await, b"six");
    assert_eq!(parse_inbound6(&recv(&mut s.injected).await).1, local6());
    assert!(s.relay.serves_port(Family::V6, port));
    assert_eq!(m.attempts.load(Ordering::SeqCst), 2, "one association each");
    // Closing the IPv6 socket ends only its session.
    s.relay.close(local6());
    let c = conn_where(&s.ctx, |c| c.ended_ms.is_some()).await;
    assert_eq!(c.local, local6());
    let open: Vec<_> = s
        .ctx
        .conns
        .list()
        .into_iter()
        .filter(|c| c.ended_ms.is_none())
        .collect();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].local, SocketAddr::V4(local()));
    // The IPv4 session keeps relaying on its existing association.
    s.relay.submit(dg(echo_addr, b"again"));
    assert_eq!(recv(&mut seen).await, b"again");
    assert_eq!(parse_inbound(&recv(&mut s.injected).await).2, b"again");
    assert_eq!(m.attempts.load(Ordering::SeqCst), 2);
    // A v4 CLOSE never ends the IPv6 socket's new session either.
    s.relay.submit(dg_at(local6(), echo6_addr, b"six2"));
    assert_eq!(recv(&mut seen6).await, b"six2");
    recv(&mut s.injected).await;
    s.relay.close(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        port,
    )));
    conn_where(&s.ctx, |c| {
        c.ended_ms.is_some() && c.local == SocketAddr::V4(local())
    })
    .await;
    tokio::time::sleep(QUIET).await;
    assert!(s
        .ctx
        .conns
        .list()
        .iter()
        .any(|c| c.local == local6() && c.ended_ms.is_none()));
}

#[test]
fn close_matching_is_family_aware() {
    let a = |s: &str| s.parse::<SocketAddr>().unwrap();
    let v4 = a("10.0.0.2:5000");
    let v6 = a("[2001:db8::2]:5000");
    // Same family, same ip / unspecified ip: matches.
    assert!(same_local(&v4, a("10.0.0.2:5000")));
    assert!(same_local(&v4, a("0.0.0.0:5000")));
    assert!(same_local(&v6, a("[2001:db8::2]:5000")));
    assert!(same_local(&v6, a("[::]:5000")));
    // v4-mapped IPv6 close: its IPv4 entry only.
    assert!(same_local(&v4, a("[::ffff:10.0.0.2]:5000")));
    assert!(!same_local(&v6, a("[::ffff:10.0.0.2]:5000")));
    // The IPv6 wildcard (a dual-stack socket) also ends IPv4 sessions on
    // the port, as before M6.
    assert!(same_local(&v4, a("[::]:5000")));
    // Other family / ip / port: no match.
    assert!(!same_local(&v6, a("0.0.0.0:5000")));
    assert!(!same_local(&v6, a("10.0.0.2:5000")));
    assert!(!same_local(&v4, a("[2001:db8::2]:5000")));
    assert!(!same_local(&v4, a("10.0.0.3:5000")));
    assert!(!same_local(&v4, a("10.0.0.2:5001")));
}
