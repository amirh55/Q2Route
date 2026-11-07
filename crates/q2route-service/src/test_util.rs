//! Shared test helpers: a mock SOCKS5 UDP proxy relaying to real local
//! sockets, an `InboundSink` that hands injected packets to the test, and a
//! test `RelayCtx`.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashSet;
use q2route_core::config::{Config, ProxyKind, ProxyProfile, Settings};
use q2route_core::domain_map::DomainMap;
use q2route_core::process_tree::ProcessTree;
use q2route_core::proxy::{decode_udp, encode_udp};
use q2route_core::ruleset::RuleSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::time::timeout;

use crate::relay::RelayCtx;
use crate::stats::Stats;
use crate::udp_relay::InboundSink;
use crate::windivert::Address;

pub const WAIT: Duration = Duration::from_secs(5);
/// How long a negative assertion ("nothing arrives") waits.
pub const QUIET: Duration = Duration::from_millis(300);

pub fn v4(a: SocketAddr) -> SocketAddrV4 {
    match a {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => panic!("expected v4"),
    }
}

pub fn profile(kind: ProxyKind, port: u16) -> ProxyProfile {
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

pub fn config(p: ProxyProfile) -> Config {
    Config {
        seed_version: q2route_core::SEED_VERSION,
        proxies: vec![p],
        groups: vec![],
        always_direct: vec![],
        default_proxy: "mock".into(),
        settings: Settings::default(),
    }
}

pub fn ctx(cfg: Config) -> Arc<RelayCtx> {
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
        domains: Arc::new(DomainMap::new()),
    })
}

/// Hands every injected packet to the test.
pub struct ChanSink(pub mpsc::UnboundedSender<Vec<u8>>);

impl InboundSink for ChanSink {
    fn inject(&self, pkt: Vec<u8>, _addr: &Address) {
        let _ = self.0.send(pkt);
    }
}

/// (src, dst, payload) of an injected IPv4/UDP packet.
pub fn parse_inbound(p: &[u8]) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
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
pub async fn echo() -> (SocketAddrV4, mpsc::UnboundedReceiver<Vec<u8>>) {
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
pub struct MockOpts {
    /// Delay before the ASSOCIATE reply.
    pub delay: Duration,
    /// REP code of the ASSOCIATE reply.
    pub rep: u8,
    /// After the first relayed datagram, also send one from this remote.
    pub unsolicited: Option<SocketAddrV4>,
    /// Serve the UDP relay on [::1] (BND.ADDR IPv6).
    pub v6: bool,
}

pub struct Mock {
    pub port: u16,
    pub attempts: Arc<AtomicUsize>,
    /// Closes the current control connections.
    pub close_control: Arc<Notify>,
    /// Source address of everything the mock relays to targets.
    pub outer: SocketAddr,
}

/// SOCKS5 proxy (no auth) that answers UDP ASSOCIATE and relays datagrams
/// through one shared UDP relay socket.
pub async fn mock(opts: MockOpts) -> Mock {
    try_mock(opts).await.expect("mock relay socket")
}

/// Like [`mock`]; `None` if the relay socket cannot be bound (no IPv6
/// loopback).
pub async fn try_mock(opts: MockOpts) -> Option<Mock> {
    let relay_bind = if opts.v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let relay = Arc::new(UdpSocket::bind(relay_bind).await.ok()?);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let outer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_port = relay.local_addr().unwrap().port();
    let outer_addr = outer.local_addr().unwrap();
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
    let (delay, rep, v6) = (opts.delay, opts.rep, opts.v6);
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
                let mut reply = if v6 {
                    let mut r = vec![5, rep, 0, 4];
                    r.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                    r
                } else {
                    vec![5, rep, 0, 1, 127, 0, 0, 1]
                };
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
    Some(Mock {
        port,
        attempts,
        close_control,
        outer: outer_addr,
    })
}

pub async fn recv<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    timeout(WAIT, rx.recv()).await.expect("timed out").unwrap()
}

pub async fn quiet<T: std::fmt::Debug>(rx: &mut mpsc::UnboundedReceiver<T>) {
    if let Ok(Some(x)) = timeout(QUIET, rx.recv()).await {
        panic!("unexpected {x:?}");
    }
}
