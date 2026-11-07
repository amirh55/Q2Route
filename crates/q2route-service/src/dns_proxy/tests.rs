//! DnsProxy tests: the M3 mock SOCKS5 UDP proxy ([`crate::test_util`]) in
//! front of a mock DNS resolver that answers A 9.9.9.9 for any name.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use q2route_core::config::{Config, ProxyKind};
use q2route_core::dns::answers;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::*;
use crate::relay::RelayCtx;
use crate::test_util::*;
use crate::windivert::Address;

const NINE: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

/// A standard query (RD) for `name`, type A.
fn query(id: u16, name: &str) -> Vec<u8> {
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
fn answer_a(q: &[u8]) -> Vec<u8> {
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
    r.extend_from_slice(&NINE.octets());
    r
}

fn id_of(m: &[u8]) -> u16 {
    u16::from_be_bytes([m[0], m[1]])
}

enum Mode {
    Answer,
    Silent,
    /// Answers at once with a wrong id, then after the delay with the right
    /// one (reported on `late`).
    WrongIdThenLate(Duration),
}

struct Resolver {
    addr: SocketAddr,
    /// (source, query) of every query received.
    seen: mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    late: mpsc::UnboundedReceiver<()>,
}

async fn resolver(mode: Mode) -> Resolver {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let (tx, seen) = mpsc::unbounded_channel();
    let (late_tx, late) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let q = buf[..n].to_vec();
            let _ = tx.send((from, q.clone()));
            match mode {
                Mode::Answer => {
                    let _ = s.send_to(&answer_a(&q), from).await;
                }
                Mode::Silent => {}
                Mode::WrongIdThenLate(delay) => {
                    let wrong = with_id(&answer_a(&q), id_of(&q) ^ 0x8000);
                    let _ = s.send_to(&wrong, from).await;
                    let (s, late_tx) = (s.clone(), late_tx.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = s.send_to(&answer_a(&q), from).await;
                        let _ = late_tx.send(());
                    });
                }
            }
        }
    });
    Resolver { addr, seen, late }
}

fn dns_config(kind: ProxyKind, port: u16, resolver: SocketAddr) -> Config {
    let mut c = config(profile(kind, port));
    c.settings.dns.proxy_resolver = resolver.to_string();
    c
}

struct Setup {
    ctx: Arc<RelayCtx>,
    dns: Arc<DnsProxy>,
    injected: mpsc::UnboundedReceiver<Vec<u8>>,
    _cancel: DropGuard,
}

fn setup(cfg: Config, dc: DnsProxyConfig) -> Setup {
    let ctx = ctx(cfg);
    let (tx, injected) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let dns = DnsProxy::new(ctx.clone(), Arc::new(ChanSink(tx)), cancel.clone(), dc);
    Setup {
        ctx,
        dns,
        injected,
        _cancel: cancel.drop_guard(),
    }
}

fn q4(id: u16, name: &str) -> DnsQuery {
    DnsQuery {
        profile: "mock".into(),
        app: "10.0.0.5:50000".parse().unwrap(),
        server: "192.168.1.1:53".parse().unwrap(),
        msg: query(id, name),
        addr: Address::default(),
    }
}

fn q6(id: u16, name: &str) -> DnsQuery {
    DnsQuery {
        app: "[2001:db8::5]:50000".parse().unwrap(),
        server: "[2001:db8::53]:53".parse().unwrap(),
        ..q4(id, name)
    }
}

/// (src, dst, payload) of an injected IPv6/UDP packet; checks the checksum.
fn parse_inbound6(p: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    let s = SlicedPacket::from_ip(p).unwrap();
    let (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Udp(u))) = (s.net, s.transport) else {
        panic!("not ipv6/udp")
    };
    let h = ip.header().to_header();
    let want = u.to_header().calc_checksum_ipv6(&h, u.payload()).unwrap();
    assert_eq!(u.checksum(), want, "udp checksum");
    (
        SocketAddr::new(IpAddr::from(h.source), u.source_port()),
        SocketAddr::new(IpAddr::from(h.destination), u.destination_port()),
        u.payload().to_vec(),
    )
}

fn rcode(m: &[u8]) -> u8 {
    m[3] & 0x0f
}

fn tc(m: &[u8]) -> bool {
    m[2] & 0x02 != 0
}

#[tokio::test]
async fn proxied_query_answered_through_proxy() {
    let m = mock(MockOpts::default()).await;
    let mut r = resolver(Mode::Answer).await;
    let mut s = setup(
        dns_config(ProxyKind::Socks5, m.port, r.addr),
        DnsProxyConfig::default(),
    );
    s.dns.submit(q4(0x1234, "example.com"));
    let (src, dst, payload) = parse_inbound(&recv(&mut s.injected).await);
    assert_eq!(src, "192.168.1.1:53".parse().unwrap());
    assert_eq!(dst, "10.0.0.5:50000".parse().unwrap());
    assert_eq!(id_of(&payload), 0x1234, "original id restored");
    let (name, ips) = answers(&payload);
    assert_eq!(name.as_deref(), Some("example.com"));
    assert_eq!(ips.first().map(|x| x.0), Some(IpAddr::V4(NINE)));
    let names = s
        .ctx
        .domains
        .names(IpAddr::V4(NINE), std::time::Instant::now());
    assert!(names.contains(&"example.com".to_string()), "{names:?}");
    let (from, _) = recv(&mut r.seen).await;
    assert_eq!(from, m.outer, "query reached the resolver via the proxy");
    quiet(&mut s.injected).await;
}

#[tokio::test]
async fn ipv6_query_answered_with_ipv6_packet() {
    let m = mock(MockOpts::default()).await;
    let r = resolver(Mode::Answer).await;
    let mut s = setup(
        dns_config(ProxyKind::Socks5, m.port, r.addr),
        DnsProxyConfig::default(),
    );
    s.dns.submit(q6(0x4321, "example.com"));
    let (src, dst, payload) = parse_inbound6(&recv(&mut s.injected).await);
    assert_eq!(src, "[2001:db8::53]:53".parse().unwrap());
    assert_eq!(dst, "[2001:db8::5]:50000".parse().unwrap());
    assert_eq!(id_of(&payload), 0x4321);
    assert_eq!(rcode(&payload), 0);
    assert_eq!(answers(&payload).1.len(), 1);
}

#[tokio::test]
async fn udp_unavailable_answers_tc_ipv4_refused_ipv6() {
    let r = resolver(Mode::Answer).await;
    // HTTP profile: no UDP at all.
    let http = mock(MockOpts::default()).await;
    // SOCKS5 proxy that refuses UDP ASSOCIATE.
    let refusing = mock(MockOpts {
        rep: 7,
        ..Default::default()
    })
    .await;
    for (kind, port) in [
        (ProxyKind::Http, http.port),
        (ProxyKind::Socks5, refusing.port),
    ] {
        let mut s = setup(dns_config(kind, port, r.addr), DnsProxyConfig::default());
        s.dns.submit(q4(7, "example.com"));
        let (src, dst, p) = parse_inbound(&recv(&mut s.injected).await);
        assert_eq!(
            (src, dst),
            (
                "192.168.1.1:53".parse().unwrap(),
                "10.0.0.5:50000".parse().unwrap()
            )
        );
        assert_eq!(id_of(&p), 7);
        assert!(tc(&p), "{kind:?}: IPv4 gets TC");
        assert_eq!(rcode(&p), 0);
        s.dns.submit(q6(8, "example.com"));
        let (_, _, p) = parse_inbound6(&recv(&mut s.injected).await);
        assert_eq!(id_of(&p), 8);
        assert!(!tc(&p));
        assert_eq!(rcode(&p), 5, "{kind:?}: IPv6 gets REFUSED");
    }
    assert_eq!(
        http.attempts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "never associates through an HTTP proxy"
    );
    assert_eq!(
        refusing.attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "second query is answered from the backoff"
    );
}

#[tokio::test]
async fn unknown_or_late_reply_dropped() {
    let m = mock(MockOpts::default()).await;
    let mut r = resolver(Mode::WrongIdThenLate(Duration::from_millis(400))).await;
    let mut s = setup(
        dns_config(ProxyKind::Socks5, m.port, r.addr),
        DnsProxyConfig {
            timeout: Duration::from_millis(150),
            ..Default::default()
        },
    );
    s.dns.submit(q4(0x0101, "example.com"));
    recv(&mut r.seen).await;
    recv(&mut r.late).await;
    quiet(&mut s.injected).await;
    assert!(s
        .ctx
        .domains
        .names(IpAddr::V4(NINE), std::time::Instant::now())
        .is_empty());
}

#[tokio::test]
async fn inflight_cap_refuses() {
    let m = mock(MockOpts::default()).await;
    let mut r = resolver(Mode::Silent).await;
    let mut s = setup(
        dns_config(ProxyKind::Socks5, m.port, r.addr),
        DnsProxyConfig {
            max_inflight: 2,
            ..Default::default()
        },
    );
    for id in 1..=3 {
        s.dns.submit(q4(id, "example.com"));
    }
    let (_, _, p) = parse_inbound(&recv(&mut s.injected).await);
    assert_eq!(id_of(&p), 3);
    assert_eq!(rcode(&p), 5, "REFUSED");
    recv(&mut r.seen).await;
    recv(&mut r.seen).await;
    quiet(&mut s.injected).await;
}

#[tokio::test]
async fn wait_returns_after_cancel() {
    let m = mock(MockOpts::default()).await;
    let r = resolver(Mode::Silent).await;
    let s = setup(
        dns_config(ProxyKind::Socks5, m.port, r.addr),
        DnsProxyConfig::default(),
    );
    s.dns.submit(q4(1, "example.com"));
    let dns = s.dns.clone();
    drop(s);
    tokio::time::timeout(WAIT, dns.wait())
        .await
        .expect("dns proxy tasks ended");
}
