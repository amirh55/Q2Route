use q2route_core::proxy::{
    connect_via, decode_udp, encode_udp, test_proxy, udp_associate, ProxyError, Target,
};
use q2route_core::{ProxyKind, ProxyProfile};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const T: Duration = Duration::from_secs(3);

fn profile(kind: ProxyKind, port: u16, auth: Option<(&str, &str)>) -> ProxyProfile {
    ProxyProfile {
        id: "p".into(),
        name: "p".into(),
        kind,
        host: "127.0.0.1".into(),
        port,
        username: auth.map(|a| a.0.to_string()),
        password: auth.map(|a| a.1.to_string()),
    }
}

async fn echo(mut s: TcpStream) {
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if s.write_all(&b[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn listen() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

/// Mock SOCKS5. `auth`: Some((u,p)) requires method 2. `rep`: reply code.
/// Returns the request tail (ATYP onwards).
async fn socks5_mock(
    l: TcpListener,
    auth: Option<(&'static str, &'static str)>,
    rep: u8,
) -> Vec<u8> {
    let (mut s, _) = l.accept().await.unwrap();
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h[0], 5);
    let mut m = vec![0u8; h[1] as usize];
    s.read_exact(&mut m).await.unwrap();
    if let Some((u, p)) = auth {
        assert!(m.contains(&2));
        s.write_all(&[5, 2]).await.unwrap();
        let mut v = [0u8; 2];
        s.read_exact(&mut v).await.unwrap();
        assert_eq!(v[0], 1);
        let mut user = vec![0u8; v[1] as usize];
        s.read_exact(&mut user).await.unwrap();
        let mut pl = [0u8; 1];
        s.read_exact(&mut pl).await.unwrap();
        let mut pass = vec![0u8; pl[0] as usize];
        s.read_exact(&mut pass).await.unwrap();
        if user != u.as_bytes() || pass != p.as_bytes() {
            s.write_all(&[1, 1]).await.unwrap();
            return vec![];
        }
        s.write_all(&[1, 0]).await.unwrap();
    } else {
        assert!(m.contains(&0));
        s.write_all(&[5, 0]).await.unwrap();
    }
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(&r[..3], &[5, 1, 0]);
    let mut tail = vec![r[3]];
    match r[3] {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.unwrap();
            tail.extend_from_slice(&b);
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await.unwrap();
            tail.extend_from_slice(&b);
        }
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await.unwrap();
            let mut b = vec![0u8; n[0] as usize + 2];
            s.read_exact(&mut b).await.unwrap();
            tail.push(n[0]);
            tail.extend_from_slice(&b);
        }
        _ => panic!("bad atyp"),
    }
    s.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    if rep == 0 {
        echo(s).await;
    }
    tail
}

#[tokio::test]
async fn socks5_noauth_domain() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, None, 0));
    let mut s = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Domain("digikala.ir".into(), 443),
        T,
    )
    .await
    .unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    drop(s);
    let tail = srv.await.unwrap();
    let mut want = vec![3, 11];
    want.extend_from_slice(b"digikala.ir");
    want.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(tail, want);
}

#[tokio::test]
async fn socks5_ip_atyps() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, None, 0));
    let s = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Ip("1.2.3.4:80".parse().unwrap()),
        T,
    )
    .await
    .unwrap();
    drop(s);
    assert_eq!(srv.await.unwrap(), vec![1, 1, 2, 3, 4, 0, 80]);

    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, None, 0));
    let s = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Ip("[::1]:80".parse().unwrap()),
        T,
    )
    .await
    .unwrap();
    drop(s);
    let t = srv.await.unwrap();
    assert_eq!(t[0], 4);
    assert_eq!(t.len(), 19);
}

#[tokio::test]
async fn socks5_userpass() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, Some(("u", "p")), 0));
    let s = connect_via(
        &profile(ProxyKind::Socks5, port, Some(("u", "p"))),
        &Target::Domain("a.com".into(), 1),
        T,
    )
    .await;
    assert!(s.is_ok());
    drop(s);
    srv.await.unwrap();

    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, Some(("u", "p")), 0));
    let r = connect_via(
        &profile(ProxyKind::Socks5, port, Some(("u", "wrong"))),
        &Target::Domain("a.com".into(), 1),
        T,
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Auth)), "{:?}", r.err());
    srv.await.unwrap();
}

#[tokio::test]
async fn socks5_refused() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(socks5_mock(l, None, 5));
    let r = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Domain("a.com".into(), 1),
        T,
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Refused)), "{:?}", r.err());
    srv.await.unwrap();
}

#[tokio::test]
async fn http_connect_ok() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            buf.push(b[0]);
        }
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        echo(s).await;
        String::from_utf8(buf).unwrap()
    });
    let mut s = connect_via(
        &profile(ProxyKind::Http, port, Some(("u", "p"))),
        &Target::Domain("digikala.ir".into(), 443),
        T,
    )
    .await
    .unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    drop(s);
    let req = srv.await.unwrap();
    assert!(
        req.starts_with("CONNECT digikala.ir:443 HTTP/1.1\r\n"),
        "{req}"
    );
    assert!(req.contains("Proxy-Authorization: Basic dTpw\r\n"), "{req}");
}

#[tokio::test]
async fn http_connect_407_is_auth_and_403_refused() {
    for (code, want_auth) in [(407, true), (403, false)] {
        let (l, port) = listen().await;
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(format!("HTTP/1.1 {code} X\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        let r = connect_via(
            &profile(ProxyKind::Http, port, None),
            &Target::Ip("1.2.3.4:443".parse().unwrap()),
            T,
        )
        .await;
        if want_auth {
            assert!(matches!(r, Err(ProxyError::Auth)));
        } else {
            assert!(matches!(r, Err(ProxyError::Refused)));
        }
        srv.await.unwrap();
    }
}

#[tokio::test]
async fn socks4a_domain_and_ip() {
    for domain in [true, false] {
        let (l, port) = listen().await;
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut h = [0u8; 8];
            s.read_exact(&mut h).await.unwrap();
            let mut rest = Vec::new();
            let mut b = [0u8; 1];
            // userid NUL, then (SOCKS4a only) host NUL
            let nuls = if h[4..7] == [0, 0, 0] && h[7] != 0 {
                2
            } else {
                1
            };
            for _ in 0..nuls {
                loop {
                    s.read_exact(&mut b).await.unwrap();
                    rest.push(b[0]);
                    if b[0] == 0 {
                        break;
                    }
                }
            }
            s.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
            echo(s).await;
            (h, rest)
        });
        let t = if domain {
            Target::Domain("digikala.ir".into(), 443)
        } else {
            Target::Ip("1.2.3.4:80".parse().unwrap())
        };
        let mut s = connect_via(&profile(ProxyKind::Socks4, port, None), &t, T)
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        drop(s);
        let (h, rest) = srv.await.unwrap();
        assert_eq!(h[0], 4);
        assert_eq!(h[1], 1);
        if domain {
            assert_eq!(&h[2..4], &443u16.to_be_bytes());
            assert_eq!(&h[4..8], &[0, 0, 0, 1]);
            assert_eq!(rest, b"\0digikala.ir\0");
        } else {
            assert_eq!(&h[4..8], &[1, 2, 3, 4]);
        }
    }
}

#[tokio::test]
async fn socks4_rejects_ipv6_and_failure_code() {
    let r = connect_via(
        &profile(ProxyKind::Socks4, 1, None),
        &Target::Ip("[::1]:80".parse().unwrap()),
        T,
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Protocol(_))), "{:?}", r.err());

    let (l, port) = listen().await;
    let srv = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 64];
        let _ = s.read(&mut b).await.unwrap();
        s.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await.unwrap();
    });
    let r = connect_via(
        &profile(ProxyKind::Socks4, port, None),
        &Target::Ip("1.2.3.4:80".parse().unwrap()),
        T,
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Refused)));
    srv.await.unwrap();
}

#[tokio::test]
async fn proxy_down() {
    let (l, port) = listen().await;
    drop(l);
    let r = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Domain("a.com".into(), 1),
        T,
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Unreachable)), "{:?}", r.err());
}

#[tokio::test]
async fn handshake_stall_times_out() {
    let (l, port) = listen().await;
    let _srv = tokio::spawn(async move {
        let (_s, _) = l.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let r = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Domain("a.com".into(), 1),
        Duration::from_millis(200),
    )
    .await;
    assert!(matches!(r, Err(ProxyError::Timeout)), "{:?}", r.err());
}

#[tokio::test]
async fn stall_after_greeting_is_target_timeout_not_down() {
    // The proxy answers the greeting, then never answers CONNECT (e.g. it is
    // slow reaching the target): the proxy itself is up.
    let (l, port) = listen().await;
    let _srv = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[5, 0]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let r = connect_via(
        &profile(ProxyKind::Socks5, port, None),
        &Target::Domain("a.com".into(), 1),
        Duration::from_millis(300),
    )
    .await;
    let e = r.err().unwrap();
    assert!(matches!(e, ProxyError::TargetTimeout), "{e:?}");
    assert!(!e.is_proxy_down());
}

#[test]
fn proxy_down_classification() {
    assert!(ProxyError::Unreachable.is_proxy_down());
    assert!(ProxyError::Timeout.is_proxy_down());
    assert!(!ProxyError::Refused.is_proxy_down());
    assert!(!ProxyError::Auth.is_proxy_down());
    assert!(!ProxyError::Protocol("x".into()).is_proxy_down());
    assert!(!ProxyError::TargetTimeout.is_proxy_down());
}

#[tokio::test]
async fn test_proxy_closed_port() {
    let (l, port) = listen().await;
    drop(l);
    let r = test_proxy(&profile(ProxyKind::Socks5, port, None)).await;
    assert!(!r.tcp_ok);
    assert!(r.error.is_some());
    assert!(r.latency_ms.is_none());
}

#[test]
fn encode_decode_roundtrip() {
    let v4: std::net::SocketAddr = "1.2.3.4:27015".parse().unwrap();
    let e = encode_udp(v4, b"abc");
    assert_eq!(&e[..10], &[0, 0, 0, 1, 1, 2, 3, 4, 0x69, 0x87]);
    assert_eq!(decode_udp(&e), Some((v4, &b"abc"[..])));
    let v6: std::net::SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
    let e = encode_udp(v6, b"abc");
    assert_eq!(decode_udp(&e), Some((v6, &b"abc"[..])));
}

#[test]
fn decode_rejects_frag_domain_short() {
    let mut e = encode_udp("1.2.3.4:5".parse().unwrap(), b"x");
    assert!(decode_udp(&e).is_some());
    e[2] = 1;
    assert!(decode_udp(&e).is_none());
    e[2] = 0;
    e[3] = 3;
    assert!(decode_udp(&e).is_none());
    assert!(decode_udp(&[0, 0, 0, 1, 1]).is_none());
}

/// Mock SOCKS5 UDP ASSOCIATE on an accepted control connection: method 0,
/// then a reply with BND `bnd_ip:<udp port>`, then `serve` handles datagrams
/// while the control connection stays open.
async fn udp_mock_conn<F, Fut>(mut s: TcpStream, rep: u8, bnd_ip: [u8; 4], serve: F)
where
    F: FnOnce(UdpSocket) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut h = [0u8; 3];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h, [5, 1, 0]);
    s.write_all(&[5, 0]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = u.local_addr().unwrap().port();
    let mut reply = vec![5, rep, 0, 1];
    reply.extend_from_slice(&bnd_ip);
    reply.extend_from_slice(&port.to_be_bytes());
    s.write_all(&reply).await.unwrap();
    if rep == 0 {
        serve(u).await;
        // Keep the control connection open until the client closes it.
        let mut b = [0u8; 1];
        let _ = s.read(&mut b).await;
    }
}

async fn udp_mock<F, Fut>(l: TcpListener, rep: u8, bnd_ip: [u8; 4], serve: F)
where
    F: FnOnce(UdpSocket) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (s, _) = l.accept().await.unwrap();
    udp_mock_conn(s, rep, bnd_ip, serve).await;
}

/// Mock for `test_proxy`: first connection is the TCP CONNECT probe, the
/// second the UDP ASSOCIATE.
async fn test_proxy_mock<F, Fut>(l: TcpListener, rep: u8, serve: F)
where
    F: FnOnce(UdpSocket) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (mut s, _) = l.accept().await.unwrap();
    let mut b = [0u8; 3];
    s.read_exact(&mut b).await.unwrap();
    s.write_all(&[5, 0]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    udp_mock(l, rep, [127, 0, 0, 1], serve).await;
}

async fn echo_udp(u: UdpSocket) {
    let mut b = [0u8; 2048];
    let (n, from) = u.recv_from(&mut b).await.unwrap();
    u.send_to(&b[..n], from).await.unwrap();
}

#[tokio::test]
async fn udp_associate_against_mock() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(udp_mock(l, 0, [127, 0, 0, 1], echo_udp));
    let a = udp_associate(&profile(ProxyKind::Socks5, port, None), T)
        .await
        .unwrap();
    assert_eq!(a.relay.ip().to_string(), "127.0.0.1");
    let dst: std::net::SocketAddr = "1.1.1.1:53".parse().unwrap();
    let c = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    c.send_to(&encode_udp(dst, b"hi"), a.relay).await.unwrap();
    let mut b = [0u8; 2048];
    let (n, _) = tokio::time::timeout(T, c.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decode_udp(&b[..n]), Some((dst, &b"hi"[..])));
    drop(a);
    srv.await.unwrap();
}

#[tokio::test]
async fn udp_associate_bnd_unspecified_uses_proxy_host() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(udp_mock(l, 0, [0, 0, 0, 0], |_u| async {}));
    let a = udp_associate(&profile(ProxyKind::Socks5, port, None), T)
        .await
        .unwrap();
    assert_eq!(a.relay.ip().to_string(), "127.0.0.1");
    drop(a);
    srv.await.unwrap();
}

#[tokio::test]
async fn udp_associate_refused() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(udp_mock(l, 7, [0, 0, 0, 0], |_u| async {}));
    let r = udp_associate(&profile(ProxyKind::Socks5, port, None), T).await;
    assert!(matches!(r, Err(ProxyError::Refused)));
    srv.await.unwrap();
    // Non-SOCKS5: error without connecting (port 1 is never dialled).
    let r = udp_associate(&profile(ProxyKind::Http, 1, None), T).await;
    assert!(matches!(r, Err(ProxyError::Protocol(_))));
}

#[tokio::test]
async fn test_proxy_udp_ok_through_mock() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(test_proxy_mock(l, 0, |u| async move {
        let mut b = [0u8; 2048];
        let (n, from) = u.recv_from(&mut b).await.unwrap();
        let (dst, q) = decode_udp(&b[..n]).unwrap();
        assert_eq!(dst.to_string(), "1.1.1.1:53");
        let mut reply = q.to_vec();
        reply[2] |= 0x80; // QR
        u.send_to(&encode_udp(dst, &reply), from).await.unwrap();
    }));
    let r = test_proxy(&profile(ProxyKind::Socks5, port, None)).await;
    assert!(r.tcp_ok);
    assert_eq!(r.udp_ok, Some(true));
    srv.await.unwrap();
}

#[tokio::test]
async fn test_proxy_udp_refused_is_false() {
    let (l, port) = listen().await;
    let srv = tokio::spawn(test_proxy_mock(l, 7, |_u| async {}));
    let r = test_proxy(&profile(ProxyKind::Socks5, port, None)).await;
    assert!(r.tcp_ok);
    assert_eq!(r.udp_ok, Some(false));
    srv.await.unwrap();
}

#[tokio::test]
async fn test_proxy_http_has_no_udp_verdict() {
    // HTTP CONNECT proxy: tcp ok, UDP not applicable.
    let (l, port) = listen().await;
    let srv = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });
    let r = test_proxy(&profile(ProxyKind::Http, port, None)).await;
    assert!(r.tcp_ok);
    assert_eq!(r.udp_ok, None);
    srv.await.unwrap();
}
