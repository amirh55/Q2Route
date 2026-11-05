use q2route_core::proxy::{connect_via, test_proxy, ProxyError, Target};
use q2route_core::{ProxyKind, ProxyProfile};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
async fn test_proxy_closed_port() {
    let (l, port) = listen().await;
    drop(l);
    let r = test_proxy(&profile(ProxyKind::Socks5, port, None)).await;
    assert!(!r.tcp_ok);
    assert!(r.error.is_some());
    assert!(r.latency_ms.is_none());
}
