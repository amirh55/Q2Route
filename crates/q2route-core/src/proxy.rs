//! Proxy types and clients (SOCKS5 incl. user/pass, SOCKS4a, HTTP CONNECT).
//!
//! Proxied connections never fall back to direct, and a `Target::Domain` is
//! always sent to the proxy as a name (never resolved locally: no DNS leak).

use crate::config::{ProxyKind, ProxyProfile};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Result of a proxy connectivity test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProxyTestResult {
    pub tcp_ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

/// Where the proxy should connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("proxy unreachable")]
    Unreachable,
    #[error("proxy authentication failed")]
    Auth,
    #[error("proxy refused the connection")]
    Refused,
    #[error("proxy handshake timed out")]
    Timeout,
    #[error("proxy protocol error: {0}")]
    Protocol(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Connect to the proxy and tunnel to `t`. The whole operation is bounded by
/// `timeout`. A TCP connect failure to the proxy itself is `Unreachable`.
pub async fn connect_via(
    p: &ProxyProfile,
    t: &Target,
    timeout: Duration,
) -> Result<TcpStream, ProxyError> {
    if p.kind == ProxyKind::Socks4 && matches!(t, Target::Ip(SocketAddr::V6(_))) {
        return Err(ProxyError::Protocol("SOCKS4 cannot reach IPv6".into()));
    }
    tokio::time::timeout(timeout, async {
        let mut s = TcpStream::connect((p.host.as_str(), p.port))
            .await
            .map_err(|_| ProxyError::Unreachable)?;
        match p.kind {
            ProxyKind::Socks5 => socks5(&mut s, p, t).await?,
            ProxyKind::Socks4 => socks4(&mut s, t).await?,
            ProxyKind::Http => http(&mut s, p, t).await?,
        }
        Ok(s)
    })
    .await
    .map_err(|_| ProxyError::Timeout)?
}

async fn socks5(s: &mut TcpStream, p: &ProxyProfile, t: &Target) -> Result<(), ProxyError> {
    let creds = p
        .username
        .as_ref()
        .map(|u| (u.as_bytes(), p.password.as_deref().unwrap_or("").as_bytes()));
    if let Some((u, pw)) = creds {
        if u.len() > 255 || pw.len() > 255 {
            return Err(ProxyError::Protocol("credentials too long".into()));
        }
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await?;
    if m[0] != 5 {
        return Err(ProxyError::Protocol("bad SOCKS5 version".into()));
    }
    match (m[1], creds) {
        (0, _) => {}
        (2, Some((u, pw))) => {
            let mut a = vec![1, u.len() as u8];
            a.extend_from_slice(u);
            a.push(pw.len() as u8);
            a.extend_from_slice(pw);
            s.write_all(&a).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(ProxyError::Auth);
            }
        }
        (0xFF, _) => return Err(ProxyError::Auth),
        (x, _) => return Err(ProxyError::Protocol(format!("unexpected auth method {x}"))),
    }

    let mut req = vec![5, 1, 0];
    match t {
        Target::Ip(SocketAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(d, port) => {
            if d.is_empty() || d.len() > 255 {
                return Err(ProxyError::Protocol("invalid domain length".into()));
            }
            req.push(3);
            req.push(d.len() as u8);
            req.extend_from_slice(d.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    s.write_all(&req).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(ProxyError::Protocol("bad SOCKS5 reply".into()));
    }
    if r[1] != 0 {
        return Err(ProxyError::Refused);
    }
    let addr_len = match r[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            n[0] as usize
        }
        _ => return Err(ProxyError::Protocol("bad reply ATYP".into())),
    };
    let mut sink = vec![0u8; addr_len + 2];
    s.read_exact(&mut sink).await?;
    Ok(())
}

async fn socks4(s: &mut TcpStream, t: &Target) -> Result<(), ProxyError> {
    let mut req = vec![4, 1];
    let mut name: Option<&str> = None;
    match t {
        Target::Ip(SocketAddr::V4(a)) => {
            req.extend_from_slice(&a.port().to_be_bytes());
            req.extend_from_slice(&a.ip().octets());
        }
        Target::Ip(SocketAddr::V6(_)) => {
            return Err(ProxyError::Protocol("SOCKS4 cannot reach IPv6".into()))
        }
        Target::Domain(d, port) => {
            if d.is_empty() || d.len() > 255 || d.contains('\0') {
                return Err(ProxyError::Protocol("invalid domain".into()));
            }
            req.extend_from_slice(&port.to_be_bytes());
            req.extend_from_slice(&[0, 0, 0, 1]);
            name = Some(d);
        }
    }
    req.push(0); // empty user id
    if let Some(d) = name {
        req.extend_from_slice(d.as_bytes());
        req.push(0);
    }
    s.write_all(&req).await?;
    let mut r = [0u8; 8];
    s.read_exact(&mut r).await?;
    match r[1] {
        90 => Ok(()),
        91 => Err(ProxyError::Refused),
        92 | 93 => Err(ProxyError::Auth),
        x => Err(ProxyError::Protocol(format!("bad SOCKS4 reply {x}"))),
    }
}

async fn http(s: &mut TcpStream, p: &ProxyProfile, t: &Target) -> Result<(), ProxyError> {
    let hp = match t {
        Target::Ip(a) => a.to_string(), // IPv6 is bracketed already
        Target::Domain(d, port) => {
            if d.is_empty() || d.bytes().any(|b| b <= b' ') {
                return Err(ProxyError::Protocol("invalid domain".into()));
            }
            format!("{d}:{port}")
        }
    };
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n");
    if let Some(u) = &p.username {
        let cred = format!("{u}:{}", p.password.as_deref().unwrap_or(""));
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // Read byte-wise so no tunnel data after the header is consumed.
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(ProxyError::Protocol("response header too large".into()));
        }
        s.read_exact(&mut b).await?;
        head.push(b[0]);
    }
    let line = head.split(|&c| c == b'\r').next().unwrap_or(&[]);
    let line = String::from_utf8_lossy(line);
    let mut it = line.split_whitespace();
    let ok_ver = it.next().is_some_and(|v| v.starts_with("HTTP/1."));
    let code: u16 = it.next().and_then(|c| c.parse().ok()).unwrap_or(0);
    if !ok_ver || code == 0 {
        return Err(ProxyError::Protocol(format!("bad status line: {line}")));
    }
    match code {
        200..=299 => Ok(()),
        407 => Err(ProxyError::Auth),
        _ => Err(ProxyError::Refused),
    }
}

fn base64(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

/// CONNECT to 1.1.1.1:443 through the profile and time it (5 s limit).
pub async fn test_proxy(p: &ProxyProfile) -> ProxyTestResult {
    let t = Target::Ip(SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 443));
    let start = Instant::now();
    match connect_via(p, &t, Duration::from_secs(5)).await {
        Ok(_) => ProxyTestResult {
            tcp_ok: true,
            latency_ms: Some(start.elapsed().as_millis().min(u32::MAX as u128) as u32),
            error: None,
        },
        Err(e) => ProxyTestResult {
            tcp_ok: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}
