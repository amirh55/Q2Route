//! Proxy types and clients (SOCKS5 incl. user/pass, SOCKS4a, HTTP CONNECT).
//!
//! Proxied connections never fall back to direct, and a `Target::Domain` is
//! always sent to the proxy as a name (never resolved locally: no DNS leak).

use crate::config::{ProxyKind, ProxyProfile};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

/// Result of a proxy connectivity test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProxyTestResult {
    pub tcp_ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
    /// UDP ASSOCIATE check (SOCKS5 only, and only when `tcp_ok`); `None` = not tested.
    #[serde(default)]
    pub udp_ok: Option<bool>,
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
    /// Timed out before the proxy sent a single handshake byte.
    #[error("proxy handshake timed out")]
    Timeout,
    /// Timed out after the proxy had answered (e.g. it is slow reaching the
    /// target): the proxy itself is up.
    #[error("proxy did not finish connecting to the target in time")]
    TargetTimeout,
    #[error("proxy protocol error: {0}")]
    Protocol(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ProxyError {
    /// Whether this failure means the proxy itself is down (unreachable, or
    /// silent from the start), as opposed to it refusing this one target.
    pub fn is_proxy_down(&self) -> bool {
        matches!(self, ProxyError::Unreachable | ProxyError::Timeout)
    }
}

/// Records whether any byte was read through it.
struct Seen<'a> {
    s: &'a mut TcpStream,
    got: &'a AtomicBool,
}

impl AsyncRead for Seen<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.s).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.got.store(true, Ordering::Relaxed);
        }
        r
    }
}

impl AsyncWrite for Seen<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.s).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.s).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.s).poll_shutdown(cx)
    }
}

/// Connect to the proxy and tunnel to `t`. The whole operation is bounded by
/// `timeout`. A TCP connect failure to the proxy itself is `Unreachable`; a
/// timeout is `Timeout` if the proxy never sent a byte, else `TargetTimeout`.
pub async fn connect_via(
    p: &ProxyProfile,
    t: &Target,
    timeout: Duration,
) -> Result<TcpStream, ProxyError> {
    if p.kind == ProxyKind::Socks4 && matches!(t, Target::Ip(SocketAddr::V6(_))) {
        return Err(ProxyError::Protocol("SOCKS4 cannot reach IPv6".into()));
    }
    let got = AtomicBool::new(false);
    tokio::time::timeout(timeout, async {
        let mut s = TcpStream::connect((p.host.as_str(), p.port))
            .await
            .map_err(|_| ProxyError::Unreachable)?;
        let mut w = Seen {
            s: &mut s,
            got: &got,
        };
        match p.kind {
            ProxyKind::Socks5 => socks5(&mut w, p, t).await?,
            ProxyKind::Socks4 => socks4(&mut w, t).await?,
            ProxyKind::Http => http(&mut w, p, t).await?,
        }
        Ok(s)
    })
    .await
    .map_err(|_| timeout_error(&got))?
}

fn timeout_error(got: &AtomicBool) -> ProxyError {
    if got.load(Ordering::Relaxed) {
        ProxyError::TargetTimeout
    } else {
        ProxyError::Timeout
    }
}

/// A live SOCKS5 UDP association. Dropping `control` ends it (RFC 1928 section 7).
pub struct UdpAssociation {
    pub control: TcpStream,
    pub relay: SocketAddr,
}

/// Open a UDP association through a SOCKS5 profile (user/pass supported).
/// Bounded by `timeout`, with the same error mapping as [`connect_via`]. A
/// BND.ADDR of 0.0.0.0 / :: is replaced by the proxy's own host IP.
pub async fn udp_associate(
    p: &ProxyProfile,
    timeout: Duration,
) -> Result<UdpAssociation, ProxyError> {
    if p.kind != ProxyKind::Socks5 {
        return Err(ProxyError::Protocol("UDP needs a SOCKS5 proxy".into()));
    }
    let got = AtomicBool::new(false);
    tokio::time::timeout(timeout, async {
        let mut s = TcpStream::connect((p.host.as_str(), p.port))
            .await
            .map_err(|_| ProxyError::Unreachable)?;
        let peer = s.peer_addr()?;
        let mut w = Seen {
            s: &mut s,
            got: &got,
        };
        socks5_negotiate(&mut w, p).await?;
        // DST.ADDR/PORT 0.0.0.0:0: the client's UDP source is not known yet.
        w.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut relay = socks5_reply(&mut w).await?;
        if relay.ip().is_unspecified() {
            relay.set_ip(peer.ip());
        }
        Ok(UdpAssociation { control: s, relay })
    })
    .await
    .map_err(|_| timeout_error(&got))?
}

/// SOCKS5 UDP request header (RSV=0, FRAG=0, ATYP IPv4/IPv6) + payload.
pub fn encode_udp(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut o = vec![0, 0, 0];
    match dst {
        SocketAddr::V4(a) => {
            o.push(1);
            o.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            o.push(4);
            o.extend_from_slice(&a.ip().octets());
        }
    }
    o.extend_from_slice(&dst.port().to_be_bytes());
    o.extend_from_slice(payload);
    o
}

/// Parses a SOCKS5 UDP datagram; `None` if too short, FRAG != 0, or ATYP is a domain.
pub fn decode_udp(d: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if d.len() < 4 || d[2] != 0 {
        return None;
    }
    let (ip, rest): (IpAddr, &[u8]) = match d[3] {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(d.get(4..8)?).ok()?),
            &d[8..],
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(d.get(4..20)?).ok()?),
            &d[20..],
        ),
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
    Some((SocketAddr::new(ip, port), &rest[2..]))
}

/// SOCKS5 greeting plus optional user/pass sub-negotiation (shared by CONNECT
/// and UDP ASSOCIATE).
async fn socks5_negotiate(s: &mut Seen<'_>, p: &ProxyProfile) -> Result<(), ProxyError> {
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
    Ok(())
}

async fn socks5(s: &mut Seen<'_>, p: &ProxyProfile, t: &Target) -> Result<(), ProxyError> {
    socks5_negotiate(s, p).await?;
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
    socks5_reply(s).await?;
    Ok(())
}

/// Reads a SOCKS5 reply and returns BND.ADDR:PORT (a domain BND yields 0.0.0.0).
async fn socks5_reply(s: &mut Seen<'_>) -> Result<SocketAddr, ProxyError> {
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(ProxyError::Protocol("bad SOCKS5 reply".into()));
    }
    if r[1] != 0 {
        return Err(ProxyError::Refused);
    }
    let ip = match r[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            IpAddr::from(b)
        }
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            let mut sink = vec![0u8; n[0] as usize];
            s.read_exact(&mut sink).await?;
            IpAddr::from([0u8; 4])
        }
        _ => return Err(ProxyError::Protocol("bad reply ATYP".into())),
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn socks4(s: &mut Seen<'_>, t: &Target) -> Result<(), ProxyError> {
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

async fn http(s: &mut Seen<'_>, p: &ProxyProfile, t: &Target) -> Result<(), ProxyError> {
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

/// Minimal DNS A query for example.com (id 0x5132).
const DNS_QUERY: &[u8] =
    b"\x51\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

/// Open a UDP association and get any decodable reply to a DNS query for
/// example.com via 1.1.1.1:53 within 2 s.
async fn udp_check(p: &ProxyProfile) -> bool {
    let Ok(assoc) = udp_associate(p, Duration::from_secs(5)).await else {
        return false;
    };
    let bind = if assoc.relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(sock) = UdpSocket::bind(bind).await else {
        return false;
    };
    // Connected like the service's relay socket: only replies from the
    // relay address count, so "UDP OK" means the relay path works.
    if sock.connect(assoc.relay).await.is_err() {
        return false;
    }
    let dst = SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53);
    if sock.send(&encode_udp(dst, DNS_QUERY)).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 2048];
    let ok = matches!(
        tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await,
        Ok(Ok(n)) if decode_udp(&buf[..n]).is_some()
    );
    drop(assoc.control); // the association must live until here
    ok
}

/// CONNECT to 1.1.1.1:443 through the profile and time it (5 s limit); for a
/// working SOCKS5 profile, also check UDP ASSOCIATE with a DNS query.
pub async fn test_proxy(p: &ProxyProfile) -> ProxyTestResult {
    let t = Target::Ip(SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 443));
    let start = Instant::now();
    match connect_via(p, &t, Duration::from_secs(5)).await {
        Ok(_) => ProxyTestResult {
            tcp_ok: true,
            latency_ms: Some(start.elapsed().as_millis().min(u32::MAX as u128) as u32),
            error: None,
            udp_ok: if p.kind == ProxyKind::Socks5 {
                Some(udp_check(p).await)
            } else {
                None
            },
        },
        Err(e) => ProxyTestResult {
            tcp_ok: false,
            latency_ms: None,
            error: Some(e.to_string()),
            udp_ok: None,
        },
    }
}
