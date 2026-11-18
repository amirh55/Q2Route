//! Leak check: tiny HTTP/1.1 client, response parsers and the verdict logic.
//!
//! Pure logic only; the service performs the actual probes.

use serde::Deserialize;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Country code that must never be seen for a proxied app.
pub const HOME_COUNTRY: &str = "IR";
pub const IP_API_HOST: &str = "ip-api.com";
const IP_API_FIELDS: &str = "fields=status,message,country,countryCode,isp,query";
pub const IPV6_HOST: &str = "api6.ipify.org";
pub const IPV6_PATH: &str = "/";
/// TXT name whose answer reveals the DNS resolver's egress IP (and ECS subnet).
pub const RESOLVER_TXT_NAME: &str = "o-o.myaddr.l.google.com";
/// Max response size (headers + body).
pub const MAX_RESPONSE: usize = 64 * 1024;

/// Path for ip-api.com: the caller's own IP when `None`, else the given IP.
pub fn ip_api_path(ip: Option<IpAddr>) -> String {
    match ip {
        None => format!("/json/?{IP_API_FIELDS}"),
        Some(ip) => format!("/json/{ip}?{IP_API_FIELDS}"),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeakError {
    #[error("io: {0}")]
    Io(String),
    #[error("http: {0}")]
    Http(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("timeout")]
    Timeout,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Decode a chunked body. `None` if incomplete.
fn dechunk(mut b: &[u8]) -> Result<Option<Vec<u8>>, LeakError> {
    let mut out = Vec::new();
    loop {
        let Some(p) = find(b, b"\r\n") else {
            return Ok(None);
        };
        let size_s = std::str::from_utf8(&b[..p])
            .map_err(|_| LeakError::Http("bad chunk size".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_s, 16)
            .map_err(|_| LeakError::Http("bad chunk size".into()))?;
        b = &b[p + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if b.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

/// Parsed state of the bytes received so far.
enum Parsed {
    NeedMore,
    Done(String),
}

fn parse_response(buf: &[u8], eof: bool) -> Result<Parsed, LeakError> {
    let Some(h_end) = find(buf, b"\r\n\r\n") else {
        return if eof {
            Err(LeakError::Http("truncated headers".into()))
        } else {
            Ok(Parsed::NeedMore)
        };
    };
    let head = String::from_utf8_lossy(&buf[..h_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(LeakError::Http(format!("status {status_line}")));
    }
    let mut content_length = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "content-length" {
                content_length = v.parse::<usize>().ok();
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let body = &buf[h_end + 4..];
    let bytes = if chunked {
        match dechunk(body)? {
            Some(b) => b,
            None if eof => return Err(LeakError::Http("truncated chunked body".into())),
            None => return Ok(Parsed::NeedMore),
        }
    } else if let Some(n) = content_length {
        if body.len() >= n {
            body[..n].to_vec()
        } else if eof {
            return Err(LeakError::Http("truncated body".into()));
        } else {
            return Ok(Parsed::NeedMore);
        }
    } else if eof {
        body.to_vec()
    } else {
        return Ok(Parsed::NeedMore);
    };
    Ok(Parsed::Done(String::from_utf8_lossy(&bytes).to_string()))
}

/// Minimal `GET` over an already-connected stream; returns the body text.
pub async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    host: &str,
    path: &str,
) -> Result<String, LeakError> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: q2route-leak-check\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| LeakError::Io(e.to_string()))?;
    s.flush().await.map_err(|e| LeakError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s
            .read(&mut chunk)
            .await
            .map_err(|e| LeakError::Io(e.to_string()))?;
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE {
            return Err(LeakError::Http("response too large".into()));
        }
        match parse_response(&buf, n == 0)? {
            Parsed::Done(b) => return Ok(b),
            Parsed::NeedMore => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct IpInfo {
    pub ip: IpAddr,
    pub country: String,
    pub country_code: String,
    pub isp: String,
}

#[derive(Deserialize)]
struct RawIpApi {
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "countryCode")]
    country_code: String,
    #[serde(default)]
    isp: String,
    query: Option<IpAddr>,
}

pub fn parse_ip_api(body: &str) -> Result<IpInfo, LeakError> {
    let r: RawIpApi = serde_json::from_str(body).map_err(|e| LeakError::Parse(e.to_string()))?;
    if r.status != "success" {
        return Err(LeakError::Parse(format!("ip-api: {}", r.message)));
    }
    let ip = r
        .query
        .ok_or_else(|| LeakError::Parse("ip-api: missing query".into()))?;
    Ok(IpInfo {
        ip,
        country: r.country,
        country_code: r.country_code,
        isp: r.isp,
    })
}

/// TXT strings from the resolver-identity name -> (resolver egress IP, ECS network address).
pub fn parse_resolver_txt(strings: &[String]) -> (Option<IpAddr>, Option<IpAddr>) {
    let (mut ip, mut ecs) = (None, None);
    for s in strings {
        let s = s.trim().trim_matches('"').trim();
        if let Some(rest) = s.strip_prefix("edns0-client-subnet") {
            let net = rest.trim().split('/').next().unwrap_or("");
            if ecs.is_none() {
                ecs = net.parse().ok();
            }
        } else if ip.is_none() {
            ip = s.parse().ok();
        }
    }
    (ip, ecs)
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeRoute {
    Proxy { group: String },
    Block { group: String },
    Direct { group: String },
    Unknown,
}

impl ProbeRoute {
    fn group(&self) -> Option<&str> {
        match self {
            Self::Proxy { group } | Self::Block { group } | Self::Direct { group } => Some(group),
            Self::Unknown => None,
        }
    }
    fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeOutcome {
    Got(IpInfo),
    Failed(String),
    NoIpv6,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Probe {
    pub outcome: ProbeOutcome,
    pub route: ProbeRoute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LeakInputs {
    pub running: bool,
    pub ipv4: Probe,
    /// `Got` is the resolver's geolocation.
    pub dns: Probe,
    pub ipv6: Probe,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Level {
    NoLeak,
    Leak,
    CantTell,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub level: Level,
    pub headline: String,
    pub lines: Vec<String>,
}

fn describe(i: &IpInfo) -> String {
    format!("{} ({}, {})", i.ip, i.country, i.isp)
}

fn line(label: &str, p: &Probe) -> String {
    let body = match &p.outcome {
        ProbeOutcome::Got(i) if label == "DNS" => format!("resolver {}", describe(i)),
        ProbeOutcome::Got(i) => describe(i),
        ProbeOutcome::Failed(e) => format!("failed ({e})"),
        ProbeOutcome::NoIpv6 => "none (nothing to leak)".to_string(),
    };
    match p.route.group() {
        Some(g) => format!("{label}: {body} \u{2014} via {g}"),
        None => format!("{label}: {body}"),
    }
}

fn is_home(p: &Probe) -> bool {
    matches!(&p.outcome, ProbeOutcome::Got(i) if i.country_code.eq_ignore_ascii_case(HOME_COUNTRY))
}

pub fn verdict(i: &LeakInputs) -> Verdict {
    let lines = vec![
        line("IPv4", &i.ipv4),
        line("DNS", &i.dns),
        line("IPv6", &i.ipv6),
    ];
    let mk = |level, headline: String| Verdict {
        level,
        headline,
        lines: lines.clone(),
    };
    if !i.running {
        return mk(
            Level::CantTell,
            "Can't tell: Q2Route is stopped (everything goes direct)".into(),
        );
    }
    let probes = [("IPv4", &i.ipv4), ("DNS", &i.dns), ("IPv6", &i.ipv6)];
    let leaks: Vec<&str> = probes
        .iter()
        .filter(|(_, p)| is_home(p) && !p.route.is_direct())
        .map(|(n, _)| *n)
        .collect();
    if !leaks.is_empty() {
        return mk(
            Level::Leak,
            format!("LEAK: {} show your Iranian IP", leaks.join(", ")),
        );
    }
    // IPv4 first, then whichever other probe was routed Direct.
    let direct = probes
        .iter()
        .map(|(_, p)| *p)
        .find(|p| p.route.is_direct() && p.outcome != ProbeOutcome::NoIpv6);
    if let Some(g) = direct.and_then(|p| p.route.group()) {
        return mk(
            Level::CantTell,
            format!("Can't tell: this check was routed Direct by \"{g}\""),
        );
    }
    if let ProbeOutcome::Failed(_) = i.ipv4.outcome {
        return mk(
            Level::NoLeak,
            "No leak, but proxied traffic isn't getting through".into(),
        );
    }
    if let ProbeOutcome::Got(info) = &i.ipv4.outcome {
        return mk(
            Level::NoLeak,
            format!("No leak: proxied apps appear as {}", describe(info)),
        );
    }
    // IPv4 gave nothing; judge by the other probes.
    if let Some(info) = probes.iter().find_map(|(_, p)| match &p.outcome {
        ProbeOutcome::Got(i) => Some(i),
        _ => None,
    }) {
        return mk(
            Level::NoLeak,
            format!("No leak: proxied apps appear as {}", describe(info)),
        );
    }
    if probes
        .iter()
        .any(|(_, p)| matches!(p.outcome, ProbeOutcome::Failed(_)))
    {
        return mk(
            Level::NoLeak,
            "No leak, but proxied traffic isn't getting through".into(),
        );
    }
    mk(
        Level::CantTell,
        "Can't tell: no probe produced an address".into(),
    )
}
