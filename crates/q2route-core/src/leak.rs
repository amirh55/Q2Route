//! Leak check: tiny HTTP/1.1 client, response parsers and the verdict logic.
//!
//! Pure logic only; the UI process performs the actual probes.

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
        if size > MAX_RESPONSE {
            return Err(LeakError::Http("chunk too large".into()));
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
            Err(LeakError::Io("connection closed before the headers".into()))
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
                content_length = Some(
                    v.parse::<usize>()
                        .map_err(|_| LeakError::Http("bad content-length".into()))?,
                );
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let body = &buf[h_end + 4..];
    let bytes = if chunked {
        match dechunk(body)? {
            Some(b) => b,
            None if eof => return Err(LeakError::Io("truncated chunked body".into())),
            None => return Ok(Parsed::NeedMore),
        }
    } else if let Some(n) = content_length {
        if body.len() >= n {
            body[..n].to_vec()
        } else if eof {
            return Err(LeakError::Io("truncated body".into()));
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
    Proxy {
        group: String,
    },
    Block {
        group: String,
    },
    /// `group` is `None` for an always-direct app or a connection that
    /// matched no group.
    Direct {
        group: Option<String>,
    },
    Unknown,
}

impl ProbeRoute {
    fn group(&self) -> Option<&str> {
        match self {
            Self::Proxy { group } | Self::Block { group } => Some(group),
            Self::Direct { group } => group.as_deref(),
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
    /// Not reached, or no full answer (connect, timeout, I/O).
    Failed(String),
    /// Reached, but the service answered with an error (e.g. HTTP 429).
    Refused(String),
    NoIpv6,
}

impl ProbeOutcome {
    /// `Failed` for connect/timeout/I-O errors, `Refused` for HTTP/parse errors.
    pub fn from_error(e: &LeakError) -> ProbeOutcome {
        match e {
            LeakError::Http(m) | LeakError::Parse(m) => ProbeOutcome::Refused(m.clone()),
            LeakError::Io(_) | LeakError::Timeout => ProbeOutcome::Failed(e.to_string()),
        }
    }
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
    /// `Got` is the resolver's geolocation. Its route is the route of the
    /// geolocation connection, used only for the honesty rules (the DNS query
    /// itself is routed by name).
    pub dns: Probe,
    /// The resolver's EDNS client subnet (network address) and its
    /// geolocation, when the TXT answer carried one.
    pub dns_subnet: Option<(IpAddr, Probe)>,
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

fn outcome_text(o: &ProbeOutcome) -> String {
    match o {
        ProbeOutcome::Got(i) => describe(i),
        ProbeOutcome::Failed(e) => format!("failed ({e})"),
        ProbeOutcome::Refused(e) => format!("service error: {e}"),
        ProbeOutcome::NoIpv6 => "none (nothing to leak)".to_string(),
    }
}

/// IPv4/IPv6 line. A Direct-routed address is the real one, so it is never shown.
fn addr_line(label: &str, p: &Probe) -> String {
    let body = match (&p.route, &p.outcome) {
        (ProbeRoute::Direct { .. }, ProbeOutcome::Got(_)) => {
            "address not shown (routed Direct)".to_string()
        }
        (_, o) => outcome_text(o),
    };
    match p.route.group() {
        Some(g) => format!("{label}: {body} \u{2014} via {g}"),
        None => format!("{label}: {body}"),
    }
}

/// No route suffix: the DNS query is routed by name, not by this process's route.
fn dns_line(dns: &Probe, subnet: Option<&(IpAddr, Probe)>) -> String {
    let mut s = match &dns.outcome {
        ProbeOutcome::Got(i) => format!("DNS: resolver {}", describe(i)),
        o => format!("DNS: {}", outcome_text(o)),
    };
    if let Some((net, p)) = subnet {
        match &p.outcome {
            ProbeOutcome::Got(i) => s.push_str(&format!("; client subnet {net} ({})", i.country)),
            o => s.push_str(&format!("; client subnet {net}: {}", outcome_text(o))),
        }
    }
    s
}

fn is_home(p: &Probe) -> bool {
    matches!(&p.outcome, ProbeOutcome::Got(i) if i.country_code.eq_ignore_ascii_case(HOME_COUNTRY))
}

const UNCONFIRMED: &str = "Can't tell: couldn't confirm how this check was routed";
const NOT_THROUGH: &str = "No leak, but proxied traffic isn't getting through";

fn direct_headline(r: &ProbeRoute) -> String {
    match r.group() {
        Some(g) => format!("Can't tell: this check was routed Direct by \"{g}\""),
        None => "Can't tell: this check was routed Direct (always-direct app or no group)".into(),
    }
}

pub fn verdict(i: &LeakInputs) -> Verdict {
    if !i.running {
        return Verdict {
            level: Level::CantTell,
            headline: "Can't tell: Q2Route is stopped (everything goes direct)".into(),
            lines: Vec::new(),
        };
    }
    // IPv4 routed Direct: the other probes say nothing about proxied apps,
    // and no line may show the real address.
    if i.ipv4.route.is_direct() {
        return Verdict {
            level: Level::CantTell,
            headline: direct_headline(&i.ipv4.route),
            lines: vec![addr_line("IPv4", &i.ipv4)],
        };
    }
    let lines = vec![
        addr_line("IPv4", &i.ipv4),
        dns_line(&i.dns, i.dns_subnet.as_ref()),
        addr_line("IPv6", &i.ipv6),
    ];
    let mk = |level, headline: String| Verdict {
        level,
        headline,
        lines: lines.clone(),
    };

    let mut probes = vec![("IPv4", &i.ipv4), ("DNS", &i.dns)];
    probes.extend(i.dns_subnet.as_ref().map(|(_, p)| ("DNS", p)));
    probes.push(("IPv6", &i.ipv6));

    let mut leaks: Vec<&str> = Vec::new();
    for (n, p) in &probes {
        if is_home(p) && !p.route.is_direct() && !leaks.contains(n) {
            leaks.push(n);
        }
    }
    if !leaks.is_empty() {
        return mk(
            Level::Leak,
            format!("LEAK: {} appear from Iran", leaks.join(", ")),
        );
    }
    if let Some((_, p)) = probes
        .iter()
        .find(|(_, p)| p.route.is_direct() && p.outcome != ProbeOutcome::NoIpv6)
    {
        return mk(Level::CantTell, direct_headline(&p.route));
    }
    // In probe order (IPv4 first): an unconfirmed route or a service error
    // means we can't tell; a proxied IPv4 failure means traffic isn't getting through.
    for (n, p) in &probes {
        match &p.outcome {
            ProbeOutcome::Failed(_) | ProbeOutcome::Refused(_)
                if p.route == ProbeRoute::Unknown =>
            {
                return mk(Level::CantTell, UNCONFIRMED.into());
            }
            ProbeOutcome::Refused(e) => {
                return mk(
                    Level::CantTell,
                    format!("Can't tell: the IP service answered with an error ({e})"),
                );
            }
            ProbeOutcome::Failed(_) if *n == "IPv4" => {
                return mk(Level::NoLeak, NOT_THROUGH.into());
            }
            _ => {}
        }
    }
    if let ProbeOutcome::Got(info) = &i.ipv4.outcome {
        return mk(
            Level::NoLeak,
            format!("No leak: proxied apps appear as {}", describe(info)),
        );
    }
    if probes
        .iter()
        .any(|(_, p)| matches!(p.outcome, ProbeOutcome::Failed(_)))
    {
        return mk(Level::NoLeak, NOT_THROUGH.into());
    }
    mk(
        Level::CantTell,
        "Can't tell: no probe produced an address".into(),
    )
}
