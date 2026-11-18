//! Domain / IP / port / app matchers compiled from config rule strings.

use crate::geoip::{GeoIp, IpSet};
use crate::geosite::{DomainSet, GeoSite};
use globset::GlobBuilder;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("invalid domain pattern '{0}'")]
    Domain(String),
    #[error("invalid ip/cidr '{0}'")]
    Ip(String),
    #[error("invalid port range '{0}'")]
    Port(String),
    #[error("invalid app pattern '{0}'")]
    App(String),
    #[error("group '{group}': {source}")]
    Group {
        group: String,
        source: Box<MatchError>,
    },
}

fn norm_host(h: &str) -> String {
    h.trim_end_matches('.').to_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    Exact(String),
    /// `*.ir` stores `ir`.
    Suffix(String),
    Keyword(String),
    /// `geosite:<code>[@attr]`. `set` is `None` when no geosite data has that
    /// key: it then matches nothing (traffic falls through to later groups).
    Geo {
        key: String,
        set: Option<std::sync::Arc<DomainSet>>,
    },
}

impl DomainPattern {
    /// Parse without geosite data (`geosite:` entries match nothing).
    pub fn parse(s: &str) -> Result<Self, MatchError> {
        Self::parse_with(s, &GeoSite::default())
    }

    pub fn parse_with(s: &str, sites: &GeoSite) -> Result<Self, MatchError> {
        let bad = || MatchError::Domain(s.to_string());
        let t = s.trim();
        if let Some(key) = geosite_key(t) {
            let key = key.ok_or_else(bad)?;
            let set = sites.get(&key);
            return Ok(Self::Geo { key, set });
        }
        if let Some(k) = t.strip_prefix("keyword:") {
            let k = k.trim().to_lowercase();
            return if k.is_empty() {
                Err(bad())
            } else {
                Ok(Self::Keyword(k))
            };
        }
        if let Some(rest) = t.strip_prefix("*.") {
            let r = norm_host(rest);
            return if r.is_empty() {
                Err(bad())
            } else {
                Ok(Self::Suffix(r))
            };
        }
        let h = norm_host(t);
        if h.is_empty() || h.contains('*') {
            return Err(bad());
        }
        Ok(Self::Exact(h))
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = norm_host(host);
        match self {
            Self::Exact(e) => h == *e,
            Self::Suffix(sfx) => {
                h == *sfx
                    || (h.len() > sfx.len()
                        && h.ends_with(sfx.as_str())
                        && h.as_bytes()[h.len() - sfx.len() - 1] == b'.')
            }
            Self::Keyword(k) => h.contains(k.as_str()),
            Self::Geo { set, .. } => set.as_ref().is_some_and(|s| s.contains(&h)),
        }
    }
}

/// `None` if `t` is not a `geosite:` entry; `Some(None)` if it is but the code
/// or attribute is empty; else the lowercase key (`code` or `code@attr`).
fn geosite_key(t: &str) -> Option<Option<String>> {
    let rest = t.strip_prefix("geosite:")?;
    let rest = rest.trim().to_lowercase();
    let (code, attr) = match rest.split_once('@') {
        Some((c, a)) => (c.trim(), Some(a.trim())),
        None => (rest.as_str(), None),
    };
    if code.is_empty() || attr == Some("") {
        return Some(None);
    }
    Some(Some(match attr {
        Some(a) => format!("{code}@{a}"),
        None => code.to_string(),
    }))
}

/// Keys referenced as `geosite:<code>[@attr]` in `domains` entries, lowercase,
/// sorted and deduplicated.
pub fn geosite_codes<'a>(domains: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut v: Vec<String> = domains
        .into_iter()
        .filter_map(|s| geosite_key(s.trim()).flatten())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMatcher {
    Net(ipnet::IpNet),
    /// `geoip:<code>`. `set` is `None` when no geoip data has that code: it
    /// then matches nothing, so such traffic falls through to later groups
    /// (normally the proxy) instead of being sent direct by mistake.
    Geo {
        code: String,
        set: Option<std::sync::Arc<IpSet>>,
    },
}

impl IpMatcher {
    /// Parse without geoip data (`geoip:` entries match nothing).
    pub fn parse(s: &str) -> Result<Self, MatchError> {
        Self::parse_with(s, &GeoIp::default())
    }

    pub fn parse_with(s: &str, geo: &GeoIp) -> Result<Self, MatchError> {
        let t = s.trim();
        if let Some(code) = t.strip_prefix("geoip:") {
            let code = code.trim().to_lowercase();
            if code.is_empty() {
                return Err(MatchError::Ip(s.to_string()));
            }
            let set = geo.get(&code);
            return Ok(Self::Geo { code, set });
        }
        if let Ok(n) = t.parse::<ipnet::IpNet>() {
            return Ok(Self::Net(n));
        }
        t.parse::<IpAddr>()
            .map(|a| Self::Net(ipnet::IpNet::from(a)))
            .map_err(|_| MatchError::Ip(s.to_string()))
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Net(n) => n.contains(&ip),
            Self::Geo { set, .. } => set.as_ref().is_some_and(|s| s.contains(ip)),
        }
    }
}

/// Country codes referenced as `geoip:<code>` in `ips` entries, lowercase.
pub fn geoip_codes<'a>(ips: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut v: Vec<String> = ips
        .into_iter()
        .filter_map(|s| s.trim().strip_prefix("geoip:"))
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> Result<Self, MatchError> {
        let bad = || MatchError::Port(s.to_string());
        let t = s.trim();
        let (lo, hi) = match t.split_once('-') {
            Some((a, b)) => (
                a.trim().parse().map_err(|_| bad())?,
                b.trim().parse().map_err(|_| bad())?,
            ),
            None => {
                let p = t.parse().map_err(|_| bad())?;
                (p, p)
            }
        };
        if lo > hi {
            return Err(bad());
        }
        Ok(Self { lo, hi })
    }

    pub fn matches(&self, p: u16) -> bool {
        (self.lo..=self.hi).contains(&p)
    }
}

#[derive(Debug, Clone)]
pub enum AppMatcher {
    /// Case-insensitive glob against the file name only.
    Name(globset::GlobMatcher),
    /// Exact exe path (case-insensitive).
    Path(PathBuf),
    /// Any exe below this folder (case-insensitive).
    Folder(PathBuf),
}

/// Lowercase, `/` -> `\`, for separator- and case-insensitive comparison.
fn norm_path(p: &Path) -> String {
    p.to_string_lossy().to_lowercase().replace('/', "\\")
}

impl AppMatcher {
    pub fn parse(s: &str) -> Result<Self, MatchError> {
        let t = s.trim();
        if t.is_empty() {
            return Err(MatchError::App(s.to_string()));
        }
        if t.ends_with('\\') || t.ends_with('/') {
            return Ok(Self::Folder(PathBuf::from(t)));
        }
        if t.contains('\\') || t.contains('/') {
            return Ok(Self::Path(PathBuf::from(t)));
        }
        let g = GlobBuilder::new(t)
            .case_insensitive(true)
            .build()
            .map_err(|_| MatchError::App(s.to_string()))?;
        Ok(Self::Name(g.compile_matcher()))
    }

    pub fn matches(&self, exe_path: &Path) -> bool {
        match self {
            Self::Name(g) => {
                let n = norm_path(exe_path);
                let file = n.rsplit('\\').next().unwrap_or("");
                g.is_match(file)
            }
            Self::Path(p) => norm_path(p) == norm_path(exe_path),
            Self::Folder(f) => {
                let mut prefix = norm_path(f);
                if !prefix.ends_with('\\') {
                    prefix.push('\\');
                }
                norm_path(exe_path).starts_with(&prefix)
            }
        }
    }
}

/// Destinations that always go Direct: loopback, private/LAN, link-local, multicast, broadcast.
pub fn is_always_direct_dst(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            a.is_loopback() || (first & 0xffc0) == 0xfe80 || (first & 0xff00) == 0xff00
        }
    }
}
