//! Config model: proxies, rule groups, settings, TOML persistence.

use crate::matchers::{AppMatcher, DomainPattern, IpMatcher, MatchError, PortRange};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub type ProfileId = String;
pub type GroupId = String;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Socks5,
    Socks4,
    Http,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProxyProfile {
    pub id: ProfileId,
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// TOML: `"direct"` | `"block"` | `{ proxy = "<id>" }`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    Block,
    Proxy(ProfileId),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Rule {
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default = "yes")]
    pub include_children: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            apps: vec![],
            domains: vec![],
            ips: vec![],
            ports: vec![],
            protocol: None,
            include_children: true,
        }
    }
}

impl Rule {
    /// A rule with no conditions matches nothing.
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
            && self.domains.is_empty()
            && self.ips.is_empty()
            && self.ports.is_empty()
            && self.protocol.is_none()
    }

    /// Non-empty, and every entry parses with its matcher.
    pub fn check(&self) -> Result<(), ConfigError> {
        let bad = |e: MatchError| ConfigError::Invalid(e.to_string());
        if self.is_empty() {
            return Err(ConfigError::Invalid("rule has no conditions".into()));
        }
        for a in &self.apps {
            AppMatcher::parse(a).map_err(bad)?;
        }
        for d in &self.domains {
            DomainPattern::parse(d).map_err(bad)?;
        }
        for i in &self.ips {
            IpMatcher::parse(i).map_err(bad)?;
        }
        for p in &self.ports {
            PortRange::parse(p).map_err(bad)?;
        }
        Ok(())
    }
}

/// Lowercase ASCII alphanumerics; other runs become a single `-`.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() { "group" } else { out }.to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub catch_all: bool,
}

fn default_resolver() -> String {
    "1.1.1.1:53".into()
}

/// DNS routing settings: DNS is routed by the queried name; names that
/// resolve through the proxy go to `proxy_resolver` over the proxy.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DnsSettings {
    #[serde(default = "default_resolver")]
    pub proxy_resolver: String,
    /// Block DoH (known hosts on TCP 443) and DoT/DoQ (port 853) for proxied flows.
    #[serde(default = "yes")]
    pub block_doh: bool,
    /// Names always resolved directly (rule-domain syntax: `example.com`,
    /// `*.example.com`, `keyword:x`), e.g. the VPN server the proxy
    /// client connects to when it is not detected automatically.
    #[serde(default)]
    pub direct_names: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        DnsSettings {
            proxy_resolver: default_resolver(),
            block_doh: true,
            direct_names: Vec::new(),
        }
    }
}

fn default_peek() -> u64 {
    300
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Settings {
    #[serde(default)]
    pub start_with_windows: bool,
    #[serde(default)]
    pub close_to_tray: bool,
    #[serde(default)]
    pub tray_traffic_icon: bool,
    #[serde(default = "default_peek")]
    pub peek_timeout_ms: u64,
    /// Whether routing was running when the service last stopped (restored on start).
    #[serde(default = "yes")]
    pub last_running: bool,
    #[serde(default)]
    pub dns: DnsSettings,
    /// Proxy IPv6 traffic of proxied apps. Off: their IPv6 is blocked (not
    /// proxied, never direct), so apps fall back to IPv4 (for a proxy whose
    /// server has no IPv6).
    #[serde(default = "yes")]
    pub proxy_ipv6: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            start_with_windows: false,
            close_to_tray: false,
            tray_traffic_icon: false,
            peek_timeout_ms: 300,
            last_running: true,
            dns: DnsSettings::default(),
            proxy_ipv6: true,
        }
    }
}

/// Bumped when the seed gains something existing configs should get too
/// (see [`Config::migrate`]). 1: `geoip:ir` in "Iranian sites".
/// 2: `geosite:ir` in "Iranian sites", `geosite:steam` in "Steam".
pub const SEED_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    /// Seed additions already applied to this config.
    #[serde(default)]
    pub seed_version: u32,
    #[serde(default)]
    pub proxies: Vec<ProxyProfile>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub always_direct: Vec<String>,
    pub default_proxy: ProfileId,
    #[serde(default)]
    pub settings: Settings,
}

impl Config {
    pub fn seed() -> Config {
        let group = |id: &str,
                     name: &str,
                     enabled: bool,
                     action: Action,
                     rules: Vec<Rule>,
                     catch_all: bool| Group {
            id: id.into(),
            name: name.into(),
            enabled,
            action,
            rules,
            catch_all,
        };
        Config {
            seed_version: SEED_VERSION,
            proxies: vec![ProxyProfile {
                id: "v2ray".into(),
                name: "V2Ray".into(),
                kind: ProxyKind::Socks5,
                host: "127.0.0.1".into(),
                port: 10808,
                username: None,
                password: None,
            }],
            groups: vec![
                group(
                    "iranian-sites",
                    "Iranian sites",
                    true,
                    Action::Direct,
                    vec![
                        Rule {
                            domains: vec!["*.ir".into(), "geosite:ir".into()],
                            ..Rule::default()
                        },
                        Rule {
                            ips: vec!["geoip:ir".into()],
                            ..Rule::default()
                        },
                    ],
                    false,
                ),
                group(
                    "steam",
                    "Steam",
                    false,
                    Action::Direct,
                    vec![
                        Rule {
                            apps: vec!["steam.exe".into()],
                            include_children: true,
                            ..Rule::default()
                        },
                        Rule {
                            domains: vec!["geosite:steam".into()],
                            ..Rule::default()
                        },
                    ],
                    false,
                ),
                group("games", "Games", true, Action::Direct, vec![], false),
                group(
                    "everything-else",
                    "Everything else",
                    true,
                    Action::Proxy("v2ray".into()),
                    vec![],
                    true,
                ),
            ],
            always_direct: [
                "v2ray.exe",
                "xray.exe",
                "sing-box.exe",
                "v2rayN.exe",
                "nekoray.exe",
                "hiddify.exe",
                "clash*.exe",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            default_proxy: "v2ray".into(),
            settings: Settings::default(),
        }
    }

    /// Load from `path`; a missing file yields (and saves) the seed config.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let mut c: Config = toml::from_str(&s)?;
                c.validate()?;
                if c.migrate() {
                    c.save(path)?;
                }
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let c = Config::seed();
                c.save(path)?;
                Ok(c)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Applies seed additions newer than `seed_version`. Returns whether
    /// anything changed. Groups the user deleted or renamed are left alone.
    pub fn migrate(&mut self) -> bool {
        if self.seed_version >= SEED_VERSION {
            return false;
        }
        if self.seed_version < 1 {
            if let Some(g) = self.groups.iter_mut().find(|g| g.id == "iranian-sites") {
                let has = g.rules.iter().any(|r| {
                    r.ips
                        .iter()
                        .any(|i| i.trim().eq_ignore_ascii_case("geoip:ir"))
                });
                if !has {
                    g.rules.push(Rule {
                        ips: vec!["geoip:ir".into()],
                        ..Rule::default()
                    });
                }
            }
        }
        if self.seed_version < 2 {
            let has = |g: &Group, code: &str| {
                g.rules.iter().any(|r| {
                    r.domains
                        .iter()
                        .any(|d| d.trim().eq_ignore_ascii_case(code))
                })
            };
            if let Some(g) = self.groups.iter_mut().find(|g| g.id == "iranian-sites") {
                if !has(g, "geosite:ir") {
                    let holder = g.rules.iter_mut().find(|r| {
                        r.domains
                            .iter()
                            .any(|d| d.trim().eq_ignore_ascii_case("*.ir"))
                    });
                    match holder {
                        Some(r) => r.domains.push("geosite:ir".into()),
                        None => g.rules.push(Rule {
                            domains: vec!["geosite:ir".into()],
                            ..Rule::default()
                        }),
                    }
                }
            }
            if let Some(g) = self.groups.iter_mut().find(|g| g.id == "steam") {
                if !has(g, "geosite:steam") {
                    g.rules.push(Rule {
                        domains: vec!["geosite:steam".into()],
                        ..Rule::default()
                    });
                }
            }
        }
        self.seed_version = SEED_VERSION;
        true
    }

    /// Atomic save: write a temp file next to `path`, then rename over it.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        std::fs::write(&tmp, text)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        let mut pids = HashSet::new();
        for p in &self.proxies {
            if !pids.insert(p.id.as_str()) {
                return bad(format!("duplicate proxy id '{}'", p.id));
            }
        }
        if !pids.contains(self.default_proxy.as_str()) {
            return bad(format!(
                "default_proxy '{}' is not a known proxy",
                self.default_proxy
            ));
        }
        let mut gids = HashSet::new();
        for (i, g) in self.groups.iter().enumerate() {
            if !gids.insert(g.id.as_str()) {
                return bad(format!("duplicate group id '{}'", g.id));
            }
            if let Action::Proxy(id) = &g.action {
                if !pids.contains(id.as_str()) {
                    return bad(format!("group '{}' uses unknown proxy '{}'", g.id, id));
                }
            }
            if g.catch_all && i + 1 != self.groups.len() {
                return bad(format!("catch-all group '{}' must be last", g.id));
            }
        }
        let dns = &self.settings.dns;
        if dns.proxy_resolver.parse::<std::net::SocketAddr>().is_err() {
            return bad(format!(
                "DNS proxy resolver '{}' is not an address:port",
                dns.proxy_resolver
            ));
        }
        if let Some(n) = dns
            .direct_names
            .iter()
            .find(|n| !matches!(DomainPattern::parse(n), Ok(p) if !matches!(p, DomainPattern::Geo { .. })))
        {
            return bad(format!("DNS direct name '{n}' is not a valid domain (geosite: lists are not supported here)"));
        }
        // Ruling R18: an enabled catch-all must always exist, so unmatched
        // traffic is never silently routed some other way.
        match self.groups.last() {
            Some(g) if g.catch_all && g.enabled => Ok(()),
            Some(g) if g.catch_all => bad(format!("catch-all group '{}' must be enabled", g.id)),
            _ => bad("a catch-all group (last) is required".into()),
        }
    }

    /// Apply `f` to a clone, validate, and commit only on success (rollback by construction).
    fn mutate(
        &mut self,
        f: impl FnOnce(&mut Config) -> Result<(), ConfigError>,
    ) -> Result<(), ConfigError> {
        let mut next = self.clone();
        f(&mut next)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn group_mut<'a>(&'a mut self, id: &str) -> Result<&'a mut Group, ConfigError> {
        self.groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or_else(|| ConfigError::Invalid(format!("unknown group '{id}'")))
    }

    pub fn set_dns(&mut self, d: DnsSettings) -> Result<(), ConfigError> {
        // Checked by `validate` (resolver address, direct name patterns).
        self.mutate(|c| {
            c.settings.dns = d;
            Ok(())
        })
    }

    pub fn set_group_action(&mut self, id: &str, a: Action) -> Result<(), ConfigError> {
        self.mutate(|c| {
            c.group_mut(id)?.action = a;
            Ok(())
        })
    }

    /// Enables or disables a group. The catch-all cannot be disabled (Ruling R18).
    pub fn set_group_enabled(&mut self, id: &str, on: bool) -> Result<(), ConfigError> {
        self.mutate(|c| {
            let g = c.group_mut(id)?;
            if g.catch_all && !on {
                return Err(ConfigError::Invalid(format!(
                    "the catch-all group '{id}' cannot be disabled"
                )));
            }
            g.enabled = on;
            Ok(())
        })
    }

    /// Insert a proxy, or replace the one with the same id.
    pub fn upsert_proxy(&mut self, p: ProxyProfile) -> Result<(), ConfigError> {
        self.mutate(|c| {
            match c.proxies.iter_mut().find(|x| x.id == p.id) {
                Some(slot) => *slot = p,
                None => c.proxies.push(p),
            }
            Ok(())
        })
    }

    /// New enabled, empty group just before the catch-all. Returns its id.
    pub fn add_group(&mut self, name: &str, action: Action) -> Result<GroupId, ConfigError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ConfigError::Invalid("group name is empty".into()));
        }
        let base = slug(name);
        let mut id = base.clone();
        let mut n = 2;
        while self.groups.iter().any(|g| g.id == id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        let group = Group {
            id: id.clone(),
            name: name.into(),
            enabled: true,
            action,
            rules: vec![],
            catch_all: false,
        };
        self.mutate(|c| {
            let at = c.groups.len().saturating_sub(1);
            c.groups.insert(at, group);
            Ok(())
        })?;
        Ok(id)
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<(), ConfigError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ConfigError::Invalid("group name is empty".into()));
        }
        self.mutate(|c| {
            c.group_mut(id)?.name = name.into();
            Ok(())
        })
    }

    pub fn delete_group(&mut self, id: &str) -> Result<(), ConfigError> {
        self.mutate(|c| {
            if c.group_mut(id)?.catch_all {
                return Err(ConfigError::Invalid(format!(
                    "the catch-all group '{id}' cannot be deleted"
                )));
            }
            c.groups.retain(|g| g.id != id);
            Ok(())
        })
    }

    /// Moves a group so it ends up at index `to`; nothing may land at or after the catch-all.
    pub fn move_group(&mut self, id: &str, to: usize) -> Result<(), ConfigError> {
        self.mutate(|c| {
            let from = c
                .groups
                .iter()
                .position(|g| g.id == id)
                .ok_or_else(|| ConfigError::Invalid(format!("unknown group '{id}'")))?;
            if c.groups[from].catch_all {
                return Err(ConfigError::Invalid(
                    "the catch-all group cannot be moved".into(),
                ));
            }
            if to >= c.groups.len().saturating_sub(1) {
                return Err(ConfigError::Invalid(format!(
                    "cannot move group to index {to}"
                )));
            }
            let g = c.groups.remove(from);
            c.groups.insert(to, g);
            Ok(())
        })
    }

    /// Replaces a group's rules (action and enabled state are untouched).
    pub fn set_group_rules(&mut self, id: &str, rules: Vec<Rule>) -> Result<(), ConfigError> {
        rules.iter().try_for_each(Rule::check)?;
        self.mutate(|c| {
            c.group_mut(id)?.rules = rules;
            Ok(())
        })
    }

    /// Appends a rule; `Ok(false)` if an equal rule already exists.
    pub fn add_rule(&mut self, id: &str, rule: Rule) -> Result<bool, ConfigError> {
        rule.check()?;
        let mut added = false;
        self.mutate(|c| {
            let g = c.group_mut(id)?;
            if g.catch_all {
                return Err(ConfigError::Invalid(format!(
                    "the catch-all group '{id}' takes no rules"
                )));
            }
            if !g.rules.contains(&rule) {
                g.rules.push(rule);
                added = true;
            }
            Ok(())
        })?;
        Ok(added)
    }

    /// Delete a proxy; fails if unknown or still referenced (validation catches references).
    pub fn delete_proxy(&mut self, id: &str) -> Result<(), ConfigError> {
        self.mutate(|c| {
            let n = c.proxies.len();
            c.proxies.retain(|p| p.id != id);
            if c.proxies.len() == n {
                return Err(ConfigError::Invalid(format!("unknown proxy '{id}'")));
            }
            Ok(())
        })
    }
}
