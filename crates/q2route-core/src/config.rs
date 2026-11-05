//! Config model: proxies, rule groups, settings, TOML persistence.

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
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            start_with_windows: false,
            close_to_tray: false,
            tray_traffic_icon: false,
            peek_timeout_ms: 300,
            last_running: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
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
        let group = |id: &str, name: &str, enabled: bool, action: Action, rules: Vec<Rule>, catch_all: bool| Group {
            id: id.into(),
            name: name.into(),
            enabled,
            action,
            rules,
            catch_all,
        };
        Config {
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
                    vec![Rule { domains: vec!["*.ir".into()], ..Rule::default() }],
                    false,
                ),
                group(
                    "steam",
                    "Steam",
                    false,
                    Action::Direct,
                    vec![Rule { apps: vec!["steam.exe".into()], include_children: true, ..Rule::default() }],
                    false,
                ),
                group("games", "Games", true, Action::Direct, vec![], false),
                group("everything-else", "Everything else", true, Action::Proxy("v2ray".into()), vec![], true),
            ],
            always_direct: ["v2ray.exe", "xray.exe", "sing-box.exe", "v2rayN.exe", "nekoray.exe", "hiddify.exe", "clash*.exe"]
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
                let c: Config = toml::from_str(&s)?;
                c.validate()?;
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
            return bad(format!("default_proxy '{}' is not a known proxy", self.default_proxy));
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
        Ok(())
    }
}
