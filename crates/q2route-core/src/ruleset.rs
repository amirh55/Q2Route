//! Compile a `Config` into matcher-backed groups for the decision engine.

use crate::config::{Action, Config, GroupId, Protocol};
use crate::geoip::GeoIp;
use crate::matchers::{geoip_codes, AppMatcher, DomainPattern, IpMatcher, MatchError, PortRange};

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub apps: Vec<AppMatcher>,
    pub domains: Vec<DomainPattern>,
    pub ips: Vec<IpMatcher>,
    pub ports: Vec<PortRange>,
    pub protocol: Option<Protocol>,
    pub include_children: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledGroup {
    pub id: GroupId,
    pub action: Action,
    pub rules: Vec<CompiledRule>,
    pub catch_all: bool,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    /// Enabled groups only, in config order.
    pub groups: Vec<CompiledGroup>,
    pub always_direct: Vec<AppMatcher>,
    /// Whether loopback/LAN destinations are forced Direct (always true outside relay tests).
    pub lan_direct: bool,
}

fn all<T>(
    items: &[String],
    f: impl Fn(&str) -> Result<T, MatchError>,
) -> Result<Vec<T>, MatchError> {
    items.iter().map(|s| f(s)).collect()
}

impl RuleSet {
    /// Compile without geoip data (`geoip:` entries match nothing).
    pub fn compile(cfg: &Config) -> Result<RuleSet, MatchError> {
        Self::compile_with(cfg, &GeoIp::default())
    }

    /// `geoip:` codes used by enabled groups' rules.
    pub fn wanted_geoip(cfg: &Config) -> Vec<String> {
        geoip_codes(
            cfg.groups
                .iter()
                .filter(|g| g.enabled)
                .flat_map(|g| g.rules.iter().flat_map(|r| r.ips.iter())),
        )
    }

    pub fn compile_with(cfg: &Config, geo: &GeoIp) -> Result<RuleSet, MatchError> {
        let mut groups = Vec::new();
        for g in cfg.groups.iter().filter(|g| g.enabled) {
            let wrap = |e: MatchError| MatchError::Group {
                group: g.id.clone(),
                source: Box::new(e),
            };
            let mut rules = Vec::new();
            for r in &g.rules {
                rules.push(CompiledRule {
                    apps: all(&r.apps, AppMatcher::parse).map_err(wrap)?,
                    domains: all(&r.domains, DomainPattern::parse).map_err(wrap)?,
                    ips: all(&r.ips, |s| IpMatcher::parse_with(s, geo)).map_err(wrap)?,
                    ports: all(&r.ports, PortRange::parse).map_err(wrap)?,
                    protocol: r.protocol,
                    include_children: r.include_children,
                });
            }
            groups.push(CompiledGroup {
                id: g.id.clone(),
                action: g.action.clone(),
                rules,
                catch_all: g.catch_all,
            });
        }
        let always_direct = all(&cfg.always_direct, AppMatcher::parse)?;
        Ok(RuleSet {
            groups,
            always_direct,
            lan_direct: true,
        })
    }
}
