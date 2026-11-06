//! Rule suggestions derived from observed connections.

use crate::config::Rule;
use crate::decide::MatchReason;
use crate::process_tree::ProcessTree;
use ipnet::IpNet;
use std::net::IpAddr;

/// App rule for an exe name; `None` for unknown / system pseudo-processes.
pub fn app_rule(exe: &str) -> Option<Rule> {
    if ["", "?", "system", "idle"]
        .iter()
        .any(|s| exe.eq_ignore_ascii_case(s))
    {
        return None;
    }
    Some(Rule {
        apps: vec![exe.into()],
        include_children: true,
        ..Rule::default()
    })
}

/// The host itself plus `*.parent` (the parent drops the first label when
/// the host has more than two labels). Empty host yields nothing.
pub fn domain_patterns(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return vec![];
    }
    let parent = match host.split_once('.') {
        Some((_, rest)) if rest.contains('.') => rest,
        Some(_) => host.as_str(),
        None => return vec![host],
    };
    let wild = format!("*.{parent}");
    vec![host, wild]
}

/// The address itself plus its /24 (IPv4) or /64 (IPv6) network.
pub fn ip_patterns(ip: IpAddr) -> Vec<String> {
    let prefix = if ip.is_ipv4() { 24 } else { 64 };
    let net = IpNet::new(ip, prefix).expect("valid prefix").trunc();
    vec![ip.to_string(), net.to_string()]
}

pub fn reason_text(reason: &MatchReason, tree: &ProcessTree) -> String {
    match reason {
        MatchReason::AlwaysDirectDst | MatchReason::AlwaysDirectApp => "always-direct app".into(),
        MatchReason::ExcludedPid => "excluded".into(),
        MatchReason::Own => "own".into(),
        MatchReason::Inherited { from_pid } => {
            match tree
                .get(*from_pid)
                .and_then(|p| p.exe.file_name())
                .map(|n| n.to_string_lossy())
            {
                Some(n) => format!("inherited from {n}"),
                None => "inherited".into(),
            }
        }
        MatchReason::CatchAll => "catch-all".into(),
        MatchReason::NoMatch => "no match".into(),
    }
}
