//! Routing decision engine: Direct / Proxy / Block for each new connection.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use crate::config::{Action, GroupId, ProfileId, Protocol};
use crate::matchers::is_always_direct_dst;
use crate::process_tree::ProcessTree;
use crate::ruleset::{CompiledRule, RuleSet};

#[derive(Debug, Clone)]
pub struct FlowInfo<'a> {
    pub proto: Protocol,
    pub pid: u32,
    pub dst: SocketAddr,
    pub domain: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Direct,
    Block,
    Proxy(ProfileId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchReason {
    AlwaysDirectDst,
    AlwaysDirectApp,
    ExcludedPid,
    Own,
    Inherited { from_pid: u32 },
    CatchAll,
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchInfo {
    pub group_id: Option<GroupId>,
    pub reason: MatchReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Final(Route, MatchInfo),
    NeedDomain,
}

enum RuleOutcome {
    Match,
    NoMatch,
    NeedDomain,
}

/// Evaluate the non-app conditions of `rule` against the flow.
fn eval_conditions(rule: &CompiledRule, f: &FlowInfo) -> RuleOutcome {
    // A rule with no conditions at all matches nothing.
    if rule.apps.is_empty()
        && rule.domains.is_empty()
        && rule.ips.is_empty()
        && rule.ports.is_empty()
        && rule.protocol.is_none()
    {
        return RuleOutcome::NoMatch;
    }
    if rule.protocol.is_some_and(|p| p != f.proto) {
        return RuleOutcome::NoMatch;
    }
    if !rule.ips.is_empty() && !rule.ips.iter().any(|m| m.matches(f.dst.ip())) {
        return RuleOutcome::NoMatch;
    }
    if !rule.ports.is_empty() && !rule.ports.iter().any(|m| m.matches(f.dst.port())) {
        return RuleOutcome::NoMatch;
    }
    if !rule.domains.is_empty() {
        return match f.domain {
            Some(d) if rule.domains.iter().any(|m| m.matches(d)) => RuleOutcome::Match,
            Some(_) => RuleOutcome::NoMatch,
            None if f.proto == Protocol::Tcp && matches!(f.dst.port(), 80 | 443) => RuleOutcome::NeedDomain,
            None => RuleOutcome::NoMatch,
        };
    }
    RuleOutcome::Match
}

fn finalize(action: &Action, f: &FlowInfo, info: MatchInfo) -> Decision {
    let route = match action {
        Action::Direct => Route::Direct,
        Action::Block => Route::Block,
        // M1: no UDP / IPv6 relay, so proxied UDP and IPv6 are blocked, never leaked.
        Action::Proxy(_) if f.proto == Protocol::Udp || f.dst.is_ipv6() => Route::Block,
        Action::Proxy(id) => Route::Proxy(id.clone()),
    };
    Decision::Final(route, info)
}

fn direct(reason: MatchReason) -> Decision {
    Decision::Final(Route::Direct, MatchInfo { group_id: None, reason })
}

pub fn decide(rs: &RuleSet, tree: &ProcessTree, excluded_pids: &HashSet<u32>, f: &FlowInfo) -> Decision {
    // 1. Always-direct destinations (LAN, multicast, DNS, NTP).
    if rs.lan_direct {
        let port = f.dst.port();
        if is_always_direct_dst(f.dst.ip()) || port == 53 || (f.proto == Protocol::Udp && port == 123) {
            return direct(MatchReason::AlwaysDirectDst);
        }
    }
    // 2. Excluded pids (relay's own sockets, proxy listeners).
    if excluded_pids.contains(&f.pid) {
        return direct(MatchReason::ExcludedPid);
    }
    let proc = tree.get(f.pid);
    let ancestors = tree.ancestors(f.pid);
    // 3. Always-direct apps (the process or any ancestor).
    if proc
        .into_iter()
        .chain(ancestors.iter().copied())
        .any(|p| rs.always_direct.iter().any(|m| m.matches(&p.exe)))
    {
        return direct(MatchReason::AlwaysDirectApp);
    }

    // 4. Own pass.
    let own_exe: Option<&Path> = proc.map(|p| p.exe.as_path());
    for g in rs.groups.iter().filter(|g| !g.catch_all) {
        for r in &g.rules {
            if !r.apps.is_empty() && !own_exe.is_some_and(|e| r.apps.iter().any(|m| m.matches(e))) {
                continue;
            }
            match eval_conditions(r, f) {
                RuleOutcome::Match => {
                    let info = MatchInfo { group_id: Some(g.id.clone()), reason: MatchReason::Own };
                    return finalize(&g.action, f, info);
                }
                RuleOutcome::NeedDomain => return Decision::NeedDomain,
                RuleOutcome::NoMatch => {}
            }
        }
    }

    // 5. Inherited pass: nearest ancestor first.
    for anc in &ancestors {
        for g in rs.groups.iter().filter(|g| !g.catch_all) {
            for r in &g.rules {
                if r.apps.is_empty() || !r.include_children || !r.apps.iter().any(|m| m.matches(&anc.exe)) {
                    continue;
                }
                match eval_conditions(r, f) {
                    RuleOutcome::Match => {
                        let info = MatchInfo {
                            group_id: Some(g.id.clone()),
                            reason: MatchReason::Inherited { from_pid: anc.pid },
                        };
                        return finalize(&g.action, f, info);
                    }
                    RuleOutcome::NeedDomain => return Decision::NeedDomain,
                    RuleOutcome::NoMatch => {}
                }
            }
        }
    }

    // 6. Catch-all.
    match rs.groups.iter().find(|g| g.catch_all) {
        Some(g) => finalize(&g.action, f, MatchInfo { group_id: Some(g.id.clone()), reason: MatchReason::CatchAll }),
        None => direct(MatchReason::NoMatch),
    }
}
