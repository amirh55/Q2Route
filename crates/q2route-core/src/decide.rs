//! Routing decision engine: Direct / Proxy / Block for each new connection.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use crate::config::{Action, GroupId, ProfileId, Protocol};
use crate::matchers::is_always_direct_dst;
use crate::process_tree::ProcessTree;
use crate::ruleset::{CompiledGroup, CompiledRule, RuleSet};

#[derive(Debug, Clone)]
pub struct FlowInfo<'a> {
    pub proto: Protocol,
    pub pid: u32,
    pub dst: SocketAddr,
    pub domain: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    Inherited {
        from_pid: u32,
    },
    CatchAll,
    /// No group matched and the rule set has no enabled catch-all. Fails
    /// closed: the route is [`Route::Block`], never Direct (Ruling R18).
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
            None if f.proto == Protocol::Tcp && matches!(f.dst.port(), 80 | 443) => {
                RuleOutcome::NeedDomain
            }
            None => RuleOutcome::NoMatch,
        };
    }
    RuleOutcome::Match
}

fn finalize(action: &Action, f: &FlowInfo, info: MatchInfo) -> Decision {
    let route = match action {
        Action::Direct => Route::Direct,
        Action::Block => Route::Block,
        // IPv6 has no relay; proxied UDP/443 (QUIC) is blocked so apps fall back
        // to TCP through the proxy. Blocked, never leaked direct.
        Action::Proxy(_)
            if f.dst.is_ipv6() || (f.proto == Protocol::Udp && f.dst.port() == 443) =>
        {
            Route::Block
        }
        Action::Proxy(id) => Route::Proxy(id.clone()),
    };
    Decision::Final(route, info)
}

fn direct(reason: MatchReason) -> Decision {
    Decision::Final(
        Route::Direct,
        MatchInfo {
            group_id: None,
            reason,
        },
    )
}

/// Decide the route for a new flow. Steps run in order: always-direct destination,
/// excluded pid, always-direct app (own exe), own rules, inherited rules, catch-all
/// (or Block when there is none).
/// Returns `NeedDomain` only when the route may depend on a domain not yet known.
pub fn decide(
    rs: &RuleSet,
    tree: &ProcessTree,
    excluded_pids: &HashSet<u32>,
    f: &FlowInfo,
) -> Decision {
    // 1. Always-direct destinations (LAN, multicast, DNS, NTP).
    if rs.lan_direct {
        let port = f.dst.port();
        if is_always_direct_dst(f.dst.ip())
            || port == 53
            || (f.proto == Protocol::Udp && port == 123)
        {
            return direct(MatchReason::AlwaysDirectDst);
        }
    }
    // 2. Excluded pids (relay's own sockets, proxy listeners).
    if excluded_pids.contains(&f.pid) {
        return direct(MatchReason::ExcludedPid);
    }
    let proc = tree.get(f.pid);
    let ancestors = tree.ancestors(f.pid);
    // 3. Always-direct apps: the process's OWN exe only. Children of a proxy GUI
    //    (e.g. a browser launched from v2rayN.exe) must still be routed normally.
    if proc.is_some_and(|p| rs.always_direct.iter().any(|m| m.matches(&p.exe))) {
        return direct(MatchReason::AlwaysDirectApp);
    }

    // 4. Own pass, then 5. inherited pass (nearest ancestor first): the
    //    candidate rules in evaluation order.
    let own_exe: Option<&Path> = proc.map(|p| p.exe.as_path());
    let mut cands: Vec<Candidate> = Vec::new();
    for g in rs.groups.iter().filter(|g| !g.catch_all) {
        for r in &g.rules {
            if r.apps.is_empty() || own_exe.is_some_and(|e| r.apps.iter().any(|m| m.matches(e))) {
                cands.push((g, r, MatchReason::Own));
            }
        }
    }
    for anc in &ancestors {
        for g in rs.groups.iter().filter(|g| !g.catch_all) {
            for r in &g.rules {
                if !r.apps.is_empty()
                    && r.include_children
                    && r.apps.iter().any(|m| m.matches(&anc.exe))
                {
                    cands.push((g, r, MatchReason::Inherited { from_pid: anc.pid }));
                }
            }
        }
    }
    eval_from(rs, &cands, f)
}

type Candidate<'r> = (&'r CompiledGroup, &'r CompiledRule, MatchReason);

/// Evaluates `cands` in order, then the catch-all (6.). A rule that needs
/// the domain only forces `NeedDomain` if knowing the domain could change
/// the route: when the rest of the evaluation (that rule not matching)
/// gives the same route as the rule itself, that outcome is final (spec
/// 5.4: direct flows that need no peek must not be slowed down).
fn eval_from(rs: &RuleSet, cands: &[Candidate], f: &FlowInfo) -> Decision {
    for (i, (g, r, reason)) in cands.iter().enumerate() {
        let info = || MatchInfo {
            group_id: Some(g.id.clone()),
            reason: reason.clone(),
        };
        match eval_conditions(r, f) {
            RuleOutcome::Match => return finalize(&g.action, f, info()),
            RuleOutcome::NoMatch => {}
            RuleOutcome::NeedDomain => {
                let Decision::Final(if_match, _) = finalize(&g.action, f, info()) else {
                    return Decision::NeedDomain;
                };
                return match eval_from(rs, &cands[i + 1..], f) {
                    Decision::Final(route, rest) if route == if_match => {
                        Decision::Final(route, rest)
                    }
                    _ => Decision::NeedDomain,
                };
            }
        }
    }
    // 6. Catch-all.
    match rs.groups.iter().find(|g| g.catch_all) {
        Some(g) => finalize(
            &g.action,
            f,
            MatchInfo {
                group_id: Some(g.id.clone()),
                reason: MatchReason::CatchAll,
            },
        ),
        // Fail closed (Ruling R18): without a catch-all, unmatched traffic
        // is blocked, never sent direct from the real IP.
        None => Decision::Final(
            Route::Block,
            MatchInfo {
                group_id: None,
                reason: MatchReason::NoMatch,
            },
        ),
    }
}
