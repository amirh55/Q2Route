//! Routing decision engine: Direct / Proxy / Block for each new connection.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use crate::config::{Action, GroupId, ProfileId, Protocol};
use crate::dns::is_doh_host;
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
    /// DoH (known host on TCP 443) or DoT/DoQ (port 853) on a flow that
    /// would have been proxied: blocked so clients fall back to plain DNS.
    DohBlocked,
    /// A DNS query resolved directly so the VPN can come up: the proxy
    /// program's own query, or a proxy host / `direct_names` / detected
    /// proxy server name.
    BootstrapName,
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

fn finalize(rs: &RuleSet, action: &Action, f: &FlowInfo, mut info: MatchInfo) -> Decision {
    let mut route = match action {
        Action::Direct => Route::Direct,
        Action::Block => Route::Block,
        // Proxied UDP/443 (QUIC, either family) is blocked so apps fall back
        // to TCP through the proxy. Blocked, never leaked direct.
        Action::Proxy(_) if f.proto == Protocol::Udp && f.dst.port() == 443 => Route::Block,
        Action::Proxy(id) => Route::Proxy(id.clone()),
    };
    if rs.block_doh && matches!(route, Route::Proxy(_)) && is_doh_flow(f) {
        route = Route::Block;
        info.reason = MatchReason::DohBlocked;
    }
    Decision::Final(route, info)
}

fn is_doh_flow(f: &FlowInfo) -> bool {
    f.dst.port() == 853
        || (f.proto == Protocol::Tcp && f.dst.port() == 443 && f.domain.is_some_and(is_doh_host))
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
    // 1. Always-direct destinations (LAN, multicast, NTP). Port 53 is excluded:
    //    DNS is routed by the queried name (`decide_dns`), not by destination.
    if rs.lan_direct {
        let port = f.dst.port();
        if (is_always_direct_dst(f.dst.ip()) && port != 53)
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
    let d = eval_from(rs, &cands, f);
    // A proxied TCP/443 flow with no domain yet could be DoH: peek the SNI so
    // `finalize` can check it (this also covers eval_from's no-peek shortcut).
    if rs.block_doh
        && f.domain.is_none()
        && f.proto == Protocol::Tcp
        && f.dst.port() == 443
        && matches!(d, Decision::Final(Route::Proxy(_), _))
    {
        return Decision::NeedDomain;
    }
    d
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
            RuleOutcome::Match => return finalize(rs, &g.action, f, info()),
            RuleOutcome::NoMatch => {}
            RuleOutcome::NeedDomain => {
                let Decision::Final(if_match, _) = finalize(rs, &g.action, f, info()) else {
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
            rs,
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

/// Route a DNS query by its name only. Only pure domain rules (rules whose sole
/// conditions are domains) count: rules with apps, ips, ports or a protocol
/// describe connections, not names. First matching enabled group wins, else the
/// catch-all's action. The DNS layer handles transport, so no IPv6/UDP-443
/// conversion happens here; a missing catch-all fails closed.
pub fn decide_dns(rs: &RuleSet, name: &str) -> (Route, MatchInfo) {
    let route_of = |a: &Action| match a {
        Action::Direct => Route::Direct,
        Action::Block => Route::Block,
        Action::Proxy(id) => Route::Proxy(id.clone()),
    };
    for g in rs.groups.iter().filter(|g| !g.catch_all) {
        let hit = g.rules.iter().any(|r| {
            r.apps.is_empty()
                && r.ips.is_empty()
                && r.ports.is_empty()
                && r.protocol.is_none()
                && r.domains.iter().any(|m| m.matches(name))
        });
        if hit {
            return (
                route_of(&g.action),
                MatchInfo {
                    group_id: Some(g.id.clone()),
                    reason: MatchReason::Own,
                },
            );
        }
    }
    match rs.groups.iter().find(|g| g.catch_all) {
        Some(g) => (
            route_of(&g.action),
            MatchInfo {
                group_id: Some(g.id.clone()),
                reason: MatchReason::CatchAll,
            },
        ),
        None => (
            Route::Block,
            MatchInfo {
                group_id: None,
                reason: MatchReason::NoMatch,
            },
        ),
    }
}

/// Decide with names learned from DNS for `f.dst` (used when `f.domain` is
/// None). No names -> `decide`. All names give the same Final route -> that
/// decision with the first name's MatchInfo, except that a Direct result on
/// TCP 80/443 still peeks (`NeedDomain`) unless the flow is Direct without a
/// domain. Otherwise TCP 80/443 -> `NeedDomain` (peek); else the most
/// protective route (Proxy > Block > Direct).
pub fn decide_mapped(
    rs: &RuleSet,
    tree: &ProcessTree,
    excluded_pids: &HashSet<u32>,
    f: &FlowInfo,
    names: &[String],
) -> Decision {
    if names.is_empty() {
        return decide(rs, tree, excluded_pids, f);
    }
    let mut finals: Vec<(Route, MatchInfo)> = Vec::with_capacity(names.len());
    let mut unresolved = false;
    for n in names {
        let fi = FlowInfo {
            domain: Some(n),
            ..f.clone()
        };
        match decide(rs, tree, excluded_pids, &fi) {
            Decision::Final(r, i) => finals.push((r, i)),
            Decision::NeedDomain => unresolved = true,
        }
    }
    let web = f.proto == Protocol::Tcp && matches!(f.dst.port(), 80 | 443);
    if !unresolved && finals.iter().all(|(r, _)| *r == finals[0].0) {
        let (r, i) = finals.swap_remove(0);
        // Names come from DNS answers anyone on the path could forge: on a
        // web port a Direct verdict from names alone is confirmed by a peek,
        // unless the flow is Direct without any domain.
        if web
            && r == Route::Direct
            && !matches!(
                decide(rs, tree, excluded_pids, f),
                Decision::Final(Route::Direct, _)
            )
        {
            return Decision::NeedDomain;
        }
        return Decision::Final(r, i);
    }
    if web {
        return Decision::NeedDomain;
    }
    if unresolved {
        // Defensive: cannot happen with a domain set; fall back to the
        // domain-less decision rather than guess.
        return decide(rs, tree, excluded_pids, f);
    }
    most_protective(finals)
}

/// The most protective of non-empty `finals` (Proxy > Block > Direct; the
/// first one on ties).
fn most_protective(finals: Vec<(Route, MatchInfo)>) -> Decision {
    let rank = |r: &Route| match r {
        Route::Proxy(_) => 2,
        Route::Block => 1,
        Route::Direct => 0,
    };
    let (r, i) = finals
        .into_iter()
        .reduce(|a, b| if rank(&b.0) > rank(&a.0) { b } else { a })
        .expect("finals non-empty");
    Decision::Final(r, i)
}

/// Like [`decide_mapped`] for a flow whose peek found nothing (no further
/// peek is possible): never `NeedDomain`. No names -> `decide` with an empty
/// domain (matches no domain rule). Otherwise each name is decided and the
/// most protective route wins (Proxy > Block > Direct), on any port.
pub fn decide_mapped_no_peek(
    rs: &RuleSet,
    tree: &ProcessTree,
    excluded_pids: &HashSet<u32>,
    f: &FlowInfo,
    names: &[String],
) -> Decision {
    let empty = FlowInfo {
        domain: Some(""),
        ..f.clone()
    };
    if names.is_empty() {
        return decide(rs, tree, excluded_pids, &empty);
    }
    let finals: Vec<(Route, MatchInfo)> = names
        .iter()
        .map(|n| {
            let fi = FlowInfo {
                domain: Some(n),
                ..f.clone()
            };
            // With a domain set this is always Final; the empty-domain
            // decision stands in defensively.
            match decide(rs, tree, excluded_pids, &fi) {
                Decision::Final(r, i) => (r, i),
                Decision::NeedDomain => match decide(rs, tree, excluded_pids, &empty) {
                    Decision::Final(r, i) => (r, i),
                    Decision::NeedDomain => (
                        Route::Block,
                        MatchInfo {
                            group_id: None,
                            reason: MatchReason::NoMatch,
                        },
                    ),
                },
            }
        })
        .collect();
    most_protective(finals)
}
