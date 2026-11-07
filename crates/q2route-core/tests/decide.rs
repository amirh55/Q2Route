use q2route_core::decide::*;
use q2route_core::process_tree::*;
use q2route_core::ruleset::*;
use q2route_core::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

fn cfg() -> Config {
    let mut c = Config::seed();
    c.set_group_enabled("steam", true).unwrap();
    c.groups.insert(
        2,
        Group {
            id: "filtered-game".into(),
            name: "Filtered game".into(),
            enabled: true,
            action: Action::Proxy("v2ray".into()),
            rules: vec![Rule {
                apps: vec!["fgame.exe".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    c
}

fn tree() -> ProcessTree {
    let mut t = ProcessTree::default();
    let mut add = |pid, parent, exe: &str, st| {
        t.insert(ProcInfo {
            pid,
            parent,
            exe: PathBuf::from(exe),
            start_time: st,
        });
    };
    add(10, 0, r"C:\Program Files (x86)\Steam\steam.exe", 1);
    add(
        20,
        10,
        r"C:\Program Files (x86)\Steam\bin\steamwebhelper.exe",
        2,
    );
    add(30, 10, r"C:\Games\fgame.exe", 3);
    add(40, 0, r"C:\Program Files\Google\Chrome\chrome.exe", 4);
    add(50, 0, r"C:\Tools\v2ray.exe", 5);
    add(60, 0, r"C:\Windows\System32\svchost.exe", 6);
    add(70, 0, r"C:\Tools\v2rayN.exe", 7);
    add(80, 70, r"C:\Program Files\Google\Chrome\chrome.exe", 8);
    t
}

fn run(
    rs: &RuleSet,
    ex: &HashSet<u32>,
    proto: Protocol,
    pid: u32,
    dst: &str,
    domain: Option<&str>,
) -> Decision {
    let dst: SocketAddr = dst.parse().unwrap();
    decide(
        rs,
        &tree(),
        ex,
        &FlowInfo {
            proto,
            pid,
            dst,
            domain,
        },
    )
}

fn d(proto: Protocol, pid: u32, dst: &str, domain: Option<&str>) -> Decision {
    run(
        &RuleSet::compile(&cfg()).unwrap(),
        &HashSet::new(),
        proto,
        pid,
        dst,
        domain,
    )
}

fn fin(route: Route, gid: Option<&str>, reason: MatchReason) -> Decision {
    Decision::Final(
        route,
        MatchInfo {
            group_id: gid.map(String::from),
            reason,
        },
    )
}

fn proxy() -> Route {
    Route::Proxy("v2ray".into())
}

#[test]
fn ir_domain_direct() {
    assert_eq!(
        d(Protocol::Tcp, 40, "5.6.7.8:443", Some("digikala.ir")),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn unknown_domain_443_needs_peek() {
    assert_eq!(
        d(Protocol::Tcp, 40, "1.2.3.4:443", None),
        Decision::NeedDomain
    );
}

#[test]
fn unknown_domain_other_port_no_peek() {
    assert_eq!(
        d(Protocol::Tcp, 40, "1.2.3.4:8443", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn server_first_no_domain() {
    let mut c = cfg();
    c.groups.remove(0);
    c.settings.dns.block_doh = false;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "1.2.3.4:443", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    // with DoH blocking on, a proxied 443 flow peeks the SNI first
    c.settings.dns.block_doh = true;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "1.2.3.4:443", None),
        Decision::NeedDomain
    );
}

#[test]
fn steam_child_inherits() {
    assert_eq!(
        d(Protocol::Tcp, 20, "8.8.8.8:443", Some("example.com")),
        fin(
            Route::Direct,
            Some("steam"),
            MatchReason::Inherited { from_pid: 10 }
        )
    );
}

#[test]
fn steam_itself_is_own() {
    assert_eq!(
        d(Protocol::Tcp, 10, "8.8.8.8:443", Some("example.com")),
        fin(Route::Direct, Some("steam"), MatchReason::Own)
    );
}

#[test]
fn inherited_direct_skips_peek_when_domain_cannot_change_route() {
    // *.ir would say Direct, and so does Steam without it: no peek (spec 5.4).
    assert_eq!(
        d(Protocol::Tcp, 20, "8.8.8.8:443", None),
        fin(
            Route::Direct,
            Some("steam"),
            MatchReason::Inherited { from_pid: 10 }
        )
    );
    assert_eq!(
        d(Protocol::Tcp, 20, "8.8.8.8:27015", None),
        fin(
            Route::Direct,
            Some("steam"),
            MatchReason::Inherited { from_pid: 10 }
        )
    );
}

#[test]
fn inherited_rule_other_conditions_must_hold() {
    let mut c = cfg();
    c.groups[1].rules[0].ports = vec!["27015".into()];
    let rs = RuleSet::compile(&c).unwrap();
    let ex = HashSet::new();
    assert_eq!(
        run(
            &rs,
            &ex,
            Protocol::Tcp,
            20,
            "8.8.8.8:27015",
            Some("example.com")
        ),
        fin(
            Route::Direct,
            Some("steam"),
            MatchReason::Inherited { from_pid: 10 }
        )
    );
    assert_eq!(
        run(
            &rs,
            &ex,
            Protocol::Tcp,
            20,
            "8.8.8.8:443",
            Some("example.com")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn own_beats_inherited() {
    assert_eq!(
        d(Protocol::Tcp, 30, "9.9.9.9:443", Some("x.com")),
        fin(proxy(), Some("filtered-game"), MatchReason::Own)
    );
}

#[test]
fn v2ray_never_proxied() {
    assert_eq!(
        d(Protocol::Tcp, 50, "9.9.9.9:443", Some("x.com")),
        fin(Route::Direct, None, MatchReason::AlwaysDirectApp)
    );
}

#[test]
fn excluded_pid() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    let ex = HashSet::from([40]);
    assert_eq!(
        run(&rs, &ex, Protocol::Tcp, 40, "9.9.9.9:443", Some("x.com")),
        fin(Route::Direct, None, MatchReason::ExcludedPid)
    );
}

#[test]
fn lan_direct() {
    assert_eq!(
        d(Protocol::Tcp, 40, "192.168.1.1:80", None),
        fin(Route::Direct, None, MatchReason::AlwaysDirectDst)
    );
}

#[test]
fn lan_rule_off() {
    let mut rs = RuleSet::compile(&cfg()).unwrap();
    rs.lan_direct = false;
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "127.0.0.1:443",
            Some("x.com")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn ntp_still_always_direct() {
    let direct = fin(Route::Direct, None, MatchReason::AlwaysDirectDst);
    assert_eq!(d(Protocol::Udp, 60, "1.2.3.4:123", None), direct);
    assert_eq!(d(Protocol::Udp, 60, "192.168.1.1:80", None), direct);
}

#[test]
fn lan_resolver_still_routed_by_name() {
    let direct = fin(Route::Direct, None, MatchReason::AlwaysDirectDst);
    assert_ne!(d(Protocol::Udp, 60, "192.168.1.1:53", None), direct);
    assert_ne!(d(Protocol::Tcp, 60, "127.0.0.1:53", None), direct);
    assert_ne!(d(Protocol::Udp, 60, "8.8.8.8:53", None), direct);
}

#[test]
fn dns_by_name() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    assert_eq!(
        decide_dns(&rs, "foo.ir"),
        (
            Route::Direct,
            MatchInfo {
                group_id: Some("iranian-sites".into()),
                reason: MatchReason::Own
            }
        )
    );
    assert_eq!(
        decide_dns(&rs, "example.com"),
        (
            proxy(),
            MatchInfo {
                group_id: Some("everything-else".into()),
                reason: MatchReason::CatchAll
            }
        )
    );
}

#[test]
fn dns_ignores_app_rules() {
    let mut c = cfg();
    c.groups.insert(
        0,
        Group {
            id: "appdom".into(),
            name: "x".into(),
            enabled: true,
            action: Action::Direct,
            rules: vec![Rule {
                apps: vec!["x.exe".into()],
                domains: vec!["example.com".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    let rs = RuleSet::compile(&c).unwrap();
    let (r, i) = decide_dns(&rs, "example.com");
    assert_eq!(r, proxy());
    assert_eq!(i.reason, MatchReason::CatchAll);
}

#[test]
fn doh_blocked_only_when_proxied() {
    let blocked = fin(
        Route::Block,
        Some("everything-else"),
        MatchReason::DohBlocked,
    );
    assert_eq!(
        d(Protocol::Tcp, 40, "8.8.8.8:443", Some("dns.google")),
        blocked
    );
    assert_eq!(d(Protocol::Udp, 40, "8.8.8.8:853", None), blocked);
    assert_eq!(d(Protocol::Tcp, 40, "8.8.8.8:853", None), blocked);
    // not a DoH host
    assert_eq!(
        d(Protocol::Tcp, 40, "8.8.8.8:443", Some("example.com")),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    // disabled
    let mut c = cfg();
    c.settings.dns.block_doh = false;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "8.8.8.8:443",
            Some("dns.google")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    // a direct-matched flow to 853 stays Direct
    assert_eq!(
        d(Protocol::Tcp, 40, "5.6.7.8:853", Some("foo.ir")),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn dns_settings_defaults() {
    assert_eq!(Config::seed().settings.dns, DnsSettings::default());
}

#[test]
fn udp_proxy_ipv4_routes_to_proxy() {
    assert_eq!(
        d(Protocol::Udp, 40, "5.6.7.8:27015", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn udp_443_stays_blocked() {
    // QUIC (UDP/443) stays blocked so apps fall back to TCP through the proxy.
    assert_eq!(
        d(Protocol::Udp, 40, "1.2.3.4:443", None),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        d(Protocol::Udp, 40, "[2606:4700::1]:443", None),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn ipv6_proxy_routes_to_proxy() {
    // M6: IPv6 goes through the proxy (dual-stack relay / UDP relay).
    assert_eq!(
        d(Protocol::Tcp, 40, "[2606:4700::1]:443", Some("x.com")),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        d(Protocol::Udp, 40, "[2606:4700::1]:27015", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        d(Protocol::Udp, 40, "[2606:4700::1]:443", None),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn empty_rule_matches_nothing_and_no_catch_all_is_block() {
    let mut c = cfg();
    c.groups.retain(|g| g.id == "games");
    c.groups[0].rules.push(Rule::default());
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "1.2.3.4:443",
            Some("x.com")
        ),
        fin(Route::Block, None, MatchReason::NoMatch)
    );
}

#[test]
fn disabled_catch_all_blocks_never_direct() {
    // Ruling R18: a RuleSet without an enabled catch-all must fail closed.
    let mut c = cfg();
    c.groups.last_mut().unwrap().enabled = false;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "1.2.3.4:8443",
            None
        ),
        fin(Route::Block, None, MatchReason::NoMatch)
    );
}

#[test]
fn unknown_pid_falls_to_catch_all() {
    assert_eq!(
        d(Protocol::Tcp, 999, "1.2.3.4:8000", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn child_of_proxy_gui_not_direct() {
    assert_eq!(
        d(Protocol::Tcp, 80, "1.1.1.1:443", Some("x.com")),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn steam_child_443_with_direct_groups_is_final_direct() {
    assert_eq!(
        d(Protocol::Tcp, 20, "1.2.3.4:443", None),
        fin(
            Route::Direct,
            Some("steam"),
            MatchReason::Inherited { from_pid: 10 }
        )
    );
    assert_eq!(
        d(Protocol::Tcp, 10, "1.2.3.4:443", None),
        fin(Route::Direct, Some("steam"), MatchReason::Own)
    );
}

#[test]
fn chrome_443_still_needs_domain() {
    // catch-all Proxy vs Iranian Direct: the domain decides.
    assert_eq!(
        d(Protocol::Tcp, 40, "1.2.3.4:443", None),
        Decision::NeedDomain
    );
}

#[test]
fn later_domain_rule_with_other_route_still_needs_domain() {
    // *.ir Direct, then x.com Proxy, then Steam Direct: the second domain
    // rule could change the route, so the peek is still needed.
    let mut c = cfg();
    c.groups.insert(
        1,
        Group {
            id: "xcom".into(),
            name: "x.com".into(),
            enabled: true,
            action: Action::Proxy("v2ray".into()),
            rules: vec![Rule {
                domains: vec!["x.com".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 20, "1.2.3.4:443", None),
        Decision::NeedDomain
    );
    // ...but with the domain known it is decided normally.
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            20,
            "1.2.3.4:443",
            Some("x.com")
        ),
        fin(proxy(), Some("xcom"), MatchReason::Own)
    );
}

#[test]
fn proxied_domain_group_with_proxied_fallback_skips_peek() {
    // Both outcomes are the same proxy: no peek needed.
    let mut c = cfg();
    c.groups[0].action = Action::Proxy("v2ray".into());
    c.settings.dns.block_doh = false;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "1.2.3.4:443", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

fn d_geo(proto: Protocol, pid: u32, dst: &str, domain: Option<&str>) -> Decision {
    use q2route_core::geoip::{GeoIp, IpSet};
    let geo = GeoIp::from_sets([(
        "ir".to_string(),
        IpSet::from_cidrs(&[("185.188.104.0".parse().unwrap(), 22)]),
    )]);
    run(
        &RuleSet::compile_with(&cfg(), &geo).unwrap(),
        &HashSet::new(),
        proto,
        pid,
        dst,
        domain,
    )
}

#[test]
fn geoip_ir_direct_without_peek() {
    // digikala.com on an Iranian IP: Direct straight away, no SNI peek needed.
    assert_eq!(
        d_geo(Protocol::Tcp, 40, "185.188.107.12:443", None),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
    assert_eq!(
        d_geo(
            Protocol::Tcp,
            40,
            "185.188.107.12:443",
            Some("www.digikala.com")
        ),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
    // Non-HTTP port and UDP to an Iranian IP (Eitaa, games) are Direct too.
    assert_eq!(
        d_geo(Protocol::Udp, 40, "185.188.105.1:5000", None),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn geoip_ir_foreign_ip_still_proxied() {
    assert_eq!(
        d_geo(Protocol::Tcp, 40, "34.160.111.145:443", Some("ifconfig.me")),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    // Without geoip data the Iranian IP is not special: it goes to the proxy.
    assert_eq!(
        d(
            Protocol::Tcp,
            40,
            "185.188.107.12:443",
            Some("www.digikala.com")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn doh_unknown_domain_peeks_when_proxied() {
    // catch-all Proxy, TCP 443, no domain yet -> peek
    let mut c = cfg();
    c.groups.remove(0);
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "8.8.8.8:443", None),
        Decision::NeedDomain
    );
    // block_doh off -> no peek
    c.settings.dns.block_doh = false;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "8.8.8.8:443", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    // port 80 and UDP are unaffected
    c.settings.dns.block_doh = true;
    let rs = RuleSet::compile(&c).unwrap();
    let r = |p, dst| run(&rs, &HashSet::new(), p, 40, dst, None);
    assert_eq!(
        r(Protocol::Tcp, "8.8.8.8:80"),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        r(Protocol::Udp, "8.8.8.8:443"),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn doh_peek_covers_proxy_proxy_shortcut() {
    // domain rule -> Proxy, rest -> Proxy: eval_from would skip the peek
    let mut c = cfg();
    c.groups.insert(
        0,
        Group {
            id: "dom".into(),
            name: "d".into(),
            enabled: true,
            action: Action::Proxy("v2ray".into()),
            rules: vec![Rule {
                domains: vec!["example.com".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "8.8.8.8:443", None),
        Decision::NeedDomain
    );
}

#[test]
fn direct_tcp443_without_domain_needs_no_peek() {
    let mut c = cfg();
    c.set_group_action("everything-else", Action::Direct)
        .unwrap();
    let rs = RuleSet::compile(&c).unwrap();
    // *.ir rule may still need the domain, but Direct/Direct shortcut applies
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "8.8.8.8:443", None),
        fin(
            Route::Direct,
            Some("everything-else"),
            MatchReason::CatchAll
        )
    );
}

fn dm(pid: u32, dst: &str, names: &[&str], rs: &RuleSet) -> Decision {
    let dst: SocketAddr = dst.parse().unwrap();
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    decide_mapped(
        rs,
        &tree(),
        &HashSet::new(),
        &FlowInfo {
            proto: Protocol::Tcp,
            pid,
            dst,
            domain: None,
        },
        &names,
    )
}

#[test]
fn mapped_single_name_direct() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    assert_eq!(
        dm(40, "5.6.7.8:5222", &["x.ir"], &rs),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn mapped_conflict_most_protective_or_peek() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    let names = ["x.ir", "example.com"];
    assert!(matches!(
        dm(40, "5.6.7.8:5222", &names, &rs),
        Decision::Final(Route::Proxy(_), _)
    ));
    assert_eq!(dm(40, "5.6.7.8:443", &names, &rs), Decision::NeedDomain);
}

#[test]
fn mapped_names_dont_override_app_rules() {
    let mut c = cfg();
    c.groups.insert(
        0,
        Group {
            id: "app-block".into(),
            name: "App block".into(),
            enabled: true,
            action: Action::Block,
            rules: vec![Rule {
                apps: vec!["chrome.exe".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        dm(40, "5.6.7.8:5222", &["x.ir"], &rs),
        fin(Route::Block, Some("app-block"), MatchReason::Own)
    );
}

#[test]
fn no_names_same_as_decide() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    for dst in ["5.6.7.8:443", "5.6.7.8:5222"] {
        assert_eq!(
            dm(40, dst, &[], &rs),
            run(&rs, &HashSet::new(), Protocol::Tcp, 40, dst, None)
        );
    }
}

fn dm_no_peek(dst: &str, names: &[&str], rs: &RuleSet) -> Decision {
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    decide_mapped_no_peek(
        rs,
        &tree(),
        &HashSet::new(),
        &FlowInfo {
            proto: Protocol::Tcp,
            pid: 40,
            dst: dst.parse().unwrap(),
            domain: None,
        },
        &names,
    )
}

#[test]
fn mapped_no_peek_most_protective_on_443() {
    let mut c = cfg();
    c.set_group_action("everything-else", Action::Direct)
        .unwrap();
    c.groups.insert(
        0,
        Group {
            id: "blocked".into(),
            name: "Blocked".into(),
            enabled: true,
            action: Action::Proxy("v2ray".into()),
            rules: vec![Rule {
                domains: vec!["blocked.com".into()],
                ..Rule::default()
            }],
            catch_all: false,
        },
    );
    let rs = RuleSet::compile(&c).unwrap();
    let names = ["x.ir", "blocked.com"];
    assert_eq!(dm(40, "5.6.7.8:443", &names, &rs), Decision::NeedDomain);
    assert_eq!(
        dm_no_peek("5.6.7.8:443", &names, &rs),
        fin(
            Route::Proxy("v2ray".into()),
            Some("blocked"),
            MatchReason::Own
        )
    );
    // Agreeing names: that route, first name's info.
    assert_eq!(
        dm_no_peek("5.6.7.8:443", &["x.ir", "y.ir"], &rs),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn mapped_no_peek_without_names_is_empty_domain() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    for dst in ["5.6.7.8:443", "5.6.7.8:5222"] {
        assert_eq!(
            dm_no_peek(dst, &[], &rs),
            run(&rs, &HashSet::new(), Protocol::Tcp, 40, dst, Some(""))
        );
        assert_ne!(dm_no_peek(dst, &[], &rs), Decision::NeedDomain);
    }
}

/// Names from (forgeable) DNS answers alone never skip the peek on a web
/// port for a flow that is not Direct without a domain.
#[test]
fn mapped_direct_name_on_web_port_still_peeks() {
    let rs = RuleSet::compile(&cfg()).unwrap();
    // Proxied app (chrome, catch-all Proxy), IP mapped only to x.ir.
    for dst in ["5.6.7.8:443", "5.6.7.8:80"] {
        assert_eq!(dm(40, dst, &["x.ir"], &rs), Decision::NeedDomain, "{dst}");
        assert_eq!(dm(40, dst, &["x.ir", "y.ir"], &rs), Decision::NeedDomain);
    }
    // Not a web port: the mapped name decides, as before.
    assert_eq!(
        dm(40, "5.6.7.8:5222", &["x.ir"], &rs),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
    // A Direct app (steam child): Direct without a peek.
    assert!(matches!(
        dm(20, "5.6.7.8:443", &["x.ir"], &rs),
        Decision::Final(Route::Direct, _)
    ));
    // Proxy from names alone stays final on 443 (no peek needed to protect).
    assert!(matches!(
        dm(40, "5.6.7.8:443", &["example.com"], &rs),
        Decision::Final(Route::Proxy(_), _)
    ));
}
