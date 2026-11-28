use q2route_core::decide::*;
use q2route_core::process_tree::*;
use q2route_core::ruleset::*;
use q2route_core::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

fn cfg() -> Config {
    let mut c = Config::seed();
    // The shared-names exception has its own test; these index the others.
    c.groups.remove(0);
    c.set_group_enabled("steam", true).unwrap();
    // These tests exercise the app rule; the seed's geosite:steam rule would
    // make unknown domains matter (it has its own tests).
    c.groups[1].rules.truncate(1);
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
fn proxy_ipv6_off_blocks_proxied_ipv6_only() {
    // settings.proxy_ipv6 off (a proxy server without IPv6): proxied IPv6
    // TCP and UDP are blocked (apps fall back to IPv4), as before M6.
    let mut c = cfg();
    assert!(c.settings.proxy_ipv6, "default on");
    c.settings.proxy_ipv6 = false;
    let rs = RuleSet::compile(&c).unwrap();
    let ex = HashSet::new();
    let catch = |r: Route| fin(r, Some("everything-else"), MatchReason::CatchAll);
    for (proto, dst, domain) in [
        (Protocol::Tcp, "[2606:4700::1]:443", Some("x.com")),
        (Protocol::Tcp, "[2606:4700::1]:22", None),
        (Protocol::Udp, "[2606:4700::1]:27015", None),
    ] {
        assert_eq!(
            run(&rs, &ex, proto, 40, dst, domain),
            catch(Route::Block),
            "{proto:?} {dst}"
        );
    }
    // IPv4 is unaffected.
    assert_eq!(
        run(&rs, &ex, Protocol::Tcp, 40, "1.2.3.4:443", Some("x.com")),
        catch(proxy())
    );
    assert_eq!(
        run(&rs, &ex, Protocol::Udp, 40, "1.2.3.4:27015", None),
        catch(proxy())
    );
    // On: proxied IPv6 TCP and UDP go to the proxy.
    c.settings.proxy_ipv6 = true;
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &ex, Protocol::Tcp, 40, "[2606:4700::1]:22", None),
        catch(proxy())
    );
    assert_eq!(
        run(&rs, &ex, Protocol::Udp, 40, "[2606:4700::1]:27015", None),
        catch(proxy())
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
        &RuleSet::compile_with(&cfg(), &geo, &Default::default()).unwrap(),
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

fn geo_cfg(c: &Config, with_data: bool) -> RuleSet {
    use q2route_core::geosite::{DomainSet, GeoSite};
    let sites = if with_data {
        GeoSite::from_sets([(
            "ir".to_string(),
            DomainSet::from_entries(&[], &["digikala.com"], &[]),
        )])
    } else {
        GeoSite::default()
    };
    RuleSet::compile_with(c, &q2route_core::geoip::GeoIp::default(), &sites).unwrap()
}

#[test]
fn geosite_ir_direct() {
    let rs = geo_cfg(&cfg(), true);
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:443",
            Some("www.digikala.com")
        ),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn shared_names_in_geosite_ir_are_proxied_not_direct() {
    use q2route_core::geosite::{DomainSet, GeoSite};
    let sites = GeoSite::from_sets([(
        "ir".to_string(),
        DomainSet::from_entries(&[], &["co.com", "digikala.com"], &[]),
    )]);
    let rs = RuleSet::compile_with(
        &Config::seed(),
        &q2route_core::geoip::GeoIp::default(),
        &sites,
    )
    .unwrap();
    let go = |host| {
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:443",
            Some(host),
        )
    };
    assert_eq!(
        go("shop.co.com"),
        fin(proxy(), Some("not-iranian"), MatchReason::Own)
    );
    assert_eq!(
        go("www.digikala.com"),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn geosite_missing_data_goes_to_proxy() {
    let rs = geo_cfg(&cfg(), false);
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:443",
            Some("www.digikala.com")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn geosite_rule_needs_domain_like_suffix() {
    let rs = geo_cfg(&cfg(), true);
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:443",
            None
        ),
        Decision::NeedDomain
    );
}

#[test]
fn geosite_and_port_anded() {
    let mut c = cfg();
    c.groups[0].rules = vec![Rule {
        domains: vec!["geosite:ir".into()],
        ports: vec!["8443".into()],
        ..Rule::default()
    }];
    let rs = geo_cfg(&c, true);
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:443",
            Some("www.digikala.com")
        ),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            40,
            "34.160.111.145:8443",
            Some("www.digikala.com")
        ),
        fin(Route::Direct, Some("iranian-sites"), MatchReason::Own)
    );
}

#[test]
fn seed_steam_geosite_end_to_end() {
    use q2route_core::geosite::{DomainSet, GeoSite};
    let mut c = Config::seed();
    c.set_group_enabled("steam", true).unwrap();
    let sites = GeoSite::from_sets([
        (
            "steam".to_string(),
            DomainSet::from_entries(&[], &["steampowered.com"], &[]),
        ),
        (
            "ir".to_string(),
            DomainSet::from_entries(&[], &["digikala.com"], &[]),
        ),
    ]);
    let rs = RuleSet::compile_with(&c, &q2route_core::geoip::GeoIp::default(), &sites).unwrap();
    let go = |dst, dom| run(&rs, &HashSet::new(), Protocol::Tcp, 40, dst, dom);
    assert_eq!(
        go("34.160.111.145:443", Some("store.steampowered.com")),
        fin(Route::Direct, Some("steam"), MatchReason::Own)
    );
    assert_eq!(go("34.160.111.145:443", None), Decision::NeedDomain);
}

fn app_rule(app: &str, action: Action, enabled: bool) -> AppRule {
    AppRule {
        app: app.into(),
        action,
        enabled,
    }
}

fn app_route(c: &Config, pid: u32) -> Decision {
    run(
        &RuleSet::compile(c).unwrap(),
        &HashSet::new(),
        Protocol::Tcp,
        pid,
        "8.8.8.8:443",
        Some("example.ir"),
    )
}

#[test]
fn app_rules_precede_matching_groups_and_first_match_wins() {
    let mut c = cfg();
    c.app_rules = vec![
        app_rule("steam.exe", Action::Block, true),
        app_rule("steam*.exe", Action::Direct, true),
    ];
    assert_eq!(
        app_route(&c, 10),
        Decision::Final(
            Route::Block,
            MatchInfo {
                group_id: None,
                reason: MatchReason::Own
            }
        )
    );
    c.app_rules.swap(0, 1);
    assert!(matches!(
        app_route(&c, 10),
        Decision::Final(Route::Direct, _)
    ));
}

#[test]
fn app_rules_disabled_ignored_and_do_not_inherit() {
    let mut c = cfg();
    c.app_rules = vec![app_rule("steam.exe", Action::Block, false)];
    assert!(matches!(
        app_route(&c, 10),
        Decision::Final(Route::Direct, _)
    ));
    c.app_rules[0].enabled = true;
    assert!(matches!(
        app_route(&c, 20),
        Decision::Final(Route::Direct, _)
    ));
    // Even when no ancestor/group can route it, the child's own exe is required.
    c.groups.retain(|g| g.catch_all);
    assert!(matches!(
        app_route(&c, 20),
        Decision::Final(Route::Proxy(_), _)
    ));
}

#[test]
fn app_rules_folder_matches_descendants_not_sibling_prefix() {
    let mut c = cfg();
    c.app_rules = vec![app_rule(
        r"c:/PROGRAM FILES (x86)/Steam/",
        Action::Block,
        true,
    )];
    assert!(matches!(
        app_route(&c, 20),
        Decision::Final(Route::Block, _)
    ));
    c.app_rules[0].app = r"C:\Program Files (x86)\Stea\".into();
    assert!(matches!(
        app_route(&c, 20),
        Decision::Final(Route::Direct, _)
    ));
}

#[test]
fn app_rules_deleted_proxy_is_block_not_fallback() {
    let mut c = cfg();
    let mut proxy = c.proxies[0].clone();
    proxy.id = "deleted".into();
    c.upsert_proxy(proxy).unwrap();
    c.app_rules = vec![app_rule("steam.exe", Action::Proxy("deleted".into()), true)];
    c.delete_proxy("deleted").unwrap();
    c.validate().unwrap();
    assert!(matches!(
        app_route(&c, 10),
        Decision::Final(Route::Block, _)
    ));
}

#[test]
fn app_rules_preserve_infrastructure_and_proxy_guards() {
    let mut c = cfg();
    c.app_rules = vec![app_rule("*.exe", Action::Block, true)];
    let rs = RuleSet::compile(&c).unwrap();
    for (pid, dst, ex, reason) in [
        (
            10,
            "192.168.1.1:80",
            HashSet::new(),
            MatchReason::AlwaysDirectDst,
        ),
        (
            10,
            "8.8.8.8:80",
            HashSet::from([10]),
            MatchReason::ExcludedPid,
        ),
        (
            50,
            "8.8.8.8:80",
            HashSet::new(),
            MatchReason::AlwaysDirectApp,
        ),
    ] {
        assert_eq!(
            run(&rs, &ex, Protocol::Tcp, pid, dst, None),
            Decision::Final(
                Route::Direct,
                MatchInfo {
                    group_id: None,
                    reason
                }
            )
        );
    }
    c.app_rules = vec![app_rule("steam.exe", Action::Proxy("v2ray".into()), true)];
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 10, "8.8.8.8:443", None),
        Decision::NeedDomain
    );
    assert!(matches!(
        run(
            &rs,
            &HashSet::new(),
            Protocol::Tcp,
            10,
            "8.8.8.8:443",
            Some("dns.google")
        ),
        Decision::Final(Route::Block, _)
    ));
    assert!(matches!(
        run(&rs, &HashSet::new(), Protocol::Udp, 10, "8.8.8.8:443", None),
        Decision::Final(Route::Block, _)
    ));
}

#[test]
fn app_rules_dns_process_priority_disabled_children_and_exclusions() {
    let mut c = cfg();
    c.app_rules = vec![app_rule("steam.exe", Action::Block, true)];
    let query = |c: &Config, pid, ex: &HashSet<u32>| {
        decide_dns_for_process(
            &RuleSet::compile(c).unwrap(),
            &tree(),
            ex,
            pid,
            "example.ir",
        )
        .0
    };
    assert_eq!(query(&c, 10, &HashSet::new()), Route::Block);
    assert_eq!(query(&c, 20, &HashSet::new()), Route::Direct);
    assert_eq!(query(&c, 10, &HashSet::from([10])), Route::Direct);
    c.app_rules[0].enabled = false;
    assert_eq!(query(&c, 10, &HashSet::new()), Route::Direct);
    c.app_rules = vec![app_rule("*.exe", Action::Proxy("deleted".into()), true)];
    assert_eq!(query(&c, 10, &HashSet::new()), Route::Block);
    assert_eq!(query(&c, 50, &HashSet::new()), Route::Direct);
    c.app_rules[0].action = Action::Proxy("v2ray".into());
    assert_eq!(query(&c, 10, &HashSet::new()), Route::Proxy("v2ray".into()));
}
