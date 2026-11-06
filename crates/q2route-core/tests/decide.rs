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
    let rs = RuleSet::compile(&c).unwrap();
    assert_eq!(
        run(&rs, &HashSet::new(), Protocol::Tcp, 40, "1.2.3.4:443", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
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
fn dns_ntp_direct_m1() {
    let direct = fin(Route::Direct, None, MatchReason::AlwaysDirectDst);
    assert_eq!(d(Protocol::Udp, 60, "8.8.8.8:53", None), direct);
    assert_eq!(d(Protocol::Udp, 60, "1.2.3.4:123", None), direct);
    assert_eq!(d(Protocol::Tcp, 60, "8.8.8.8:53", None), direct);
}

#[test]
fn udp_proxy_ipv4_routes_to_proxy() {
    assert_eq!(
        d(Protocol::Udp, 40, "5.6.7.8:27015", None),
        fin(proxy(), Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn udp_443_and_ipv6_stay_blocked() {
    // QUIC (UDP/443) stays blocked so apps fall back to TCP through the proxy.
    assert_eq!(
        d(Protocol::Udp, 40, "1.2.3.4:443", None),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
    assert_eq!(
        d(Protocol::Udp, 40, "[2606:4700::1]:5000", None),
        fin(Route::Block, Some("everything-else"), MatchReason::CatchAll)
    );
}

#[test]
fn ipv6_proxy_blocked_m1() {
    assert_eq!(
        d(Protocol::Tcp, 40, "[2606:4700::1]:443", Some("x.com")),
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
