use q2route_core::decide::MatchReason;
use q2route_core::process_tree::{ProcInfo, ProcessTree};
use q2route_core::suggest::*;

#[test]
fn app_rule_skips_system_and_unknown() {
    for x in ["", "?", "System", "system", "Idle"] {
        assert!(app_rule(x).is_none(), "{x}");
    }
    let r = app_rule("game.exe").unwrap();
    assert_eq!(r.apps, ["game.exe"]);
    assert!(r.include_children);
}

#[test]
fn domain_and_ip_patterns() {
    assert_eq!(
        domain_patterns("www.Digikala.com."),
        ["www.digikala.com", "*.digikala.com"]
    );
    assert_eq!(
        domain_patterns("digikala.com"),
        ["digikala.com", "*.digikala.com"]
    );
    assert!(domain_patterns("").is_empty());
    assert_eq!(
        ip_patterns("185.188.107.12".parse().unwrap()),
        ["185.188.107.12", "185.188.107.0/24"]
    );
    assert_eq!(
        ip_patterns("2001:db8::1".parse().unwrap()),
        ["2001:db8::1", "2001:db8::/64"]
    );
}

#[test]
fn reason_texts() {
    let mut t = ProcessTree::default();
    t.insert(ProcInfo {
        pid: 10,
        parent: 1,
        exe: r"C:\Steam\steam.exe".into(),
        start_time: 1,
    });
    let s = |r| reason_text(&r, &t);
    assert_eq!(
        s(MatchReason::Inherited { from_pid: 10 }),
        "inherited from steam.exe"
    );
    assert_eq!(s(MatchReason::Inherited { from_pid: 99 }), "inherited");
    assert_eq!(s(MatchReason::Own), "own");
    assert_eq!(s(MatchReason::CatchAll), "catch-all");
    assert_eq!(s(MatchReason::AlwaysDirectApp), "always-direct app");
    assert_eq!(s(MatchReason::AlwaysDirectDst), "always-direct app");
    assert_eq!(s(MatchReason::ExcludedPid), "excluded");
    assert_eq!(s(MatchReason::NoMatch), "no match");
}
