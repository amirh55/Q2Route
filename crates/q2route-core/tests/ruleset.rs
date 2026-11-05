use q2route_core::ruleset::*;
use q2route_core::*;

#[test]
fn compile_seed() {
    let rs = RuleSet::compile(&Config::seed()).unwrap();
    let ids: Vec<&str> = rs.groups.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids, vec!["iranian-sites", "games", "everything-else"]);
    assert!(rs.groups[2].catch_all);
    assert_eq!(rs.groups[2].action, Action::Proxy("v2ray".into()));
    assert_eq!(rs.groups[0].rules[0].domains.len(), 1);
    assert_eq!(rs.always_direct.len(), 7);
    assert!(rs.lan_direct);
}

#[test]
fn enabled_group_bad_pattern_names_group() {
    let mut cfg = Config::seed();
    cfg.groups[0].rules[0].domains = vec!["*.".into()];
    match RuleSet::compile(&cfg) {
        Err(e) => assert!(e.to_string().contains("iranian-sites"), "{e}"),
        Ok(_) => panic!("expected error"),
    }
}

#[test]
fn bad_pattern_errors() {
    let mut cfg = Config::seed();
    cfg.groups[2].rules.push(Rule { domains: vec!["*.".into()], ..Rule::default() });
    let e = RuleSet::compile(&cfg).expect_err("error");
    assert!(e.to_string().contains("games"), "{e}");
}

#[test]
fn disabled_group_bad_pattern_is_skipped() {
    let mut cfg = Config::seed();
    cfg.groups[1].rules[0].domains = vec!["*.".into()]; // steam is disabled
    assert!(RuleSet::compile(&cfg).is_ok());
}
