use q2route_core::*;

#[test]
fn seed_matches_spec() {
    let c = Config::seed();
    let g: Vec<_> = c
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.action.clone(), g.enabled))
        .collect();
    assert_eq!(
        g,
        vec![
            ("Iranian sites", Action::Direct, true),
            ("Steam", Action::Direct, false),
            ("Games", Action::Direct, true),
            ("Everything else", Action::Proxy("v2ray".into()), true),
        ]
    );
    let ids: Vec<_> = c.groups.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids, ["iranian-sites", "steam", "games", "everything-else"]);
    assert_eq!(c.groups[0].rules[0].domains, ["*.ir"]);
    assert_eq!(c.groups[0].rules[1].ips, ["geoip:ir"]);
    assert_eq!(c.seed_version, SEED_VERSION);
    assert_eq!(c.groups[1].rules[0].apps, ["steam.exe"]);
    assert!(c.groups[1].rules[0].include_children);
    assert!(c.groups[2].rules.is_empty());
    assert!(c.groups[3].catch_all && c.groups[3].rules.is_empty());
    assert_eq!(c.proxies.len(), 1);
    let p = &c.proxies[0];
    assert_eq!(
        (p.id.as_str(), p.kind, p.host.as_str(), p.port),
        ("v2ray", ProxyKind::Socks5, "127.0.0.1", 10808)
    );
    assert_eq!(c.default_proxy, "v2ray");
    assert_eq!(
        c.always_direct,
        [
            "v2ray.exe",
            "xray.exe",
            "sing-box.exe",
            "v2rayN.exe",
            "nekoray.exe",
            "hiddify.exe",
            "clash*.exe"
        ]
    );
    assert_eq!(c.settings.peek_timeout_ms, 300);
    assert!(c.settings.last_running);
    c.validate().unwrap();
}

#[test]
fn roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let c = Config::seed();
    c.save(&path).unwrap();
    assert_eq!(Config::load(&path).unwrap(), c);
}

#[test]
fn load_missing_creates_seed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("config.toml");
    assert_eq!(Config::load(&path).unwrap(), Config::seed());
    assert!(path.exists());
}

#[test]
fn action_toml_shape() {
    // Semantic shape: Proxy is a single-key table `{ proxy = "v2ray" }`, Direct a bare string.
    let v = toml::Value::try_from(Action::Proxy("v2ray".into())).unwrap();
    assert_eq!(
        v,
        toml::Value::Table(
            [("proxy".to_string(), "v2ray".into())]
                .into_iter()
                .collect()
        )
    );
    assert_eq!(
        toml::Value::try_from(Action::Direct).unwrap(),
        toml::Value::String("direct".into())
    );
    // Hand-written inline form parses back.
    #[derive(serde::Deserialize)]
    struct W {
        action: Action,
    }
    let w: W = toml::from_str(r#"action = { proxy = "v2ray" }"#).unwrap();
    assert_eq!(w.action, Action::Proxy("v2ray".into()));
    let w: W = toml::from_str(r#"action = "block""#).unwrap();
    assert_eq!(w.action, Action::Block);
}

#[test]
fn hand_written_toml_uses_defaults() {
    let c: Config = toml::from_str(
        r#"
default_proxy = "v2ray"
[[proxies]]
id = "v2ray"
name = "V2Ray"
kind = "socks5"
host = "127.0.0.1"
port = 10808
[[groups]]
id = "g"
name = "G"
action = "block"
[[groups.rules]]
domains = ["a.com"]
"#,
    )
    .unwrap();
    assert!(c.groups[0].enabled);
    assert!(c.groups[0].rules[0].include_children);
    assert_eq!(c.settings.peek_timeout_ms, 300);
    assert!(c.always_direct.is_empty());
}

#[test]
fn proxy_ipv6_defaults_on_for_old_configs() {
    assert!(Config::seed().settings.proxy_ipv6);
    // A config written before the setting existed loads with it on.
    let c: Config = toml::from_str(
        r#"
default_proxy = "v2ray"
[settings]
peek_timeout_ms = 300
[settings.dns]
block_doh = true
"#,
    )
    .unwrap();
    assert!(c.settings.proxy_ipv6);
    let off: Config = toml::from_str(
        r#"
default_proxy = "v2ray"
[settings]
proxy_ipv6 = false
"#,
    )
    .unwrap();
    assert!(!off.settings.proxy_ipv6);
}

#[test]
fn validate_rejects() {
    let mut c = Config::seed();
    c.groups[0].action = Action::Proxy("nope".into());
    assert!(c.validate().is_err());

    let mut c = Config::seed();
    c.groups[1].id = c.groups[0].id.clone();
    assert!(c.validate().is_err());

    let mut c = Config::seed();
    c.groups.swap(2, 3);
    assert!(c.validate().is_err());

    let mut c = Config::seed();
    c.default_proxy = "nope".into();
    assert!(c.validate().is_err());

    // Ruling R18: the catch-all must exist and be enabled.
    let mut c = Config::seed();
    c.groups.pop();
    assert!(c.validate().is_err(), "missing catch-all");

    let mut c = Config::seed();
    c.groups.last_mut().unwrap().enabled = false;
    assert!(c.validate().is_err(), "disabled catch-all");

    let mut c = Config::seed();
    c.groups.clear();
    assert!(c.validate().is_err(), "no groups at all");
}

#[test]
fn catch_all_cannot_be_disabled() {
    let mut c = Config::seed();
    let before = c.clone();
    assert!(c.set_group_enabled("everything-else", false).is_err());
    assert_eq!(c, before);
    // Other groups still toggle.
    c.set_group_enabled("games", false).unwrap();
}

#[test]
fn load_rejects_disabled_catch_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut c = Config::seed();
    c.groups.last_mut().unwrap().enabled = false;
    std::fs::write(&path, toml::to_string_pretty(&c).unwrap()).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn toggle_persists_across_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut c = Config::seed();
    c.set_group_action("steam", Action::Proxy("v2ray".into()))
        .unwrap();
    c.set_group_enabled("steam", true).unwrap();
    c.save(&path).unwrap();
    let l = Config::load(&path).unwrap();
    let steam = l.groups.iter().find(|g| g.id == "steam").unwrap();
    assert_eq!(steam.action, Action::Proxy("v2ray".into()));
    assert!(steam.enabled);
}

#[test]
fn group_helpers_reject_unknown_and_roll_back() {
    let mut c = Config::seed();
    let before = c.clone();
    assert!(c.set_group_action("nope", Action::Direct).is_err());
    assert!(c.set_group_enabled("nope", false).is_err());
    assert!(c
        .set_group_action("steam", Action::Proxy("ghost".into()))
        .is_err());
    assert_eq!(c, before);
}

#[test]
fn delete_proxy_in_use_fails() {
    let mut c = Config::seed();
    let before = c.clone();
    assert!(c.delete_proxy("v2ray").is_err());
    assert_eq!(c, before);
}

#[test]
fn upsert_and_delete_proxy() {
    let mut c = Config::seed();
    let p = ProxyProfile {
        id: "alt".into(),
        name: "Alt".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: 8080,
        username: None,
        password: None,
    };
    c.upsert_proxy(p.clone()).unwrap();
    assert_eq!(c.proxies.len(), 2);
    let mut p2 = p;
    p2.port = 9090;
    c.upsert_proxy(p2).unwrap();
    assert_eq!(c.proxies.len(), 2);
    assert_eq!(c.proxies[1].port, 9090);
    c.delete_proxy("alt").unwrap();
    assert_eq!(c.proxies.len(), 1);
    assert!(c.delete_proxy("alt").is_err());
}

#[test]
fn migrate_adds_geoip_ir_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // An M1 config: no seed_version, "Iranian sites" has only *.ir.
    let mut old = Config::seed();
    old.seed_version = 0;
    old.groups[0].rules.truncate(1);
    old.save(&path).unwrap();

    let c = Config::load(&path).unwrap();
    assert_eq!(c.seed_version, SEED_VERSION);
    assert_eq!(c.groups[0].rules.len(), 2);
    assert_eq!(c.groups[0].rules[1].ips, ["geoip:ir"]);
    // Saved, and not added again on the next load.
    let again = Config::load(&path).unwrap();
    assert_eq!(again, c);
}

#[test]
fn migrate_respects_user_changes() {
    // geoip:ir already present (any case): not duplicated.
    let mut c = Config::seed();
    c.seed_version = 0;
    c.groups[0].rules[1].ips = vec!["GeoIP:IR".into()];
    assert!(c.migrate());
    assert_eq!(c.groups[0].rules.len(), 2);
    // Group removed by the user: nothing re-created.
    let mut c = Config::seed();
    c.seed_version = 0;
    c.groups.remove(0);
    let before = c.groups.clone();
    assert!(c.migrate());
    assert_eq!(c.groups, before);
    // Up to date: no change.
    assert!(!Config::seed().migrate());
}

#[test]
fn add_group_inserts_before_catch_all_with_unique_id() {
    let mut c = Config::seed();
    assert_eq!(
        c.add_group("My Games!", Action::Direct).unwrap(),
        "my-games"
    );
    assert_eq!(
        c.add_group("my games", Action::Block).unwrap(),
        "my-games-2"
    );
    let ids: Vec<_> = c.groups.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "iranian-sites",
            "steam",
            "games",
            "my-games",
            "my-games-2",
            "everything-else"
        ]
    );
    assert!(c.add_group("   ", Action::Direct).is_err());
}

#[test]
fn delete_rename_move_respect_catch_all() {
    let mut c = Config::seed();
    assert!(c.delete_group("everything-else").is_err());
    assert!(c.move_group("everything-else", 0).is_err());
    assert!(c.move_group("games", 3).is_err()); // catch-all's index
    c.move_group("games", 0).unwrap();
    assert_eq!(c.groups[0].id, "games");
    c.rename_group("games", "Online games").unwrap();
    assert_eq!(
        (c.groups[0].id.as_str(), c.groups[0].name.as_str()),
        ("games", "Online games")
    );
    assert!(c.rename_group("games", " ").is_err());
    c.delete_group("games").unwrap();
    assert!(c.groups.iter().all(|g| g.id != "games"));
    assert!(c.delete_group("games").is_err());
}

#[test]
fn set_group_rules_keeps_action_and_enabled() {
    let mut c = Config::seed();
    c.set_group_action("steam", Action::Proxy("v2ray".into()))
        .unwrap();
    let rules = vec![Rule {
        apps: vec!["steam.exe".into(), "steamwebhelper.exe".into()],
        ..Rule::default()
    }];
    c.set_group_rules("steam", rules.clone()).unwrap();
    let g = c.groups.iter().find(|g| g.id == "steam").unwrap();
    assert_eq!(g.rules, rules);
    assert_eq!(g.action, Action::Proxy("v2ray".into()));
    assert!(!g.enabled);
}

#[test]
fn set_group_rules_rejects_bad_entries() {
    let mut c = Config::seed();
    let before = c.clone();
    for bad in [
        Rule {
            ips: vec!["10.0.0.0/33".into()],
            ..Rule::default()
        },
        Rule {
            domains: vec!["*".into()],
            ..Rule::default()
        },
        Rule {
            ports: vec!["80-70".into()],
            ..Rule::default()
        },
        Rule {
            ips: vec!["geoip:".into()],
            ..Rule::default()
        },
        Rule::default(), // no conditions
    ] {
        assert!(c.set_group_rules("games", vec![bad]).is_err());
    }
    assert_eq!(c, before);
    let e = c
        .set_group_rules(
            "games",
            vec![Rule {
                ips: vec!["10.0.0.0/33".into()],
                ..Rule::default()
            }],
        )
        .unwrap_err();
    assert!(e.to_string().contains("10.0.0.0/33"), "{e}");
}

#[test]
fn add_rule_dedupes() {
    let mut c = Config::seed();
    let r = Rule {
        apps: vec!["game.exe".into()],
        ..Rule::default()
    };
    assert!(c.add_rule("games", r.clone()).unwrap());
    assert!(!c.add_rule("games", r).unwrap());
    assert_eq!(
        c.groups
            .iter()
            .find(|g| g.id == "games")
            .unwrap()
            .rules
            .len(),
        1
    );
    assert!(c
        .add_rule(
            "everything-else",
            Rule {
                apps: vec!["x.exe".into()],
                ..Rule::default()
            }
        )
        .is_err());
}

#[test]
fn slug_cases() {
    assert_eq!(slug("Online  Games (UDP)"), "online-games-udp");
    assert_eq!(slug("بازی"), "group");
}

#[test]
fn move_group_huge_index_is_rejected() {
    let mut c = Config::seed();
    let before = c.clone();
    assert!(c.move_group("games", usize::MAX).is_err());
    assert_eq!(c, before);
}

#[test]
fn dns_settings_defaults_and_validation() {
    let mut c = Config::seed();
    assert_eq!(c.settings.dns.proxy_resolver, "1.1.1.1:53");
    assert!(c.settings.dns.block_doh);
    assert!(c.settings.dns.direct_names.is_empty());
    let bad = DnsSettings {
        proxy_resolver: "1.1.1.1".into(),
        block_doh: true,
        direct_names: vec![],
    };
    let e = c.set_dns(bad).unwrap_err().to_string();
    assert!(e.contains("1.1.1.1"));
    assert_eq!(c.settings.dns.proxy_resolver, "1.1.1.1:53");
    c.set_dns(DnsSettings {
        proxy_resolver: "9.9.9.9:53".into(),
        block_doh: false,
        direct_names: vec![],
    })
    .unwrap();
    assert_eq!(c.settings.dns.proxy_resolver, "9.9.9.9:53");
    assert!(!c.settings.dns.block_doh);
}

#[test]
fn dns_direct_names_validated() {
    let mut c = Config::seed();
    let before = c.clone();
    let mut d = c.settings.dns.clone();
    d.direct_names = vec!["vpn.example.com".into(), "*.".into()];
    let e = c.set_dns(d.clone()).unwrap_err().to_string();
    assert!(e.contains("'*.'"), "{e}");
    assert_eq!(c, before);
    d.direct_names = vec![
        "vpn.example.com".into(),
        "*.cdn.example.org".into(),
        "keyword:myvpn".into(),
    ];
    c.set_dns(d.clone()).unwrap();
    assert_eq!(c.settings.dns.direct_names, d.direct_names);
    // Old configs without the field still load.
    let json = r#"{"proxy_resolver":"1.1.1.1:53","block_doh":true}"#;
    let old: DnsSettings = serde_json::from_str(json).unwrap();
    assert!(old.direct_names.is_empty());
}

#[test]
fn hand_edited_bad_dns_settings_rejected_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut c = Config::seed();
    c.settings.dns.proxy_resolver = "not-an-address".into();
    c.save(&path).unwrap();
    let e = Config::load(&path).unwrap_err().to_string();
    assert!(e.contains("not-an-address"), "{e}");
    let mut c = Config::seed();
    c.settings.dns.direct_names = vec!["ok.example.com".into(), "*.".into()];
    c.save(&path).unwrap();
    let e = Config::load(&path).unwrap_err().to_string();
    assert!(e.contains("'*.'"), "{e}");
    c.settings.dns.direct_names = vec!["ok.example.com".into()];
    c.save(&path).unwrap();
    assert_eq!(Config::load(&path).unwrap(), c);
}
