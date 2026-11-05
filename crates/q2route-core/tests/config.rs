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
