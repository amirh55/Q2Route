use q2route_core::ipc::*;
use q2route_core::proxy::ProxyTestResult;
use q2route_core::{Action, Config, ProxyKind, ProxyProfile};
use std::collections::HashMap;
use std::io::ErrorKind;
use tokio::io::{duplex, AsyncWriteExt};

fn profile() -> ProxyProfile {
    Config::seed().proxies[0].clone()
}

#[tokio::test]
async fn roundtrip_over_duplex() {
    let reqs = vec![
        Request::GetState,
        Request::Start,
        Request::Stop,
        Request::SetGroupAction {
            group_id: "g".into(),
            action: Action::Direct,
        },
        Request::SetGroupEnabled {
            group_id: "g".into(),
            enabled: false,
        },
        Request::UpsertProxy(profile()),
        Request::DeleteProxy { id: "v2ray".into() },
        Request::TestProxy { id: "v2ray".into() },
        Request::Subscribe,
    ];
    let (mut a, mut b) = duplex(1 << 16);
    for r in &reqs {
        write_msg(&mut a, r).await.unwrap();
    }
    for r in &reqs {
        let got: Request = read_msg(&mut b).await.unwrap();
        assert_eq!(&got, r);
    }
}

#[tokio::test]
async fn server_msgs_roundtrip() {
    let snap = StateSnapshot {
        running: true,
        config: Config::seed(),
        groups: HashMap::from([(
            "g".to_string(),
            GroupStats {
                up_bps: 1,
                down_bps: 2,
                active: 3,
            },
        )]),
        proxy_up: HashMap::from([("v2ray".to_string(), true)]),
        total_up_bps: 10,
        total_down_bps: 20,
        proxy_servers: vec!["vpn.example.com".into()],
    };
    let msgs = vec![
        ServerMsg::Response(Response::Ok),
        ServerMsg::Response(Response::State(snap.clone())),
        ServerMsg::Response(Response::ProxyTest(ProxyTestResult {
            tcp_ok: true,
            latency_ms: Some(5),
            error: None,
            udp_ok: Some(true),
        })),
        ServerMsg::Response(Response::Error("x".into())),
        ServerMsg::Event(Event::Snapshot(Box::new(snap))),
        ServerMsg::Event(Event::ProxyDown { id: "v2ray".into() }),
        ServerMsg::Event(Event::ProxyUp { id: "v2ray".into() }),
    ];
    let (mut a, mut b) = duplex(1 << 20);
    for m in &msgs {
        write_msg(&mut a, m).await.unwrap();
    }
    for m in &msgs {
        let got: ServerMsg = read_msg(&mut b).await.unwrap();
        assert_eq!(&got, m);
    }
}

#[tokio::test]
async fn oversize_rejected() {
    let (mut a, mut b) = duplex(64);
    a.write_all(&(17u32 * 1024 * 1024).to_le_bytes())
        .await
        .unwrap();
    let e = read_msg::<_, Request>(&mut b).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn eof_and_bad_json() {
    let (a, mut b) = duplex(64);
    drop(a);
    let e = read_msg::<_, Request>(&mut b).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedEof);

    let (mut a, mut b) = duplex(64);
    a.write_all(&3u32.to_le_bytes()).await.unwrap();
    a.write_all(b"xyz").await.unwrap();
    let e = read_msg::<_, Request>(&mut b).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
}

#[test]
fn pipe_name() {
    assert_eq!(PIPE_NAME, r"\\.\pipe\q2route");
    assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
    let _ = ProxyKind::Socks5;
}

#[test]
fn new_variants_round_trip() {
    use q2route_core::decide::Route;
    use q2route_core::{Protocol, Rule};
    let rule = Rule {
        apps: vec!["a.exe".into()],
        ..Rule::default()
    };
    for r in [
        Request::AddGroup {
            name: "n".into(),
            action: Action::Block,
        },
        Request::RenameGroup {
            group_id: "g".into(),
            name: "n".into(),
        },
        Request::DeleteGroup {
            group_id: "g".into(),
        },
        Request::MoveGroup {
            group_id: "g".into(),
            to: 2,
        },
        Request::SetGroupRules {
            group_id: "g".into(),
            rules: vec![rule.clone()],
        },
        Request::AddRule {
            group_id: "g".into(),
            rule,
        },
        Request::GetConnections,
        Request::ListProcesses,
    ] {
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }
    let conn = ConnInfo {
        id: 1,
        proto: Protocol::Tcp,
        pid: 4,
        exe: "a.exe".into(),
        exe_path: r"C:\Example\a.exe".into(),
        local: "127.0.0.1:5000".parse().unwrap(),
        dst: "1.2.3.4:443".parse().unwrap(),
        domain: Some("x.com".into()),
        route: Route::Proxy("v2ray".into()),
        group_id: Some("g".into()),
        reason: "own".into(),
        started_ms: 10,
        ended_ms: None,
        up: Some(1),
        down: None,
    };
    for r in [
        Response::Connections(vec![conn]),
        Response::Processes(vec![ProcEntry {
            pid: 4,
            name: "a.exe".into(),
            path: r"C:\a.exe".into(),
        }]),
    ] {
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), r);
    }
}

#[test]
fn connection_exe_path_is_optional_on_wire_and_preserved() {
    let legacy = serde_json::json!({
        "id": 1, "proto": "tcp", "pid": 4, "exe": "a.exe",
        "local": "127.0.0.1:5000", "dst": "1.2.3.4:443", "domain": null,
        "route": "Direct", "group_id": null, "reason": "own", "started_ms": 10,
        "ended_ms": null, "up": null, "down": null
    });
    let mut conn: ConnInfo = serde_json::from_value(legacy).unwrap();
    assert!(conn.exe_path.is_empty());
    conn.exe_path = r"C:\Program Files\Example\a.exe".into();
    let encoded = serde_json::to_value(&conn).unwrap();
    assert_eq!(encoded["exe_path"], r"C:\Program Files\Example\a.exe");
    assert_eq!(serde_json::from_value::<ConnInfo>(encoded).unwrap(), conn);
}

#[test]
fn proxy_test_result_without_udp_ok_decodes() {
    let r: ProxyTestResult =
        serde_json::from_str(r#"{"tcp_ok":true,"latency_ms":5,"error":null}"#).unwrap();
    assert_eq!(r.udp_ok, None);
}

#[test]
fn set_dns_and_flush_roundtrip() {
    for r in [
        Request::SetDns(q2route_core::config::DnsSettings {
            proxy_resolver: "9.9.9.9:53".into(),
            block_doh: false,
            direct_names: vec!["vpn.example.com".into()],
        }),
        Request::FlushDns,
        Request::SetProxyIpv6 { enabled: false },
        Request::SetProxyIpv6 { enabled: true },
    ] {
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }
}

#[test]
fn snapshot_without_proxy_servers_decodes() {
    let snap = StateSnapshot {
        running: false,
        config: Config::seed(),
        groups: HashMap::new(),
        proxy_up: HashMap::new(),
        total_up_bps: 0,
        total_down_bps: 0,
        proxy_servers: vec!["x.example".into()],
    };
    let mut v = serde_json::to_value(&snap).unwrap();
    v.as_object_mut().unwrap().remove("proxy_servers");
    let old: StateSnapshot = serde_json::from_value(v).unwrap();
    assert!(old.proxy_servers.is_empty());
}
