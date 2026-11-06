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
    };
    let msgs = vec![
        ServerMsg::Response(Response::Ok),
        ServerMsg::Response(Response::State(snap.clone())),
        ServerMsg::Response(Response::ProxyTest(ProxyTestResult {
            tcp_ok: true,
            latency_ms: Some(5),
            error: None,
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
