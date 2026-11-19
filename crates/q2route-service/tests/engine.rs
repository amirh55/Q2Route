//! Engine control-plane tests that need no admin rights: config mutations
//! through `Control::handle` (routing is never started here).

use std::path::PathBuf;

use q2route_core::config::{Action, Config};
use q2route_core::ipc::{Request, Response};
use q2route_service::engine::Engine;
use q2route_service::ipc_server::Control;

fn temp_config(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("q2route-engine-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("config.toml")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutations_persist_and_failures_change_nothing() {
    let path = temp_config("mutate");
    let engine = Engine::new(path.clone()).unwrap();
    assert!(path.exists(), "seed config saved");
    assert!(engine.last_running());

    let r = engine
        .handle(Request::SetGroupEnabled {
            group_id: "steam".into(),
            enabled: true,
        })
        .await;
    assert_eq!(r, Response::Ok);
    let saved = Config::load(&path).unwrap();
    assert!(
        saved
            .groups
            .iter()
            .find(|g| g.id == "steam")
            .unwrap()
            .enabled
    );

    // Unknown proxy: rejected, neither memory nor disk changes.
    let before = std::fs::read_to_string(&path).unwrap();
    let r = engine
        .handle(Request::SetGroupAction {
            group_id: "games".into(),
            action: Action::Proxy("nope".into()),
        })
        .await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    let r = engine
        .handle(Request::DeleteProxy { id: "v2ray".into() })
        .await;
    assert!(
        matches!(r, Response::Error(_)),
        "referenced proxy cannot be deleted: {r:?}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    match engine.handle(Request::GetState).await {
        Response::State(s) => {
            assert!(!s.running);
            assert_eq!(s.config, Config::load(&path).unwrap());
        }
        other => panic!("unexpected {other:?}"),
    }

    // A fresh engine (service restart) sees the toggle.
    let again = Engine::new(path.clone()).unwrap();
    assert!(
        again
            .snapshot()
            .config
            .groups
            .iter()
            .find(|g| g.id == "steam")
            .unwrap()
            .enabled
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_when_stopped_persists_last_running() {
    let path = temp_config("stop");
    let engine = Engine::new(path.clone()).unwrap();
    assert_eq!(engine.handle(Request::Stop).await, Response::Ok);
    assert!(!Config::load(&path).unwrap().settings.last_running);
    assert!(!Engine::new(path).unwrap().last_running());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_proxy_is_an_error() {
    let engine = Engine::new(temp_config("test-proxy")).unwrap();
    let r = engine
        .handle(Request::TestProxy {
            id: "missing".into(),
        })
        .await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_proxy_ipv6_persists() {
    let path = temp_config("proxy-ipv6");
    let engine = Engine::new(path.clone()).unwrap();
    assert!(engine.snapshot().config.settings.proxy_ipv6, "default on");
    let r = engine
        .handle(Request::SetProxyIpv6 { enabled: false })
        .await;
    assert_eq!(r, Response::Ok);
    assert!(!Config::load(&path).unwrap().settings.proxy_ipv6);
    assert!(!engine.snapshot().config.settings.proxy_ipv6);
    let r = engine.handle(Request::SetProxyIpv6 { enabled: true }).await;
    assert_eq!(r, Response::Ok);
    assert!(Config::load(&path).unwrap().settings.proxy_ipv6);
}

fn key(group: &str) -> q2route_service::usage::UsageKey {
    q2route_service::usage::UsageKey {
        group: group.into(),
        app: "app.exe".into(),
        proxy: "v2ray".into(),
    }
}

async fn usage_report(engine: &Engine) -> q2route_core::ipc::UsageReport {
    match engine.handle(Request::GetUsage).await {
        Response::Usage(r) => r,
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usage_ipc_get_set_reset() {
    let path = temp_config("usage-ipc");
    let usage_path = path.with_file_name("usage.json");
    let engine = Engine::new(path.clone()).unwrap();
    let r = usage_report(&engine).await;
    assert!(!r.enabled && r.session.is_empty() && r.days.is_empty());
    // Off: nothing counted, nothing written.
    engine.usage().add(&key("g"), 5, 5);
    assert!(usage_report(&engine).await.session.is_empty());
    assert!(!usage_path.exists());

    let r = engine.handle(Request::SetDataUsage { enabled: true }).await;
    assert_eq!(r, Response::Ok);
    assert!(Config::load(&path).unwrap().settings.data_usage);
    engine.usage().add(&key("g"), 5, 7);
    let r = usage_report(&engine).await;
    assert!(r.enabled);
    assert_eq!((r.session[0].up, r.session[0].down), (5, 7));
    assert_eq!(r.days.len(), 1);

    engine.usage().save_if_dirty().unwrap();
    assert!(usage_path.exists());
    assert_eq!(engine.handle(Request::ResetUsage).await, Response::Ok);
    let r = usage_report(&engine).await;
    assert!(r.enabled && r.session.is_empty() && r.days.is_empty());
    assert!(!usage_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn toggle_keeps_history() {
    let path = temp_config("usage-toggle");
    let usage_path = path.with_file_name("usage.json");
    let engine = Engine::new(path.clone()).unwrap();
    engine.handle(Request::SetDataUsage { enabled: true }).await;
    engine.usage().add(&key("g"), 10, 20);
    // Turning it off saves, keeps the history and the session, and stops counting.
    engine
        .handle(Request::SetDataUsage { enabled: false })
        .await;
    assert!(usage_path.exists(), "saved when turned off");
    engine.usage().add(&key("g"), 1000, 1000);
    let r = usage_report(&engine).await;
    assert!(!r.enabled);
    assert_eq!((r.session[0].up, r.session[0].down), (10, 20));
    assert_eq!((r.days[0].1[0].up, r.days[0].1[0].down), (10, 20));
    // Back on: continues from the same totals.
    engine.handle(Request::SetDataUsage { enabled: true }).await;
    engine.usage().add(&key("g"), 1, 2);
    let r = usage_report(&engine).await;
    assert_eq!((r.session[0].up, r.session[0].down), (11, 22));
    // A restart loads the history (session starts empty), even while off.
    engine
        .handle(Request::SetDataUsage { enabled: false })
        .await;
    let again = Engine::new(path).unwrap();
    let r = usage_report(&again).await;
    assert!(!r.enabled && r.session.is_empty());
    assert_eq!((r.days[0].1[0].up, r.days[0].1[0].down), (11, 22));
}
