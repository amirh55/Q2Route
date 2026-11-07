//! IPC client tests against a fake `Control` served over a real named pipe.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use q2route_core::config::{Action, Config};
use q2route_core::ipc::{Event, Request, Response, StateSnapshot};
use q2route_service::ipc_server::{serve_pipe, BoxFuture, Control};
use q2route_ui::client::Client;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

fn snapshot() -> StateSnapshot {
    StateSnapshot {
        running: true,
        config: Config::seed(),
        groups: Default::default(),
        proxy_up: Default::default(),
        total_up_bps: 0,
        total_down_bps: 0,
        proxy_servers: vec![],
    }
}

struct Fake {
    events: broadcast::Sender<Event>,
    seen: Mutex<Vec<Request>>,
}

impl Control for Fake {
    fn handle(&self, r: Request) -> BoxFuture<'_, Response> {
        self.seen.lock().unwrap().push(r);
        Box::pin(async { Response::Ok })
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

fn pipe_name(test: &str) -> String {
    format!(r"\\.\pipe\q2route-ui-test-{}-{test}", std::process::id())
}

/// Starts a fake server emitting a snapshot every 100 ms; returns it and its cancel token.
fn serve(name: &str) -> (Arc<Fake>, CancellationToken) {
    let cancel = CancellationToken::new();
    let (events, _) = broadcast::channel(16);
    let fake = Arc::new(Fake {
        events: events.clone(),
        seen: Mutex::new(vec![]),
    });
    let c = cancel.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = c.cancelled() => break,
                _ = tick.tick() => { let _ = events.send(Event::Snapshot(Box::new(snapshot()))); }
            }
        }
    });
    let (f, n, c) = (fake.clone(), name.to_string(), cancel.clone());
    tokio::spawn(async move { serve_pipe(f, &n, c).await.expect("serve_pipe") });
    (fake, cancel)
}

async fn wait_for(what: &str, within: Duration, f: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reconnects() {
    let name = pipe_name("reconnect");
    let (_fake, cancel) = serve(&name);
    let client = Client::connect(&name);
    wait_for("first connect", Duration::from_secs(5), || {
        client.connected()
    })
    .await;
    wait_for("snapshot", Duration::from_secs(5), || {
        client.latest().is_some()
    })
    .await;

    cancel.cancel();
    wait_for("disconnect", Duration::from_secs(5), || !client.connected()).await;

    let (_fake2, cancel2) = serve(&name);
    wait_for("reconnect", Duration::from_secs(5), || client.connected()).await;
    cancel2.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_set_group_action() {
    let name = pipe_name("set-action");
    let (fake, cancel) = serve(&name);
    let client = Client::connect(&name);
    wait_for("connect", Duration::from_secs(5), || client.connected()).await;

    let req = Request::SetGroupAction {
        group_id: "steam".into(),
        action: Action::Direct,
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), client.send(req.clone()))
        .await
        .expect("response in time")
        .expect("sender kept");
    assert_eq!(resp, Response::Ok);
    assert_eq!(fake.seen.lock().unwrap().as_slice(), &[req]);
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_while_disconnected_fails() {
    let client = Client::connect(&pipe_name("nobody"));
    let resp = tokio::time::timeout(Duration::from_secs(5), client.send(Request::Start))
        .await
        .expect("response in time")
        .expect("sender kept");
    assert_eq!(resp, Response::Error("disconnected".into()));
}
