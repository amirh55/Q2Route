//! Pipe server tests with a fake `Control` over a uniquely named real pipe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use q2route_core::config::Config;
use q2route_core::ipc::{read_msg, write_msg, Event, Request, Response, ServerMsg, StateSnapshot};
use q2route_service::ipc_server::{serve_pipe, BoxFuture, Control};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
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
}

impl Fake {
    /// Emits a snapshot every 100 ms until `cancel` fires.
    fn start(cancel: CancellationToken) -> Arc<Fake> {
        let (events, _) = broadcast::channel(16);
        let tx = events.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => { let _ = tx.send(Event::Snapshot(Box::new(snapshot()))); }
                }
            }
        });
        Arc::new(Fake { events })
    }
}

impl Control for Fake {
    fn handle(&self, r: Request) -> BoxFuture<'_, Response> {
        Box::pin(async move {
            match r {
                Request::GetState => Response::State(snapshot()),
                _ => Response::Ok,
            }
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

fn pipe_name(test: &str) -> String {
    format!(r"\\.\pipe\q2route-test-{}-{test}", std::process::id())
}

/// Starts the server and returns its cancel token.
fn serve(test: &str) -> (String, CancellationToken) {
    let name = pipe_name(test);
    let cancel = CancellationToken::new();
    let fake = Fake::start(cancel.clone());
    let (n, c) = (name.clone(), cancel.clone());
    tokio::spawn(async move { serve_pipe(fake, &n, c).await.expect("serve_pipe") });
    (name, cancel)
}

async fn connect(name: &str) -> NamedPipeClient {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match ClientOptions::new().open(name) {
            Ok(c) => return c,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("connect {name}: {e}"),
        }
    }
}

async fn request(c: &mut NamedPipeClient, r: Request) -> ServerMsg {
    write_msg(c, &r).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), read_msg::<_, ServerMsg>(c))
        .await
        .expect("response in time")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_state_roundtrip() {
    let (name, cancel) = serve("get-state");
    let mut c = connect(&name).await;
    match request(&mut c, Request::GetState).await {
        ServerMsg::Response(Response::State(s)) => assert!(s.running),
        other => panic!("unexpected {other:?}"),
    }
    cancel.cancel();
}

async fn count_snapshots(c: &mut NamedPipeClient, within: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + within;
    let mut n = 0;
    while let Ok(m) = tokio::time::timeout_at(deadline, read_msg::<_, ServerMsg>(c)).await {
        if let ServerMsg::Event(Event::Snapshot(_)) = m.unwrap() {
            n += 1;
        }
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_streams_events() {
    let (name, cancel) = serve("subscribe");
    let mut c = connect(&name).await;
    assert_eq!(
        request(&mut c, Request::Subscribe).await,
        ServerMsg::Response(Response::Ok)
    );
    let n = count_snapshots(&mut c, Duration::from_secs(1)).await;
    assert!(n >= 2, "got {n} snapshots");
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_drop_harmless() {
    let (name, cancel) = serve("drop");
    for _ in 0..3 {
        let mut c = connect(&name).await;
        assert_eq!(
            request(&mut c, Request::Subscribe).await,
            ServerMsg::Response(Response::Ok)
        );
        let _ = read_msg::<_, ServerMsg>(&mut c).await.unwrap();
        drop(c); // mid-stream
    }
    let mut c = connect(&name).await;
    assert!(matches!(
        request(&mut c, Request::GetState).await,
        ServerMsg::Response(Response::State(_))
    ));
    // Two concurrent clients are served independently.
    let mut c2 = connect(&name).await;
    assert!(matches!(
        request(&mut c2, Request::GetState).await,
        ServerMsg::Response(Response::State(_))
    ));
    assert!(matches!(
        request(&mut c, Request::GetState).await,
        ServerMsg::Response(Response::State(_))
    ));
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_request_gets_error_and_connection_survives() {
    let (name, cancel) = serve("unknown-request");
    let mut c = connect(&name).await;
    write_msg(&mut c, &serde_json::json!({"FromTheFuture": {"x": 1}}))
        .await
        .unwrap();
    let m = tokio::time::timeout(Duration::from_secs(2), read_msg::<_, ServerMsg>(&mut c))
        .await
        .expect("reply in time")
        .unwrap();
    assert_eq!(
        m,
        ServerMsg::Response(Response::Error("unsupported request".into()))
    );
    assert!(matches!(
        request(&mut c, Request::GetState).await,
        ServerMsg::Response(Response::State(_))
    ));
    cancel.cancel();
}
