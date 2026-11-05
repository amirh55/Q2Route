//! Named-pipe IPC client. A background thread owns a current-thread tokio
//! runtime, (re)connects every 2 s, subscribes on every connect and keeps the
//! latest `Event::Snapshot`. Requests are answered in order: each `send`
//! queues a oneshot that the next `Response` resolves.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use q2route_core::ipc::{read_msg, write_msg, Event, Request, Response, ServerMsg, StateSnapshot};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{mpsc, oneshot};

const RECONNECT: Duration = Duration::from_secs(2);
/// ERROR_PIPE_BUSY: every server instance is taken; retry soon.
const ERROR_PIPE_BUSY: i32 = 231;

type Job = (Request, oneshot::Sender<Response>);

#[derive(Default)]
struct Shared {
    connected: AtomicBool,
    latest: Mutex<Option<StateSnapshot>>,
}

pub struct Client {
    tx: mpsc::UnboundedSender<Job>,
    shared: Arc<Shared>,
}

impl Client {
    /// Starts the background connection thread for pipe `name`.
    pub fn connect(name: &str) -> Client {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let (name, sh) = (name.to_string(), shared.clone());
        std::thread::Builder::new()
            .name("q2route-ipc".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                rt.block_on(run(name, rx, sh));
            })
            .expect("spawn ipc thread");
        Client { tx, shared }
    }

    /// Sends `r`; the receiver yields its `Response`, or
    /// `Response::Error("disconnected")` if the pipe is not (or no longer) connected.
    pub fn send(&self, r: Request) -> oneshot::Receiver<Response> {
        let (tx, rx) = oneshot::channel();
        if let Err(mpsc::error::SendError((_, tx))) = self.tx.send((r, tx)) {
            let _ = tx.send(disconnected());
        }
        rx
    }

    /// Fire-and-forget `send`.
    pub fn post(&self, r: Request) {
        drop(self.send(r));
    }

    pub fn latest(&self) -> Option<StateSnapshot> {
        self.shared.latest.lock().expect("latest lock").clone()
    }

    pub fn connected(&self) -> bool {
        self.shared.connected.load(Ordering::Relaxed)
    }
}

fn disconnected() -> Response {
    Response::Error("disconnected".into())
}

async fn run(name: String, mut rx: mpsc::UnboundedReceiver<Job>, sh: Arc<Shared>) {
    loop {
        let retry = match ClientOptions::new().open(&name) {
            Ok(pipe) => {
                if !session(pipe, &mut rx, &sh).await {
                    return;
                }
                RECONNECT
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => Duration::from_millis(100),
            Err(_) => RECONNECT,
        };
        // While offline, fail requests immediately instead of queueing them.
        let wait = tokio::time::sleep(retry);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                job = rx.recv() => match job {
                    Some((_, tx)) => { let _ = tx.send(disconnected()); }
                    None => return,
                },
            }
        }
    }
}

/// Serves one connection until it drops. Returns false once the `Client` is gone.
async fn session(
    pipe: NamedPipeClient,
    rx: &mut mpsc::UnboundedReceiver<Job>,
    sh: &Shared,
) -> bool {
    let (mut rd, mut wr) = tokio::io::split(pipe);
    // read_msg is not cancel-safe, so it runs in its own task.
    let (msg_tx, mut msgs) = mpsc::unbounded_channel::<ServerMsg>();
    let reader = tokio::spawn(async move {
        while let Ok(m) = read_msg::<_, ServerMsg>(&mut rd).await {
            if msg_tx.send(m).is_err() {
                break;
            }
        }
    });
    // `None` marks our own Subscribe, whose Ok nobody awaits.
    let mut pending: VecDeque<Option<oneshot::Sender<Response>>> = VecDeque::new();
    let mut alive = true;
    if write_msg(&mut wr, &Request::Subscribe).await.is_ok() {
        pending.push_back(None);
        sh.connected.store(true, Ordering::Relaxed);
        loop {
            tokio::select! {
                job = rx.recv() => match job {
                    Some((r, tx)) => {
                        if write_msg(&mut wr, &r).await.is_err() {
                            let _ = tx.send(disconnected());
                            break;
                        }
                        pending.push_back(Some(tx));
                    }
                    None => { alive = false; break; }
                },
                m = msgs.recv() => match m {
                    Some(ServerMsg::Response(resp)) => {
                        if let Some(Some(tx)) = pending.pop_front() {
                            let _ = tx.send(resp);
                        }
                    }
                    Some(ServerMsg::Event(ev)) => apply(sh, ev),
                    None => break,
                },
            }
        }
    }
    reader.abort();
    sh.connected.store(false, Ordering::Relaxed);
    *sh.latest.lock().expect("latest lock") = None;
    for tx in pending.into_iter().flatten() {
        let _ = tx.send(disconnected());
    }
    alive
}

fn apply(sh: &Shared, ev: Event) {
    let mut latest = sh.latest.lock().expect("latest lock");
    let (id, up) = match ev {
        Event::Snapshot(s) => {
            *latest = Some(s);
            return;
        }
        Event::ProxyDown { id } => (id, false),
        Event::ProxyUp { id } => (id, true),
    };
    if let Some(s) = latest.as_mut() {
        s.proxy_up.insert(id, up);
    }
}
