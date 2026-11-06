//! Named-pipe IPC server: one tokio task per client, requests answered in
//! order, `Subscribe` starts streaming engine events on that pipe. A client
//! disconnect only ends its own task; the engine is never touched.

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use q2route_core::ipc::{read_msg, write_msg, Event, Request, Response, ServerMsg};
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use windows::core::w;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the pipe server drives. `handle` returns a boxed future so the trait
/// stays object-safe (`Arc<dyn Control>`).
pub trait Control: Send + Sync {
    fn handle(&self, r: Request) -> BoxFuture<'_, Response>;
    fn subscribe(&self) -> broadcast::Receiver<Event>;
}

/// Pipe DACL:
/// * Interactive Users: read + write data, but not FILE_CREATE_PIPE_INSTANCE
///   (0x12019b = FILE_GENERIC_READ | FILE_GENERIC_WRITE minus
///   FILE_APPEND_DATA), so an unprivileged process cannot add a rogue server
///   instance of the pipe and intercept UI clients;
/// * Administrators, SYSTEM and the pipe's owner: full access.
const PIPE_SDDL: windows::core::PCWSTR =
    w!("D:(A;;0x12019b;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;OW)");

/// An owned security descriptor parsed from SDDL (freed on drop).
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable heap block owned by this value.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above; it is only read after construction.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn new() -> io::Result<SecurityDescriptor> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: PIPE_SDDL is a static NUL-terminated wide string and `sd`
        // is a valid out-pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PIPE_SDDL,
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(io::Error::from)?;
        Ok(SecurityDescriptor(sd))
    }

    fn create(&self, name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        };
        let mut opts = ServerOptions::new();
        // `first_pipe_instance` fails if anyone else already owns the name.
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES whose descriptor lives
        // as long as `self`; CreateNamedPipeW copies what it needs.
        unsafe {
            opts.create_with_security_attributes_raw(
                name,
                (&mut sa as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // with LocalAlloc and freed exactly once.
        unsafe {
            LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

/// Serves `name` until `cancel` fires. Each connected client gets its own
/// task; the function returns only on cancel or if a new pipe instance
/// cannot be created.
pub async fn serve_pipe(
    ctrl: Arc<dyn Control>,
    name: &str,
    cancel: CancellationToken,
) -> io::Result<()> {
    let sd = SecurityDescriptor::new()?;
    let mut server = sd.create(name, true)?;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            r = server.connect() => {
                if let Err(e) = r {
                    tracing::debug!("pipe connect failed: {e}");
                    server = sd.create(name, false)?;
                    continue;
                }
            }
        }
        let client = std::mem::replace(&mut server, sd.create(name, false)?);
        tokio::spawn(serve_client(client, ctrl.clone(), cancel.clone()));
    }
}

async fn serve_client(pipe: NamedPipeServer, ctrl: Arc<dyn Control>, cancel: CancellationToken) {
    let (mut rd, mut wr) = tokio::io::split(pipe);
    // read_msg is not cancel-safe, so it runs in its own task.
    let (tx, mut rx) = mpsc::channel::<Request>(8);
    let reader = tokio::spawn(async move {
        while let Ok(r) = read_msg::<_, Request>(&mut rd).await {
            if tx.send(r).await.is_err() {
                break;
            }
        }
    });
    let mut events: Option<broadcast::Receiver<Event>> = None;
    let mut pending: Option<BoxFuture<'_, Response>> = None;
    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => break,
            r = rx.recv(), if pending.is_none() => match r {
                None => break,
                Some(Request::Subscribe) => {
                    events = Some(ctrl.subscribe());
                    ServerMsg::Response(Response::Ok)
                }
                Some(r) => {
                    pending = Some(ctrl.handle(r));
                    continue;
                }
            },
            resp = async { pending.as_mut().expect("guarded").await }, if pending.is_some() => {
                pending = None;
                ServerMsg::Response(resp)
            }
            ev = async { events.as_mut().expect("guarded").recv().await }, if events.is_some() => match ev {
                Ok(ev) => ServerMsg::Event(ev),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    events = None;
                    continue;
                }
            },
        };
        if write_msg(&mut wr, &msg).await.is_err() {
            break;
        }
    }
    reader.abort();
    let _ = wr.shutdown().await;
}
