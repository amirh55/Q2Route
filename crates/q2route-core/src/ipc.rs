//! UI <-> service IPC: u32-LE length-prefixed JSON frames over a named pipe.

use crate::config::{Action, Config, GroupId, ProfileId, ProxyProfile};
use crate::proxy::ProxyTestResult;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PIPE_NAME: &str = r"\\.\pipe\q2route";
/// Maximum accepted frame body (16 MiB).
pub const MAX_MSG: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Request {
    GetState,
    Start,
    Stop,
    SetGroupAction { group_id: GroupId, action: Action },
    SetGroupEnabled { group_id: GroupId, enabled: bool },
    UpsertProxy(ProxyProfile),
    DeleteProxy { id: ProfileId },
    TestProxy { id: ProfileId },
    Subscribe,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GroupStats {
    pub up_bps: u64,
    pub down_bps: u64,
    pub active: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StateSnapshot {
    pub running: bool,
    pub config: Config,
    pub groups: HashMap<GroupId, GroupStats>,
    pub proxy_up: HashMap<ProfileId, bool>,
    pub total_up_bps: u64,
    pub total_down_bps: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Response {
    Ok,
    State(StateSnapshot),
    ProxyTest(ProxyTestResult),
    Error(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Event {
    /// Sent ~4x per second after `Subscribe`.
    Snapshot(StateSnapshot),
    ProxyDown { id: ProfileId },
    ProxyUp { id: ProfileId },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ServerMsg {
    Response(Response),
    Event(Event),
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, m: &T) -> io::Result<()> {
    let body = serde_json::to_vec(m).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    w.write_all(&frame).await?;
    w.flush().await
}

/// Not cancel-safe: dropping the future mid-read loses framing. Do not use it
/// directly inside `select!`; run it in a dedicated reader task.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
