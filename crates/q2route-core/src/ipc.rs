//! UI <-> service IPC: u32-LE length-prefixed JSON frames over a named pipe.

use crate::config::{Action, Config, GroupId, ProfileId, Protocol, ProxyProfile, Rule};
use crate::decide::Route;
use crate::proxy::ProxyTestResult;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
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
    AddGroup { name: String, action: Action },
    RenameGroup { group_id: GroupId, name: String },
    DeleteGroup { group_id: GroupId },
    MoveGroup { group_id: GroupId, to: usize },
    SetGroupRules { group_id: GroupId, rules: Vec<Rule> },
    AddRule { group_id: GroupId, rule: Rule },
    GetConnections,
    ListProcesses,
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

// The snapshot embeds Config (now with DNS settings); boxing would ripple through every IPC site.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Response {
    Ok,
    State(StateSnapshot),
    ProxyTest(ProxyTestResult),
    Error(String),
    Connections(Vec<ConnInfo>),
    Processes(Vec<ProcEntry>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnInfo {
    pub id: u64,
    pub proto: Protocol,
    pub pid: u32,
    /// File name; "System" / "?" when unknown.
    pub exe: String,
    pub local: SocketAddr,
    pub dst: SocketAddr,
    pub domain: Option<String>,
    pub route: Route,
    pub group_id: Option<GroupId>,
    /// "own", "inherited from steam.exe", "catch-all", "always-direct app", "excluded", "no match".
    pub reason: String,
    /// Unix ms.
    pub started_ms: u64,
    /// `None` while active.
    pub ended_ms: Option<u64>,
    /// Bytes; `None` when not relayed.
    pub up: Option<u64>,
    pub down: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProcEntry {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Event {
    /// Sent ~4x per second after `Subscribe`.
    Snapshot(Box<StateSnapshot>),
    ProxyDown {
        id: ProfileId,
    },
    ProxyUp {
        id: ProfileId,
    },
}

// Short-lived wire messages; boxing would only add an allocation per frame.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ServerMsg {
    Response(Response),
    Event(Event),
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, m: &T) -> io::Result<()> {
    let body = serde_json::to_vec(m).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
