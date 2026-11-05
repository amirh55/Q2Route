//! Flow table: maps connections to the owning pid, fed from WinDivert
//! Socket-layer CONNECT/CLOSE events.
//!
//! Engine usage: the Network-layer SYN can arrive before or after the
//! Socket-layer CONNECT event, so look up with [`FlowTable::pid_for`] first
//! and fall back to [`FlowTable::pid_for_local`] (the app's local ip:port is
//! unique among its live connects); if both miss, the event may still be in
//! flight and the engine should retry briefly before deciding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

use crate::windivert::SocketData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Default)]
struct Inner {
    by_key: HashMap<FlowKey, u32>,
    by_local: HashMap<SocketAddr, u32>,
}

/// Thread-safe; all methods take `&self`.
#[derive(Default)]
pub struct FlowTable {
    inner: Mutex<Inner>,
}

fn key(s: &SocketData) -> FlowKey {
    FlowKey {
        local: s.local,
        remote: s.remote,
    }
}

fn unspecified(local: SocketAddr) -> SocketAddr {
    let ip = match local {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, local.port())
}

impl FlowTable {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave the maps inconsistent
        // in a harmful way, so recover from poisoning.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn on_connect(&self, s: &SocketData) {
        let mut g = self.lock();
        g.by_key.insert(key(s), s.pid);
        g.by_local.insert(s.local, s.pid);
    }

    pub fn on_close(&self, s: &SocketData) {
        let mut g = self.lock();
        g.by_key.remove(&key(s));
        if g.by_local.get(&s.local) == Some(&s.pid) {
            g.by_local.remove(&s.local);
        }
    }

    pub fn pid_for(&self, k: &FlowKey) -> Option<u32> {
        self.lock().by_key.get(k).copied()
    }

    /// Lookup by local ip:port only. Also matches a CONNECT recorded with an
    /// unspecified local ip (`0.0.0.0` / `::`) and the same port.
    pub fn pid_for_local(&self, local: SocketAddr) -> Option<u32> {
        let g = self.lock();
        g.by_local
            .get(&local)
            .or_else(|| g.by_local.get(&unspecified(local)))
            .copied()
    }
}
