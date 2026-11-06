//! In-memory connection log behind `Request::GetConnections`: active
//! connections plus a bounded list of recently ended ones. Observation only;
//! nothing here influences routing. Every method takes one short `Mutex`
//! lock and never holds it across I/O or an await.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use q2route_core::config::{GroupId, Protocol};
use q2route_core::decide::Route;
use q2route_core::ipc::ConnInfo;

/// Ended connections kept.
pub const RECENT_CAP: usize = 500;
/// Active entries kept (oldest dropped beyond).
pub const ACTIVE_CAP: usize = 5000;

/// Live byte counters of a relayed connection.
#[derive(Default)]
pub struct ConnBytes {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

pub struct NewConn {
    pub proto: Protocol,
    pub pid: u32,
    pub exe: String,
    pub local: SocketAddr,
    pub dst: SocketAddr,
    pub domain: Option<String>,
    pub route: Route,
    pub group_id: Option<GroupId>,
    pub reason: String,
}

struct Active {
    info: ConnInfo,
    bytes: Option<Arc<ConnBytes>>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    /// Oldest first.
    active: VecDeque<Active>,
    /// Oldest first.
    ended: VecDeque<ConnInfo>,
}

#[derive(Default)]
pub struct ConnLog {
    state: Mutex<State>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn snapshot(a: &Active) -> ConnInfo {
    let mut i = a.info.clone();
    if let Some(b) = &a.bytes {
        i.up = Some(b.up.load(Ordering::Relaxed));
        i.down = Some(b.down.load(Ordering::Relaxed));
    }
    i
}

impl State {
    fn end(&mut self, idx: usize, now: u64) {
        let Some(a) = self.active.remove(idx) else {
            return;
        };
        let mut info = snapshot(&a);
        info.ended_ms = Some(now);
        self.ended.push_back(info);
        while self.ended.len() > RECENT_CAP {
            self.ended.pop_front();
        }
    }
}

impl ConnLog {
    /// Records a connection and returns its id. If an active entry for the
    /// same (proto, local, dst) exists it is updated in place and its id
    /// returned: a flow is one connection even if both the packet layer and
    /// the relay (or a re-decision after a rules change) record it.
    pub fn open(&self, c: NewConn, bytes: Option<Arc<ConnBytes>>) -> u64 {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(a) = s
            .active
            .iter_mut()
            .find(|a| a.info.proto == c.proto && a.info.local == c.local && a.info.dst == c.dst)
        {
            a.info.route = c.route;
            a.info.group_id = c.group_id;
            a.info.reason = c.reason;
            a.info.domain = c.domain;
            if bytes.is_some() {
                a.bytes = bytes;
            }
            return a.info.id;
        }
        s.next_id += 1;
        let id = s.next_id;
        let info = ConnInfo {
            id,
            proto: c.proto,
            pid: c.pid,
            exe: c.exe,
            local: c.local,
            dst: c.dst,
            domain: c.domain,
            route: c.route,
            group_id: c.group_id,
            reason: c.reason,
            started_ms: now_ms(),
            ended_ms: None,
            up: None,
            down: None,
        };
        s.active.push_back(Active { info, bytes });
        while s.active.len() > ACTIVE_CAP {
            s.active.pop_front();
        }
        id
    }

    /// Marks the connection ended.
    pub fn close(&self, id: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = s.active.iter().position(|a| a.info.id == id) {
            s.end(i, now_ms());
        }
    }

    /// Marks every active connection with this protocol and local address
    /// ended (Socket-layer CLOSE; packet-layer flows only know their local
    /// address).
    pub fn close_local(&self, proto: Protocol, local: SocketAddr) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_ms();
        let mut i = 0;
        while i < s.active.len() {
            let a = &s.active[i].info;
            if a.proto == proto && a.local == local {
                s.end(i, now);
            } else {
                i += 1;
            }
        }
    }

    /// Active first (newest first), then ended (newest first).
    pub fn list(&self) -> Vec<ConnInfo> {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.active
            .iter()
            .rev()
            .map(snapshot)
            .chain(s.ended.iter().rev().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn conn(i: usize) -> NewConn {
        NewConn {
            proto: Protocol::Tcp,
            pid: 1,
            exe: "a.exe".into(),
            local: "10.0.0.1:1000".parse().unwrap(),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(i as u32)), 443),
            domain: None,
            route: Route::Direct,
            group_id: None,
            reason: "own".into(),
        }
    }

    fn local(c: &mut NewConn, port: u16) {
        c.local = SocketAddr::new("10.0.0.1".parse().unwrap(), port);
    }

    #[test]
    fn open_close_and_order() {
        let log = ConnLog::default();
        let a = log.open(conn(1), None);
        let b = log.open(conn(2), None);
        log.close(a);
        let l = log.list();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].id, b);
        assert!(l[0].ended_ms.is_none());
        assert_eq!(l[1].id, a);
        assert!(l[1].ended_ms.is_some());
    }

    #[test]
    fn close_local_ends_matching_active_only() {
        let log = ConnLog::default();
        let (mut t1, mut t2, mut u1) = (conn(1), conn(2), conn(3));
        local(&mut t1, 5000);
        local(&mut t2, 5001);
        local(&mut u1, 5000);
        u1.proto = Protocol::Udp;
        let id1 = log.open(t1, None);
        log.open(t2, None);
        log.open(u1, None);
        log.close_local(Protocol::Tcp, "10.0.0.1:5000".parse().unwrap());
        let l = log.list();
        assert_eq!(l.iter().filter(|c| c.ended_ms.is_some()).count(), 1);
        let ended = l.iter().find(|c| c.ended_ms.is_some()).unwrap();
        assert_eq!(ended.id, id1);
        assert_eq!(ended.proto, Protocol::Tcp);
    }

    #[test]
    fn log_is_bounded() {
        let log = ConnLog::default();
        for i in 0..(ACTIVE_CAP + RECENT_CAP + 100) {
            let id = log.open(conn(i), None);
            if i % 2 == 0 {
                log.close(id)
            }
        }
        let l = log.list();
        assert!(l.iter().filter(|c| c.ended_ms.is_none()).count() <= ACTIVE_CAP);
        assert!(l.iter().filter(|c| c.ended_ms.is_some()).count() <= RECENT_CAP);
    }

    #[test]
    fn bytes_are_live() {
        let log = ConnLog::default();
        let bytes = Arc::new(ConnBytes::default());
        let id = log.open(conn(1), Some(bytes.clone()));
        assert_eq!(log.list()[0].up, Some(0));
        bytes.up.fetch_add(10, Ordering::Relaxed);
        bytes.down.fetch_add(3, Ordering::Relaxed);
        let l = log.list();
        assert_eq!((l[0].up, l[0].down), (Some(10), Some(3)));
        bytes.up.fetch_add(5, Ordering::Relaxed);
        log.close(id);
        assert_eq!(log.list()[0].up, Some(15));
    }

    #[test]
    fn reopen_same_flow_updates_in_place() {
        let log = ConnLog::default();
        let a = log.open(conn(1), None);
        let mut again = conn(1);
        again.route = Route::Block;
        again.reason = "catch-all".into();
        again.domain = Some("x.com".into());
        let bytes = Arc::new(ConnBytes::default());
        let b = log.open(again, Some(bytes));
        assert_eq!(a, b);
        let l = log.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].route, Route::Block);
        assert_eq!(l[0].reason, "catch-all");
        assert_eq!(l[0].domain.as_deref(), Some("x.com"));
        assert_eq!(l[0].up, Some(0));
        // An ended flow is not reopened: a new connection gets a new row.
        log.close(a);
        let c = log.open(conn(1), None);
        assert_ne!(a, c);
        assert_eq!(log.list().len(), 2);
    }
}
