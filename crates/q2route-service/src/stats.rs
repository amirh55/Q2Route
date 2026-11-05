//! Per-group traffic counters for the relay: cumulative bytes, open
//! connections, and bytes/second sampled over windows of at least 1 s.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use q2route_core::config::GroupId;
use q2route_core::ipc::GroupStats;

const WINDOW: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
    active: AtomicU32,
}

#[derive(Default)]
struct Sample {
    at: Option<Instant>,
    /// Cumulative (up, down) per group at `at`.
    prev: HashMap<GroupId, (u64, u64)>,
    /// (up_bps, down_bps) per group over the last completed window.
    rates: HashMap<GroupId, (u64, u64)>,
}

/// Thread-safe; all methods take `&self`.
#[derive(Default)]
pub struct Stats {
    groups: DashMap<GroupId, Arc<Counters>>,
    sample: Mutex<Sample>,
}

/// Counts one open connection for a group until dropped.
pub struct ActiveGuard {
    c: Arc<Counters>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.c.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Stats {
    fn counters(&self, group: &str) -> Arc<Counters> {
        if let Some(c) = self.groups.get(group) {
            return c.clone();
        }
        self.groups.entry(group.to_string()).or_default().clone()
    }

    /// Adds `up` (client to upstream) and `down` (upstream to client) bytes.
    pub fn add(&self, group: &str, up: u64, down: u64) {
        let c = self.counters(group);
        c.up.fetch_add(up, Ordering::Relaxed);
        c.down.fetch_add(down, Ordering::Relaxed);
    }

    /// Marks a connection of `group` as open until the guard is dropped.
    pub fn open(&self, group: &str) -> ActiveGuard {
        let c = self.counters(group);
        c.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard { c }
    }

    /// Cumulative (up, down) bytes for `group`.
    pub fn bytes(&self, group: &str) -> (u64, u64) {
        self.groups.get(group).map_or((0, 0), |c| {
            (c.up.load(Ordering::Relaxed), c.down.load(Ordering::Relaxed))
        })
    }

    /// Per-group stats plus total (up_bps, down_bps). Rates are recomputed
    /// once at least 1 s has passed since the previous sample; in between,
    /// the last computed rates are returned. `active` is always current.
    pub fn snapshot(&self) -> (HashMap<GroupId, GroupStats>, u64, u64) {
        let now = Instant::now();
        let mut s = self.sample.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = s.at.map(|at| now.saturating_duration_since(at));
        if elapsed.is_none_or(|e| e >= WINDOW) {
            let mut cur = HashMap::new();
            let mut rates = HashMap::new();
            for e in self.groups.iter() {
                let (up, down) = (e.up.load(Ordering::Relaxed), e.down.load(Ordering::Relaxed));
                if let Some(secs) = elapsed.map(|e| e.as_secs_f64()) {
                    let (pu, pd) = s.prev.get(e.key()).copied().unwrap_or((0, 0));
                    let bps = |d: u64| (d as f64 / secs) as u64;
                    rates.insert(e.key().clone(), (bps(up.saturating_sub(pu)), bps(down.saturating_sub(pd))));
                }
                cur.insert(e.key().clone(), (up, down));
            }
            *s = Sample { at: Some(now), prev: cur, rates };
        }
        let (mut tu, mut td) = (0, 0);
        let mut out = HashMap::new();
        for e in self.groups.iter() {
            let (up_bps, down_bps) = s.rates.get(e.key()).copied().unwrap_or((0, 0));
            tu += up_bps;
            td += down_bps;
            let active = e.active.load(Ordering::Relaxed);
            out.insert(e.key().clone(), GroupStats { up_bps, down_bps, active });
        }
        (out, tu, td)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_active() {
        let s = Stats::default();
        let g = s.open("a");
        let (m, _, _) = s.snapshot();
        assert_eq!(m["a"], GroupStats { up_bps: 0, down_bps: 0, active: 1 });
        s.add("a", 1000, 500);
        std::thread::sleep(WINDOW);
        let (m, tu, td) = s.snapshot();
        assert!(m["a"].up_bps > 0 && m["a"].up_bps <= 1000, "{:?}", m["a"]);
        assert!(m["a"].down_bps > 0 && m["a"].down_bps <= 500);
        assert_eq!((tu, td), (m["a"].up_bps, m["a"].down_bps));
        drop(g);
        assert_eq!(s.snapshot().0["a"].active, 0);
        assert_eq!(s.bytes("a"), (1000, 500));
    }
}
