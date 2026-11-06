//! In-memory process tree used to resolve inherited (parent) routes.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub exe: PathBuf,
    pub start_time: u64,
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    procs: HashMap<u32, ProcInfo>,
}

impl ProcessTree {
    pub fn insert(&mut self, p: ProcInfo) {
        self.procs.insert(p.pid, p);
    }

    pub fn remove(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    pub fn get(&self, pid: u32) -> Option<&ProcInfo> {
        self.procs.get(&pid)
    }

    /// Ancestors, nearest first. Stops at a cycle, a missing parent, or a parent that
    /// started after its child (PID reuse).
    pub fn ancestors(&self, pid: u32) -> Vec<&ProcInfo> {
        let mut out = Vec::new();
        let mut seen = HashSet::from([pid]);
        let mut cur = match self.procs.get(&pid) {
            Some(c) => c,
            None => return out,
        };
        while let Some(parent) = self.procs.get(&cur.parent) {
            if !seen.insert(parent.pid) || parent.start_time > cur.start_time {
                break;
            }
            out.push(parent);
            cur = parent;
        }
        out
    }
}
