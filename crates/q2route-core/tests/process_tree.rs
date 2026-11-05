use q2route_core::process_tree::*;
use std::path::PathBuf;

fn p(pid: u32, parent: u32, name: &str, start: u64) -> ProcInfo {
    ProcInfo { pid, parent, exe: PathBuf::from(name), start_time: start }
}

fn pids(v: Vec<&ProcInfo>) -> Vec<u32> {
    v.into_iter().map(|p| p.pid).collect()
}

#[test]
fn ancestors_chain() {
    let mut t = ProcessTree::default();
    t.insert(p(10, 1, "steam.exe", 100));
    t.insert(p(20, 10, "steamwebhelper.exe", 200));
    t.insert(p(30, 20, "game.exe", 300));
    assert_eq!(pids(t.ancestors(30)), vec![20, 10]);
    assert_eq!(t.get(20).unwrap().exe, PathBuf::from("steamwebhelper.exe"));
    t.remove(20);
    assert!(t.get(20).is_none());
    assert!(t.ancestors(30).is_empty());
}

#[test]
fn pid_reuse_cut() {
    let mut t = ProcessTree::default();
    t.insert(p(10, 1, "old.exe", 500)); // pid 10 reused later than child start
    t.insert(p(30, 10, "game.exe", 300));
    assert!(t.ancestors(30).is_empty());
}

#[test]
fn cycle_safe() {
    let mut t = ProcessTree::default();
    t.insert(p(1, 1, "self.exe", 10));
    assert!(t.ancestors(1).len() <= 1);
    let mut t = ProcessTree::default();
    t.insert(p(2, 3, "a.exe", 10));
    t.insert(p(3, 2, "b.exe", 10));
    assert_eq!(pids(t.ancestors(2)), vec![3]);
}
