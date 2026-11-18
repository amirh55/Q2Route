//! Data usage: proxied bytes per (group, app, proxy), kept per local
//! calendar day (last 90 days) plus a per-run session total. Off by default;
//! while off, [`Usage::add`] is one atomic load and nothing touches the disk.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use q2route_core::config::{GroupId, ProfileId};
use q2route_core::ipc::{UsageReport, UsageRow};
use serde::{Deserialize, Serialize};
use windows::Win32::System::SystemInformation::GetLocalTime;

/// Days of history kept (today included).
const KEEP_DAYS: i64 = 90;

/// What a byte is attributed to.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct UsageKey {
    pub group: GroupId,
    /// Lowercase exe file name, or `?`.
    pub app: String,
    pub proxy: ProfileId,
}

#[derive(Default)]
struct PerKey {
    session_up: AtomicU64,
    session_down: AtomicU64,
    /// "YYYY-MM-DD" -> (up, down).
    days: Mutex<BTreeMap<String, (u64, u64)>>,
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    days: Vec<(String, Vec<UsageRow>)>,
}

pub struct Usage {
    path: PathBuf,
    enabled: AtomicBool,
    dirty: AtomicBool,
    keys: DashMap<UsageKey, Arc<PerKey>>,
}

/// Today's local date as `YYYY-MM-DD`.
pub fn today() -> String {
    // SAFETY: GetLocalTime has no preconditions.
    let t = unsafe { GetLocalTime() };
    format!("{:04}-{:02}-{:02}", t.wYear, t.wMonth, t.wDay)
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` string.
fn day_number(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let (y, m, d) = (
        it.next()?.parse::<i64>().ok()?,
        it.next()?.parse::<i64>().ok()?,
        it.next()?.parse::<i64>().ok()?,
    );
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

impl Usage {
    /// Loads `path` when it exists (even with counting off, so switching it
    /// on continues the history). A corrupt file is renamed to `.bad`.
    pub fn new(path: PathBuf, enabled: bool) -> Usage {
        let u = Usage {
            path,
            enabled: AtomicBool::new(enabled),
            dirty: AtomicBool::new(false),
            keys: DashMap::new(),
        };
        u.load();
        u
    }

    fn load(&self) {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!("cannot read {}: {e}", self.path.display());
                return;
            }
        };
        match serde_json::from_str::<File>(&text) {
            Ok(f) => {
                for (day, rows) in f.days {
                    for r in rows {
                        let key = UsageKey {
                            group: r.group,
                            app: r.app,
                            proxy: r.proxy,
                        };
                        let pk = self.per_key(&key);
                        let mut days = pk.days.lock().unwrap_or_else(|e| e.into_inner());
                        let d = days.entry(day.clone()).or_default();
                        d.0 = d.0.saturating_add(r.up);
                        d.1 = d.1.saturating_add(r.down);
                    }
                }
            }
            Err(e) => {
                let bad = self.path.with_extension("json.bad");
                tracing::warn!(
                    "{} is corrupt ({e}); kept as {}, starting empty",
                    self.path.display(),
                    bad.display()
                );
                if let Err(e) = std::fs::rename(&self.path, &bad) {
                    tracing::warn!("cannot set the corrupt usage file aside: {e}");
                }
            }
        }
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn per_key(&self, key: &UsageKey) -> Arc<PerKey> {
        if let Some(p) = self.keys.get(key) {
            return p.clone();
        }
        self.keys.entry(key.clone()).or_default().clone()
    }

    /// Adds proxied bytes to the session and to today.
    pub fn add(&self, key: &UsageKey, up: u64, down: u64) {
        if !self.enabled() {
            return;
        }
        self.add_on(&today(), key, up, down);
    }

    /// [`Usage::add`] for a given day (test seam).
    pub fn add_on(&self, day: &str, key: &UsageKey, up: u64, down: u64) {
        if !self.enabled() {
            return;
        }
        let pk = self.per_key(key);
        pk.session_up.fetch_add(up, Ordering::Relaxed);
        pk.session_down.fetch_add(down, Ordering::Relaxed);
        {
            let mut days = pk.days.lock().unwrap_or_else(|e| e.into_inner());
            if !days.contains_key(day) {
                days.insert(day.to_string(), (0, 0));
            }
            if let Some(d) = days.get_mut(day) {
                d.0 = d.0.saturating_add(up);
                d.1 = d.1.saturating_add(down);
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn report(&self) -> UsageReport {
        let mut session = Vec::new();
        let mut days: BTreeMap<String, Vec<UsageRow>> = BTreeMap::new();
        for e in self.keys.iter() {
            let k = e.key();
            let row = |up, down| UsageRow {
                group: k.group.clone(),
                app: k.app.clone(),
                proxy: k.proxy.clone(),
                up,
                down,
            };
            let (su, sd) = (
                e.session_up.load(Ordering::Relaxed),
                e.session_down.load(Ordering::Relaxed),
            );
            if su > 0 || sd > 0 {
                session.push(row(su, sd));
            }
            for (day, (up, down)) in e.days.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                days.entry(day.clone()).or_default().push(row(*up, *down));
            }
        }
        let sort = |rows: &mut Vec<UsageRow>| {
            rows.sort_by(|a, b| (&a.group, &a.app, &a.proxy).cmp(&(&b.group, &b.app, &b.proxy)))
        };
        sort(&mut session);
        let days = days
            .into_iter()
            .map(|(d, mut rows)| {
                sort(&mut rows);
                (d, rows)
            })
            .collect();
        UsageReport {
            enabled: self.enabled(),
            session,
            days,
        }
    }

    /// Drops days older than [`KEEP_DAYS`] (never today).
    fn prune(&self) {
        let today = today();
        let Some(now) = day_number(&today) else {
            return;
        };
        for e in self.keys.iter() {
            e.days
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|d, _| *d == today || day_number(d).is_some_and(|n| n > now - KEEP_DAYS));
        }
    }

    /// Writes `usage.json` atomically (tmp + rename) when something changed.
    pub fn save_if_dirty(&self) -> io::Result<()> {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let r = self.save();
        if r.is_err() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        r
    }

    fn save(&self) -> io::Result<()> {
        self.prune();
        let file = File {
            days: self.report().days,
        };
        let body = serde_json::to_vec(&file).map_err(io::Error::other)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Clears session and history and deletes the file.
    pub fn reset(&self) -> io::Result<()> {
        self.keys.clear();
        self.dirty.store(false, Ordering::Relaxed);
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(g: &str, a: &str) -> UsageKey {
        UsageKey {
            group: g.into(),
            app: a.into(),
            proxy: "p1".into(),
        }
    }

    fn path(d: &tempfile::TempDir) -> PathBuf {
        d.path().join("usage.json")
    }

    #[test]
    fn disabled_counts_nothing_and_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let u = Usage::new(path(&d), false);
        u.add(&key("g", "a.exe"), 10, 20);
        u.add_on("2026-01-01", &key("g", "a.exe"), 10, 20);
        u.save_if_dirty().unwrap();
        let r = u.report();
        assert!(!r.enabled && r.session.is_empty() && r.days.is_empty());
        assert!(!path(&d).exists());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn adds_go_to_session_and_today() {
        let d = tempfile::tempdir().unwrap();
        let u = Usage::new(path(&d), true);
        let k = key("g", "a.exe");
        u.add(&k, 10, 20);
        u.add(&k, 1, 2);
        u.add(&key("g", "b.exe"), 5, 0);
        let r = u.report();
        assert!(r.enabled);
        assert_eq!(r.session.len(), 2);
        assert_eq!(
            r.session[0],
            UsageRow {
                group: "g".into(),
                app: "a.exe".into(),
                proxy: "p1".into(),
                up: 11,
                down: 22
            }
        );
        assert_eq!(r.days.len(), 1);
        assert_eq!(r.days[0].0, today());
        assert_eq!(r.days[0].1, r.session);
    }

    #[test]
    fn report_roundtrips_through_file() {
        let d = tempfile::tempdir().unwrap();
        let u = Usage::new(path(&d), true);
        u.add(&key("g", "a.exe"), 10, 20);
        u.add_on(
            &date_of(day_number(&today()).unwrap() - 5),
            &key("h", "b.exe"),
            7,
            8,
        );
        u.save_if_dirty().unwrap();
        assert!(!d.path().join("usage.json.tmp").exists());
        let before = u.report();
        let u2 = Usage::new(path(&d), true);
        let after = u2.report();
        assert!(after.session.is_empty());
        assert_eq!(after.days, before.days);
        assert_eq!(after.days.len(), 2);
    }

    #[test]
    fn corrupt_file_is_set_aside() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(path(&d), b"{ not json").unwrap();
        let u = Usage::new(path(&d), true);
        assert!(u.report().days.is_empty());
        assert!(!path(&d).exists());
        assert_eq!(
            std::fs::read(d.path().join("usage.json.bad")).unwrap(),
            b"{ not json"
        );
        u.add(&key("g", "a.exe"), 1, 1);
        u.save_if_dirty().unwrap();
        assert!(path(&d).exists());
        assert!(d.path().join("usage.json.bad").exists());
    }

    fn date_of(n: i64) -> String {
        // civil_from_days, the inverse of day_number.
        let z = n + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!("{y:04}-{m:02}-{d:02}")
    }

    #[test]
    fn keeps_90_days() {
        let d = tempfile::tempdir().unwrap();
        let u = Usage::new(path(&d), true);
        let now = day_number(&today()).unwrap();
        assert_eq!(date_of(now), today());
        let k = key("g", "a.exe");
        for back in 0..100 {
            u.add_on(&date_of(now - back), &k, 1, 1);
        }
        u.save_if_dirty().unwrap();
        let days = u.report().days;
        assert_eq!(days.len(), 90);
        assert_eq!(days.last().unwrap().0, today());
        assert_eq!(days[0].0, date_of(now - 89));
        let u2 = Usage::new(path(&d), true);
        assert_eq!(u2.report().days.len(), 90);
    }

    #[test]
    fn concurrent_adds_sum() {
        let d = tempfile::tempdir().unwrap();
        let u = Arc::new(Usage::new(path(&d), true));
        let k = key("g", "a.exe");
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (u, k) = (u.clone(), k.clone());
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        u.add(&k, 2, 3);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let r = u.report();
        assert_eq!((r.session[0].up, r.session[0].down), (160_000, 240_000));
        assert_eq!((r.days[0].1[0].up, r.days[0].1[0].down), (160_000, 240_000));
    }

    #[test]
    fn reset_clears_and_deletes_file() {
        let d = tempfile::tempdir().unwrap();
        let u = Usage::new(path(&d), true);
        u.add(&key("g", "a.exe"), 1, 1);
        u.save_if_dirty().unwrap();
        assert!(path(&d).exists());
        u.reset().unwrap();
        assert!(!path(&d).exists());
        let r = u.report();
        assert!(r.session.is_empty() && r.days.is_empty());
        u.reset().unwrap();
    }

    #[test]
    fn today_format() {
        let t = today();
        let b = t.as_bytes();
        assert_eq!(b.len(), 10);
        assert!(b.iter().enumerate().all(|(i, c)| if i == 4 || i == 7 {
            *c == b'-'
        } else {
            c.is_ascii_digit()
        }));
        assert!(day_number(&t).is_some());
    }
}
