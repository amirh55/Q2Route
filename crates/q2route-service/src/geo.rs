//! Loads `geoip.dat` for `geoip:` rules and compiles rule sets with it.
//!
//! Source: `%ProgramData%\Q2Route\geoip.dat`. When a proxy program
//! (v2rayN, xray, v2ray, sing-box) is running and has a newer `geoip.dat`
//! next to its exe (or up to two folders above), that file is copied there
//! first, so Q2Route follows v2rayN's geo updates without a download.
//! Without data, `geoip:` entries match nothing (traffic falls through to
//! later groups, normally the proxy: never a leak).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use q2route_core::config::Config;
use q2route_core::geoip::GeoIp;
use q2route_core::matchers::MatchError;
use q2route_core::process_tree::ProcInfo;
use q2route_core::ruleset::RuleSet;

pub const GEOIP_FILE: &str = "geoip.dat";
const PROXY_EXES: &[&str] = &["v2rayn.exe", "xray.exe", "v2ray.exe", "sing-box.exe"];

pub struct GeoCache {
    dir: PathBuf,
    /// Codes last asked for, and what was loaded for them.
    loaded: Mutex<Option<(Vec<String>, Arc<GeoIp>)>>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// `geoip.dat` next to a running proxy program, newest first.
pub fn find_external(procs: &[ProcInfo]) -> Option<PathBuf> {
    let mut found: Vec<(SystemTime, PathBuf)> = Vec::new();
    for p in procs {
        let name = p
            .exe
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !PROXY_EXES.contains(&name.as_str()) {
            continue;
        }
        for dir in p.exe.ancestors().skip(1).take(3) {
            let f = dir.join(GEOIP_FILE);
            if let Some(t) = mtime(&f) {
                found.push((t, f));
                break;
            }
        }
    }
    found.sort();
    found.pop().map(|(_, f)| f)
}

impl GeoCache {
    pub fn new(dir: PathBuf) -> GeoCache {
        GeoCache {
            dir,
            loaded: Mutex::new(None),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(GEOIP_FILE)
    }

    /// Copies a newer external `geoip.dat` over ours. Returns whether it did.
    fn refresh_from(&self, external: Option<PathBuf>) -> bool {
        let Some(src) = external else { return false };
        let dst = self.path();
        let newer = match (mtime(&src), mtime(&dst)) {
            (Some(s), Some(d)) => s > d,
            (Some(_), None) => true,
            _ => false,
        };
        if !newer {
            return false;
        }
        let tmp = self.dir.join("geoip.dat.tmp");
        let r = std::fs::create_dir_all(&self.dir)
            .and_then(|()| std::fs::copy(&src, &tmp))
            .and_then(|_| std::fs::rename(&tmp, &dst));
        match r {
            Ok(()) => {
                tracing::info!("geoip: copied {} to {}", src.display(), dst.display());
                true
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                tracing::warn!("geoip: copy from {} failed: {e}", src.display());
                false
            }
        }
    }

    fn load(&self, wanted: &[String]) -> GeoIp {
        if wanted.is_empty() {
            return GeoIp::default();
        }
        let path = self.path();
        let geo = match std::fs::read(&path) {
            Ok(data) => GeoIp::parse(&data, wanted).unwrap_or_else(|e| {
                tracing::warn!("geoip: {}: {e}", path.display());
                GeoIp::default()
            }),
            Err(e) => {
                tracing::warn!("geoip: {}: {e}", path.display());
                GeoIp::default()
            }
        };
        for code in wanted {
            match geo.get(code) {
                Some(s) => tracing::info!("geoip:{code}: {} ranges", s.len()),
                None => tracing::warn!(
                    "geoip:{code}: no data, so these rules match nothing \
                     (that traffic follows later groups)"
                ),
            }
        }
        geo
    }

    /// Re-checks the proxy programs' `geoip.dat` and reloads (used on Start).
    pub fn reload(&self, procs: &[ProcInfo]) {
        self.refresh_from(find_external(procs));
        *self.loaded.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Compiles `cfg`, loading geo data only when the wanted codes changed.
    pub fn compile(&self, cfg: &Config) -> Result<RuleSet, MatchError> {
        let wanted = RuleSet::wanted_geoip(cfg);
        let mut slot = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        let geo = match slot.as_ref() {
            Some((w, g)) if *w == wanted => g.clone(),
            _ => {
                let g = Arc::new(self.load(&wanted));
                *slot = Some((wanted, g.clone()));
                g
            }
        };
        drop(slot);
        RuleSet::compile_with(cfg, &geo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(exe: &Path) -> ProcInfo {
        ProcInfo {
            pid: 1,
            parent: 0,
            exe: exe.to_path_buf(),
            start_time: 0,
        }
    }

    #[test]
    fn finds_geoip_above_proxy_exe_and_copies_newer() {
        let root = tempfile::tempdir().unwrap();
        // v2rayN layout: C:\v2rayN\bin\geoip.dat, C:\v2rayN\bin\xray\xray.exe
        let bin = root.path().join("v2rayN").join("bin");
        std::fs::create_dir_all(bin.join("xray")).unwrap();
        std::fs::write(bin.join(GEOIP_FILE), b"data").unwrap();
        let procs = [
            proc(&root.path().join("other").join("chrome.exe")),
            proc(&bin.join("xray").join("xray.exe")),
        ];
        assert_eq!(find_external(&procs), Some(bin.join(GEOIP_FILE)));

        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        assert!(cache.refresh_from(find_external(&procs)));
        assert_eq!(std::fs::read(cache.path()).unwrap(), b"data");
        // Same age now: not copied again.
        assert!(!cache.refresh_from(find_external(&procs)));
    }

    #[test]
    fn no_proxy_running_finds_nothing() {
        assert_eq!(find_external(&[proc(Path::new(r"C:\x\chrome.exe"))]), None);
    }

    #[test]
    fn missing_file_compiles_with_geo_matching_nothing() {
        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        let rs = cache.compile(&Config::seed()).unwrap();
        let ip = "185.188.107.12".parse().unwrap();
        assert!(!rs.groups[0].rules[1].ips[0].matches(ip));
    }
}
