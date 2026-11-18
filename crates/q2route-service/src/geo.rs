//! Loads `geoip.dat` and `geosite.dat` for `geoip:` / `geosite:` rules and
//! compiles rule sets with them.
//!
//! Source: `%ProgramData%\Q2Route\<file>`. When a proxy program
//! (v2rayN, xray, v2ray, sing-box) is running and has a newer copy of a file
//! next to its exe (or up to two folders above), that file is copied there
//! first, so Q2Route follows v2rayN's geo updates without a download.
//! Without data, `geoip:` / `geosite:` entries match nothing (traffic falls
//! through to later groups, normally the proxy: never a leak).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use q2route_core::config::Config;
use q2route_core::geoip::GeoIp;
use q2route_core::geosite::GeoSite;
use q2route_core::matchers::MatchError;
use q2route_core::process_tree::ProcInfo;
use q2route_core::ruleset::RuleSet;

pub const GEOIP_FILE: &str = "geoip.dat";
pub const GEOSITE_FILE: &str = "geosite.dat";
const PROXY_EXES: &[&str] = &["v2rayn.exe", "xray.exe", "v2ray.exe", "sing-box.exe"];

/// Keys last asked for, and what was loaded for them.
type Loaded<T> = Option<(Vec<String>, Arc<T>)>;

pub struct GeoCache {
    dir: PathBuf,
    ip: Mutex<Loaded<GeoIp>>,
    site: Mutex<Loaded<GeoSite>>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// `file` next to a running proxy program, newest first.
pub fn find_external(procs: &[ProcInfo], file: &str) -> Option<PathBuf> {
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
            let f = dir.join(file);
            if let Some(t) = mtime(&f) {
                found.push((t, f));
                break;
            }
        }
    }
    found.sort();
    found.pop().map(|(_, f)| f)
}

/// Reuses `slot` when it was loaded for `wanted`, else loads and stores anew.
fn cached<T>(slot: &Mutex<Loaded<T>>, wanted: Vec<String>, load: impl FnOnce() -> T) -> Arc<T> {
    let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some((w, g)) if *w == wanted => g.clone(),
        _ => {
            let g = Arc::new(load());
            *slot = Some((wanted, g.clone()));
            g
        }
    }
}

impl GeoCache {
    pub fn new(dir: PathBuf) -> GeoCache {
        GeoCache {
            dir,
            ip: Mutex::new(None),
            site: Mutex::new(None),
        }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// Copies a newer external `file` over ours. Returns whether it did.
    fn refresh_from(&self, file: &str, external: Option<PathBuf>) -> bool {
        let Some(src) = external else { return false };
        let dst = self.path(file);
        let newer = match (mtime(&src), mtime(&dst)) {
            (Some(s), Some(d)) => s > d,
            (Some(_), None) => true,
            _ => false,
        };
        if !newer {
            return false;
        }
        let tmp = self.dir.join(format!("{file}.tmp"));
        let r = std::fs::create_dir_all(&self.dir)
            .and_then(|()| std::fs::copy(&src, &tmp))
            .and_then(|_| std::fs::rename(&tmp, &dst));
        match r {
            Ok(()) => {
                tracing::info!("{file}: copied {} to {}", src.display(), dst.display());
                true
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                tracing::warn!("{file}: copy from {} failed: {e}", src.display());
                false
            }
        }
    }

    /// Reads `file` from our folder; `None` (after a warning) if unreadable.
    fn read(&self, file: &str) -> Option<Vec<u8>> {
        let path = self.path(file);
        match std::fs::read(&path) {
            Ok(data) => Some(data),
            Err(e) => {
                tracing::warn!("{file}: {}: {e}", path.display());
                None
            }
        }
    }

    fn load_ip(&self, wanted: &[String]) -> GeoIp {
        if wanted.is_empty() {
            return GeoIp::default();
        }
        let geo = self
            .read(GEOIP_FILE)
            .and_then(|data| {
                GeoIp::parse(&data, wanted)
                    .map_err(|e| tracing::warn!("{GEOIP_FILE}: {e}"))
                    .ok()
            })
            .unwrap_or_default();
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

    fn load_site(&self, wanted: &[String]) -> GeoSite {
        if wanted.is_empty() {
            return GeoSite::default();
        }
        let geo = self
            .read(GEOSITE_FILE)
            .and_then(|data| {
                GeoSite::parse(&data, wanted)
                    .map_err(|e| tracing::warn!("{GEOSITE_FILE}: {e}"))
                    .ok()
            })
            .unwrap_or_default();
        for key in wanted {
            match geo.get(key) {
                Some(s) => {
                    tracing::info!("geosite:{key}: {} names", s.len());
                    let n = geo.skipped(key);
                    if n > 0 {
                        tracing::info!("geosite:{key}: {n} entries skipped (regex or unsupported)");
                    }
                }
                None => tracing::warn!(
                    "geosite:{key}: no data, so these rules match nothing \
                     (that traffic follows later groups)"
                ),
            }
        }
        geo
    }

    /// Re-checks the proxy programs' geo files and reloads (used on Start).
    pub fn reload(&self, procs: &[ProcInfo]) {
        for file in [GEOIP_FILE, GEOSITE_FILE] {
            self.refresh_from(file, find_external(procs, file));
        }
        *self.ip.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.site.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Compiles `cfg`, loading each geo file only when its wanted keys changed.
    pub fn compile(&self, cfg: &Config) -> Result<RuleSet, MatchError> {
        let wanted_ip = RuleSet::wanted_geoip(cfg);
        let wanted_site = RuleSet::wanted_geosite(cfg);
        let ip = cached(&self.ip, wanted_ip.clone(), || self.load_ip(&wanted_ip));
        let site = cached(&self.site, wanted_site.clone(), || {
            self.load_site(&wanted_site)
        });
        RuleSet::compile_with(cfg, &ip, &site)
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

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn bytes_field(num: u64, payload: &[u8], out: &mut Vec<u8>) {
        varint(num << 3 | 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    /// A `geosite.dat` with one list: `code` holding root-domain `domain`.
    fn geosite_dat(code: &str, domain: &str) -> Vec<u8> {
        let mut d = Vec::new();
        varint(1 << 3, &mut d);
        varint(2, &mut d); // root domain
        bytes_field(2, domain.as_bytes(), &mut d);
        let mut site = Vec::new();
        bytes_field(1, code.as_bytes(), &mut site);
        bytes_field(2, &d, &mut site);
        let mut out = Vec::new();
        bytes_field(1, &site, &mut out);
        out
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
        assert_eq!(
            find_external(&procs, GEOIP_FILE),
            Some(bin.join(GEOIP_FILE))
        );

        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        assert!(cache.refresh_from(GEOIP_FILE, find_external(&procs, GEOIP_FILE)));
        assert_eq!(std::fs::read(cache.path(GEOIP_FILE)).unwrap(), b"data");
        // Same age now: not copied again.
        assert!(!cache.refresh_from(GEOIP_FILE, find_external(&procs, GEOIP_FILE)));
    }

    #[test]
    fn finds_and_copies_geosite_like_geoip() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("v2rayN").join("bin");
        std::fs::create_dir_all(bin.join("xray")).unwrap();
        std::fs::write(bin.join(GEOIP_FILE), b"ip").unwrap();
        std::fs::write(bin.join(GEOSITE_FILE), b"site").unwrap();
        let procs = [proc(&bin.join("xray").join("xray.exe"))];
        assert_eq!(
            find_external(&procs, GEOSITE_FILE),
            Some(bin.join(GEOSITE_FILE))
        );

        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        cache.reload(&procs);
        assert_eq!(std::fs::read(cache.path(GEOIP_FILE)).unwrap(), b"ip");
        assert_eq!(std::fs::read(cache.path(GEOSITE_FILE)).unwrap(), b"site");
        // Same age now: not copied again.
        assert!(!cache.refresh_from(GEOSITE_FILE, find_external(&procs, GEOSITE_FILE)));
    }

    #[test]
    fn no_proxy_running_finds_nothing() {
        let p = [proc(Path::new(r"C:\x\chrome.exe"))];
        assert_eq!(find_external(&p, GEOIP_FILE), None);
        assert_eq!(find_external(&p, GEOSITE_FILE), None);
    }

    #[test]
    fn missing_file_compiles_with_geo_matching_nothing() {
        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        let rs = cache.compile(&Config::seed()).unwrap();
        let ip = "185.188.107.12".parse().unwrap();
        assert!(!rs.groups[1].rules[1].ips[0].matches(ip));
    }

    #[test]
    fn missing_geosite_matches_nothing() {
        let ours = tempfile::tempdir().unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        let rs = cache.compile(&Config::seed()).unwrap();
        let rule = &rs.groups[1].rules[0];
        assert!(!rule.domains.iter().any(|d| d.matches("www.digikala.com")));
        assert!(rule.domains.iter().any(|d| d.matches("example.ir")));
    }

    #[test]
    fn corrupt_geosite_matches_nothing() {
        let ours = tempfile::tempdir().unwrap();
        std::fs::write(
            ours.path().join(GEOSITE_FILE),
            [
                0xffu8, 0xfe, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
        )
        .unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        let rs = cache.compile(&Config::seed()).unwrap();
        let rule = &rs.groups[1].rules[0];
        assert!(!rule.domains.iter().any(|d| d.matches("www.digikala.com")));
        assert!(rule.domains.iter().any(|d| d.matches("example.ir")));
    }

    #[test]
    fn loads_geosite_codes() {
        let ours = tempfile::tempdir().unwrap();
        std::fs::write(
            ours.path().join(GEOSITE_FILE),
            geosite_dat("IR", "digikala.com"),
        )
        .unwrap();
        let cache = GeoCache::new(ours.path().to_path_buf());
        let rs = cache.compile(&Config::seed()).unwrap();
        let rule = &rs.groups[1].rules[0];
        assert!(rule.domains.iter().any(|d| d.matches("www.digikala.com")));
        assert!(!rule.domains.iter().any(|d| d.matches("example.com")));
    }
}
