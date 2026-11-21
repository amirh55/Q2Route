//! Update check against GitHub releases and the one-click update.
//!
//! The pure helpers (`parse_release`, `newer`, `verify`, `Schedule`) are unit
//! tested; the WinHTTP calls run on background threads and are covered by the
//! smoke test. Results reach the UI through an `mpsc` channel polled each frame.

use std::ffi::c_void;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use serde::Deserialize;
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_FLAG_SECURE, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::views::dashboard::BLOCK;

/// Public GitHub repository whose releases are checked.
pub const UPDATE_REPO: &str = "amirh55/Q2Route";
/// The running version.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Largest accepted release JSON.
pub const MAX_JSON: usize = 1024 * 1024;
/// Largest accepted setup download.
pub const MAX_SETUP: usize = 100 * 1000 * 1000;

const FIRST_CHECK: Duration = Duration::from_secs(10);
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
const TIMEOUT_MS: i32 = 15_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
    /// Lower-case hex SHA-256 from the release's `digest` field, if any.
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub html_url: String,
    /// The `Q2Route-Setup-*.exe` asset.
    pub setup: Option<Asset>,
}

impl Release {
    /// The tag without its leading `v`.
    pub fn version(&self) -> &str {
        self.tag.trim_start_matches(['v', 'V'])
    }
}

#[derive(Deserialize)]
struct RawRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

#[derive(Deserialize)]
struct RawAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

fn is_setup_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l.starts_with("q2route-setup-") && l.ends_with(".exe")
}

/// Reads the `releases/latest` JSON.
pub fn parse_release(json: &str) -> Result<Release, String> {
    let raw: RawRelease =
        serde_json::from_str(json).map_err(|e| format!("unexpected reply ({e})"))?;
    let setup = raw
        .assets
        .into_iter()
        .find(|a| is_setup_name(&a.name) && a.browser_download_url.starts_with("https://"))
        .map(|a| Asset {
            sha256: a
                .digest
                .as_deref()
                .and_then(|d| d.strip_prefix("sha256:"))
                .map(str::to_ascii_lowercase),
            name: a.name,
            url: a.browser_download_url,
            size: a.size,
        });
    Ok(Release {
        tag: raw.tag_name,
        html_url: raw.html_url,
        setup,
    })
}

/// `major.minor.patch` of plain numbers; anything else (pre-release suffix,
/// `nightly`) is `None`.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let mut it = v.split('.');
    let mut num = || {
        let p = it.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse::<u64>().ok()
    };
    let r = (num()?, num()?, num()?);
    it.next().is_none().then_some(r)
}

/// True when `tag` is a plain release newer than `current`.
pub fn newer(tag: &str, current: &str) -> bool {
    match (parse_version(tag), parse_version(current)) {
        (Some(t), Some(c)) => t > c,
        _ => false,
    }
}

/// Checks a finished download: `bytes_len` and `actual_sha256` are measured,
/// `sha256_hex` is the digest the release promised (if any).
pub fn verify(
    bytes_len: u64,
    sha256_hex: Option<&str>,
    expected: &Asset,
    actual_sha256: &str,
) -> Result<(), String> {
    if bytes_len != expected.size {
        return Err("Update download is incomplete, try again.".into());
    }
    if let Some(d) = sha256_hex {
        let d = d.strip_prefix("sha256:").unwrap_or(d);
        if !d.eq_ignore_ascii_case(actual_sha256) {
            return Err("Update download is damaged, try again.".into());
        }
    }
    Ok(())
}

/// When the automatic check is due: 10 s after start, then every 24 h, no
/// matter whether the check worked.
pub struct Schedule {
    next: Instant,
}

impl Schedule {
    pub fn new(start: Instant) -> Schedule {
        Schedule {
            next: start + FIRST_CHECK,
        }
    }

    pub fn due(&self, now: Instant) -> bool {
        now >= self.next
    }

    pub fn mark(&mut self, now: Instant) {
        self.next = now + CHECK_EVERY;
    }
}

/// Splits `https://host[:port]/path?query` (HTTPS only).
fn split_https(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "only https addresses are allowed".to_string())?;
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "bad port".to_string())?),
        None => (auth, 443),
    };
    if host.is_empty() || host.contains('@') {
        return Err("bad address".into());
    }
    Ok((host.into(), port, path.into()))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Owned WinHTTP handle.
struct Handle(*mut c_void);

impl Handle {
    fn new(h: *mut c_void, what: &str) -> Result<Handle, String> {
        if h.is_null() {
            Err(format!("{what}: {}", std::io::Error::last_os_error()))
        } else {
            Ok(Handle(h))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a WinHTTP open/connect call and is
        // closed exactly once, here.
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn query_number(req: &Handle, what: u32) -> Option<u32> {
    let mut v = 0u32;
    let mut len = 4u32;
    // SAFETY: `v` is a 4-byte buffer and `len` says so; the NUMBER flag makes
    // WinHTTP write a DWORD. `req` is a live request handle.
    let ok = unsafe {
        WinHttpQueryHeaders(
            req.0,
            what | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut v as *mut u32).cast(),
            &mut len,
            null_mut(),
        )
    };
    (ok != 0).then_some(v)
}

type OnData<'a> = dyn FnMut(&[u8], u64) -> Result<(), String> + 'a;

/// GETs an https URL (redirects followed, never https to http) and feeds the
/// body to `on_data(chunk, content_length_or_0)`. Fails when more than `cap`
/// bytes arrive.
fn fetch(url: &str, accept: &str, cap: usize, on_data: &mut OnData) -> Result<(), String> {
    let (host, port, path) = split_https(url)?;
    let agent = wide(&format!("Q2Route/{CURRENT}"));
    // SAFETY (this whole block): every pointer passed is either null where the
    // API allows it or a NUL-terminated UTF-16 buffer / valid out-parameter
    // that outlives its call; handles are closed by `Handle::drop`.
    unsafe {
        let session = Handle::new(
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                null(),
                null(),
                0,
            ),
            "WinHttpOpen",
        )?;
        WinHttpSetTimeouts(session.0, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS);
        let host_w = wide(&host);
        let conn = Handle::new(
            WinHttpConnect(session.0, host_w.as_ptr(), port, 0),
            "WinHttpConnect",
        )?;
        let get = wide("GET");
        let path_w = wide(&path);
        let req = Handle::new(
            WinHttpOpenRequest(
                conn.0,
                get.as_ptr(),
                path_w.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE,
            ),
            "WinHttpOpenRequest",
        )?;
        let policy: u32 = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
        WinHttpSetOption(
            req.0,
            WINHTTP_OPTION_REDIRECT_POLICY,
            (&policy as *const u32).cast(),
            4,
        );
        let hdr = wide(&format!("Accept: {accept}"));
        WinHttpAddRequestHeaders(req.0, hdr.as_ptr(), u32::MAX, WINHTTP_ADDREQ_FLAG_ADD);
        if WinHttpSendRequest(req.0, null(), 0, null(), 0, 0, 0) == 0
            || WinHttpReceiveResponse(req.0, null_mut()) == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let status = query_number(&req, WINHTTP_QUERY_STATUS_CODE).unwrap_or(0);
        if status != 200 {
            return Err(match status {
                403 | 429 => format!("HTTP {status} (rate limited, try later)"),
                _ => format!("HTTP {status}"),
            });
        }
        let total = query_number(&req, WINHTTP_QUERY_CONTENT_LENGTH).unwrap_or(0) as u64;
        if total > cap as u64 {
            return Err("the file is too large".into());
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0usize;
        loop {
            let mut n = 0u32;
            if WinHttpReadData(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n) == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if n == 0 {
                return Ok(());
            }
            got += n as usize;
            if got > cap {
                return Err("the file is too large".into());
            }
            on_data(&buf[..n as usize], total)?;
        }
    }
}

fn http_get(url: &str, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    fetch(url, "application/vnd.github+json", cap, &mut |c, _| {
        out.extend_from_slice(c);
        Ok(())
    })?;
    Ok(out)
}

fn download(url: &str, path: &Path, cap: usize, progress: impl Fn(u64, u64)) -> Result<(), String> {
    let mut f = std::fs::File::create(path).map_err(|e| format!("cannot write {path:?}: {e}"))?;
    let mut done = 0u64;
    let r = fetch(url, "application/octet-stream", cap, &mut |c, total| {
        f.write_all(c).map_err(|e| e.to_string())?;
        done += c.len() as u64;
        progress(done, total);
        Ok(())
    });
    drop(f);
    if r.is_err() {
        std::fs::remove_file(path).ok();
    }
    r
}

/// Lower-case hex SHA-256 of everything `r` yields (Windows CNG).
fn sha256_hex(mut r: impl Read) -> Result<String, String> {
    let mut alg = null_mut();
    let mut hash = null_mut();
    let mut out = [0u8; 32];
    let mut buf = vec![0u8; 64 * 1024];
    // SAFETY: standard CNG sequence. Out-pointers are valid locals, `buf`/`out`
    // lengths are passed exactly, and each handle is destroyed/closed once
    // after use on every path below.
    unsafe {
        if BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, null(), 0) != 0 {
            return Err("SHA-256 is unavailable".into());
        }
        if BCryptCreateHash(alg, &mut hash, null_mut(), 0, null(), 0, 0) != 0 {
            BCryptCloseAlgorithmProvider(alg, 0);
            return Err("SHA-256 is unavailable".into());
        }
        let mut res = Ok(());
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if BCryptHashData(hash, buf.as_ptr(), n as u32, 0) != 0 {
                        res = Err("SHA-256 failed".to_string());
                        break;
                    }
                }
                Err(e) => {
                    res = Err(e.to_string());
                    break;
                }
            }
        }
        if res.is_ok() && BCryptFinishHash(hash, out.as_mut_ptr(), 32, 0) != 0 {
            res = Err("SHA-256 failed".into());
        }
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        res?;
    }
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
}

/// `open` through the shell (browser for a URL, or runs a program).
fn shell_open(target: &str, args: Option<&str>) -> bool {
    let (verb, t) = (wide("open"), wide(target));
    let a = args.map(wide);
    // SAFETY: NUL-terminated UTF-16 buffers that outlive the call. The return
    // value is an HINSTANCE-like code: values above 32 mean success.
    let rc = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            t.as_ptr(),
            a.as_ref().map_or(null(), |a| a.as_ptr()),
            null(),
            SW_SHOWNORMAL,
        )
    };
    rc as usize > 32
}

enum Msg {
    Checked {
        manual: bool,
        result: Result<Release, String>,
    },
    Progress(u64, u64),
    Downloaded(Result<PathBuf, String>),
}

/// `3.1 / 6.0 MB`.
pub fn fmt_progress(done: u64, total: u64) -> String {
    let mb = |b: u64| b as f64 / 1_000_000.0;
    if total == 0 {
        format!("{:.1} MB", mb(done))
    } else {
        format!("{:.1} / {:.1} MB", mb(done), mb(total))
    }
}

/// Update state kept by the app.
pub struct Updater {
    schedule: Schedule,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    checking: bool,
    /// Download in progress, as (done, total) bytes.
    downloading: Option<(u64, u64)>,
    /// A newer release, if one was found.
    pub available: Option<Release>,
    dismissed: bool,
    /// Line under the Settings buttons from "Check now": (is error, text).
    pub manual_msg: Option<(bool, String)>,
    /// Error from the last install attempt, shown in the banner.
    install_error: Option<String>,
}

impl Updater {
    pub fn new(now: Instant) -> Updater {
        let (tx, rx) = channel();
        Updater {
            schedule: Schedule::new(now),
            tx,
            rx,
            checking: false,
            downloading: None,
            available: None,
            dismissed: false,
            manual_msg: None,
            install_error: None,
        }
    }

    pub fn busy(&self) -> bool {
        self.checking || self.downloading.is_some()
    }

    fn start_check(&mut self, ctx: &egui::Context, manual: bool) {
        self.checking = true;
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let url = format!("https://api.github.com/repos/{UPDATE_REPO}/releases/latest");
            let result = http_get(&url, MAX_JSON)
                .and_then(|b| String::from_utf8(b).map_err(|_| "unexpected reply".to_string()))
                .and_then(|s| parse_release(&s));
            tx.send(Msg::Checked { manual, result }).ok();
            ctx.request_repaint();
        });
    }

    /// "Check now": always runs, reports its result in `manual_msg`.
    pub fn check_now(&mut self, ctx: &egui::Context) {
        if !self.busy() {
            self.manual_msg = None;
            self.start_check(ctx, true);
        }
    }

    /// Downloads, verifies and runs the setup; `poll` reports when to exit.
    pub fn install(&mut self, ctx: &egui::Context) {
        let Some(rel) = self.available.clone() else {
            return;
        };
        let Some(asset) = rel.setup.clone() else {
            return;
        };
        if self.busy() {
            return;
        }
        self.install_error = None;
        self.downloading = Some((0, asset.size));
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        let path = std::env::temp_dir().join(format!("Q2Route-Setup-{}.exe", rel.version()));
        std::thread::spawn(move || {
            let last = std::cell::Cell::new(Instant::now() - Duration::from_secs(1));
            let r = download(&asset.url, &path, MAX_SETUP, |done, total| {
                if last.get().elapsed() > Duration::from_millis(200) {
                    last.set(Instant::now());
                    tx.send(Msg::Progress(done, total.max(asset.size))).ok();
                    ctx.request_repaint();
                }
            })
            .and_then(|()| {
                let len = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
                let actual = match asset.sha256 {
                    Some(_) => sha256_hex(std::fs::File::open(&path).map_err(|e| e.to_string())?)?,
                    None => String::new(),
                };
                verify(len, asset.sha256.as_deref(), &asset, &actual)
            });
            let r = match r {
                Ok(()) => Ok(path),
                Err(e) => {
                    std::fs::remove_file(&path).ok();
                    Err(e)
                }
            };
            tx.send(Msg::Downloaded(r)).ok();
            ctx.request_repaint();
        });
    }

    /// Handles finished work and starts the scheduled check. Returns true
    /// when the setup was launched and the UI should close.
    pub fn poll(&mut self, ctx: &egui::Context, auto_check: bool) -> bool {
        let now = Instant::now();
        if auto_check && !self.busy() && self.schedule.due(now) {
            self.schedule.mark(now);
            self.start_check(ctx, false);
        }
        let mut launched = false;
        loop {
            match self.rx.try_recv() {
                Ok(Msg::Checked { manual, result }) => {
                    self.checking = false;
                    self.on_checked(manual, result);
                }
                Ok(Msg::Progress(d, t)) => {
                    if self.downloading.is_some() {
                        self.downloading = Some((d, t));
                    }
                }
                Ok(Msg::Downloaded(r)) => {
                    self.downloading = None;
                    match r {
                        Ok(path) => {
                            let args = "/SILENT /SUPPRESSMSGBOXES /NORESTART";
                            if shell_open(&path.to_string_lossy(), Some(args)) {
                                // Setup closes this window itself once it is really
                                // installing (after UAC); if UAC is cancelled we stay open.
                                launched = true;
                                self.install_error = Some(
                                    "Setup started. Accept the Windows prompt; Q2Route closes and reopens when it installs."
                                        .into(),
                                );
                            } else {
                                self.install_error =
                                    Some("Could not start the setup (was it cancelled?).".into());
                            }
                        }
                        Err(e) => self.install_error = Some(e),
                    }
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        launched
    }

    fn on_checked(&mut self, manual: bool, result: Result<Release, String>) {
        match result {
            Ok(rel) if newer(&rel.tag, CURRENT) => {
                if self.available.as_ref().is_none_or(|a| a.tag != rel.tag) {
                    self.dismissed = false;
                }
                if manual {
                    self.manual_msg =
                        Some((false, format!("Q2Route {} is available.", rel.version())));
                }
                self.available = Some(rel);
            }
            Ok(_) => {
                if manual {
                    self.manual_msg = Some((false, "Q2Route is up to date.".into()));
                }
            }
            Err(e) => {
                if manual {
                    self.manual_msg = Some((true, format!("Could not check for updates: {e}")));
                }
            }
        }
    }

    /// The banner above the page; nothing when there is no update or it was
    /// dismissed with "Later" (and nothing is happening).
    pub fn banner(&mut self, ui: &mut egui::Ui) {
        let Some(rel) = self.available.clone() else {
            return;
        };
        if self.dismissed && self.downloading.is_none() {
            return;
        }
        let (mut install, mut notes, mut later) = (false, false, false);
        let (downloading, error) = (self.downloading, self.install_error.clone());
        crate::views::dashboard::banner(ui, egui::Color32::from_rgb(0x2b, 0x5c, 0x8a), |ui| {
            if let Some((d, t)) = downloading {
                ui.label(format!("Downloading… {}", fmt_progress(d, t)));
                ui.spinner();
                return;
            }
            ui.label(format!("Q2Route {} is available.", rel.version()));
            install = rel.setup.is_some() && ui.button("Install update").clicked();
            notes = ui.button("Release notes").clicked();
            later = ui.button("Later").clicked();
            if let Some(e) = &error {
                ui.label(e);
            }
        });
        if install {
            self.install(ui.ctx());
        }
        if notes && rel.html_url.starts_with("https://") {
            shell_open(&rel.html_url, None);
        }
        if later {
            self.dismissed = true;
        }
        if downloading.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }
    }
}

/// Error colour for the Settings result line.
pub const ERROR_COLOR: egui::Color32 = BLOCK;

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{
      "url": "https://api.github.com/repos/amirh55/Q2Route/releases/1",
      "html_url": "https://github.com/amirh55/Q2Route/releases/tag/v0.2.1",
      "tag_name": "v0.2.1",
      "name": "Q2Route 0.2.1",
      "prerelease": false,
      "assets": [
        {"name": "Q2Route-0.2.1-win-x64.zip", "size": 111,
         "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
         "browser_download_url": "https://github.com/amirh55/Q2Route/releases/download/v0.2.1/Q2Route-0.2.1-win-x64.zip"},
        {"name": "Q2Route-Setup-0.2.1.exe", "size": 6000000,
         "digest": "sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
         "browser_download_url": "https://github.com/amirh55/Q2Route/releases/download/v0.2.1/Q2Route-Setup-0.2.1.exe"}
      ]
    }"#;

    fn asset(size: u64, digest: Option<&str>) -> Asset {
        Asset {
            name: "Q2Route-Setup-0.2.1.exe".into(),
            url: "https://example.com/x.exe".into(),
            size,
            sha256: digest.map(str::to_string),
        }
    }

    #[test]
    fn parse_release_picks_setup_asset() {
        let r = parse_release(JSON).unwrap();
        assert_eq!(r.tag, "v0.2.1");
        assert_eq!(r.version(), "0.2.1");
        assert_eq!(
            r.html_url,
            "https://github.com/amirh55/Q2Route/releases/tag/v0.2.1"
        );
        let a = r.setup.unwrap();
        assert_eq!(a.name, "Q2Route-Setup-0.2.1.exe");
        assert!(a.url.ends_with("/Q2Route-Setup-0.2.1.exe"));
        assert_eq!(a.size, 6_000_000);
        assert_eq!(
            a.sha256.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    #[test]
    fn parse_release_without_setup_or_digest() {
        let r = parse_release(
            r#"{"tag_name":"v1.0.0","html_url":"https://x","assets":[
            {"name":"Q2Route-Setup-1.0.0.exe","size":5,"browser_download_url":"https://x/s.exe"}]}"#,
        )
        .unwrap();
        assert_eq!(r.setup.unwrap().sha256, None);
        let r = parse_release(r#"{"tag_name":"v1.0.0","html_url":"https://x"}"#).unwrap();
        assert!(r.setup.is_none());
        assert!(parse_release("not json").is_err());
        assert!(parse_release(r#"{"message":"Not Found"}"#).is_err());
    }

    #[test]
    fn version_compare() {
        assert!(newer("v0.2.1", "0.2.0"));
        assert!(!newer("v0.2.0", "0.2.0"));
        assert!(!newer("v0.1.9", "0.2.0"));
        assert!(newer("v0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("v0.1.0-m12", "0.0.1"));
        assert!(!newer("nightly", "0.2.0"));
        assert!(!newer("v0.3", "0.2.0"));
        assert!(!newer("v0.3.0.1", "0.2.0"));
        assert!(!newer("v0.3.0", "garbage"));
    }

    #[test]
    fn digest_mismatch_rejected() {
        let good = "ab".repeat(32);
        let a = asset(10, Some(&good));
        assert!(verify(10, a.sha256.as_deref(), &a, &good.to_uppercase()).is_ok());
        let e = verify(10, a.sha256.as_deref(), &a, &"cd".repeat(32)).unwrap_err();
        assert_eq!(e, "Update download is damaged, try again.");
        // No digest published: only the size is checked.
        let n = asset(10, None);
        assert!(verify(10, None, &n, "").is_ok());
    }

    #[test]
    fn size_mismatch_rejected() {
        let a = asset(10, None);
        assert!(verify(9, None, &a, "").is_err());
        assert!(verify(11, None, &a, "").is_err());
    }

    #[test]
    fn schedule_backs_off() {
        let t0 = Instant::now();
        let mut s = Schedule::new(t0);
        assert!(!s.due(t0 + Duration::from_secs(9)));
        assert!(s.due(t0 + Duration::from_secs(10)));
        let t1 = t0 + Duration::from_secs(12);
        s.mark(t1);
        assert!(!s.due(t1 + Duration::from_secs(3600)));
        assert!(!s.due(t1 + Duration::from_secs(24 * 3600 - 1)));
        assert!(s.due(t1 + Duration::from_secs(24 * 3600)));
    }

    #[test]
    fn https_only_urls() {
        assert_eq!(
            split_https("https://api.github.com/repos/a/b?x=1").unwrap(),
            ("api.github.com".into(), 443, "/repos/a/b?x=1".into())
        );
        assert_eq!(
            split_https("https://h:8443").unwrap(),
            ("h".into(), 8443, "/".into())
        );
        assert!(split_https("http://github.com/x").is_err());
        assert!(split_https("https://u@evil/x").is_err());
    }

    #[test]
    fn progress_text() {
        assert_eq!(fmt_progress(3_100_000, 6_000_000), "3.1 / 6.0 MB");
        assert_eq!(fmt_progress(3_100_000, 0), "3.1 MB");
    }

    #[test]
    fn sha256_known_vector() {
        let h = sha256_hex(&b"abc"[..]).unwrap();
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
