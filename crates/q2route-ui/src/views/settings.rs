//! Settings page: General, Appearance, Geo data, Backup, Leak check.

use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;
use q2route_core::config::Config;
use q2route_core::ipc::{GeoFile, GeoStatus, Request, Response};
use q2route_core::leak::{Level, Verdict};
use tokio::sync::oneshot;

use crate::app::Requests;
use crate::client::Client;
use crate::file_dialog;
use crate::leak::LeakCheck;
use crate::settings::{set_autostart, Theme, UiSettings};
use crate::views::dashboard::{BLOCK, DIRECT};
use crate::views::log::local_offset_min;
use crate::views::usage::fmt_bytes;

/// Import files bigger than this are refused before parsing.
pub const MAX_IMPORT_BYTES: u64 = 1024 * 1024;

/// Leak-check state kept by the app: the running probe and the last verdict.
#[derive(Default)]
pub struct LeakState {
    check: Option<LeakCheck>,
    verdict: Option<Verdict>,
}

/// Geo data and backup state kept by the app.
#[derive(Default)]
pub struct BackupState {
    geo: Option<GeoStatus>,
    geo_rx: Option<oneshot::Receiver<Response>>,
    /// The pending request is an `UpdateGeo` (not a plain status read).
    geo_updating: bool,
    /// Line shown under the geo buttons after an update.
    geo_msg: Option<String>,
    last_shown: Option<Instant>,
    include_passwords: bool,
    /// A parsed import waiting for the Yes/No answer.
    confirm: Option<Config>,
    import_rx: Option<oneshot::Receiver<Response>>,
    /// Result line under the Backup buttons.
    message: Option<(bool, String)>,
}

/// Text of `cfg` for export; proxy passwords only when asked.
pub fn export_text(cfg: &Config, with_passwords: bool) -> String {
    let mut c = cfg.clone();
    if !with_passwords {
        for p in &mut c.proxies {
            p.password = None;
        }
    }
    toml::to_string_pretty(&c).unwrap_or_default()
}

/// Reads and validates an import file (at most 1 MiB).
pub fn read_import(path: &Path) -> Result<Config, String> {
    let len = std::fs::metadata(path)
        .map_err(|e| format!("Import failed: {e}"))?
        .len();
    if len > MAX_IMPORT_BYTES {
        return Err("Import failed: the file is bigger than 1 MiB.".into());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Import failed: {e}"))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| "Import failed: the file is not a text (TOML) file.".to_string())?;
    Config::parse(&text).map_err(|e| format!("Import failed: {e}"))
}

/// (year, month, day) of a day count since 1970-01-01 (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `2026-11-15 (4.1 MB)`, or `missing`. `offset_min` is the local UTC offset.
pub fn fmt_geo(f: Option<&GeoFile>, offset_min: i32) -> String {
    let Some(f) = f else {
        return "missing".into();
    };
    let secs = (f.modified_ms / 1000) as i64 + i64::from(offset_min) * 60;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02} ({})", fmt_bytes(f.size))
}

/// The line shown after an update.
pub fn geo_update_line(updated: &[String]) -> String {
    if updated.is_empty() {
        "No newer geo files found (v2rayN, xray, v2ray or sing-box must be running).".into()
    } else {
        format!("Updated: {}", updated.join(", "))
    }
}

pub fn level_color(level: Level) -> egui::Color32 {
    match level {
        Level::NoLeak => DIRECT,
        Level::Leak => BLOCK,
        Level::CantTell => egui::Color32::GRAY,
    }
}

pub fn show(
    ui: &mut egui::Ui,
    s: &mut UiSettings,
    req: &mut Requests,
    client: &Client,
    leak: &mut LeakState,
    backup: &mut BackupState,
) {
    ui.heading("Settings");
    ui.add_space(8.0);
    let mut changed = false;
    if ui
        .checkbox(&mut s.start_with_windows, "Start with Windows")
        .changed()
    {
        match set_autostart(s.start_with_windows) {
            Ok(()) => changed = true,
            Err(e) => {
                s.start_with_windows = !s.start_with_windows;
                req.last_error = Some(format!("Start with Windows: {e}"));
            }
        }
    }
    changed |= ui.checkbox(&mut s.close_to_tray, "Close to tray").changed();
    if changed {
        if let Err(e) = s.save() {
            req.last_error = Some(format!("Saving settings: {e}"));
        }
    }
    appearance_section(ui, s, req);
    geo_section(ui, client, req, backup);
    backup_section(ui, client, backup);
    leak_section(ui, client, leak);
}

fn appearance_section(ui: &mut egui::Ui, s: &mut UiSettings, req: &mut Requests) {
    ui.add_space(16.0);
    ui.heading("Appearance");
    ui.add_space(8.0);
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label("Theme:");
        for (t, label) in [
            (Theme::Dark, "Dark"),
            (Theme::Light, "Light"),
            (Theme::System, "Follow Windows"),
        ] {
            if ui.selectable_value(&mut s.theme, t, label).changed() {
                ui.ctx().set_theme(s.theme.preference());
                changed = true;
            }
        }
    });
    changed |= ui
        .checkbox(&mut s.tray_graph, "Traffic graph in the tray icon")
        .changed();
    if changed {
        if let Err(e) = s.save() {
            req.last_error = Some(format!("Saving settings: {e}"));
        }
    }
}

fn geo_section(ui: &mut egui::Ui, client: &Client, req: &mut Requests, b: &mut BackupState) {
    // The page was just opened (it is drawn every frame while it is open).
    let fresh = b
        .last_shown
        .is_none_or(|t| t.elapsed() > Duration::from_secs(2));
    b.last_shown = Some(Instant::now());
    if fresh && b.geo_rx.is_none() && client.connected() {
        b.geo_rx = Some(client.send(Request::GetGeoStatus));
        b.geo_updating = false;
        b.geo_msg = None;
    }
    if let Some(rx) = b.geo_rx.as_mut() {
        let done = match rx.try_recv() {
            Ok(Response::Geo(g)) => {
                if b.geo_updating {
                    b.geo_msg = Some(geo_update_line(&g.updated));
                }
                b.geo = Some(g);
                true
            }
            Ok(Response::Error(e)) => {
                req.last_error = Some(e);
                true
            }
            Ok(_) | Err(oneshot::error::TryRecvError::Closed) => true,
            Err(oneshot::error::TryRecvError::Empty) => {
                ui.ctx().request_repaint_after(Duration::from_millis(200));
                false
            }
        };
        if done {
            b.geo_rx = None;
            b.geo_updating = false;
        }
    }
    ui.add_space(16.0);
    ui.heading("Geo data");
    ui.add_space(8.0);
    let off = local_offset_min();
    let g = b.geo.clone().unwrap_or_default();
    ui.label(format!("geoip.dat: {}", fmt_geo(g.geoip.as_ref(), off)));
    ui.label(format!("geosite.dat: {}", fmt_geo(g.geosite.as_ref(), off)));
    ui.horizontal(|ui| {
        let can = client.connected() && b.geo_rx.is_none();
        if ui
            .add_enabled(can, egui::Button::new("Update now"))
            .clicked()
        {
            b.geo_rx = Some(client.send(Request::UpdateGeo));
            b.geo_updating = true;
            b.geo_msg = None;
        }
        if b.geo_updating {
            ui.spinner();
        }
    });
    if let Some(m) = &b.geo_msg {
        ui.label(m);
    }
}

fn backup_section(ui: &mut egui::Ui, client: &Client, b: &mut BackupState) {
    if let Some(rx) = b.import_rx.as_mut() {
        let done = match rx.try_recv() {
            Ok(Response::Error(e)) => {
                b.message = Some((true, format!("Import failed: {e}")));
                true
            }
            Ok(_) => {
                b.message = Some((
                    false,
                    "Imported. A backup is kept as config.toml.bak.".into(),
                ));
                true
            }
            Err(oneshot::error::TryRecvError::Closed) => true,
            Err(oneshot::error::TryRecvError::Empty) => {
                ui.ctx().request_repaint_after(Duration::from_millis(200));
                false
            }
        };
        if done {
            b.import_rx = None;
        }
    }
    ui.add_space(16.0);
    ui.heading("Backup");
    ui.add_space(8.0);
    ui.checkbox(&mut b.include_passwords, "Include proxy passwords");
    if b.include_passwords {
        ui.colored_label(
            BLOCK,
            "The file will contain your proxy passwords in plain text.",
        );
    }
    ui.horizontal(|ui| {
        let snap = client.latest();
        if ui
            .add_enabled(snap.is_some(), egui::Button::new("Export…"))
            .clicked()
        {
            if let (Some(snap), Some(path)) =
                (snap.as_ref(), file_dialog::pick_save("q2route-config.toml"))
            {
                let text = export_text(&snap.config, b.include_passwords);
                b.message = Some(match std::fs::write(&path, text) {
                    Ok(()) => (false, format!("Exported to {}", path.display())),
                    Err(e) => (true, format!("Export failed: {e}")),
                });
            }
        }
        let can = client.connected() && b.import_rx.is_none() && b.confirm.is_none();
        if ui.add_enabled(can, egui::Button::new("Import…")).clicked() {
            if let Some(path) = file_dialog::pick_open("TOML files (*.toml)") {
                match read_import(&path) {
                    Ok(cfg) => {
                        b.confirm = Some(cfg);
                        b.message = None;
                    }
                    Err(e) => b.message = Some((true, e)),
                }
            }
        }
    });
    if b.confirm.is_some() {
        ui.add_space(6.0);
        ui.label(
            "Replace all groups, rules and proxies with this file? \
             A backup is kept as config.toml.bak.",
        );
        ui.horizontal(|ui| {
            if ui.button("Yes").clicked() {
                if let Some(cfg) = b.confirm.take() {
                    b.import_rx = Some(client.send(Request::ImportConfig(cfg)));
                    b.message = None;
                }
            }
            if ui.button("No").clicked() {
                b.confirm = None;
            }
        });
    }
    if let Some((bad, m)) = &b.message {
        ui.add_space(6.0);
        if *bad {
            ui.colored_label(BLOCK, m);
        } else {
            ui.label(m);
        }
    }
}

fn leak_section(ui: &mut egui::Ui, client: &Client, leak: &mut LeakState) {
    if let Some(v) = leak.check.as_ref().and_then(|c| c.poll()) {
        leak.verdict = Some(v);
        leak.check = None;
    }
    let running = leak.check.as_ref().is_some_and(|c| c.running());
    ui.add_space(16.0);
    ui.heading("Leak check");
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!running, egui::Button::new("Run leak check"))
            .clicked()
        {
            leak.check = Some(LeakCheck::start(client));
            leak.verdict = None;
        }
        if running {
            ui.spinner();
            ui.label("Checking… (up to 30 s)");
        }
    });
    if running {
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
    if let Some(v) = &leak.verdict {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(&v.headline)
                .strong()
                .color(level_color(v.level.clone())),
        );
        for line in &v.lines {
            ui.label(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_colors() {
        assert_eq!(level_color(Level::NoLeak), DIRECT);
        assert_eq!(level_color(Level::Leak), BLOCK);
        assert_eq!(level_color(Level::CantTell), egui::Color32::GRAY);
    }

    fn with_password() -> Config {
        let mut c = Config::seed();
        c.proxies[0].password = Some("hunter2".into());
        c
    }

    #[test]
    fn export_strips_passwords() {
        let t = export_text(&with_password(), false);
        assert!(!t.contains("password"), "{t}");
        assert!(!t.contains("hunter2"));
    }

    #[test]
    fn export_with_passwords_keeps_them() {
        let t = export_text(&with_password(), true);
        assert!(t.contains("password = \"hunter2\""), "{t}");
    }

    #[test]
    fn export_then_parse_roundtrips() {
        let c = with_password();
        assert_eq!(Config::parse(&export_text(&c, true)).unwrap(), c);
        let mut stripped = c.clone();
        stripped.proxies[0].password = None;
        assert_eq!(Config::parse(&export_text(&c, false)).unwrap(), stripped);
    }

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("q2route-m12-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn import_too_big_refused() {
        let p = temp_file("big.toml", &vec![b'#'; 1024 * 1024 + 1]);
        let e = read_import(&p).unwrap_err();
        std::fs::remove_file(&p).ok();
        assert!(e.contains("1 MiB"), "{e}");
    }

    #[test]
    fn import_rejects_binary_and_bad_toml() {
        let p = temp_file("bin.toml", &[0xff, 0xfe, 0x00, 0x80]);
        assert!(read_import(&p).unwrap_err().starts_with("Import failed"));
        std::fs::write(&p, "this is = not [valid").unwrap();
        assert!(read_import(&p).unwrap_err().starts_with("Import failed"));
        std::fs::remove_file(&p).ok();
        assert!(read_import(&p).is_err());
    }

    #[test]
    fn import_good_file() {
        let c = Config::seed();
        let p = temp_file("ok.toml", export_text(&c, false).as_bytes());
        let got = read_import(&p);
        std::fs::remove_file(&p).ok();
        assert_eq!(got.unwrap(), c);
    }

    #[test]
    fn fmt_geo_formats() {
        // 2026-11-15 12:00:00 UTC.
        let noon = 20_772 * 86_400_000 + 43_200_000;
        let f = GeoFile {
            modified_ms: noon,
            size: 4_100_000,
        };
        assert_eq!(fmt_geo(Some(&f), 0), "2026-11-15 (4.1 MB)");
        assert_eq!(fmt_geo(None, 0), "missing");
        // 23:00 UTC is already the 16th at UTC+3:30.
        let late = GeoFile {
            modified_ms: noon + 11 * 3_600_000,
            size: 999,
        };
        assert_eq!(fmt_geo(Some(&late), 210), "2026-11-16 (999 B)");
        assert_eq!(fmt_geo(Some(&late), -1439), "2026-11-14 (999 B)");
        // Leap day and the epoch.
        let leap = GeoFile {
            modified_ms: 1_709_164_800_000,
            size: 0,
        };
        assert_eq!(fmt_geo(Some(&leap), 0), "2024-02-29 (0 B)");
        let zero = GeoFile {
            modified_ms: 0,
            size: 0,
        };
        assert_eq!(fmt_geo(Some(&zero), 0), "1970-01-01 (0 B)");
    }

    #[test]
    fn update_lines() {
        assert!(geo_update_line(&[]).starts_with("No newer geo files found"));
        assert_eq!(
            geo_update_line(&["geosite.dat".into(), "geoip.dat".into()]),
            "Updated: geosite.dat, geoip.dat"
        );
    }
}
