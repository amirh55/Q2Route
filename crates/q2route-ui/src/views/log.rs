//! Log: the service's recent log lines, polled once a second while the page
//! is visible, with a level filter, search, pause, copy and clear.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use q2route_core::ipc::{LogEntry, LogLevel, Request, Response};
use tokio::sync::oneshot;

use crate::client::Client;

const POLL: Duration = Duration::from_secs(1);
const CAP: usize = 2000;
const ROW_HEIGHT: f32 = 18.0;
/// The local time offset is re-read at most this often.
const TZ_REFRESH: Duration = Duration::from_secs(60);

/// The UI's copy of the service log, oldest first.
#[derive(Default)]
pub struct LogBuf {
    entries: VecDeque<LogEntry>,
    last_seq: u64,
}

impl LogBuf {
    /// Appends `new`, keeping the newest `CAP`. A first entry that is not
    /// newer than what we have means the service restarted: start over.
    pub fn merge(&mut self, new: Vec<LogEntry>) {
        let Some(first) = new.first() else { return };
        if first.seq <= self.last_seq {
            self.entries.clear();
        }
        for e in new {
            self.last_seq = e.seq;
            self.entries.push_back(e);
        }
        while self.entries.len() > CAP {
            self.entries.pop_front();
        }
    }

    /// Forgets the shown lines; the next poll continues after `last_seq`.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LevelFilter {
    Errors,
    Warnings,
    Info,
}

impl LevelFilter {
    const ALL: [LevelFilter; 3] = [
        LevelFilter::Errors,
        LevelFilter::Warnings,
        LevelFilter::Info,
    ];

    fn label(self) -> &'static str {
        match self {
            LevelFilter::Errors => "Errors",
            LevelFilter::Warnings => "Warnings",
            LevelFilter::Info => "Info",
        }
    }

    pub fn shows(self, l: LogLevel) -> bool {
        match self {
            LevelFilter::Errors => l == LogLevel::Error,
            LevelFilter::Warnings => matches!(l, LogLevel::Error | LogLevel::Warn),
            LevelFilter::Info => true,
        }
    }
}

/// Entries passing the level filter and the case-insensitive search on
/// `target + msg`.
pub fn visible<'a>(buf: &'a LogBuf, f: LevelFilter, search: &str) -> Vec<&'a LogEntry> {
    let needle = search.trim().to_lowercase();
    buf.entries
        .iter()
        .filter(|e| f.shows(e.level))
        .filter(|e| {
            needle.is_empty()
                || format!("{} {}", e.target, e.msg)
                    .to_lowercase()
                    .contains(&needle)
        })
        .collect()
}

/// `HH:MM:SS` of Unix `ms` at `offset_min` minutes from UTC.
pub fn hms(ms: u64, offset_min: i32) -> String {
    let secs = (ms / 1000) as i64 + i64::from(offset_min) * 60;
    let d = secs.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", d / 3600, d % 3600 / 60, d % 60)
}

/// `q2route_service::relay` -> `relay`.
pub fn short_target(t: &str) -> &str {
    t.rsplit("::").next().unwrap_or(t)
}

fn level_text(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN",
        LogLevel::Info => "INFO",
        LogLevel::Debug => "DEBUG",
        LogLevel::Trace => "TRACE",
    }
}

/// Local time zone offset east of UTC, in minutes (0 if unknown).
pub(crate) fn local_offset_min() -> i32 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: an all-zero TIME_ZONE_INFORMATION is valid plain data that the
    // call overwrites.
    let mut tz: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let id = unsafe { GetTimeZoneInformation(&mut tz) };
    let bias = match id {
        1 => tz.Bias + tz.StandardBias,
        2 => tz.Bias + tz.DaylightBias,
        0 => tz.Bias,
        _ => return 0,
    };
    -bias
}

/// `%ProgramData%\Q2Route\logs`.
fn log_dir() -> std::path::PathBuf {
    let pd = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
    std::path::PathBuf::from(pd).join("Q2Route").join("logs")
}

pub struct LogView {
    buf: LogBuf,
    level: LevelFilter,
    search: String,
    paused: bool,
    /// While paused, only entries up to this seq are shown.
    frozen_seq: u64,
    pending: Option<oneshot::Receiver<Response>>,
    last_sent: Option<Instant>,
    offset: Option<(i32, Instant)>,
}

impl Default for LogView {
    fn default() -> Self {
        LogView {
            buf: LogBuf::default(),
            level: LevelFilter::Info,
            search: String::new(),
            paused: false,
            frozen_seq: 0,
            pending: None,
            last_sent: None,
            offset: None,
        }
    }
}

impl LogView {
    fn poll(&mut self, client: &Client) {
        if let Some(rx) = self.pending.as_mut() {
            match rx.try_recv() {
                Ok(Response::Log(v)) => {
                    self.buf.merge(v);
                    self.pending = None;
                }
                // Errors (including "disconnected") are ignored: the app
                // shows a banner when the service is down.
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => self.pending = None,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        let due = self.pending.is_none() && self.last_sent.is_none_or(|t| t.elapsed() >= POLL);
        if due {
            let after = self.buf.last_seq;
            self.pending = Some(client.send(Request::GetLog { after }));
            self.last_sent = Some(Instant::now());
        }
    }

    fn offset_min(&mut self) -> i32 {
        match self.offset {
            Some((o, t)) if t.elapsed() < TZ_REFRESH => o,
            _ => {
                let o = local_offset_min();
                self.offset = Some((o, Instant::now()));
                o
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, client: &Client) {
        if !client.connected() {
            self.pending = None;
            return;
        }
        self.poll(client);
        ui.ctx().request_repaint_after(POLL);
        let off = self.offset_min();
        ui.horizontal_wrapped(|ui| {
            for f in LevelFilter::ALL {
                ui.selectable_value(&mut self.level, f, f.label());
            }
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search).desired_width(160.0));
        });
        let mut rows = visible(&self.buf, self.level, &self.search);
        if self.paused {
            rows.retain(|e| e.seq <= self.frozen_seq);
        }
        let mut clear = false;
        ui.horizontal_wrapped(|ui| {
            let label = if self.paused { "Resume" } else { "Pause" };
            if ui.button(label).clicked() {
                self.paused = !self.paused;
                self.frozen_seq = self.buf.last_seq;
            }
            if ui.button("Copy").clicked() {
                let text: String = rows
                    .iter()
                    .map(|e| {
                        format!(
                            "{} {} {} {}\n",
                            hms(e.ms, off),
                            level_text(e.level),
                            short_target(&e.target),
                            e.msg
                        )
                    })
                    .collect();
                ui.ctx().copy_text(text);
            }
            if ui.button("Clear").clicked() {
                clear = true;
            }
            if ui.button("Open log folder").clicked() {
                let _ = std::process::Command::new("explorer.exe")
                    .arg(log_dir())
                    .spawn();
            }
            ui.weak(format!("{} shown", rows.len()));
        });
        ui.separator();
        let warn = Color32::from_rgb(230, 190, 60);
        egui::ScrollArea::vertical()
            .id_salt("log_rows")
            .auto_shrink(false)
            .stick_to_bottom(!self.paused)
            .show_rows(ui, ROW_HEIGHT, rows.len(), |ui, range| {
                for e in &rows[range] {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.label(RichText::new(hms(e.ms, off)).monospace());
                        let lvl = RichText::new(format!("{:<5}", level_text(e.level))).monospace();
                        match e.level {
                            LogLevel::Error => {
                                ui.label(lvl.color(ui.visuals().error_fg_color));
                            }
                            LogLevel::Warn => {
                                ui.label(lvl.color(warn));
                            }
                            _ => {
                                ui.label(lvl);
                            }
                        }
                        ui.weak(short_target(&e.target));
                        ui.add(egui::Label::new(e.msg.as_str()).truncate());
                    });
                }
            });
        if clear {
            self.buf.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(seq: u64, level: LogLevel, target: &str, msg: &str) -> LogEntry {
        LogEntry {
            seq,
            ms: seq * 1000,
            level,
            target: target.into(),
            msg: msg.into(),
        }
    }

    fn many(from: u64, to: u64) -> Vec<LogEntry> {
        (from..=to)
            .map(|s| e(s, LogLevel::Info, "t", "m"))
            .collect()
    }

    #[test]
    fn merge_appends_and_caps() {
        let mut b = LogBuf::default();
        b.merge(many(1, 1500));
        b.merge(many(1501, 2500));
        assert_eq!(b.entries.len(), 2000);
        assert_eq!(b.entries.front().unwrap().seq, 501);
        assert_eq!(b.entries.back().unwrap().seq, 2500);
        assert_eq!(b.last_seq, 2500);
        b.merge(vec![]);
        assert_eq!(b.last_seq, 2500);
    }

    #[test]
    fn merge_resets_on_seq_going_back() {
        let mut b = LogBuf::default();
        b.merge(many(1, 10));
        b.merge(many(1, 3));
        assert_eq!(b.entries.len(), 3);
        assert_eq!(b.last_seq, 3);
        // A restart whose first seq equals the old last_seq also resets.
        b.merge(many(3, 4));
        assert_eq!(b.entries.len(), 2);
    }

    #[test]
    fn filter_levels_and_search() {
        let mut b = LogBuf::default();
        b.merge(vec![
            e(1, LogLevel::Error, "q2route_service::engine", "boom"),
            e(2, LogLevel::Warn, "q2route_service::relay", "slow"),
            e(3, LogLevel::Info, "q2route_service::dns", "ok"),
        ]);
        assert_eq!(visible(&b, LevelFilter::Errors, "").len(), 1);
        assert_eq!(visible(&b, LevelFilter::Warnings, "").len(), 2);
        assert_eq!(visible(&b, LevelFilter::Info, "").len(), 3);
        let r = visible(&b, LevelFilter::Info, "RELAY");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].seq, 2);
        assert_eq!(visible(&b, LevelFilter::Errors, "relay").len(), 0);
        assert_eq!(visible(&b, LevelFilter::Info, "BOOM").len(), 1);
    }

    #[test]
    fn hms_applies_offset() {
        assert_eq!(hms(0, 210), "03:30:00");
        assert_eq!(hms(0, -60), "23:00:00");
        assert_eq!(hms(3_661_000, 0), "01:01:01");
    }

    #[test]
    fn short_target_takes_last_segment() {
        assert_eq!(short_target("q2route_service::relay"), "relay");
        assert_eq!(short_target("plain"), "plain");
        assert_eq!(short_target(""), "");
    }
}
