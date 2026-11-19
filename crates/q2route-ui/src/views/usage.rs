//! Data usage: proxied traffic per group, app and proxy for this session,
//! today, this month and the last 90 days. Off by default.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use q2route_core::ipc::{Request, Response, StateSnapshot, UsageReport, UsageRow};
use tokio::sync::oneshot;

use crate::app::Requests;
use crate::client::Client;

/// Shown under the switch.
pub const EXPLANATION: &str = "Counts traffic sent through a proxy (what uses your VPN data). \
     Direct traffic is not counted.";

/// How often the totals are refreshed while the page is visible.
const POLL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
    Session,
    Today,
    Month,
    All,
}

impl Period {
    const ALL: [Period; 4] = [Period::Session, Period::Today, Period::Month, Period::All];

    fn label(self) -> &'static str {
        match self {
            Period::Session => "Session",
            Period::Today => "Today",
            Period::Month => "This month",
            Period::All => "Last 90 days",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
    Group,
    App,
    Proxy,
}

/// Totals of `period` grouped by `by`: (name, up, down), biggest total
/// first (ties by name). `Month` is the days of `today`'s `YYYY-MM`.
pub fn aggregate(
    report: &UsageReport,
    period: Period,
    today: &str,
    by: By,
) -> Vec<(String, u64, u64)> {
    let month = today.get(..7).unwrap_or(today);
    let mut totals: HashMap<String, (u64, u64)> = HashMap::new();
    let mut add = |rows: &[UsageRow]| {
        for r in rows {
            let name = match by {
                By::Group => r.group.as_str(),
                By::App => r.app.as_str(),
                By::Proxy => r.proxy.as_str(),
            };
            let t = totals.entry(name.to_string()).or_default();
            t.0 = t.0.saturating_add(r.up);
            t.1 = t.1.saturating_add(r.down);
        }
    };
    match period {
        Period::Session => add(&report.session),
        _ => {
            for (day, rows) in &report.days {
                let keep = match period {
                    Period::Today => day == today,
                    Period::Month => day.starts_with(month),
                    _ => true,
                };
                if keep {
                    add(rows);
                }
            }
        }
    }
    let mut out: Vec<(String, u64, u64)> =
        totals.into_iter().map(|(n, (u, d))| (n, u, d)).collect();
    out.sort_by(|a, b| {
        let (ta, tb) = (a.1.saturating_add(a.2), b.1.saturating_add(b.2));
        tb.cmp(&ta).then_with(|| a.0.cmp(&b.0))
    });
    out
}

/// `999 B`, `1.0 KB`, `12.3 MB`, `1.20 GB` (1000-based).
pub fn fmt_bytes(n: u64) -> String {
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    let units = ["B", "KB", "MB", "GB", "TB"];
    while i < units.len() - 1 && v >= 1000.0 {
        v /= 1000.0;
        i += 1;
        // 999.96 KB prints as 1000.0: go up a unit instead.
        if i < units.len() - 1 && (v * 10.0).round() >= 10_000.0 {
            v /= 1000.0;
            i += 1;
        }
    }
    if i >= 3 {
        format!("{v:.2} {}", units[i])
    } else {
        format!("{v:.1} {}", units[i])
    }
}

/// (name, up, down) rows.
type Table = Vec<(String, u64, u64)>;

pub struct UsageView {
    report: Option<UsageReport>,
    /// Aggregates of `report` for one period (by group, app, proxy); dropped
    /// when a new report arrives.
    tables: Option<(Period, [Table; 3])>,
    pending: Option<oneshot::Receiver<Response>>,
    last_sent: Option<Instant>,
    period: Period,
    confirm_reset: bool,
}

impl Default for UsageView {
    fn default() -> Self {
        UsageView {
            report: None,
            tables: None,
            pending: None,
            last_sent: None,
            period: Period::Today,
            confirm_reset: false,
        }
    }
}

impl UsageView {
    /// Collects a finished `GetUsage` and sends the next when due.
    fn poll(&mut self, client: &Client, req: &mut Requests) {
        if let Some(rx) = self.pending.as_mut() {
            match rx.try_recv() {
                Ok(Response::Usage(r)) => {
                    self.report = Some(r);
                    self.tables = None;
                    self.pending = None;
                }
                Ok(Response::Error(e)) => {
                    if e != "disconnected" && req.last_error.as_ref() != Some(&e) {
                        req.last_error = Some(e);
                    }
                    self.pending = None;
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => self.pending = None,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        let due = self.pending.is_none() && self.last_sent.is_none_or(|t| t.elapsed() >= POLL);
        if due {
            self.pending = Some(client.send(Request::GetUsage));
            self.last_sent = Some(Instant::now());
        }
    }

    /// Asks for fresh totals on the next frame.
    fn refresh_soon(&mut self) {
        self.last_sent = None;
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        snap: Option<&StateSnapshot>,
        client: &Client,
        req: &mut Requests,
    ) {
        let Some(s) = snap else { return };
        ui.heading("Data usage");
        ui.add_space(6.0);
        let mut on = s.config.settings.data_usage;
        if ui.checkbox(&mut on, "Count data usage").changed() {
            req.send(client, Request::SetDataUsage { enabled: on });
            self.refresh_soon();
        }
        ui.weak(EXPLANATION);
        if !s.config.settings.data_usage {
            self.confirm_reset = false;
            return;
        }
        self.poll(client, req);
        if self.report.is_none() {
            ui.add_space(8.0);
            ui.spinner();
            return;
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for p in Period::ALL {
                ui.selectable_value(&mut self.period, p, p.label());
            }
        });
        ui.add_space(6.0);
        if self.tables.as_ref().is_none_or(|t| t.0 != self.period) {
            if let Some(r) = self.report.as_ref() {
                let agg = |by| aggregate(r, self.period, &r.today, by);
                self.tables = Some((self.period, [agg(By::Group), agg(By::App), agg(By::Proxy)]));
            }
        }
        let Some((_, tables)) = self.tables.as_ref() else {
            return;
        };
        let group_name = |id: &str| {
            s.config
                .groups
                .iter()
                .find(|g| g.id == id)
                .map_or_else(|| id.to_string(), |g| g.name.clone())
        };
        let proxy_name = |id: &str| {
            s.config
                .proxies
                .iter()
                .find(|p| p.id == id)
                .map_or_else(|| id.to_string(), |p| p.name.clone())
        };
        for (i, (title, by)) in [
            ("By group", By::Group),
            ("By app", By::App),
            ("By proxy", By::Proxy),
        ]
        .into_iter()
        .enumerate()
        {
            let rows = &tables[i];
            ui.add_space(6.0);
            ui.label(RichText::new(title).strong());
            if rows.is_empty() {
                ui.weak("Nothing yet");
                continue;
            }
            egui::Grid::new(title)
                .striped(true)
                .min_col_width(56.0)
                .show(ui, |ui| {
                    for h in ["Name", "Up", "Down", "Total"] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for (name, up, down) in rows.iter().cloned() {
                        let shown = match by {
                            By::Group => group_name(&name),
                            By::Proxy => proxy_name(&name),
                            By::App => name,
                        };
                        ui.add(egui::Label::new(shown).truncate());
                        ui.label(fmt_bytes(up));
                        ui.label(fmt_bytes(down));
                        ui.label(fmt_bytes(up.saturating_add(down)));
                        ui.end_row();
                    }
                });
        }
        ui.add_space(10.0);
        if self.confirm_reset {
            ui.horizontal_wrapped(|ui| {
                ui.label("Delete all data usage history?");
                if ui.button("Yes").clicked() {
                    req.send(client, Request::ResetUsage);
                    // A GetUsage sent before the reset must not bring the old totals back.
                    self.pending = None;
                    self.report = None;
                    self.tables = None;
                    self.confirm_reset = false;
                    self.refresh_soon();
                }
                if ui.button("No").clicked() {
                    self.confirm_reset = false;
                }
            });
        } else if ui.button("Reset").clicked() {
            self.confirm_reset = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::ipc::{UsageReport, UsageRow};

    fn row(g: &str, a: &str, p: &str, up: u64, down: u64) -> UsageRow {
        UsageRow {
            group: g.into(),
            app: a.into(),
            proxy: p.into(),
            up,
            down,
        }
    }

    fn report() -> UsageReport {
        UsageReport {
            enabled: true,
            today: "2026-11-18".into(),
            session: vec![row("g1", "chrome.exe", "v2ray", 5, 7)],
            days: vec![
                (
                    "2026-10-31".into(),
                    vec![row("g1", "chrome.exe", "v2ray", 1000, 2000)],
                ),
                (
                    "2026-11-02".into(),
                    vec![
                        row("g1", "chrome.exe", "v2ray", 10, 20),
                        row("g2", "steam.exe", "v2ray", 100, 200),
                    ],
                ),
                (
                    "2026-11-18".into(),
                    vec![
                        row("g1", "chrome.exe", "v2ray", 1, 2),
                        row("g1", "firefox.exe", "alt", 3, 4),
                        row("g2", "steam.exe", "v2ray", 50, 60),
                    ],
                ),
            ],
        }
    }

    #[test]
    fn aggregate_by_group_today() {
        let r = report();
        let v = aggregate(&r, Period::Today, "2026-11-18", By::Group);
        assert_eq!(v, vec![("g2".into(), 50, 60), ("g1".into(), 4, 6)]);
    }

    #[test]
    fn aggregate_month_spans_days() {
        let r = report();
        let v = aggregate(&r, Period::Month, "2026-11-18", By::App);
        // October is excluded; November's days add up.
        assert_eq!(
            v,
            vec![
                ("steam.exe".into(), 150, 260),
                ("chrome.exe".into(), 11, 22),
                ("firefox.exe".into(), 3, 4),
            ]
        );
        let all = aggregate(&r, Period::All, "2026-11-18", By::Proxy);
        assert_eq!(
            all,
            vec![("v2ray".into(), 1161, 2282), ("alt".into(), 3, 4)]
        );
    }

    #[test]
    fn aggregate_session() {
        let r = report();
        let v = aggregate(&r, Period::Session, "2026-11-18", By::Proxy);
        assert_eq!(v, vec![("v2ray".into(), 5, 7)]);
        let empty = UsageReport {
            session: vec![],
            ..r
        };
        assert!(aggregate(&empty, Period::Session, "2026-11-18", By::Group).is_empty());
    }

    #[test]
    fn aggregate_sorted_by_total() {
        let r = UsageReport {
            enabled: true,
            today: "2026-11-18".into(),
            session: vec![
                row("small", "a.exe", "p", 1, 1),
                row("big", "a.exe", "p", 500, 500),
                row("mid", "a.exe", "p", 100, 0),
                row("tie-b", "a.exe", "p", 50, 0),
                row("tie-a", "a.exe", "p", 0, 50),
            ],
            days: vec![],
        };
        let names: Vec<String> = aggregate(&r, Period::Session, "2026-11-18", By::Group)
            .into_iter()
            .map(|x| x.0)
            .collect();
        assert_eq!(names, ["big", "mid", "tie-a", "tie-b", "small"]);
    }

    #[test]
    fn fmt_bytes_units() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(999), "999 B");
        assert_eq!(fmt_bytes(1_000), "1.0 KB");
        assert_eq!(fmt_bytes(12_300_000), "12.3 MB");
        assert_eq!(fmt_bytes(1_200_000_000), "1.20 GB");
        // Rounding never shows 1000.0 of a unit.
        assert_eq!(fmt_bytes(999_999), "1.0 MB");
        assert_eq!(fmt_bytes(1_500_000_000_000), "1.50 TB");
    }

    #[test]
    fn explanation_text_exact() {
        assert_eq!(
            EXPLANATION,
            "Counts traffic sent through a proxy (what uses your VPN data). \
             Direct traffic is not counted."
        );
    }
}
