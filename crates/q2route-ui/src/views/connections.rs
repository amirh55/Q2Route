//! Connections: live table of active and recently ended connections, with
//! an add-to-group context menu.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, RichText};
use q2route_core::config::{GroupId, Rule};
use q2route_core::decide::Route;
use q2route_core::ipc::{ConnInfo, Request, Response, StateSnapshot};
use q2route_core::suggest::{app_rule, domain_patterns, ip_patterns};
use tokio::sync::oneshot;

use crate::app::Requests;
use crate::client::Client;
use crate::views::dashboard;

const POLL: Duration = Duration::from_secs(1);
const ROW_HEIGHT: f32 = 20.0;
/// Column widths: App, PID, Destination, Proto, Route, Group, Why, up, down, Duration.
const COLS: [f32; 10] = [
    110.0, 50.0, 250.0, 40.0, 90.0, 100.0, 130.0, 62.0, 62.0, 62.0,
];
const HEADERS: [&str; 10] = [
    "App",
    "PID",
    "Destination",
    "Proto",
    "Route",
    "Group",
    "Why",
    "\u{2191}",
    "\u{2193}",
    "Duration",
];

#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    pub text: String,
    pub active_only: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            text: String::new(),
            active_only: true,
        }
    }
}

/// Connections matching the filter; text is matched case-insensitively
/// against exe, domain, destination IP and group id.
pub fn filter<'a>(conns: &'a [ConnInfo], f: &Filter) -> Vec<&'a ConnInfo> {
    let needle = f.text.trim().to_lowercase();
    conns
        .iter()
        .filter(|c| !(f.active_only && c.ended_ms.is_some()))
        .filter(|c| {
            needle.is_empty()
                || [
                    Some(c.exe.as_str()),
                    c.domain.as_deref(),
                    c.group_id.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(&needle))
                || c.dst.ip().to_string().contains(&needle)
        })
        .collect()
}

pub fn route_label(r: &Route) -> String {
    match r {
        Route::Direct => "Direct".into(),
        Route::Block => "Block".into(),
        Route::Proxy(id) => format!("Proxy ({id})"),
    }
}

pub fn human_bytes(n: Option<u64>) -> String {
    let Some(n) = n else { return "\u{2014}".into() };
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut unit = "B";
    for u in ["KB", "MB", "GB", "TB"] {
        v /= 1024.0;
        unit = u;
        if v < 1024.0 {
            break;
        }
    }
    format!("{v:.1} {unit}")
}

pub fn duration_label(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {:02}s", s / 60, s % 60),
        _ => format!("{}h {:02}m", s / 3600, s % 3600 / 60),
    }
}

/// Whether the next poll may go out: nothing in flight and the last send is
/// at least `POLL` ago (or there was none).
fn due(in_flight: bool, since_last: Option<Duration>) -> bool {
    !in_flight && since_last.is_none_or(|d| d >= POLL)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Default)]
pub struct ConnectionsView {
    filter: Filter,
    conns: Vec<ConnInfo>,
    pending: Option<oneshot::Receiver<Response>>,
    last_sent: Option<Instant>,
}

impl ConnectionsView {
    /// Collects a finished poll and sends the next one when due.
    fn poll(&mut self, client: &Client, req: &mut Requests) {
        if let Some(rx) = self.pending.as_mut() {
            match rx.try_recv() {
                Ok(Response::Connections(v)) => {
                    self.conns = v;
                    self.pending = None;
                }
                Ok(Response::Error(e)) => {
                    req.last_error = Some(e);
                    self.pending = None;
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => self.pending = None,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if due(self.pending.is_some(), self.last_sent.map(|t| t.elapsed())) {
            self.pending = Some(client.send(Request::GetConnections));
            self.last_sent = Some(Instant::now());
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        snap: Option<&StateSnapshot>,
        client: &Client,
        req: &mut Requests,
    ) {
        self.poll(client, req);
        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.filter.text);
            ui.checkbox(&mut self.filter.active_only, "Active only");
        });
        let rows = filter(&self.conns, &self.filter);
        ui.label(format!("{} shown", rows.len()));
        ui.separator();
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.horizontal(|ui| {
            for (h, w) in HEADERS.iter().zip(COLS) {
                ui.add_sized(
                    [w, ROW_HEIGHT],
                    egui::Label::new(RichText::new(*h).strong()),
                );
            }
        });
        let now = now_ms();
        let scroll_h = (ui.available_height() - 24.0).max(ROW_HEIGHT);
        egui::ScrollArea::vertical()
            .id_salt("connections_rows")
            .auto_shrink(false)
            .max_height(scroll_h)
            .show_rows(ui, ROW_HEIGHT, rows.len(), |ui, range| {
                for c in &rows[range] {
                    if let Some((group_id, rule)) = row(ui, c, snap, now) {
                        req.send(client, Request::AddRule { group_id, rule });
                    }
                }
            });
        ui.weak("Changing a rule applies to new connections; open ones keep their route.");
    }
}

fn group_name(snap: Option<&StateSnapshot>, c: &ConnInfo) -> String {
    let Some(id) = c.group_id.as_ref() else {
        return "\u{2014}".into();
    };
    snap.and_then(|s| s.config.groups.iter().find(|g| &g.id == id))
        .map_or(id.clone(), |g| g.name.clone())
}

/// One table row; returns the (group, rule) picked in its context menu.
fn row(
    ui: &mut egui::Ui,
    c: &ConnInfo,
    snap: Option<&StateSnapshot>,
    now: u64,
) -> Option<(GroupId, Rule)> {
    let ended = c.ended_ms.is_some();
    let dest = match &c.domain {
        Some(d) => format!("{d} {}", c.dst),
        None => c.dst.to_string(),
    };
    let route = match (&c.route, snap) {
        (Route::Proxy(id), Some(s)) => dashboard::profile(&s.config, id)
            .map_or_else(|| route_label(&c.route), |p| format!("Proxy ({})", p.name)),
        _ => route_label(&c.route),
    };
    let proto = format!("{:?}", c.proto).to_uppercase();
    let dur = duration_label(c.ended_ms.unwrap_or(now).saturating_sub(c.started_ms));
    let cells = [
        c.exe.clone(),
        c.pid.to_string(),
        dest,
        proto,
        route,
        group_name(snap, c),
        c.reason.clone(),
        human_bytes(c.up),
        human_bytes(c.down),
        dur,
    ];
    let inner = ui.horizontal(|ui| {
        for (text, w) in cells.into_iter().zip(COLS) {
            let mut t = RichText::new(text);
            if ended {
                t = t.weak();
            }
            ui.add_sized([w, ROW_HEIGHT], egui::Label::new(t).truncate());
        }
    });
    let resp = ui.interact(
        inner.response.rect,
        ui.make_persistent_id(("conn_row", c.id)),
        egui::Sense::click(),
    );
    let mut pick = None;
    resp.context_menu(|ui| pick = menu(ui, c, snap));
    pick
}

fn group_items(
    ui: &mut egui::Ui,
    snap: Option<&StateSnapshot>,
    rule: &Rule,
    pick: &mut Option<(GroupId, Rule)>,
) {
    let Some(s) = snap else { return };
    for g in s.config.groups.iter().filter(|g| !g.catch_all) {
        if ui.button(&g.name).clicked() {
            *pick = Some((g.id.clone(), rule.clone()));
            ui.close();
        }
    }
}

fn menu(ui: &mut egui::Ui, c: &ConnInfo, snap: Option<&StateSnapshot>) -> Option<(GroupId, Rule)> {
    let mut pick = None;
    if let Some(rule) = app_rule(&c.exe) {
        ui.menu_button("Add app to group \u{25b8}", |ui| {
            group_items(ui, snap, &rule, &mut pick)
        });
    }
    let domains = c.domain.as_deref().map(domain_patterns).unwrap_or_default();
    if !domains.is_empty() {
        ui.menu_button("Add domain to group \u{25b8}", |ui| {
            for p in domains {
                ui.menu_button(p.clone(), |ui| {
                    let rule = Rule {
                        domains: vec![p],
                        ..Rule::default()
                    };
                    group_items(ui, snap, &rule, &mut pick)
                });
            }
        });
    }
    let ips = ip_patterns(c.dst.ip());
    if !ips.is_empty() {
        ui.menu_button("Add IP to group \u{25b8}", |ui| {
            for p in ips {
                ui.menu_button(p.clone(), |ui| {
                    let rule = Rule {
                        ips: vec![p],
                        ..Rule::default()
                    };
                    group_items(ui, snap, &rule, &mut pick)
                });
            }
        });
    }
    pick
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::config::Protocol;

    fn conn(
        exe: &str,
        domain: Option<&str>,
        dst: &str,
        group: Option<&str>,
        ended: bool,
    ) -> ConnInfo {
        ConnInfo {
            id: 1,
            proto: Protocol::Tcp,
            pid: 1,
            exe: exe.into(),
            local: "127.0.0.1:5000".parse().unwrap(),
            dst: dst.parse().unwrap(),
            domain: domain.map(String::from),
            route: Route::Direct,
            group_id: group.map(String::from),
            reason: "own".into(),
            started_ms: 0,
            ended_ms: ended.then_some(10),
            up: None,
            down: None,
        }
    }

    fn f(text: &str, active_only: bool) -> Filter {
        Filter {
            text: text.into(),
            active_only,
        }
    }

    #[test]
    fn filter_matches_each_field() {
        let v = vec![conn(
            "Steam.exe",
            Some("www.Digikala.com"),
            "185.1.2.3:443",
            Some("iran"),
            false,
        )];
        for t in ["", "steam", "DIGIKALA", "185.1.2", "IRA"] {
            assert_eq!(filter(&v, &f(t, true)).len(), 1, "{t}");
        }
        assert!(filter(&v, &f("nomatch", true)).is_empty());
        assert!(filter(&v, &f("443", true)).is_empty()); // ip only, not port
    }

    #[test]
    fn active_only_hides_ended() {
        let v = vec![conn("a.exe", None, "1.1.1.1:1", None, true)];
        assert!(filter(&v, &f("", true)).is_empty());
        assert_eq!(filter(&v, &f("", false)).len(), 1);
    }

    #[test]
    fn labels_and_units() {
        assert_eq!(route_label(&Route::Direct), "Direct");
        assert_eq!(route_label(&Route::Block), "Block");
        assert_eq!(route_label(&Route::Proxy("v2ray".into())), "Proxy (v2ray)");
        assert_eq!(human_bytes(None), "\u{2014}");
        assert_eq!(human_bytes(Some(0)), "0 B");
        assert_eq!(human_bytes(Some(1536)), "1.5 KB");
        assert_eq!(human_bytes(Some(5_000_000)), "4.8 MB");
        assert_eq!(duration_label(999), "0s");
        assert_eq!(duration_label(65_000), "1m 05s");
        assert_eq!(duration_label(3_726_000), "1h 02m");
    }

    #[test]
    fn polling_is_throttled_and_not_stacked() {
        assert!(due(false, None));
        assert!(!due(true, None));
        assert!(!due(false, Some(Duration::from_millis(500))));
        assert!(due(false, Some(Duration::from_secs(1))));
        assert!(!due(true, Some(Duration::from_secs(5))));
    }
}
