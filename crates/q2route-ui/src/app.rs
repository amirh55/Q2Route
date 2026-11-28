//! App shell: left navigation, page routing, request bookkeeping.

use std::time::{Duration, Instant};

use eframe::egui;
use q2route_core::ipc::{Request, Response};
use tokio::sync::oneshot;

use crate::client::Client;
use crate::settings::UiSettings;
use crate::tray::{Tray, TrayAction};
use crate::update::Updater;
use crate::views::{
    app_rules::AppRulesView, connections::ConnectionsView, dashboard, dns::DnsView,
    groups::GroupsView, log::LogView, placeholder, proxies::ProxiesView, settings as settings_view,
    usage::UsageView,
};

/// How often the UI and the tray refresh from `Client::latest()`.
pub const REFRESH: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Dashboard,
    Connections,
    Groups,
    AppRules,
    Proxies,
    Dns,
    DataUsage,
    Log,
    Settings,
}

impl Page {
    pub const ALL: [Page; 9] = [
        Page::Dashboard,
        Page::Connections,
        Page::Groups,
        Page::AppRules,
        Page::Proxies,
        Page::Dns,
        Page::DataUsage,
        Page::Log,
        Page::Settings,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::Connections => "Connections",
            Page::Groups => "Groups & rules",
            Page::AppRules => "App rules",
            Page::Proxies => "Proxies",
            Page::Dns => "DNS",
            Page::DataUsage => "Data usage",
            Page::Log => "Log",
            Page::Settings => "Settings",
        }
    }
}

/// Fire-and-forget requests whose errors are surfaced in the status bar.
#[derive(Default)]
pub struct Requests {
    pending: Vec<oneshot::Receiver<Response>>,
    pub last_error: Option<String>,
    app_rule_write: Option<AppRuleWrite>,
    app_rules: Option<Vec<q2route_core::config::AppRule>>,
    observed_app_rules: Option<Vec<q2route_core::config::AppRule>>,
}

/// One global gate, shared by every app-rule editor, including while hidden.
enum AppRuleWrite {
    Saving(oneshot::Receiver<Response>),
    Refreshing(oneshot::Receiver<Response>),
}

impl Requests {
    pub fn app_rules_ready(&self) -> bool {
        self.app_rules.is_some() && self.app_rule_write.is_none()
    }

    pub fn app_rules(&self) -> &[q2route_core::config::AppRule] {
        self.app_rules.as_deref().unwrap_or_default()
    }

    /// The snapshot cache has no revision. Never adopt a changed cache value
    /// directly: a queued pre-write event may arrive after the write's response.
    /// GetState is ordered after our write and provides the authoritative base.
    fn observe_app_rules(
        &mut self,
        snap: &q2route_core::ipc::StateSnapshot,
        send: impl FnOnce(Request) -> oneshot::Receiver<Response>,
    ) {
        let rules = &snap.config.app_rules;
        let first = self.observed_app_rules.is_none();
        let changed = self.observed_app_rules.as_ref() != Some(rules);
        self.observed_app_rules = Some(rules.clone());
        if first && self.app_rule_write.is_none() {
            self.app_rules = Some(rules.clone());
        } else if self.app_rule_write.is_none() && (changed || self.app_rules.is_none()) {
            self.app_rule_write = Some(AppRuleWrite::Refreshing(send(Request::GetState)));
        }
    }

    pub fn write_app_rules(
        &mut self,
        rules: Vec<q2route_core::config::AppRule>,
        send: impl FnOnce(Request) -> oneshot::Receiver<Response>,
    ) {
        if self.app_rules_ready() {
            self.app_rule_write = Some(AppRuleWrite::Saving(send(Request::SetAppRules(rules))));
        }
    }

    fn poll_app_rules(&mut self, send: impl FnOnce(Request) -> oneshot::Receiver<Response>) {
        let Some(write) = self.app_rule_write.as_mut() else {
            return;
        };
        let refreshing = matches!(write, AppRuleWrite::Refreshing(_));
        let rx = match write {
            AppRuleWrite::Saving(rx) | AppRuleWrite::Refreshing(rx) => rx,
        };
        let result = rx.try_recv();
        if matches!(result, Err(oneshot::error::TryRecvError::Empty)) {
            return;
        }
        self.app_rule_write = None;
        match result {
            Ok(Response::Ok) if !refreshing => {
                self.app_rule_write = Some(AppRuleWrite::Refreshing(send(Request::GetState)));
            }
            Ok(Response::State(snap)) if refreshing => {
                self.app_rules = Some(snap.config.app_rules);
            }
            other => {
                self.last_error = Some(match other {
                    Ok(Response::Error(e)) => e,
                    _ => "App rules update was not acknowledged".into(),
                });
                // A failed/closed write may have reached the service; require
                // an authoritative refresh before allowing another replacement.
                self.app_rules = None;
            }
        }
    }

    pub fn send(&mut self, client: &Client, r: Request) {
        self.pending.push(client.send(r));
    }

    /// Collects finished responses; keeps the latest error.
    pub fn poll(&mut self) {
        self.pending.retain_mut(|rx| match rx.try_recv() {
            Ok(Response::Error(e)) => {
                self.last_error = Some(e);
                false
            }
            Ok(_) | Err(oneshot::error::TryRecvError::Closed) => false,
            Err(oneshot::error::TryRecvError::Empty) => true,
        });
    }
}

pub struct App {
    pub client: Client,
    pub page: Page,
    pub settings: UiSettings,
    pub requests: Requests,
    proxies: ProxiesView,
    dns: DnsView,
    usage: UsageView,
    groups: GroupsView,
    app_rules: AppRulesView,
    connections: ConnectionsView,
    log: LogView,
    leak: settings_view::LeakState,
    backup: settings_view::BackupState,
    updater: Updater,
    tray: Option<Tray>,
    /// Set by the tray's Exit: the next close request is not turned into hide.
    exiting: bool,
    hide_on_start: bool,
    /// The window has been subclassed by `dpi_guard`.
    dpi_hooked: bool,
    /// True while we keep the window hidden in the tray.
    hidden: bool,
}

impl App {
    /// `hidden` (`--minimized`): start in the tray. eframe always shows the
    /// window after its first frame, so it is hidden again from the first
    /// `logic` call; without a tray icon it stays visible.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        client: Client,
        settings: UiSettings,
        hidden: bool,
    ) -> App {
        let ctx = &cc.egui_ctx;
        ctx.set_theme(settings.theme.preference());
        let mut requests = Requests::default();
        let tray = Tray::new(ctx)
            .map_err(|e| requests.last_error = Some(format!("Tray icon: {e}")))
            .ok();
        App {
            client,
            page: Page::Dashboard,
            settings,
            requests,
            proxies: ProxiesView::default(),
            dns: DnsView::default(),
            usage: UsageView::default(),
            groups: GroupsView::default(),
            app_rules: AppRulesView::default(),
            connections: ConnectionsView::default(),
            log: LogView::default(),
            leak: settings_view::LeakState::default(),
            backup: settings_view::BackupState::default(),
            updater: Updater::new(Instant::now()),
            hide_on_start: hidden && tray.is_some(),
            dpi_hooked: false,
            tray,
            exiting: false,
            hidden: false,
        }
    }

    fn hide_window(&mut self, ctx: &egui::Context) {
        self.hidden = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Q2Route");
        ui.add_space(8.0);
        for page in Page::ALL {
            let label = egui::RichText::new(page.label()).size(14.0);
            let r = ui.add_sized(
                [ui.available_width(), 28.0],
                egui::Button::selectable(self.page == page, label),
            );
            if r.clicked() {
                self.page = page;
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.requests.poll();
        self.requests.poll_app_rules(|r| self.client.send(r));
        // A started setup closes and relaunches the UI itself (taskkill in
        // PrepareToInstall); exiting here would lose the window if UAC is cancelled.
        let _ = self.updater.poll(ctx, self.settings.check_updates);
        if !self.dpi_hooked && frame.winit_window().is_some() {
            // One attempt only: the handle either exists now or never will.
            self.dpi_hooked = true;
            if let Ok(h) = raw_window_handle::HasWindowHandle::window_handle(frame) {
                if let raw_window_handle::RawWindowHandle::Win32(w) = h.as_raw() {
                    let hwnd = w.hwnd.get() as windows_sys::Win32::Foundation::HWND;
                    // SAFETY: eframe's own window, and we run on its UI thread.
                    unsafe { crate::dpi_guard::install(hwnd) };
                    crate::file_dialog::set_owner(hwnd);
                }
            }
        }
        if std::mem::take(&mut self.hide_on_start) {
            self.hide_window(ctx);
        }
        // A second instance shows us with ShowWindow behind winit's back;
        // re-send Visible(true) so winit's own visibility flag matches again.
        let shown = frame.winit_window().and_then(|w| w.is_visible());
        if self.hidden && shown == Some(true) {
            self.show_window(ctx);
        }
        let actions = match self.tray.as_mut() {
            Some(tray) => {
                tray.tick(self.client.latest().as_ref(), self.settings.tray_graph);
                tray.poll()
            }
            None => vec![],
        };
        for a in actions {
            match a {
                TrayAction::Open => self.show_window(ctx),
                TrayAction::Exit => {
                    // Closes the UI only; the service keeps routing.
                    self.exiting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                TrayAction::Send(r) => self.requests.send(&self.client, r),
            }
        }
        let close = ctx.input(|i| i.viewport().close_requested());
        if close && !self.exiting && self.settings.close_to_tray && self.tray.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_window(ctx);
        }
        ctx.request_repaint_after(REFRESH);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let snap = self.client.latest();
        let connected = self.client.connected();
        if let Some(snap) = snap.as_ref().filter(|_| connected) {
            self.requests
                .observe_app_rules(snap, |r| self.client.send(r));
        } else {
            self.requests.app_rules = None;
            self.requests.observed_app_rules = None;
        }
        // Slimmer nav on narrow windows to leave room for the page.
        let narrow = ui.available_width() < 640.0;
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(if narrow { 120.0 } else { 170.0 })
            .show(ui, |ui| self.nav(ui));
        if let Some(err) = self.requests.last_error.clone() {
            egui::Panel::bottom("status").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(ui.visuals().error_fg_color, format!("Error: {err}"));
                    if ui.small_button("Dismiss").clicked() {
                        self.requests.last_error = None;
                    }
                });
            });
        }
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.updater.banner(ui);
            if !connected {
                dashboard::service_banner(ui);
            }
            if self.page == Page::Connections {
                // Has its own virtualised scroll area.
                self.connections
                    .show(ui, snap.as_ref(), &self.client, &mut self.requests);
                return;
            }
            if self.page == Page::Log {
                // Has its own virtualised scroll area.
                self.log.show(ui, &self.client);
                return;
            }
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| match self.page {
                    Page::Dashboard => {
                        dashboard::show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Groups => {
                        self.groups
                            .show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::AppRules => {
                        self.app_rules
                            .show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Proxies => {
                        self.proxies
                            .show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Dns => self.dns.show(ui, snap.as_ref(), &self.client),
                    Page::DataUsage => {
                        self.usage
                            .show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Settings => settings_view::show(
                        ui,
                        &mut self.settings,
                        &mut self.requests,
                        &self.client,
                        &mut self.leak,
                        &mut self.backup,
                        &mut self.updater,
                    ),
                    _ => placeholder::show(ui, self.page.label()),
                });
        });
    }
}

#[cfg(test)]
mod app_rule_write_tests {
    use super::*;
    use q2route_core::config::Config;
    use q2route_core::ipc::StateSnapshot;

    fn snapshot(rules: Vec<q2route_core::config::AppRule>) -> StateSnapshot {
        StateSnapshot {
            running: false,
            config: Config {
                app_rules: rules,
                ..Config::seed()
            },
            groups: Default::default(),
            proxy_up: Default::default(),
            total_up_bps: 0,
            total_down_bps: 0,
            proxy_servers: vec![],
        }
    }

    #[test]
    fn rapid_blocks_are_globally_gated_then_use_fresh_rules() {
        let mut req = Requests::default();
        let mut sent = vec![];
        let mut replies = vec![];
        let mut send = |r| {
            sent.push(r);
            let (tx, rx) = oneshot::channel();
            replies.push(tx);
            rx
        };
        req.observe_app_rules(&snapshot(vec![]), &mut send);
        let mut a = req.app_rules().to_vec();
        crate::views::app_rules::set_internet(&mut a, r"C:\A.exe", false).unwrap();
        req.write_app_rules(a.clone(), &mut send);
        assert!(!req.app_rules_ready());
        req.write_app_rules(vec![], &mut send); // Another page cannot overwrite A.
        drop(send);
        assert_eq!(sent.len(), 1);
        replies.remove(0).send(Response::Ok).unwrap();
        let (tx, rx) = oneshot::channel();
        req.poll_app_rules(|r| {
            assert_eq!(r, Request::GetState);
            rx
        });
        assert!(!req.app_rules_ready());
        tx.send(Response::State(snapshot(a.clone()))).unwrap();
        req.poll_app_rules(|_| panic!("no request"));
        assert!(req.app_rules_ready());
        let mut b = req.app_rules().to_vec();
        crate::views::app_rules::set_internet(&mut b, r"C:\B.exe", false).unwrap();
        assert_eq!(b.len(), 2);
        assert!(b.contains(&a[0]));
        let (_tx, rx) = oneshot::channel();
        req.write_app_rules(b.clone(), |r| {
            assert_eq!(r, Request::SetAppRules(b));
            rx
        });
        assert!(!req.app_rules_ready());
    }

    #[test]
    fn delayed_stale_event_requires_ordered_read_not_cache_adoption() {
        let mut req = Requests::default();
        let mut rules = vec![];
        crate::views::app_rules::set_internet(&mut rules, r"C:\A.exe", false).unwrap();
        req.observe_app_rules(&snapshot(rules.clone()), |_| panic!("initial"));
        let (tx, rx) = oneshot::channel();
        req.observe_app_rules(&snapshot(vec![]), |r| {
            assert_eq!(r, Request::GetState);
            rx
        });
        assert!(!req.app_rules_ready());
        assert_eq!(req.app_rules(), rules);
        tx.send(Response::State(snapshot(rules.clone()))).unwrap();
        req.poll_app_rules(|_| panic!("no request"));
        assert!(req.app_rules_ready());
        assert_eq!(req.app_rules(), rules);
    }

    #[test]
    fn closed_write_requires_refresh_and_recovers() {
        let mut req = Requests::default();
        let snap = snapshot(vec![]);
        req.observe_app_rules(&snap, |_| panic!("initial"));
        let (tx, rx) = oneshot::channel();
        req.write_app_rules(vec![], |_| rx);
        drop(tx);
        req.poll_app_rules(|_| panic!("no request"));
        assert!(!req.app_rules_ready());
        assert!(req.last_error.is_some());
        let (tx, rx) = oneshot::channel();
        req.observe_app_rules(&snap, |_| rx);
        tx.send(Response::State(snap)).unwrap();
        req.poll_app_rules(|_| panic!("no request"));
        assert!(req.app_rules_ready());
    }

    #[test]
    fn cross_page_supersession_and_stale_snapshot_do_not_freeze_or_regress() {
        let mut req = Requests::default();
        let old = snapshot(vec![]);
        req.observe_app_rules(&old, |_| panic!("initial snapshot needs no read"));
        let mut submitted = vec![];
        crate::views::app_rules::set_internet(&mut submitted, r"C:\A.exe", false).unwrap();
        let (tx, rx) = oneshot::channel();
        req.write_app_rules(submitted.clone(), |_| rx);
        tx.send(Response::Ok).unwrap();
        let (tx, rx) = oneshot::channel();
        req.poll_app_rules(|_| rx);
        // Fresh state can supersede the submitted historical value.
        let mut fresh = submitted;
        crate::views::app_rules::set_internet(&mut fresh, r"C:\B.exe", false).unwrap();
        tx.send(Response::State(snapshot(fresh.clone()))).unwrap();
        req.poll_app_rules(|_| panic!("no request"));
        req.observe_app_rules(&old, |_| panic!("unchanged stale cache ignored"));
        assert!(req.app_rules_ready());
        assert_eq!(req.app_rules(), fresh);
        fresh[0].enabled = false; // App rules edit starts from coordinator, not old page state.
        let (_tx, rx) = oneshot::channel();
        req.write_app_rules(fresh.clone(), |r| {
            assert_eq!(r, Request::SetAppRules(fresh));
            rx
        });
        assert!(!req.app_rules_ready());
    }
}
