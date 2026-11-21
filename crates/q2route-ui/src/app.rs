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
    connections::ConnectionsView, dashboard, dns::DnsView, groups::GroupsView, log::LogView,
    placeholder, proxies::ProxiesView, settings as settings_view, usage::UsageView,
};

/// How often the UI and the tray refresh from `Client::latest()`.
pub const REFRESH: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Dashboard,
    Connections,
    Groups,
    Proxies,
    Dns,
    DataUsage,
    Log,
    Settings,
}

impl Page {
    pub const ALL: [Page; 8] = [
        Page::Dashboard,
        Page::Connections,
        Page::Groups,
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
}

impl Requests {
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
