//! App shell: left navigation, page routing, request bookkeeping.

use std::time::Duration;

use eframe::egui;
use q2route_core::ipc::{Request, Response};
use tokio::sync::oneshot;

use crate::client::Client;
use crate::settings::UiSettings;
use crate::views::{dashboard, placeholder, proxies::ProxiesView, settings as settings_view};

/// How often the UI (and later the tray) refreshes from `Client::latest()`.
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
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, client: Client, settings: UiSettings) -> App {
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        App {
            client,
            page: Page::Dashboard,
            settings,
            requests: Requests::default(),
            proxies: ProxiesView::default(),
        }
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
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.requests.poll();
        ctx.request_repaint_after(REFRESH);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let snap = self.client.latest();
        let connected = self.client.connected();
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(170.0)
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
            if !connected {
                dashboard::service_banner(ui);
            }
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| match self.page {
                    Page::Dashboard => {
                        dashboard::show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Proxies => {
                        self.proxies
                            .show(ui, snap.as_ref(), &self.client, &mut self.requests)
                    }
                    Page::Settings => {
                        settings_view::show(ui, &mut self.settings, &mut self.requests)
                    }
                    _ => placeholder::show(ui, self.page.label()),
                });
        });
    }
}
