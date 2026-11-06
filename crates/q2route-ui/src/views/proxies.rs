//! Proxies: profile list with Test / Edit / Delete, plus an add/edit form.

use std::collections::HashMap;

use eframe::egui::{self, Color32, RichText};
use q2route_core::config::{Config, ProfileId, ProxyKind, ProxyProfile};
use q2route_core::ipc::{Request, Response, StateSnapshot};
use tokio::sync::oneshot;

use crate::app::Requests;
use crate::client::Client;
use crate::views::placeholder::LATER;

const KINDS: [(ProxyKind, &str); 3] = [
    (ProxyKind::Socks5, "SOCKS5"),
    (ProxyKind::Socks4, "SOCKS4/4a"),
    (ProxyKind::Http, "HTTP CONNECT"),
];

fn kind_label(k: ProxyKind) -> &'static str {
    KINDS.iter().find(|(x, _)| *x == k).map_or("?", |(_, l)| l)
}

enum TestState {
    Running(oneshot::Receiver<Response>),
    Done { ok: bool, text: String },
}

/// Turns a TestProxy response into its one-line result.
fn outcome(r: Response) -> TestState {
    let (ok, text) = match r {
        Response::ProxyTest(t) if t.tcp_ok => (
            true,
            format!(
                "TCP OK{}",
                t.latency_ms
                    .map_or(String::new(), |ms| format!(", {ms} ms"))
            ),
        ),
        Response::ProxyTest(t) => (
            false,
            format!(
                "TCP failed: {}",
                t.error.as_deref().unwrap_or("unreachable")
            ),
        ),
        Response::Error(e) => (false, format!("Test failed: {e}")),
        other => (false, format!("Unexpected reply: {other:?}")),
    };
    TestState::Done { ok, text }
}

#[derive(Clone)]
struct Form {
    /// `Some(id)` while editing an existing profile.
    editing: Option<ProfileId>,
    name: String,
    kind: ProxyKind,
    host: String,
    port: String,
    username: String,
    password: String,
}

impl Default for Form {
    fn default() -> Form {
        Form {
            editing: None,
            name: String::new(),
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }
}

impl Form {
    fn from_profile(p: &ProxyProfile) -> Form {
        Form {
            editing: Some(p.id.clone()),
            name: p.name.clone(),
            kind: p.kind,
            host: p.host.clone(),
            port: p.port.to_string(),
            username: p.username.clone().unwrap_or_default(),
            password: p.password.clone().unwrap_or_default(),
        }
    }

    fn to_profile(&self, cfg: &Config) -> Result<ProxyProfile, &'static str> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("Name is required");
        }
        let host = self.host.trim();
        if host.is_empty() {
            return Err("Host is required");
        }
        let port = match self.port.trim().parse::<u16>() {
            Ok(p) if p != 0 => p,
            _ => return Err("Port must be 1-65535"),
        };
        let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
        Ok(ProxyProfile {
            id: self.editing.clone().unwrap_or_else(|| new_id(cfg, name)),
            name: name.into(),
            kind: self.kind,
            host: host.into(),
            port,
            username: opt(self.username.trim()),
            password: opt(&self.password),
        })
    }
}

/// A unique id derived from `name`: lowercase alphanumerics and dashes.
pub fn new_id(cfg: &Config, name: &str) -> ProfileId {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if slug.is_empty() {
        "proxy".to_string()
    } else {
        slug
    };
    let taken = |id: &str| cfg.proxies.iter().any(|p| p.id == id);
    let mut id = base.clone();
    let mut n = 2;
    while taken(&id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

#[derive(Default)]
pub struct ProxiesView {
    form: Option<Form>,
    form_error: Option<&'static str>,
    tests: HashMap<ProfileId, TestState>,
}

impl ProxiesView {
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        snap: Option<&StateSnapshot>,
        client: &Client,
        req: &mut Requests,
    ) {
        let Some(s) = snap else { return };
        for t in self.tests.values_mut() {
            if let TestState::Running(rx) = t {
                match rx.try_recv() {
                    Ok(r) => *t = outcome(r),
                    Err(oneshot::error::TryRecvError::Closed) => {
                        *t = outcome(Response::Error("disconnected".into()))
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                }
            }
        }
        ui.horizontal(|ui| {
            ui.heading("Proxies");
            if ui.button("Add proxy").clicked() {
                self.form = Some(Form::default());
                self.form_error = None;
            }
        });
        ui.add_space(6.0);
        egui::Grid::new("proxies")
            .num_columns(5)
            .striped(true)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                for p in &s.config.proxies {
                    self.row(ui, s, p, client, req);
                    ui.end_row();
                }
            });
        if let Some(form) = self.form.as_mut() {
            ui.add_space(12.0);
            ui.separator();
            let mut close = false;
            let mut save = false;
            ui.heading(if form.editing.is_some() {
                "Edit proxy"
            } else {
                "Add proxy"
            });
            egui::Grid::new("proxy-form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut form.name);
                    ui.end_row();
                    ui.label("Type");
                    egui::ComboBox::from_id_salt("proxy-kind")
                        .selected_text(kind_label(form.kind))
                        .show_ui(ui, |ui| {
                            for (k, l) in KINDS {
                                ui.selectable_value(&mut form.kind, k, l);
                            }
                        });
                    ui.end_row();
                    ui.label("Host");
                    ui.text_edit_singleline(&mut form.host);
                    ui.end_row();
                    ui.label("Port");
                    ui.add(egui::TextEdit::singleline(&mut form.port).desired_width(80.0));
                    ui.end_row();
                    ui.label("Username");
                    ui.text_edit_singleline(&mut form.username);
                    ui.end_row();
                    ui.label("Password");
                    ui.add(egui::TextEdit::singleline(&mut form.password).password(true));
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                save = ui.button("Save").clicked();
                close = ui.button("Cancel").clicked();
            });
            if save {
                match form.to_profile(&s.config) {
                    Ok(p) => {
                        req.send(client, Request::UpsertProxy(p));
                        close = true;
                    }
                    Err(e) => self.form_error = Some(e),
                }
            }
            if let Some(e) = self.form_error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            if close {
                self.form = None;
                self.form_error = None;
            }
        }
    }

    fn row(
        &mut self,
        ui: &mut egui::Ui,
        s: &StateSnapshot,
        p: &ProxyProfile,
        client: &Client,
        req: &mut Requests,
    ) {
        let mut name = RichText::new(&p.name).strong();
        if p.id == s.config.default_proxy {
            name = RichText::new(format!("{} (default)", p.name)).strong();
        }
        ui.label(name);
        ui.label(format!("{} {}:{}", kind_label(p.kind), p.host, p.port));
        match s.proxy_up.get(&p.id) {
            Some(true) => ui.colored_label(Color32::from_rgb(0x66, 0xbb, 0x6a), "Up"),
            Some(false) => ui.colored_label(ui.visuals().error_fg_color, "Down"),
            None => ui.weak("Not in use"),
        };
        ui.horizontal(|ui| {
            let testing = matches!(self.tests.get(&p.id), Some(TestState::Running(_)));
            if ui
                .add_enabled(!testing, egui::Button::new("Test"))
                .clicked()
            {
                self.tests.insert(
                    p.id.clone(),
                    TestState::Running(client.send(Request::TestProxy { id: p.id.clone() })),
                );
            }
            if ui.button("Edit").clicked() {
                self.form = Some(Form::from_profile(p));
                self.form_error = None;
            }
            if ui.button("Delete").clicked() {
                req.send(client, Request::DeleteProxy { id: p.id.clone() });
            }
            ui.add_enabled(false, egui::Button::new("Set as default"))
                .on_disabled_hover_text(LATER);
        });
        match self.tests.get(&p.id) {
            Some(TestState::Running(_)) => {
                ui.spinner();
            }
            Some(TestState::Done { ok: true, text }) => {
                ui.colored_label(Color32::from_rgb(0x66, 0xbb, 0x6a), text);
            }
            Some(TestState::Done { ok: false, text }) => {
                ui.colored_label(ui.visuals().error_fg_color, text);
            }
            None => {
                ui.label("");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_slugs() {
        let cfg = Config::seed();
        assert_eq!(new_id(&cfg, "My Proxy #1"), "my-proxy-1");
        assert_eq!(new_id(&cfg, "V2Ray"), "v2ray-2");
        assert_eq!(new_id(&cfg, "!!!"), "proxy");
    }
}
