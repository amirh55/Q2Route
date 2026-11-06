//! Dashboard: run status header, banners and one card per group.

use eframe::egui::{self, Color32, RichText};
use q2route_core::config::{Action, Config, Group, ProxyProfile};
use q2route_core::ipc::{Request, StateSnapshot};

use crate::app::Requests;
use crate::client::Client;
use crate::format_speed;

pub const DIRECT: Color32 = Color32::from_rgb(0x2e, 0x8b, 0x57);
pub const PROXY: Color32 = Color32::from_rgb(0x2d, 0x5b, 0xd7);
pub const BLOCK: Color32 = Color32::from_rgb(0xb7, 0x3a, 0x3a);
const CARD: Color32 = Color32::from_rgb(0x26, 0x27, 0x2d);
const CARD_WIDTH: f32 = 250.0;

/// Short human summary of a group's rules, e.g. `*.ir` or `steam.exe + children`.
pub fn summary(g: &Group) -> String {
    if g.catch_all {
        return "catch-all".into();
    }
    let rules: Vec<String> = g
        .rules
        .iter()
        .map(|r| {
            let mut parts = vec![];
            if !r.apps.is_empty() {
                let apps = r.apps.join(", ");
                parts.push(if r.include_children {
                    format!("{apps} + children")
                } else {
                    apps
                });
            }
            parts.extend(r.domains.iter().cloned());
            parts.extend(r.ips.iter().map(|i| match i.trim().strip_prefix("geoip:") {
                Some(code) => format!("GeoIP {}", code.trim().to_uppercase()),
                None => i.clone(),
            }));
            if !r.ports.is_empty() {
                parts.push(format!("port {}", r.ports.join(", ")));
            }
            if let Some(p) = r.protocol {
                parts.push(format!("{p:?}").to_uppercase());
            }
            parts.join(" + ")
        })
        .filter(|s| !s.is_empty())
        .collect();
    if rules.is_empty() {
        "No rules yet".into()
    } else {
        rules.join("; ")
    }
}

fn banner(ui: &mut egui::Ui, fill: Color32, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(fill)
        .corner_radius(6)
        .inner_margin(10)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.visuals_mut().override_text_color = Some(Color32::WHITE);
                add(ui);
            });
        });
    ui.add_space(8.0);
}

/// Grey banner shown on every page while the pipe is not connected.
pub fn service_banner(ui: &mut egui::Ui) {
    banner(ui, Color32::from_gray(0x55), |ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Service not running. Run ");
        ui.label(RichText::new("q2route-service install").code());
        ui.label(" as administrator.");
    });
}

pub fn profile<'a>(cfg: &'a Config, id: &str) -> Option<&'a ProxyProfile> {
    cfg.proxies.iter().find(|p| p.id == id)
}

/// Names of proxies used by an enabled group that the service reports down.
pub fn down_proxies(s: &StateSnapshot) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for g in s.config.groups.iter().filter(|g| g.enabled) {
        if let Action::Proxy(id) = &g.action {
            if s.proxy_up.get(id) == Some(&false) {
                let name = profile(&s.config, id).map_or(id.clone(), |p| p.name.clone());
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    }
    out
}

pub fn show(ui: &mut egui::Ui, snap: Option<&StateSnapshot>, client: &Client, req: &mut Requests) {
    let Some(s) = snap else {
        if client.connected() {
            ui.label("Connecting…");
        }
        return;
    };
    if s.running {
        for name in down_proxies(s) {
            banner(ui, BLOCK, |ui| {
                ui.label(format!(
                    "Proxy '{name}' is not reachable. Traffic for proxied groups is blocked."
                ));
            });
        }
    }
    header(ui, s, client, req);
    ui.add_space(10.0);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(10.0, 10.0);
        for g in &s.config.groups {
            card(ui, s, g, client, req);
        }
    });
}

fn header(ui: &mut egui::Ui, s: &StateSnapshot, client: &Client, req: &mut Requests) {
    ui.horizontal(|ui| {
        if s.running {
            ui.label(
                RichText::new("● Running")
                    .strong()
                    .size(16.0)
                    .color(Color32::from_rgb(0x66, 0xbb, 0x6a)),
            );
            if ui.button("Stop").clicked() {
                req.send(client, Request::Stop);
            }
        } else {
            ui.label(
                RichText::new("Stopped: all traffic direct")
                    .strong()
                    .size(16.0)
                    .color(Color32::GRAY),
            );
            if ui.button("Start").clicked() {
                req.send(client, Request::Start);
            }
        }
        ui.separator();
        let default = profile(&s.config, &s.config.default_proxy)
            .map_or(s.config.default_proxy.clone(), |p| {
                format!("{} ({}:{})", p.name, p.host, p.port)
            });
        ui.weak(format!("Default: {default}"));
        ui.separator();
        ui.weak(format!(
            "↑ {}  ↓ {}",
            format_speed(s.total_up_bps),
            format_speed(s.total_down_bps)
        ));
    });
}

/// The catch-all cannot be disabled (Ruling R18), so its card has no
/// Enabled checkbox.
pub fn has_enabled_toggle(g: &Group) -> bool {
    !g.catch_all
}

fn card(ui: &mut egui::Ui, s: &StateSnapshot, g: &Group, client: &Client, req: &mut Requests) {
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(8)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(CARD_WIDTH);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let mut enabled = g.enabled;
                    if has_enabled_toggle(g)
                        && ui
                            .checkbox(&mut enabled, "")
                            .on_hover_text("Enabled")
                            .changed()
                    {
                        req.send(
                            client,
                            Request::SetGroupEnabled {
                                group_id: g.id.clone(),
                                enabled,
                            },
                        );
                    }
                    ui.label(RichText::new(&g.name).strong().size(15.0));
                });
                ui.weak(summary(g));
                let stats = s.groups.get(&g.id);
                let (up, down) = stats.map_or((0, 0), |st| (st.up_bps, st.down_bps));
                ui.weak(format!("↑ {}  ↓ {}", format_speed(up), format_speed(down)));
                ui.add_space(4.0);
                action_switch(ui, s, g, client, req);
            });
        });
}

fn action_switch(
    ui: &mut egui::Ui,
    s: &StateSnapshot,
    g: &Group,
    client: &Client,
    req: &mut Requests,
) {
    let mut set = |a: Action| {
        req.send(
            client,
            Request::SetGroupAction {
                group_id: g.id.clone(),
                action: a,
            },
        )
    };
    let fallback = if profile(&s.config, &s.config.default_proxy).is_some() {
        Some(s.config.default_proxy.clone())
    } else {
        s.config.proxies.first().map(|p| p.id.clone())
    };
    ui.horizontal(|ui| {
        let seg = |ui: &mut egui::Ui, on: bool, text: &str, color: Color32| {
            let b = egui::Button::new(RichText::new(text).color(Color32::WHITE))
                .fill(if on { color } else { Color32::from_gray(0x3a) })
                .min_size(egui::vec2(70.0, 24.0));
            ui.add(b).clicked() && !on
        };
        if seg(ui, g.action == Action::Direct, "Direct", DIRECT) {
            set(Action::Direct);
        }
        let is_proxy = matches!(g.action, Action::Proxy(_));
        ui.add_enabled_ui(is_proxy || fallback.is_some(), |ui| {
            if seg(ui, is_proxy, "Proxy", PROXY) {
                if let Some(id) = fallback.clone() {
                    set(Action::Proxy(id));
                }
            }
        });
        if seg(ui, g.action == Action::Block, "Block", BLOCK) {
            set(Action::Block);
        }
    });
    if let Action::Proxy(current) = &g.action {
        let name = profile(&s.config, current).map_or(current.clone(), |p| p.name.clone());
        egui::ComboBox::from_id_salt(("proxy", &g.id))
            .selected_text(name)
            .width(CARD_WIDTH - 20.0)
            .show_ui(ui, |ui| {
                for p in &s.config.proxies {
                    if ui.selectable_label(&p.id == current, &p.name).clicked() && &p.id != current
                    {
                        set(Action::Proxy(p.id.clone()));
                    }
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_summaries() {
        let cfg = Config::seed();
        let s: Vec<String> = cfg.groups.iter().map(summary).collect();
        assert_eq!(
            s,
            [
                "*.ir; GeoIP IR",
                "steam.exe + children",
                "No rules yet",
                "catch-all"
            ]
        );
    }

    #[test]
    fn catch_all_has_no_enabled_toggle() {
        let cfg = Config::seed();
        let shown: Vec<bool> = cfg.groups.iter().map(has_enabled_toggle).collect();
        assert_eq!(shown, [true, true, true, false]);
    }
}
