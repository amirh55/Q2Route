//! Tray icon: live traffic bars, speed tooltip and the group menu. Must be
//! created and driven on the thread that runs the eframe event loop.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use q2route_core::config::{Action, GroupId, ProfileId};
use q2route_core::ipc::{Request, StateSnapshot};
use tray_icon::menu::{
    CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::format_speed;
use crate::tray_icon_render::{render_icon, TrafficHistory, SIZE};

/// The icon is redrawn 4 times per second.
const TICK: Duration = Duration::from_millis(250);

/// What the app should do in response to tray input.
#[derive(Debug, Clone, PartialEq)]
pub enum TrayAction {
    Open,
    Exit,
    Send(Request),
}

/// Everything the menu shows; the menu is rebuilt only when this changes.
#[derive(Clone, PartialEq)]
struct MenuModel {
    connected: bool,
    running: bool,
    /// (id, label, action); disabled groups are labelled "<name> (off)".
    groups: Vec<(GroupId, String, Action)>,
    proxies: Vec<(ProfileId, String)>,
}

impl MenuModel {
    fn of(snap: Option<&StateSnapshot>) -> MenuModel {
        let Some(s) = snap else {
            return MenuModel {
                connected: false,
                running: false,
                groups: vec![],
                proxies: vec![],
            };
        };
        MenuModel {
            connected: true,
            running: s.running,
            groups: s
                .config
                .groups
                .iter()
                .map(|g| {
                    (
                        g.id.clone(),
                        // The catch-all is always on (Ruling R18).
                        group_label(&g.name, g.enabled || g.catch_all),
                        g.action.clone(),
                    )
                })
                .collect(),
            proxies: s
                .config
                .proxies
                .iter()
                .map(|p| (p.id.clone(), p.name.clone()))
                .collect(),
        }
    }

    fn build(&self) -> (Menu, HashMap<MenuId, TrayAction>) {
        let menu = Menu::new();
        let mut actions = HashMap::new();
        let mut plain = |text: &str, enabled: bool, a: TrayAction| {
            let i = MenuItem::new(text, enabled, None);
            actions.insert(i.id().clone(), a);
            i
        };
        let open = plain("Open", true, TrayAction::Open);
        let (label, req) = if self.running {
            ("Stop", Request::Stop)
        } else {
            ("Start", Request::Start)
        };
        let toggle = plain(label, self.connected, TrayAction::Send(req));
        let exit = plain("Exit", true, TrayAction::Exit);
        let _ = menu.append(&open);
        let _ = menu.append(&toggle);
        if !self.groups.is_empty() {
            let _ = menu.append(&PredefinedMenuItem::separator());
        }
        for (id, name, current) in &self.groups {
            let sub = Submenu::new(name, self.connected);
            let mut choices = vec![("Direct".to_string(), Action::Direct)];
            choices.extend(
                self.proxies
                    .iter()
                    .map(|(pid, pname)| (format!("Proxy ({pname})"), Action::Proxy(pid.clone()))),
            );
            choices.push(("Block".to_string(), Action::Block));
            for (text, a) in choices {
                let i = CheckMenuItem::new(text, true, *current == a, None);
                let req = Request::SetGroupAction {
                    group_id: id.clone(),
                    action: a,
                };
                actions.insert(i.id().clone(), TrayAction::Send(req));
                let _ = sub.append(&i);
            }
            let _ = menu.append(&sub);
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&exit);
        (menu, actions)
    }
}

/// Tray submenu label: disabled groups get an "(off)" suffix.
pub fn group_label(name: &str, enabled: bool) -> String {
    if enabled {
        name.to_string()
    } else {
        format!("{name} (off)")
    }
}

/// `Q2Route: ↑ 120 KB/s ↓ 2.4 MB/s`, or the stopped / offline state.
pub fn tooltip(snap: Option<&StateSnapshot>) -> String {
    match snap {
        None => "Q2Route: Service not running".into(),
        Some(s) if !s.running => "Q2Route: Stopped: all traffic direct".into(),
        Some(s) => format!(
            "Q2Route: ↑ {} ↓ {}",
            format_speed(s.total_up_bps),
            format_speed(s.total_down_bps)
        ),
    }
}

pub struct Tray {
    icon: TrayIcon,
    history: TrafficHistory,
    actions: HashMap<MenuId, TrayAction>,
    model: Option<MenuModel>,
    last_tick: Option<Instant>,
    menu_rx: mpsc::Receiver<MenuEvent>,
    icon_rx: mpsc::Receiver<TrayIconEvent>,
}

fn icon(h: &TrafficHistory, running: bool) -> Icon {
    Icon::from_rgba(render_icon(h, running), SIZE as u32, SIZE as u32).expect("32x32 RGBA icon")
}

impl Tray {
    /// Creates the tray icon; tray and menu events wake `ctx`.
    pub fn new(ctx: &egui::Context) -> Result<Tray, tray_icon::Error> {
        let (menu_tx, menu_rx) = mpsc::channel();
        let c = ctx.clone();
        MenuEvent::set_event_handler(Some(move |e| {
            let _ = menu_tx.send(e);
            c.request_repaint();
        }));
        let (icon_tx, icon_rx) = mpsc::channel();
        let c = ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |e| {
            let _ = icon_tx.send(e);
            c.request_repaint();
        }));
        let history = TrafficHistory::default();
        let icon = TrayIconBuilder::new()
            .with_icon(icon(&history, false))
            .with_tooltip(tooltip(None))
            .with_menu_on_left_click(false)
            .build()?;
        Ok(Tray {
            icon,
            history,
            actions: HashMap::new(),
            model: None,
            last_tick: None,
            menu_rx,
            icon_rx,
        })
    }

    /// Redraws the icon and tooltip (at most 4x/s) and rebuilds the menu when
    /// the groups, proxies or run state changed.
    pub fn tick(&mut self, snap: Option<&StateSnapshot>, graph: bool) {
        if self.last_tick.is_some_and(|t| t.elapsed() < TICK) {
            return;
        }
        self.last_tick = Some(Instant::now());
        let (up, down) = snap.map_or((0, 0), |s| (s.total_up_bps, s.total_down_bps));
        self.history.push(up, down);
        let running = snap.is_some_and(|s| s.running);
        // Graph off: the plain icon is the one drawn from an empty history.
        let shown = if graph {
            icon(&self.history, running)
        } else {
            icon(&TrafficHistory::default(), running)
        };
        let _ = self.icon.set_icon(Some(shown));
        let _ = self.icon.set_tooltip(Some(tooltip(snap)));
        let model = MenuModel::of(snap);
        if self.model.as_ref() != Some(&model) {
            let (menu, actions) = model.build();
            self.icon.set_menu(Some(Box::new(menu)));
            self.actions = actions;
            self.model = Some(model);
        }
    }

    /// Drains tray input: menu picks and a left click / double click on the icon (Open).
    pub fn poll(&mut self) -> Vec<TrayAction> {
        let mut out = vec![];
        while let Ok(e) = self.menu_rx.try_recv() {
            if let Some(a) = self.actions.get(&e.id) {
                out.push(a.clone());
            }
            // Check items toggle themselves natively; rebuild from the real state.
            self.model = None;
            self.last_tick = None;
        }
        while let Ok(e) = self.icon_rx.try_recv() {
            match e {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
                | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => out.push(TrayAction::Open),
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::config::Config;

    fn snap(running: bool) -> StateSnapshot {
        StateSnapshot {
            running,
            config: Config::seed(),
            groups: Default::default(),
            proxy_up: Default::default(),
            total_up_bps: 120_000,
            total_down_bps: 2_400_000,
            proxy_servers: vec![],
        }
    }

    #[test]
    fn disabled_groups_marked_off() {
        let m = MenuModel::of(Some(&snap(true)));
        let labels: Vec<&str> = m.groups.iter().map(|(_, l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Shared names (not Iranian)",
                "Iranian sites",
                "Steam (off)",
                "Games",
                "Everything else"
            ]
        );
    }

    #[test]
    fn catch_all_never_marked_off() {
        let mut s = snap(true);
        s.config.groups.last_mut().unwrap().enabled = false;
        let m = MenuModel::of(Some(&s));
        assert_eq!(m.groups.last().unwrap().1, "Everything else");
    }

    #[test]
    fn tooltips() {
        assert_eq!(tooltip(Some(&snap(true))), "Q2Route: ↑ 120 KB/s ↓ 2.4 MB/s");
        assert_eq!(
            tooltip(Some(&snap(false))),
            "Q2Route: Stopped: all traffic direct"
        );
        assert_eq!(tooltip(None), "Q2Route: Service not running");
    }
}
