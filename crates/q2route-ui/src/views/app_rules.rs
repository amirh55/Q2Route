//! Per-app overrides. Only the process itself matches, never its children.

use eframe::egui;
use q2route_core::config::{Action, AppRule, Config};
use q2route_core::ipc::{Request, Response, StateSnapshot};
use q2route_core::matchers::AppMatcher;
use tokio::sync::oneshot;

use super::groups::ProcPicker;
use crate::{app::Requests, client::Client, file_dialog};

pub fn pattern_key(app: &str) -> String {
    app.trim().replace('/', "\\").to_lowercase()
}

pub fn folder_pattern(folder: &str) -> String {
    format!("{}\\", folder.replace('/', "\\").trim_end_matches('\\'))
}

pub fn add_rule(rules: &mut Vec<AppRule>, app: String, action: Action) -> Result<(), String> {
    AppMatcher::parse(&app).map_err(|e| e.to_string())?;
    if rules
        .iter()
        .any(|r| pattern_key(&r.app) == pattern_key(&app))
    {
        return Err("App rule already exists".into());
    }
    rules.insert(
        0,
        AppRule {
            app,
            action,
            enabled: true,
        },
    );
    Ok(())
}

pub fn exact_exe(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    let absolute = (normalized.as_bytes().get(1) == Some(&b':')
        && normalized.as_bytes().get(2) == Some(&b'\\'))
        || normalized.starts_with("\\\\");
    absolute && normalized.to_lowercase().ends_with(".exe") && !normalized.contains(['*', '?'])
}

/// Block targets the exact own exe, not children. Allow disables, never forces Direct.
pub fn set_internet(rules: &mut Vec<AppRule>, path: &str, allow: bool) -> Result<(), String> {
    if !exact_exe(path) {
        return Err("Full executable path is unavailable".into());
    }
    let at = rules
        .iter()
        .position(|r| pattern_key(&r.app) == pattern_key(path));
    if allow {
        if let Some(at) = at {
            rules[at].enabled = false;
        }
    } else {
        let mut rule = at.map(|at| rules.remove(at)).unwrap_or(AppRule {
            app: path.into(),
            action: Action::Block,
            enabled: true,
        });
        rule.action = Action::Block;
        rule.enabled = true;
        rules.insert(0, rule);
    }
    Ok(())
}

pub fn proxy_deleted(cfg: &Config, action: &Action) -> bool {
    matches!(action, Action::Proxy(id) if !cfg.proxies.iter().any(|p| &p.id == id))
}

#[derive(Default)]
pub struct AppRulesView {
    picking: Option<ProcPicker>,
    saving: Option<oneshot::Receiver<Response>>,
    submitted: Option<Vec<AppRule>>,
    message: Option<String>,
}

impl AppRulesView {
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        snap: Option<&StateSnapshot>,
        client: &Client,
        req: &mut Requests,
    ) {
        ui.heading("App rules");
        ui.weak("Rules apply to the app itself, not child processes. First matching enabled rule wins before groups.");
        let Some(snap) = snap else { return };
        if let Some(rx) = self.saving.as_mut() {
            match rx.try_recv() {
                Ok(Response::Ok) => self.saving = None,
                Ok(Response::Error(e)) => {
                    req.last_error = Some(e);
                    self.saving = None;
                    self.submitted = None;
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                    req.last_error = Some("App rules update was not acknowledged".into());
                    self.saving = None;
                    self.submitted = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if self.saving.is_none() && self.submitted.as_ref() == Some(&snap.config.app_rules) {
            self.submitted = None;
        }
        let ready = self.saving.is_none() && self.submitted.is_none() && client.connected();
        let mut rules = snap.config.app_rules.clone();
        let mut changed = false;
        ui.add_enabled_ui(ready, |ui| {
            let mut app = None;
            ui.horizontal(|ui| {
                if ui.button("Add running process…").clicked() {
                    self.picking = Some(ProcPicker::new(client));
                }
                if ui.button("Add exe…").clicked() {
                    app = file_dialog::pick_exe().map(|p| p.to_string_lossy().into_owned());
                }
                if ui.button("Add folder…").clicked() {
                    app = file_dialog::pick_folder().map(|p| folder_pattern(&p.to_string_lossy()));
                }
            });
            if let Some(picker) = self.picking.as_mut() {
                let (close, picked) = picker.show(ui, true);
                if picked.is_some() {
                    app = picked;
                    self.picking = None;
                } else if close {
                    self.picking = None;
                }
            }
            if let Some(app) = app {
                match add_rule(
                    &mut rules,
                    app,
                    Action::Proxy(snap.config.default_proxy.clone()),
                ) {
                    Ok(()) => {
                        changed = true;
                        self.message = None;
                    }
                    Err(e) => self.message = Some(e),
                }
            }
            let mut remove = None;
            egui::Grid::new("app_rules_table")
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("On");
                    ui.strong("App");
                    ui.strong("Route");
                    ui.label("");
                    ui.end_row();
                    for (i, rule) in rules.iter_mut().enumerate() {
                        let deleted = proxy_deleted(&snap.config, &rule.action);
                        ui.scope(|ui| {
                            if deleted {
                                ui.visuals_mut().override_text_color =
                                    Some(ui.visuals().error_fg_color);
                            }
                            changed |= ui.checkbox(&mut rule.enabled, "").changed();
                        });
                        let name = if rule.app.ends_with(['\\', '/']) {
                            rule.app.clone()
                        } else {
                            rule.app
                                .rsplit(['\\', '/'])
                                .next()
                                .unwrap_or(&rule.app)
                                .to_string()
                        };
                        ui.scope(|ui| {
                            if deleted {
                                ui.visuals_mut().override_text_color =
                                    Some(ui.visuals().error_fg_color);
                            }
                            ui.label(name).on_hover_text(&rule.app);
                        });
                        let label = match &rule.action {
                            Action::Direct => "Direct".to_string(),
                            Action::Block => "Block".to_string(),
                            Action::Proxy(id) => snap
                                .config
                                .proxies
                                .iter()
                                .find(|p| &p.id == id)
                                .map_or("proxy deleted".into(), |p| p.name.clone()),
                        };
                        ui.scope(|ui| {
                            if deleted {
                                ui.visuals_mut().override_text_color =
                                    Some(ui.visuals().error_fg_color);
                            }
                            egui::ComboBox::from_id_salt(("app_route", i))
                                .selected_text(label)
                                .show_ui(ui, |ui| {
                                    changed |= ui
                                        .selectable_value(
                                            &mut rule.action,
                                            Action::Direct,
                                            "Direct",
                                        )
                                        .changed();
                                    for p in &snap.config.proxies {
                                        changed |= ui
                                            .selectable_value(
                                                &mut rule.action,
                                                Action::Proxy(p.id.clone()),
                                                &p.name,
                                            )
                                            .changed();
                                    }
                                    changed |= ui
                                        .selectable_value(&mut rule.action, Action::Block, "Block")
                                        .changed();
                                });
                        });
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
            if let Some(i) = remove {
                rules.remove(i);
                changed = true;
            }
        });
        if changed {
            self.submitted = Some(rules.clone());
            self.saving = Some(client.send(Request::SetAppRules(rules)));
        }
        if !ready {
            ui.weak("Waiting for service state…");
        }
        if let Some(msg) = &self.message {
            ui.colored_label(ui.visuals().error_fg_color, msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::config::{Action, AppRule};

    fn rule(app: &str, action: Action) -> AppRule {
        AppRule {
            app: app.into(),
            action,
            enabled: true,
        }
    }

    #[test]
    fn duplicate_paths_ignore_case_and_separator() {
        let mut rules = vec![rule(r"C:\Games\play.exe", Action::Block)];
        assert!(add_rule(&mut rules, "c:/games/PLAY.exe".into(), Action::Direct).is_err());
        assert_eq!(rules.len(), 1);
        assert!(add_rule(&mut rules, "C:/Other/play.exe".into(), Action::Direct).is_ok());
    }

    #[test]
    fn folder_pattern_keeps_boundary() {
        assert_eq!(folder_pattern("C:/Games/"), "C:\\Games\\");
        assert_ne!(pattern_key(r"C:\Games\"), pattern_key(r"C:\Games"));
    }

    #[test]
    fn context_block_upserts_exact_path_ahead_of_broad_rule() {
        let mut rules = vec![
            rule(r"C:\Games\", Action::Direct),
            rule(r"C:\Games\play.exe", Action::Direct),
        ];
        rules[1].enabled = false;
        set_internet(&mut rules, r"c:\games\PLAY.exe", false).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, Action::Block);
        assert!(rules[0].enabled);
        set_internet(&mut rules, r"C:\Games\play.exe", true).unwrap();
        assert!(!rules[0].enabled);
        assert_eq!(rules[0].action, Action::Block);
        assert_eq!(rules[1].action, Action::Direct);
    }

    #[test]
    fn context_unknown_path_never_becomes_name_rule() {
        let mut rules = vec![];
        for path in ["", "?", "play.exe", r"C:\Games\", r"C:\Games\*.exe"] {
            assert!(set_internet(&mut rules, path, false).is_err());
        }
        assert!(rules.is_empty());
        set_internet(&mut rules, r"C:\Games\play.exe", true).unwrap();
        assert!(rules.is_empty(), "Allow does not invent a Direct rule");
    }

    #[test]
    fn deleted_proxy_is_visible() {
        let cfg = q2route_core::config::Config::seed();
        assert!(proxy_deleted(&cfg, &Action::Proxy("gone".into())));
        assert!(!proxy_deleted(
            &cfg,
            &Action::Proxy(cfg.default_proxy.clone())
        ));
    }
}
