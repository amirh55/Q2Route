//! Groups & rules: ordered group list, per-group editor and the rule form.

use std::collections::HashSet;

use eframe::egui::{self, Color32, RichText};
use q2route_core::config::{Action, Group, GroupId, Protocol, Rule};
use q2route_core::ipc::{ProcEntry, Request, Response, StateSnapshot};
use tokio::sync::oneshot;

use crate::app::Requests;
use crate::client::Client;
use crate::views::dashboard::{self, action_switch, rule_summary};

const HINT: &str = "One per line. Apps: steam.exe, C:\\Games\\x.exe or a folder ending in \\. \
Domains: example.com, *.ir, keyword:steam. IPs: 1.2.3.4, 5.0.0.0/8, geoip:ir. \
Ports: 443 or 27000-27100.";
const LIST_WIDTH: f32 = 300.0;

/// Entries separated by newlines or commas, trimmed, blanks dropped.
pub fn split_entries(text: &str) -> Vec<String> {
    text.split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn join_entries(v: &[String]) -> String {
    v.join("\n")
}

/// Text-field state of the rule form.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleForm {
    pub apps: String,
    pub domains: String,
    pub ips: String,
    pub ports: String,
    pub protocol: Option<Protocol>,
    pub include_children: bool,
}

impl Default for RuleForm {
    fn default() -> Self {
        RuleForm {
            apps: String::new(),
            domains: String::new(),
            ips: String::new(),
            ports: String::new(),
            protocol: None,
            include_children: true,
        }
    }
}

impl RuleForm {
    pub fn from_rule(r: &Rule) -> RuleForm {
        RuleForm {
            apps: join_entries(&r.apps),
            domains: join_entries(&r.domains),
            ips: join_entries(&r.ips),
            ports: join_entries(&r.ports),
            protocol: r.protocol,
            include_children: r.include_children,
        }
    }
}

pub fn rule_from_form(f: &RuleForm) -> Rule {
    Rule {
        apps: split_entries(&f.apps),
        domains: split_entries(&f.domains),
        ips: split_entries(&f.ips),
        ports: split_entries(&f.ports),
        protocol: f.protocol,
        include_children: f.include_children,
    }
}

/// Whether the up / down buttons of group `i` are enabled. The catch-all
/// stays last, so nothing moves into or past its slot.
pub fn can_move(groups: &[Group], i: usize) -> (bool, bool) {
    if groups.get(i).is_none_or(|g| g.catch_all) {
        return (false, false);
    }
    let next_is_catch_all = groups.get(i + 1).is_none_or(|g| g.catch_all);
    (i > 0, !next_is_catch_all)
}

/// The rule list after saving `rule`: replaces `base[index]` or appends when
/// `index` is None. None when `current` no longer equals `base` (the index
/// would point at the wrong rule) or the index is out of range.
pub fn apply_edit(
    current: &[Rule],
    base: &[Rule],
    index: Option<usize>,
    rule: Rule,
) -> Option<Vec<Rule>> {
    if current != base {
        return None;
    }
    let mut rules = current.to_vec();
    match index {
        Some(i) if i < rules.len() => rules[i] = rule,
        Some(_) => return None,
        None => rules.push(rule),
    }
    Some(rules)
}

fn action_badge(s: &StateSnapshot, a: &Action) -> (String, Color32) {
    match a {
        Action::Direct => ("Direct".into(), dashboard::DIRECT),
        Action::Block => ("Block".into(), dashboard::BLOCK),
        Action::Proxy(id) => (
            dashboard::profile(&s.config, id).map_or(id.clone(), |p| p.name.clone()),
            dashboard::PROXY,
        ),
    }
}

fn protocol_name(p: Option<Protocol>) -> &'static str {
    match p {
        None => "Any",
        Some(Protocol::Tcp) => "TCP",
        Some(Protocol::Udp) => "UDP",
    }
}

struct RuleEditor {
    /// The group's rules when the editor opened; `index` refers to these.
    base: Vec<Rule>,
    /// `Some(i)` while editing rule `i`; `None` for a new rule.
    index: Option<usize>,
    form: RuleForm,
    error: Option<String>,
    saving: Option<oneshot::Receiver<Response>>,
    picking: Option<ProcPicker>,
}

struct ProcPicker {
    rx: Option<oneshot::Receiver<Response>>,
    procs: Vec<ProcEntry>,
    filter: String,
}

#[derive(Default)]
pub struct GroupsView {
    selected: Option<GroupId>,
    new_name: String,
    rename: String,
    /// Group whose name is in `rename`; reset when the selection changes.
    loaded: Option<GroupId>,
    confirm_delete: bool,
    editor: Option<RuleEditor>,
}

impl GroupsView {
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        snap: Option<&StateSnapshot>,
        client: &Client,
        req: &mut Requests,
    ) {
        let Some(s) = snap else { return };
        let groups = &s.config.groups;
        if !self
            .selected
            .as_ref()
            .is_some_and(|id| groups.iter().any(|g| &g.id == id))
        {
            self.selected = groups.first().map(|g| g.id.clone());
        }
        if self.loaded != self.selected {
            self.loaded = self.selected.clone();
            self.rename = groups
                .iter()
                .find(|g| Some(&g.id) == self.selected.as_ref())
                .map_or(String::new(), |g| g.name.clone());
            self.confirm_delete = false;
            self.editor = None;
        }
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(LIST_WIDTH);
                self.list(ui, s, client, req);
            });
            ui.separator();
            ui.vertical(|ui| {
                let sel = groups
                    .iter()
                    .find(|g| Some(&g.id) == self.selected.as_ref());
                if let Some(g) = sel {
                    self.detail(ui, s, g, client, req);
                }
            });
        });
    }

    fn list(&mut self, ui: &mut egui::Ui, s: &StateSnapshot, client: &Client, req: &mut Requests) {
        ui.heading("Groups");
        let groups = &s.config.groups;
        for (i, g) in groups.iter().enumerate() {
            let (up, down) = can_move(groups, i);
            ui.horizontal(|ui| {
                if ui.add_enabled(up, egui::Button::new("▲")).clicked() {
                    let group_id = g.id.clone();
                    req.send(
                        client,
                        Request::MoveGroup {
                            group_id,
                            to: i - 1,
                        },
                    );
                }
                if ui.add_enabled(down, egui::Button::new("▼")).clicked() {
                    let group_id = g.id.clone();
                    req.send(
                        client,
                        Request::MoveGroup {
                            group_id,
                            to: i + 1,
                        },
                    );
                }
                let mut enabled = g.enabled;
                if dashboard::has_enabled_toggle(g)
                    && ui
                        .checkbox(&mut enabled, "")
                        .on_hover_text("Enabled")
                        .changed()
                {
                    let group_id = g.id.clone();
                    req.send(client, Request::SetGroupEnabled { group_id, enabled });
                }
                let on = Some(&g.id) == self.selected.as_ref();
                if ui.selectable_label(on, &g.name).clicked() {
                    self.selected = Some(g.id.clone());
                }
                let (text, color) = action_badge(s, &g.action);
                ui.label(RichText::new(text).color(color).small());
            });
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.new_name).desired_width(150.0));
            let name = self.new_name.trim().to_string();
            if ui
                .add_enabled(!name.is_empty(), egui::Button::new("Add group"))
                .clicked()
            {
                let action = Action::Direct;
                req.send(client, Request::AddGroup { name, action });
                self.new_name.clear();
            }
        });
    }

    fn detail(
        &mut self,
        ui: &mut egui::Ui,
        s: &StateSnapshot,
        g: &Group,
        client: &Client,
        req: &mut Requests,
    ) {
        ui.heading(&g.name);
        if g.catch_all {
            ui.label("Everything not matched above goes here.");
            ui.add_space(6.0);
            action_switch(ui, s, g, client, req);
            return;
        }
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.rename).desired_width(180.0));
            let name = self.rename.trim().to_string();
            let changed = !name.is_empty() && name != g.name;
            if ui
                .add_enabled(changed, egui::Button::new("Rename"))
                .clicked()
            {
                let group_id = g.id.clone();
                req.send(client, Request::RenameGroup { group_id, name });
            }
        });
        ui.add_space(6.0);
        action_switch(ui, s, g, client, req);
        ui.add_space(6.0);
        if self.confirm_delete {
            ui.horizontal(|ui| {
                ui.label(format!("Delete '{}' and its rules?", g.name));
                if ui.button("Yes, delete").clicked() {
                    let group_id = g.id.clone();
                    req.send(client, Request::DeleteGroup { group_id });
                    self.confirm_delete = false;
                }
                if ui.button("Cancel").clicked() {
                    self.confirm_delete = false;
                }
            });
        } else if ui.button("Delete group").clicked() {
            self.confirm_delete = true;
        }
        ui.separator();
        self.rules(ui, g, client, req);
    }

    fn rules(&mut self, ui: &mut egui::Ui, g: &Group, client: &Client, req: &mut Requests) {
        ui.horizontal(|ui| {
            ui.heading("Rules");
            if ui.button("Add rule").clicked() {
                self.open_editor(g, None, RuleForm::default());
            }
        });
        if g.rules.is_empty() {
            ui.weak("No rules yet");
        }
        let mut edit = None;
        let mut remove = None;
        for (i, r) in g.rules.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui.small_button("Edit").clicked() {
                    edit = Some(i);
                }
                if ui.small_button("Remove").clicked() {
                    remove = Some(i);
                }
                ui.label(rule_summary(r));
            });
        }
        if let Some(i) = edit {
            self.open_editor(g, Some(i), RuleForm::from_rule(&g.rules[i]));
        }
        if let Some(i) = remove {
            let mut rules = g.rules.clone();
            rules.remove(i);
            let group_id = g.id.clone();
            req.send(client, Request::SetGroupRules { group_id, rules });
        }
        self.rule_form(ui, g, client);
    }

    fn open_editor(&mut self, g: &Group, index: Option<usize>, form: RuleForm) {
        self.editor = Some(RuleEditor {
            base: g.rules.clone(),
            index,
            form,
            error: None,
            saving: None,
            picking: None,
        });
    }

    fn rule_form(&mut self, ui: &mut egui::Ui, g: &Group, client: &Client) {
        let Some(ed) = self.editor.as_mut() else {
            return;
        };
        if ed.saving.is_none() && g.rules != ed.base {
            // Rules changed under the editor; its index is stale.
            self.editor = None;
            return;
        }
        if let Some(rx) = ed.saving.as_mut() {
            match rx.try_recv() {
                Ok(Response::Error(e)) => {
                    ed.error = Some(e);
                    ed.saving = None;
                }
                Ok(_) => {
                    self.editor = None;
                    return;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    ed.error = Some("disconnected".into());
                    ed.saving = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        ui.add_space(8.0);
        ui.separator();
        ui.strong(if ed.index.is_some() {
            "Edit rule"
        } else {
            "Add rule"
        });
        let f = &mut ed.form;
        for (label, text) in [
            ("Apps", &mut f.apps),
            ("Domains", &mut f.domains),
            ("IPs", &mut f.ips),
            ("Ports", &mut f.ports),
        ] {
            ui.label(label);
            ui.add(
                egui::TextEdit::multiline(text)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
        }
        ui.weak(HINT);
        ui.horizontal(|ui| {
            ui.label("Protocol");
            egui::ComboBox::from_id_salt("rule-protocol")
                .selected_text(protocol_name(f.protocol))
                .show_ui(ui, |ui| {
                    for p in [None, Some(Protocol::Tcp), Some(Protocol::Udp)] {
                        ui.selectable_value(&mut f.protocol, p, protocol_name(p));
                    }
                });
            ui.checkbox(&mut f.include_children, "Include child processes");
        });
        if ui.button("Pick running app…").clicked() && ed.picking.is_none() {
            ed.picking = Some(ProcPicker {
                rx: Some(client.send(Request::ListProcesses)),
                procs: vec![],
                filter: String::new(),
            });
        }
        if let Some(p) = ed.picking.as_mut() {
            if let Some(rx) = p.rx.as_mut() {
                match rx.try_recv() {
                    Ok(Response::Processes(v)) => {
                        p.procs = v;
                        p.rx = None;
                    }
                    Ok(_) | Err(oneshot::error::TryRecvError::Closed) => p.rx = None,
                    Err(oneshot::error::TryRecvError::Empty) => {}
                }
            }
            let (mut close, mut picked) = (false, None);
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Filter");
                    ui.text_edit_singleline(&mut p.filter);
                    close = ui.button("Close").clicked();
                });
                if p.rx.is_some() {
                    ui.spinner();
                }
                let needle = p.filter.to_lowercase();
                let mut seen = HashSet::new();
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .id_salt("procs")
                    .show(ui, |ui| {
                        for e in &p.procs {
                            let hit = e.name.to_lowercase().contains(&needle)
                                || e.path.to_lowercase().contains(&needle);
                            if hit && seen.insert(e.name.to_lowercase()) {
                                let r = ui.selectable_label(false, &e.name);
                                if r.on_hover_text(&e.path).clicked() {
                                    picked = Some(e.name.clone());
                                }
                            }
                        }
                    });
            });
            if let Some(name) = picked {
                let mut apps = split_entries(&ed.form.apps);
                if !apps.iter().any(|a| a.eq_ignore_ascii_case(&name)) {
                    apps.push(name);
                }
                ed.form.apps = join_entries(&apps);
            }
            if close {
                ed.picking = None;
            }
        }
        let rule = rule_from_form(&ed.form);
        let (mut save, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            let ready = !rule.is_empty() && ed.saving.is_none();
            save = ui.add_enabled(ready, egui::Button::new("Save")).clicked();
            cancel = ui.button("Cancel").clicked();
            if ed.saving.is_some() {
                ui.spinner();
            }
        });
        if let Some(e) = &ed.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        if save {
            match apply_edit(&g.rules, &ed.base, ed.index, rule) {
                Some(rules) => {
                    ed.error = None;
                    let group_id = g.id.clone();
                    ed.saving = Some(client.send(Request::SetGroupRules { group_id, rules }));
                }
                None => {
                    ed.error = Some("This group's rules changed; reopen the rule.".into());
                }
            }
        }
        if cancel {
            self.editor = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::config::Config;

    #[test]
    fn split_entries_commas_and_lines() {
        assert_eq!(
            split_entries(" a.com, b.com\n\n*.ir \r\n"),
            ["a.com", "b.com", "*.ir"]
        );
    }

    #[test]
    fn form_roundtrip() {
        let r = Rule {
            apps: vec!["steam.exe".into(), "C:\\Games\\".into()],
            domains: vec!["*.ir".into(), "keyword:steam".into()],
            ips: vec!["5.0.0.0/8".into(), "geoip:ir".into()],
            ports: vec!["443".into(), "27000-27100".into()],
            protocol: Some(Protocol::Udp),
            include_children: false,
        };
        assert_eq!(rule_from_form(&RuleForm::from_rule(&r)), r);
    }

    #[test]
    fn empty_form_is_empty_rule() {
        let r = rule_from_form(&RuleForm::default());
        assert!(r.is_empty());
        assert!(r.include_children);
    }

    #[test]
    fn apply_edit_replaces_appends_and_rejects_stale() {
        let rule = |d: &str| Rule {
            domains: vec![d.into()],
            ..Rule::default()
        };
        let base = vec![rule("a"), rule("b"), rule("c")];
        let edited = apply_edit(&base, &base, Some(1), rule("x")).unwrap();
        assert_eq!(edited, [rule("a"), rule("x"), rule("c")]);
        let added = apply_edit(&base, &base, None, rule("x")).unwrap();
        assert_eq!(added, [rule("a"), rule("b"), rule("c"), rule("x")]);
        let current = vec![rule("b"), rule("c")];
        assert_eq!(apply_edit(&current, &base, Some(1), rule("x")), None);
        assert_eq!(apply_edit(&base, &base, Some(3), rule("x")), None);
    }

    #[test]
    fn move_buttons_respect_edges_and_catch_all() {
        // Seed: three movable groups then the catch-all.
        let g = Config::seed().groups;
        assert_eq!(g.len(), 4);
        let m: Vec<_> = (0..4).map(|i| can_move(&g, i)).collect();
        assert_eq!(
            m,
            [(false, true), (true, true), (true, false), (false, false)]
        );
    }
}
