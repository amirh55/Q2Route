//! Settings page (M1: Start with Windows, Close to tray).

use std::time::Duration;

use eframe::egui;
use q2route_core::leak::{Level, Verdict};

use crate::app::Requests;
use crate::client::Client;
use crate::leak::LeakCheck;
use crate::settings::{set_autostart, UiSettings};
use crate::views::dashboard::{BLOCK, DIRECT};

/// Leak-check state kept by the app: the running probe and the last verdict.
#[derive(Default)]
pub struct LeakState {
    check: Option<LeakCheck>,
    verdict: Option<Verdict>,
}

pub fn level_color(level: Level) -> egui::Color32 {
    match level {
        Level::NoLeak => DIRECT,
        Level::Leak => BLOCK,
        Level::CantTell => egui::Color32::GRAY,
    }
}

pub fn show(
    ui: &mut egui::Ui,
    s: &mut UiSettings,
    req: &mut Requests,
    client: &Client,
    leak: &mut LeakState,
) {
    ui.heading("Settings");
    ui.add_space(8.0);
    let mut changed = false;
    if ui
        .checkbox(&mut s.start_with_windows, "Start with Windows")
        .changed()
    {
        match set_autostart(s.start_with_windows) {
            Ok(()) => changed = true,
            Err(e) => {
                s.start_with_windows = !s.start_with_windows;
                req.last_error = Some(format!("Start with Windows: {e}"));
            }
        }
    }
    changed |= ui.checkbox(&mut s.close_to_tray, "Close to tray").changed();
    if changed {
        if let Err(e) = s.save() {
            req.last_error = Some(format!("Saving settings: {e}"));
        }
    }
    leak_section(ui, client, leak);
}

fn leak_section(ui: &mut egui::Ui, client: &Client, leak: &mut LeakState) {
    if let Some(v) = leak.check.as_ref().and_then(|c| c.poll()) {
        leak.verdict = Some(v);
        leak.check = None;
    }
    let running = leak.check.as_ref().is_some_and(|c| c.running());
    ui.add_space(16.0);
    ui.heading("Leak check");
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!running, egui::Button::new("Run leak check"))
            .clicked()
        {
            leak.check = Some(LeakCheck::start(client));
            leak.verdict = None;
        }
        if running {
            ui.spinner();
            ui.label("Checking… (up to 30 s)");
        }
    });
    if running {
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
    if let Some(v) = &leak.verdict {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(&v.headline)
                .strong()
                .color(level_color(v.level.clone())),
        );
        for line in &v.lines {
            ui.label(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_colors() {
        assert_eq!(level_color(Level::NoLeak), DIRECT);
        assert_eq!(level_color(Level::Leak), BLOCK);
        assert_eq!(level_color(Level::CantTell), egui::Color32::GRAY);
    }
}
