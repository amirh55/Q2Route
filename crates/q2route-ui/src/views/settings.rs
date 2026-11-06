//! Settings page (M1: Start with Windows, Close to tray).

use eframe::egui;

use crate::app::Requests;
use crate::settings::{set_autostart, UiSettings};

pub fn show(ui: &mut egui::Ui, s: &mut UiSettings, req: &mut Requests) {
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
}
