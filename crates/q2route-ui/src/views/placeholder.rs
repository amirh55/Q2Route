//! Pages that arrive after M1.

use eframe::egui;

pub const LATER: &str = "Coming in a later version";

pub fn show(ui: &mut egui::Ui, title: &str) {
    ui.heading(title);
    ui.add_space(8.0);
    ui.weak(LATER);
}
