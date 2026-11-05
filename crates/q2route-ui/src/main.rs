//! `q2route`: the Q2Route desktop UI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use q2route_core::ipc::PIPE_NAME;
use q2route_ui::app::App;
use q2route_ui::client::Client;
use q2route_ui::settings::UiSettings;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
};

const TITLE: &str = "Q2Route";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Holds `Global\Q2RouteUI` for the life of the process. Returns false when
/// another instance owns it, after bringing that instance's window to front.
fn single_instance() -> bool {
    let name = wide(r"Global\Q2RouteUI");
    // SAFETY: `name` is NUL-terminated; the handle is intentionally leaked so
    // the mutex lives until the process exits.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    // SAFETY: plain thread-local error query right after CreateMutexW.
    if handle.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return true;
    }
    let title = wide(TITLE);
    // SAFETY: `title` is NUL-terminated; the HWND is only passed back to user32.
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
    false
}

fn main() -> eframe::Result {
    if !single_instance() {
        return Ok(());
    }
    let settings = UiSettings::load();
    let client = Client::connect(PIPE_NAME);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([520.0, 360.0]),
        ..Default::default()
    };
    eframe::run_native(
        TITLE,
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, client, settings)))),
    )
}
