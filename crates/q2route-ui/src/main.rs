//! `q2route`: the Q2Route desktop UI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use q2route_core::ipc::PIPE_NAME;
use q2route_ui::app::App;
use q2route_ui::client::Client;
use q2route_ui::settings::UiSettings;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HWND};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowExW, GetWindowThreadProcessId, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
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
    if let Some(hwnd) = find_own_window() {
        // SAFETY: `hwnd` came from FindWindowExW and is only passed back to user32.
        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
    false
}

/// File name of the executable that owns `hwnd`, e.g. `q2route.exe`.
fn window_image_name(hwnd: HWND) -> Option<String> {
    let mut pid = 0u32;
    // SAFETY: valid out-pointer; a stale HWND just yields pid 0.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if pid == 0 {
        return None;
    }
    // SAFETY: plain handle request; checked for null and closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s; `process` is a live handle closed right after.
    let ok = unsafe {
        let ok =
            QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(process);
        ok
    };
    if ok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    path.rsplit('\\').next().map(str::to_string)
}

/// The top-level window titled "Q2Route" that belongs to a `q2route.exe`
/// process (hidden windows included), so an unrelated window with the same
/// title is never focused.
fn find_own_window() -> Option<HWND> {
    let title = wide(TITLE);
    let mut after: HWND = std::ptr::null_mut();
    loop {
        // SAFETY: `title` is NUL-terminated; `after` is null or a previous result.
        after = unsafe {
            FindWindowExW(
                std::ptr::null_mut(),
                after,
                std::ptr::null(),
                title.as_ptr(),
            )
        };
        if after.is_null() {
            return None;
        }
        if window_image_name(after).is_some_and(|n| n.eq_ignore_ascii_case("q2route.exe")) {
            return Some(after);
        }
    }
}

fn main() -> eframe::Result {
    if !single_instance() {
        return Ok(());
    }
    let hidden = std::env::args().any(|a| a == "--minimized");
    let settings = UiSettings::load();
    q2route_ui::settings::refresh_autostart(&settings);
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
        Box::new(move |cc| Ok(Box::new(App::new(cc, client, settings, hidden)))),
    )
}
