//! UI-only settings, stored in `%APPDATA%\Q2Route\ui.toml` (the M1 IPC
//! protocol has no settings mutation), and the HKCU Run autostart entry.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Q2Route";

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UiSettings {
    #[serde(default)]
    pub start_with_windows: bool,
    #[serde(default)]
    pub close_to_tray: bool,
}

fn path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("Q2Route").join("ui.toml"))
}

impl UiSettings {
    /// Missing or unreadable file yields the defaults.
    pub fn load() -> UiSettings {
        path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        let p =
            path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "APPDATA is not set"))?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body =
            toml::to_string(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(p, body)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Adds or removes `HKCU\...\Run\Q2Route = "<exe>" --minimized`.
pub fn set_autostart(on: bool) -> io::Result<()> {
    let (key, value) = (wide(RUN_KEY), wide(RUN_VALUE));
    let rc = if on {
        let exe = std::env::current_exe()?;
        let data = wide(&format!("\"{}\" --minimized", exe.display()));
        // SAFETY: all pointers are NUL-terminated UTF-16 buffers that outlive
        // the call; the size covers `data` including its terminator.
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        }
    } else {
        // SAFETY: NUL-terminated UTF-16 buffers that outlive the call.
        match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
            rc => rc,
        }
    };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc as i32))
    }
}
