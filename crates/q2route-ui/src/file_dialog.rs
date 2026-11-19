//! Modal Windows file pickers (comdlg32). The only unsafe code of the
//! Settings page; not unit tested (it would open a dialog), see SMOKE_TEST M12.

use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};

/// The main window, owner of the dialogs (0 = no owner).
static OWNER: AtomicIsize = AtomicIsize::new(0);

pub fn set_owner(hwnd: HWND) {
    OWNER.store(hwnd as isize, Ordering::Relaxed);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `label\0*.toml\0\0` as UTF-16.
fn filter_buf(label: &str) -> Vec<u16> {
    let mut v: Vec<u16> = label.encode_utf16().collect();
    v.push(0);
    v.extend("*.toml".encode_utf16());
    v.extend([0, 0]);
    v
}

fn run(filter: &str, name: &str, save: bool) -> Option<PathBuf> {
    let filter = filter_buf(filter);
    let ext = wide("toml");
    let mut file = vec![0u16; 1024];
    for (d, s) in file.iter_mut().zip(name.encode_utf16()).take(1023) {
        *d = s;
    }
    // SAFETY: an all-zero OPENFILENAMEW is valid plain data; the fields set
    // below point to buffers that outlive the (modal) call.
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = OWNER.load(Ordering::Relaxed) as HWND;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file.as_mut_ptr();
    ofn.nMaxFile = file.len() as u32;
    ofn.lpstrDefExt = ext.as_ptr();
    ofn.Flags = OFN_EXPLORER
        | OFN_PATHMUSTEXIST
        | OFN_NOCHANGEDIR
        | if save {
            OFN_OVERWRITEPROMPT
        } else {
            OFN_FILEMUSTEXIST
        };
    // SAFETY: `ofn` is fully initialised and its buffers are alive; the call
    // blocks on this (UI) thread until the dialog closes.
    let ok = unsafe {
        if save {
            GetSaveFileNameW(&mut ofn)
        } else {
            GetOpenFileNameW(&mut ofn)
        }
    };
    if ok == 0 {
        return None; // cancelled
    }
    let end = file.iter().position(|&c| c == 0).unwrap_or(file.len());
    Some(PathBuf::from(String::from_utf16_lossy(&file[..end])))
}

/// Open-file dialog; `filter` is the label, e.g. `TOML files (*.toml)`.
pub fn pick_open(filter: &str) -> Option<PathBuf> {
    run(filter, "", false)
}

/// Save-file dialog suggesting `default_name`.
pub fn pick_save(default_name: &str) -> Option<PathBuf> {
    run("TOML files (*.toml)", default_name, true)
}

#[cfg(test)]
mod tests {
    use super::filter_buf;

    #[test]
    fn filter_is_double_nul_terminated() {
        let f = filter_buf("A");
        let s: Vec<u16> = "A\0*.toml\0\0".encode_utf16().collect();
        assert_eq!(f, s);
    }
}
