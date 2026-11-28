//! Modal Windows file and folder pickers. Tests only exercise pure buffers;
//! native dialogs require an explicit manual smoke test.

use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::{
    SHBrowseForFolderW, SHGetPathFromIDListEx, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
    BROWSEINFOW,
};

/// The main window, owner of the dialogs (0 = no owner).
static OWNER: AtomicIsize = AtomicIsize::new(0);

pub fn set_owner(hwnd: HWND) {
    OWNER.store(hwnd as isize, Ordering::Relaxed);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `label\0pattern\0\0` as UTF-16.
fn filter_buf(label: &str, pattern: &str) -> Vec<u16> {
    let mut v: Vec<u16> = label.encode_utf16().collect();
    v.push(0);
    v.extend(pattern.encode_utf16());
    v.extend([0, 0]);
    v
}

fn run(filter: &str, pattern: &str, extension: &str, name: &str, save: bool) -> Option<PathBuf> {
    let filter = filter_buf(filter, pattern);
    let ext = wide(extension);
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
    Some(PathBuf::from(std::ffi::OsString::from_wide(&file[..end])))
}

/// Open-file dialog; `filter` is the label, e.g. `TOML files (*.toml)`.
pub fn pick_open(filter: &str) -> Option<PathBuf> {
    run(filter, "*.toml", "toml", "", false)
}

/// Save-file dialog suggesting `default_name`.
pub fn pick_save(default_name: &str) -> Option<PathBuf> {
    run("TOML files (*.toml)", "*.toml", "toml", default_name, true)
}

/// Select an existing executable without changing the working directory.
pub fn pick_exe() -> Option<PathBuf> {
    run("Executables (*.exe)", "*.exe", "exe", "", false)
}

/// Select a filesystem folder. Must be called on the UI (STA) thread.
pub fn pick_folder() -> Option<PathBuf> {
    // SAFETY: initialize COM on this thread. Both S_OK and S_FALSE require a
    // matching CoUninitialize; a failed call (including changed mode) does not.
    let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    if hr < 0 {
        return None;
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: exactly balances the successful initialization above.
            unsafe { CoUninitialize() };
        }
    }
    let _apartment = Apartment;
    let title = wide("Select application folder");
    let mut display_name = [0u16; 260];
    // SAFETY: BROWSEINFOW is plain data; optional callbacks/root are null.
    let mut info: BROWSEINFOW = unsafe { std::mem::zeroed() };
    info.hwndOwner = OWNER.load(Ordering::Relaxed) as HWND;
    info.pszDisplayName = display_name.as_mut_ptr();
    info.lpszTitle = title.as_ptr();
    info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    // SAFETY: all buffers outlive the modal call; this thread has an STA.
    let pidl = unsafe { SHBrowseForFolderW(&info) };
    if pidl.is_null() {
        return None;
    }
    let mut path = vec![0u16; 32768];
    // SAFETY: the shell returned a valid PIDL, and path's advertised capacity
    // matches its allocation. Free the shell-owned allocation on every result.
    let ok = unsafe {
        let ok = SHGetPathFromIDListEx(pidl, path.as_mut_ptr(), path.len() as u32, 0);
        CoTaskMemFree(pidl.cast());
        ok
    };
    if ok == 0 {
        return None;
    }
    let end = path.iter().position(|&c| c == 0)?;
    Some(PathBuf::from(std::ffi::OsString::from_wide(&path[..end])))
}

#[cfg(test)]
mod tests {
    use super::filter_buf;

    #[test]
    fn executable_filter_is_double_nul_terminated() {
        assert_eq!(
            filter_buf("Executables (*.exe)", "*.exe"),
            "Executables (*.exe)\0*.exe\0\0"
                .encode_utf16()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn filter_preserves_unicode_label() {
        assert_eq!(
            filter_buf("برنامه 🚀", "*.exe"),
            "برنامه 🚀\0*.exe\0\0".encode_utf16().collect::<Vec<_>>()
        );
    }

    #[test]
    fn filter_is_double_nul_terminated() {
        let f = filter_buf("A", "*.toml");
        let s: Vec<u16> = "A\0*.toml\0\0".encode_utf16().collect();
        assert_eq!(f, s);
    }
}
