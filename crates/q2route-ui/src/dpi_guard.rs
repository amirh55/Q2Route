//! Stops the WM_DPICHANGED growth loop while the window is dragged (or
//! edge-resized) between monitors with different scaling (e.g. 125% and 100%).
//!
//! Windows sends WM_DPICHANGED as soon as the window crosses over, repeatedly and
//! nested while the modal loop runs. winit answers each one by rescaling the
//! window's *current* size by new/old scale, but Windows has already rescaled it,
//! so the size compounds (x1.25 per crossing) and the window runs away from the
//! cursor.
//!
//! eframe/egui-winit offer no option for this, so the window is subclassed:
//! DPI changes arriving between WM_ENTERSIZEMOVE and WM_EXITSIZEMOVE are held
//! back, and one is replayed to winit when the loop ends.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClientRect, GetWindowLongW, GetWindowRect, IsIconic, IsZoomed, SetWindowPos, GWL_EXSTYLE,
    GWL_STYLE, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER,
};

const WM_DPICHANGED: u32 = 0x02E0;
const WM_ENTERSIZEMOVE: u32 = 0x0231;
const WM_EXITSIZEMOVE: u32 = 0x0232;
const WM_CAPTURECHANGED: u32 = 0x0215;
const WM_NCDESTROY: u32 = 0x0082;
const SUBCLASS_ID: usize = 0x5132_5230;

/// True between WM_ENTERSIZEMOVE and WM_EXITSIZEMOVE (the user is dragging).
static IN_MOVE: AtomicBool = AtomicBool::new(false);
/// The DPI winit has last been told about.
static DELIVERED_DPI: AtomicU32 = AtomicU32::new(96);

/// Subclasses `hwnd`.
///
/// # Safety
/// `hwnd` must be a valid window owned by the calling (UI) thread.
pub unsafe fn install(hwnd: HWND) -> bool {
    if hwnd.is_null() {
        return false;
    }
    // SAFETY: `hwnd` is this thread's window; `subclass_proc` matches SUBCLASSPROC.
    unsafe {
        DELIVERED_DPI.store(GetDpiForWindow(hwnd), Ordering::Relaxed);
        SetWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID, 0) != 0
    }
}

/// Scales the window's client size from `now` to `old` DPI and resizes the
/// window to the matching outer size (frame computed for `old`), keeping its
/// position. No-op for maximised / minimised windows.
///
/// # Safety
/// `h` must be a valid window handle.
unsafe fn shrink_to_old_dpi(h: HWND, old: u32, now: u32) {
    // SAFETY: caller guarantees `h`; all out-pointers are to locals.
    unsafe {
        if IsZoomed(h) != 0 || IsIconic(h) != 0 {
            return;
        }
        let mut client = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        GetClientRect(h, &mut client);
        let back = |v: i32| ((v as i64 * old as i64 + now as i64 / 2) / now as i64) as i32;
        let mut r = RECT {
            left: 0,
            top: 0,
            right: back(client.right),
            bottom: back(client.bottom),
        };
        AdjustWindowRectExForDpi(
            &mut r,
            GetWindowLongW(h, GWL_STYLE) as u32,
            0,
            GetWindowLongW(h, GWL_EXSTYLE) as u32,
            old,
        );
        SetWindowPos(
            h,
            std::ptr::null_mut(),
            0,
            0,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

unsafe extern "system" fn subclass_proc(
    h: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    match msg {
        WM_ENTERSIZEMOVE => IN_MOVE.store(true, Ordering::Relaxed),
        // Never keep swallowing if the loop ends without an EXITSIZEMOVE.
        WM_CAPTURECHANGED | WM_NCDESTROY => IN_MOVE.store(false, Ordering::Relaxed),
        WM_DPICHANGED if IN_MOVE.load(Ordering::Relaxed) => return 0,
        WM_DPICHANGED => DELIVERED_DPI.store((wp & 0xffff) as u32, Ordering::Relaxed),
        WM_EXITSIZEMOVE => {
            IN_MOVE.store(false, Ordering::Relaxed);
            // SAFETY: plain message forwarding / window calls on our own window.
            unsafe {
                let r = DefSubclassProc(h, msg, wp, lp);
                let now = GetDpiForWindow(h);
                let old = DELIVERED_DPI.load(Ordering::Relaxed);
                if now != 0 && now != old {
                    // Replay the held-back change. Assumption (observed on
                    // Windows 11, per-monitor v2): during the drag Windows has
                    // already resized the window to the new DPI, whereas winit
                    // scales the current client size by now/old itself. So give
                    // the window the old-DPI equivalent of its client size first,
                    // and winit's scaling lands back on the size Windows chose.
                    // Not assumed: which direction we moved, or the window size.
                    // Maximised/minimised windows are not resized, only notified.
                    shrink_to_old_dpi(h, old, now);
                    let mut rect = RECT {
                        left: 0,
                        top: 0,
                        right: 0,
                        bottom: 0,
                    };
                    GetWindowRect(h, &mut rect);
                    DELIVERED_DPI.store(now, Ordering::Relaxed);
                    let packed = (now as usize) << 16 | now as usize;
                    DefSubclassProc(h, WM_DPICHANGED, packed, &rect as *const RECT as LPARAM);
                }
                return r;
            }
        }
        _ => {}
    }
    // SAFETY: forwards the original message untouched.
    unsafe { DefSubclassProc(h, msg, wp, lp) }
}
