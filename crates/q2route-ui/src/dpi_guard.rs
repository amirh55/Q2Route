//! Stops the WM_DPICHANGED feedback loop while the window is dragged between
//! monitors with different scaling (e.g. 125% and 100%).
//!
//! Windows sends WM_DPICHANGED as soon as the dragged window crosses over. winit
//! answers by resizing the window for the new DPI, which moves its centre of
//! gravity back onto the old monitor, so Windows sends another WM_DPICHANGED, and
//! so on: the size keeps changing and the window is hard to drop on the
//! smaller-scale monitor.
//!
//! eframe/egui-winit offer no option for this, so the window is subclassed:
//! DPI changes that arrive inside the modal move/size loop are held back
//! (the window keeps its physical size while it is dragged) and delivered to winit
//! exactly once when the drag ends, where its normal resize-for-new-DPI is safe.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GetWindowRect, GetWindowTextW, SetWindowPos, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOZORDER,
};

const WM_DPICHANGED: u32 = 0x02E0;
const WM_ENTERSIZEMOVE: u32 = 0x0231;
const WM_EXITSIZEMOVE: u32 = 0x0232;
const SUBCLASS_ID: usize = 0x5132_5230;

/// True between WM_ENTERSIZEMOVE and WM_EXITSIZEMOVE (the user is dragging).
static IN_MOVE: AtomicBool = AtomicBool::new(false);
/// The DPI winit has last been told about.
static DELIVERED_DPI: AtomicU32 = AtomicU32::new(96);

struct Find<'a> {
    title: &'a [u16],
    hwnd: HWND,
}

unsafe extern "system" fn enum_cb(h: HWND, lp: LPARAM) -> i32 {
    // SAFETY: `lp` is the `&mut Find` passed by `install` and outlives the call.
    let f = unsafe { &mut *(lp as *mut Find) };
    let mut buf = [0u16; 128];
    // SAFETY: `buf` is valid for `buf.len()` u16s.
    let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
    if n > 0 && &buf[..n as usize] == f.title {
        f.hwnd = h;
        return 0;
    }
    1
}

/// Subclasses this thread's top-level window titled `title`. Must be called on
/// the UI thread; returns false if the window does not exist (yet).
pub fn install(title: &str) -> bool {
    let title: Vec<u16> = title.encode_utf16().collect();
    let mut find = Find {
        title: &title,
        hwnd: std::ptr::null_mut(),
    };
    // SAFETY: the callback only touches `find`, which outlives the call.
    unsafe {
        EnumThreadWindows(
            windows_sys::Win32::System::Threading::GetCurrentThreadId(),
            Some(enum_cb),
            &mut find as *mut Find as LPARAM,
        );
    }
    if find.hwnd.is_null() {
        return false;
    }
    // SAFETY: `find.hwnd` belongs to this thread; `subclass_proc` matches SUBCLASSPROC.
    unsafe {
        DELIVERED_DPI.store(GetDpiForWindow(find.hwnd), Ordering::Relaxed);
        SetWindowSubclass(find.hwnd, Some(subclass_proc), SUBCLASS_ID, 0) != 0
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
        WM_DPICHANGED if IN_MOVE.load(Ordering::Relaxed) => return 0,
        WM_DPICHANGED => DELIVERED_DPI.store((wp & 0xffff) as u32, Ordering::Relaxed),
        WM_EXITSIZEMOVE => {
            IN_MOVE.store(false, Ordering::Relaxed);
            // SAFETY: plain message forwarding / window queries on our own window.
            unsafe {
                let r = DefSubclassProc(h, msg, wp, lp);
                let now = GetDpiForWindow(h);
                let old = DELIVERED_DPI.load(Ordering::Relaxed);
                if now != 0 && now != old {
                    // Replay the held-back change. Windows already resized the
                    // window to the new DPI during the drag, but winit scales
                    // the current size by new/old itself, so first give the
                    // window the size winit expects (the old-DPI equivalent).
                    let mut rect = RECT {
                        left: 0,
                        top: 0,
                        right: 0,
                        bottom: 0,
                    };
                    GetWindowRect(h, &mut rect);
                    let back =
                        |v: i32| ((v as i64 * old as i64 + now as i64 / 2) / now as i64) as i32;
                    SetWindowPos(
                        h,
                        std::ptr::null_mut(),
                        0,
                        0,
                        back(rect.right - rect.left),
                        back(rect.bottom - rect.top),
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                    );
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
