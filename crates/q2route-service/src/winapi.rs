//! Small Win32 helpers: process enumeration, TCP listener owner lookup and
//! DNS cache flushing.

use std::ffi::{c_void, OsString};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use q2route_core::process_tree::ProcInfo;
use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

#[link(name = "dnsapi")]
extern "system" {
    // Undocumented export of dnsapi.dll; returns non-zero on success.
    fn DnsFlushResolverCache() -> i32;
}

/// Closes a Win32 handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the wrapped handle was returned by a successful Win32 open
        // call and is closed exactly once, here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn wide_to_path(buf: &[u16]) -> PathBuf {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    PathBuf::from(OsString::from_wide(&buf[..len]))
}

/// Full image path and creation time (FILETIME as u64) of a process, if it
/// can be opened.
fn query_process(pid: u32) -> Option<(PathBuf, u64)> {
    // SAFETY: plain FFI call with integer/flag arguments.
    let h =
        OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?);

    let mut buf = vec![0u16; 32768];
    let mut size = buf.len() as u32;
    // SAFETY: `buf` has `size` writable u16s; `size` is valid for read/write.
    let exe = unsafe {
        QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
    }
    .ok()
    .map(|()| wide_to_path(&buf[..size as usize]))?;

    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all four out-pointers reference live, writable FILETIMEs.
    let start = match unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } {
        Ok(()) => (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime),
        Err(_) => 0,
    };
    Some((exe, start))
}

/// Snapshot of all running processes. Processes that cannot be opened
/// (protected/system) get their bare exe name and `start_time == 0`.
pub fn list_processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    // SAFETY: plain FFI call with flag/integer arguments.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let snap = OwnedHandle(snap);

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `snap` is a valid snapshot handle and `entry` is a writable
    // PROCESSENTRY32W with dwSize initialised as the API requires.
    let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) }.is_ok();
    while ok {
        let pid = entry.th32ProcessID;
        let (exe, start_time) =
            query_process(pid).unwrap_or_else(|| (wide_to_path(&entry.szExeFile), 0));
        out.push(ProcInfo {
            pid,
            parent: entry.th32ParentProcessID,
            exe,
            start_time,
        });
        // SAFETY: as for Process32FirstW above.
        ok = unsafe { Process32NextW(snap.0, &mut entry) }.is_ok();
    }
    out
}

/// Calls GetExtendedTcpTable(LISTENER) for `af`, returning the raw table
/// bytes (as u64 words to keep the table's alignment).
fn tcp_listener_table(af: u32) -> Option<Vec<u64>> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let ptr = if buf.is_empty() {
            None
        } else {
            Some(buf.as_mut_ptr().cast::<c_void>())
        };
        // SAFETY: `ptr` is None or points to at least `size` writable bytes
        // (8-byte aligned); `size` is valid for read/write.
        let rc = unsafe {
            GetExtendedTcpTable(ptr, &mut size, false, af, TCP_TABLE_OWNER_PID_LISTENER, 0)
        };
        if rc == NO_ERROR.0 {
            return Some(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

/// Rows of a MIB_TCP(6)TABLE_OWNER_PID buffer.
///
/// # Safety
/// `buf` must hold a table written by GetExtendedTcpTable whose header is
/// `Table` (a `dwNumEntries: u32` followed by `table: [Row; ANY]`).
unsafe fn rows<Row: Copy>(buf: &[u64], table_offset: usize) -> Vec<Row> {
    if buf.is_empty() {
        return Vec::new();
    }
    let base = buf.as_ptr().cast::<u8>();
    // SAFETY (caller): the first u32 is dwNumEntries.
    let n = unsafe { base.cast::<u32>().read() } as usize;
    let avail = (buf.len() * 8).saturating_sub(table_offset) / size_of::<Row>();
    // SAFETY: `table_offset` is the offset of `table` within the header
    // (4 or 8 bytes), which is within the non-empty, >= 8-byte buffer.
    let first = unsafe { base.add(table_offset).cast::<Row>() };
    (0..n.min(avail))
        // SAFETY: index < avail keeps the read within `buf`; rows are
        // plain-integer structs at their natural alignment within the table.
        .map(|i| unsafe { first.add(i).read_unaligned() })
        .collect()
}

fn port_from_dw(dw: u32) -> u16 {
    // dwLocalPort holds the port in network byte order in its low 16 bits.
    u16::from_be(dw as u16)
}

/// PID of the process listening on TCP `ip:port`. A listener bound to the
/// wildcard address (0.0.0.0 / ::) also matches; an exact address match is
/// preferred.
pub fn listener_pid(port: u16, ip: IpAddr) -> Option<u32> {
    let mut exact = None;
    let mut wildcard = None;

    let v4 = match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };

    if let Some(want) = v4 {
        if let Some(buf) = tcp_listener_table(AF_INET.0 as u32) {
            let off = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
            // SAFETY: buffer was filled by GetExtendedTcpTable(AF_INET, OWNER_PID).
            for r in unsafe { rows::<MIB_TCPROW_OWNER_PID>(&buf, off) } {
                if port_from_dw(r.dwLocalPort) != port {
                    continue;
                }
                // dwLocalAddr is in network byte order as laid out in memory.
                let addr = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
                if addr == want {
                    exact.get_or_insert(r.dwOwningPid);
                } else if addr.is_unspecified() {
                    wildcard.get_or_insert(r.dwOwningPid);
                }
            }
        }
    }

    if exact.is_none() {
        if let Some(buf) = tcp_listener_table(AF_INET6.0 as u32) {
            let off = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
            // SAFETY: buffer was filled by GetExtendedTcpTable(AF_INET6, OWNER_PID).
            for r in unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&buf, off) } {
                if port_from_dw(r.dwLocalPort) != port {
                    continue;
                }
                let addr = Ipv6Addr::from(r.ucLocalAddr);
                if IpAddr::V6(addr) == ip {
                    exact.get_or_insert(r.dwOwningPid);
                } else if addr.is_unspecified() {
                    wildcard.get_or_insert(r.dwOwningPid);
                }
            }
        }
    }

    exact.or(wildcard)
}

/// Flushes the system DNS resolver cache (best effort).
pub fn flush_dns_cache() {
    // SAFETY: argument-less FFI call into dnsapi.dll.
    unsafe {
        DnsFlushResolverCache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn listener_pid_finds_current_process() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(
            listener_pid(port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(std::process::id())
        );
        assert_eq!(
            listener_pid(port, IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))),
            None
        );
    }

    #[test]
    fn listener_pid_finds_ipv6_listener() {
        let Ok(l) = TcpListener::bind("[::1]:0") else {
            return;
        }; // no IPv6 stack
        let port = l.local_addr().unwrap().port();
        assert_eq!(
            listener_pid(port, IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(std::process::id())
        );
    }

    #[test]
    fn list_processes_contains_self() {
        let me = std::process::id();
        let procs = list_processes();
        let p = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("current pid listed");
        assert!(!p.exe.as_os_str().is_empty());
        assert!(
            p.exe.is_absolute(),
            "full path expected: {}",
            p.exe.display()
        );
        assert_ne!(p.start_time, 0);
    }

    #[test]
    fn flush_dns_cache_does_not_crash() {
        flush_dns_cache();
    }
}
