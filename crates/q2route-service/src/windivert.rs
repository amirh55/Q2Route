//! Thin safe wrapper over the WinDivert 2.2.2 C API (`vendor/windivert/windivert.h`).

use std::ffi::{c_char, c_void, CString};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::ptr;

// WINDIVERT_LAYER
pub const LAYER_NETWORK: u8 = 0;
pub const LAYER_NETWORK_FORWARD: u8 = 1;
pub const LAYER_FLOW: u8 = 2;
pub const LAYER_SOCKET: u8 = 3;
pub const LAYER_REFLECT: u8 = 4;

// WINDIVERT_EVENT
pub const EVENT_NETWORK_PACKET: u8 = 0;
pub const EVENT_FLOW_ESTABLISHED: u8 = 1;
pub const EVENT_FLOW_DELETED: u8 = 2;
pub const EVENT_SOCKET_BIND: u8 = 3;
pub const EVENT_SOCKET_CONNECT: u8 = 4;
pub const EVENT_SOCKET_LISTEN: u8 = 5;
pub const EVENT_SOCKET_ACCEPT: u8 = 6;
pub const EVENT_SOCKET_CLOSE: u8 = 7;
pub const EVENT_REFLECT_OPEN: u8 = 8;
pub const EVENT_REFLECT_CLOSE: u8 = 9;

// WINDIVERT_FLAG_*
pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_DROP: u64 = 0x0002;
pub const FLAG_RECV_ONLY: u64 = 0x0004;
pub const FLAG_SEND_ONLY: u64 = 0x0008;
pub const FLAG_NO_INSTALL: u64 = 0x0010;
pub const FLAG_FRAGMENTS: u64 = 0x0020;

const SHUTDOWN_BOTH: u32 = 0x3;

/// The layers Q2Route uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Network,
    Flow,
    Socket,
}

impl Layer {
    fn raw(self) -> u32 {
        match self {
            Layer::Network => LAYER_NETWORK as u32,
            Layer::Flow => LAYER_FLOW as u32,
            Layer::Socket => LAYER_SOCKET as u32,
        }
    }
}

// Bit positions within the 32-bit bitfield word of WINDIVERT_ADDRESS
// (MSVC allocates bitfields from the least significant bit).
const LAYER_SHIFT: u32 = 0;
const EVENT_SHIFT: u32 = 8;
const BIT_SNIFFED: u32 = 1 << 16;
const BIT_OUTBOUND: u32 = 1 << 17;
const BIT_LOOPBACK: u32 = 1 << 18;
const BIT_IMPOSTOR: u32 = 1 << 19;
const BIT_IPV6: u32 = 1 << 20;
const BIT_IP_CHECKSUM: u32 = 1 << 21;
const BIT_TCP_CHECKSUM: u32 = 1 << 22;
const BIT_UDP_CHECKSUM: u32 = 1 << 23;

/// `WINDIVERT_ADDRESS`. The trailing 64-byte union is kept opaque and
/// decoded by the accessors according to the layer.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Address {
    timestamp: i64,
    bits: u32,
    reserved2: u32,
    data: [u64; 8],
}

const _: () = assert!(size_of::<Address>() == 80);

/// `WINDIVERT_DATA_FLOW` / `WINDIVERT_DATA_SOCKET` (identical layouts).
#[repr(C)]
#[derive(Clone, Copy)]
struct RawEndpoint {
    endpoint_id: u64,
    parent_endpoint_id: u64,
    process_id: u32,
    local_addr: [u32; 4],
    remote_addr: [u32; 4],
    local_port: u16,
    remote_port: u16,
    protocol: u8,
}

const _: () = assert!(size_of::<RawEndpoint>() <= 64);

/// `WINDIVERT_DATA_NETWORK`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawNetwork {
    if_idx: u32,
    sub_if_idx: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketData {
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowData {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: u8,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("layer", &self.layer())
            .field("event", &self.event())
            .field("outbound", &self.outbound())
            .field("loopback", &self.loopback())
            .field("ipv6", &self.ipv6())
            .finish()
    }
}

impl Address {
    fn bit(&self, mask: u32) -> bool {
        self.bits & mask != 0
    }

    fn set_bit(&mut self, mask: u32, b: bool) {
        if b {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
    pub fn layer(&self) -> u8 {
        (self.bits >> LAYER_SHIFT) as u8
    }
    pub fn event(&self) -> u8 {
        (self.bits >> EVENT_SHIFT) as u8
    }
    pub fn sniffed(&self) -> bool {
        self.bit(BIT_SNIFFED)
    }
    pub fn outbound(&self) -> bool {
        self.bit(BIT_OUTBOUND)
    }
    pub fn set_outbound(&mut self, b: bool) {
        self.set_bit(BIT_OUTBOUND, b)
    }
    pub fn loopback(&self) -> bool {
        self.bit(BIT_LOOPBACK)
    }
    pub fn impostor(&self) -> bool {
        self.bit(BIT_IMPOSTOR)
    }
    pub fn set_impostor(&mut self, b: bool) {
        self.set_bit(BIT_IMPOSTOR, b)
    }
    pub fn ipv6(&self) -> bool {
        self.bit(BIT_IPV6)
    }
    pub fn ip_checksum(&self) -> bool {
        self.bit(BIT_IP_CHECKSUM)
    }
    pub fn tcp_checksum(&self) -> bool {
        self.bit(BIT_TCP_CHECKSUM)
    }
    pub fn udp_checksum(&self) -> bool {
        self.bit(BIT_UDP_CHECKSUM)
    }

    /// Interface index (network layers only).
    pub fn if_idx(&self) -> Option<(u32, u32)> {
        match self.layer() {
            LAYER_NETWORK | LAYER_NETWORK_FORWARD => {
                // SAFETY: `data` is 64 initialised bytes, RawNetwork is 8 bytes of
                // plain integers (any bit pattern valid); read_unaligned imposes
                // no alignment requirement.
                let n: RawNetwork = unsafe { ptr::read_unaligned(self.data.as_ptr().cast()) };
                Some((n.if_idx, n.sub_if_idx))
            }
            _ => None,
        }
    }

    fn endpoint(&self) -> RawEndpoint {
        // SAFETY: `data` is 64 initialised bytes and RawEndpoint (<= 64 bytes,
        // asserted above) consists only of integers, so every bit pattern is
        // valid; read_unaligned imposes no alignment requirement.
        unsafe { ptr::read_unaligned(self.data.as_ptr().cast()) }
    }

    pub fn flow(&self) -> Option<FlowData> {
        if self.layer() != LAYER_FLOW {
            return None;
        }
        let e = self.endpoint();
        Some(FlowData {
            endpoint_id: e.endpoint_id,
            parent_endpoint_id: e.parent_endpoint_id,
            pid: e.process_id,
            local: to_sockaddr(&e.local_addr, e.local_port),
            remote: to_sockaddr(&e.remote_addr, e.remote_port),
            protocol: e.protocol,
        })
    }

    pub fn socket(&self) -> Option<SocketData> {
        if self.layer() != LAYER_SOCKET {
            return None;
        }
        let e = self.endpoint();
        Some(SocketData {
            pid: e.process_id,
            local: to_sockaddr(&e.local_addr, e.local_port),
            remote: to_sockaddr(&e.remote_addr, e.remote_port),
            protocol: e.protocol,
        })
    }
}

/// WinDivert stores addresses as `UINT32[4]` in host byte order with
/// `addr[3]` the most significant word; IPv4 is mapped as `::ffff:a.b.c.d`
/// (`addr[3] == 0, addr[2] == 0, addr[1] == 0xffff, addr[0] == ipv4`).
fn to_ip(addr: &[u32; 4]) -> IpAddr {
    let v6 = Ipv6Addr::from(
        (u128::from(addr[3]) << 96)
            | (u128::from(addr[2]) << 64)
            | (u128::from(addr[1]) << 32)
            | u128::from(addr[0]),
    );
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

fn to_sockaddr(addr: &[u32; 4], port: u16) -> SocketAddr {
    SocketAddr::new(to_ip(addr), port)
}

type RawHandle = *mut c_void;
const INVALID_HANDLE_VALUE: RawHandle = -1isize as RawHandle;

// Linked via build.rs (`cargo:rustc-link-lib=dylib=WinDivert`).
extern "C" {
    fn WinDivertOpen(filter: *const c_char, layer: u32, priority: i16, flags: u64) -> RawHandle;
    fn WinDivertRecv(
        handle: RawHandle,
        packet: *mut c_void,
        packet_len: u32,
        recv_len: *mut u32,
        addr: *mut Address,
    ) -> i32;
    fn WinDivertSend(
        handle: RawHandle,
        packet: *const c_void,
        packet_len: u32,
        send_len: *mut u32,
        addr: *const Address,
    ) -> i32;
    fn WinDivertShutdown(handle: RawHandle, how: u32) -> i32;
    fn WinDivertClose(handle: RawHandle) -> i32;
    fn WinDivertHelperCalcChecksums(
        packet: *mut c_void,
        packet_len: u32,
        addr: *mut Address,
        flags: u64,
    ) -> i32;
    fn WinDivertHelperCompileFilter(
        filter: *const c_char,
        layer: u32,
        object: *mut c_char,
        obj_len: u32,
        error_str: *mut *const c_char,
        error_pos: *mut u32,
    ) -> i32;
}

/// Validates `filter` for `layer` without opening a handle (no admin or
/// driver needed). `Err` carries WinDivert's message and position.
pub fn check_filter(filter: &str, layer: Layer) -> Result<(), String> {
    let f = CString::new(filter).map_err(|_| "filter contains NUL".to_string())?;
    let mut err: *const c_char = ptr::null();
    let mut pos = 0u32;
    // SAFETY: `f` is NUL-terminated and outlives the call; a null object
    // buffer only validates; `err`/`pos` are valid out-pointers.
    let ok = unsafe {
        WinDivertHelperCompileFilter(
            f.as_ptr(),
            layer.raw(),
            ptr::null_mut(),
            0,
            &mut err,
            &mut pos,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let msg = if err.is_null() {
        "invalid filter".to_string()
    } else {
        // SAFETY: WinDivert returns a pointer to a static NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned()
    };
    Err(format!("{msg} at {pos}"))
}

/// An open WinDivert handle. Closed on drop.
#[derive(Debug)]
pub struct Handle {
    raw: RawHandle,
}

// SAFETY: a WinDivert handle is a kernel device handle; WinDivert documents
// concurrent WinDivertRecv/WinDivertSend from multiple threads on one handle
// as supported, and Handle has no interior state beyond the raw value.
unsafe impl Send for Handle {}
// SAFETY: see `Send` above; all methods take `&self` and only pass the handle
// to thread-safe WinDivert calls.
unsafe impl Sync for Handle {}

fn len_u32(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

impl Handle {
    pub fn open(filter: &str, layer: Layer, priority: i16, flags: u64) -> io::Result<Handle> {
        let filter =
            CString::new(filter).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `filter` is a valid NUL-terminated string that outlives the
        // call; the other arguments are plain integers.
        let raw = unsafe { WinDivertOpen(filter.as_ptr(), layer.raw(), priority, flags) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Handle { raw })
    }

    /// Receives one packet (or event). For the Flow and Socket layers, which
    /// carry no packet data, pass an empty `buf`.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut addr = Address::default();
        let mut got = 0u32;
        let pkt = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: `pkt` is null or points to `buf.len()` writable bytes; `got`
        // and `addr` are valid for writes for the duration of the call; `addr`
        // has the exact WINDIVERT_ADDRESS layout (80 bytes, asserted).
        let ok = unsafe { WinDivertRecv(self.raw, pkt, len_u32(buf.len())?, &mut got, &mut addr) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((got as usize, addr))
    }

    pub fn send(&self, pkt: &[u8], addr: &Address) -> io::Result<()> {
        let mut sent = 0u32;
        // SAFETY: `pkt` points to `pkt.len()` readable bytes and `addr` to a
        // valid WINDIVERT_ADDRESS; WinDivert only reads them. `sent` is valid
        // for writes.
        let ok = unsafe {
            WinDivertSend(
                self.raw,
                pkt.as_ptr().cast(),
                len_u32(pkt.len())?,
                &mut sent,
                addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Shuts down recv and send; blocked and future `recv` calls fail.
    pub fn shutdown(&self) {
        // SAFETY: `self.raw` is a valid open handle until drop.
        unsafe {
            WinDivertShutdown(self.raw, SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.raw` was returned by WinDivertOpen and is closed
        // exactly once, here.
        unsafe {
            WinDivertClose(self.raw);
        }
    }
}

/// Recomputes the IP/TCP/UDP/ICMP checksums of a raw packet in place.
pub fn calc_checksums(pkt: &mut [u8]) {
    let Ok(len) = len_u32(pkt.len()) else { return };
    // SAFETY: `pkt` points to `len` writable bytes; a null address is
    // permitted by the API; the helper parses within `len` bytes only.
    unsafe {
        WinDivertHelperCalcChecksums(pkt.as_mut_ptr().cast(), len, ptr::null_mut(), 0);
    }
}

/// Like [`calc_checksums`], but also sets the IP/TCP/UDP checksum-valid
/// flags in `addr`, as WinDivert recommends before reinjecting a modified
/// packet. Returns `false` if the helper failed.
pub fn calc_checksums_addr(pkt: &mut [u8], addr: &mut Address) -> bool {
    let Ok(len) = len_u32(pkt.len()) else {
        return false;
    };
    // SAFETY: `pkt` points to `len` writable bytes and `addr` to a valid,
    // writable WINDIVERT_ADDRESS; the helper parses within `len` bytes only.
    unsafe { WinDivertHelperCalcChecksums(pkt.as_mut_ptr().cast(), len, addr, 0) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4_to_words(ip: Ipv4Addr) -> [u32; 4] {
        [u32::from(ip), 0xffff, 0, 0]
    }

    #[test]
    fn address_is_80_bytes() {
        assert_eq!(size_of::<Address>(), 80);
    }

    #[test]
    fn outbound_round_trips() {
        let mut a = Address::default();
        assert!(!a.outbound());
        a.set_outbound(true);
        assert!(a.outbound());
        assert_eq!(a.bits, 1 << 17);
        assert!(!a.loopback() && !a.sniffed() && !a.ipv6());
        a.set_outbound(false);
        assert!(!a.outbound());
        assert_eq!(a.bits, 0);
    }

    #[test]
    fn layer_and_event_decode() {
        let a = Address {
            bits: (EVENT_SOCKET_CONNECT as u32) << 8 | LAYER_SOCKET as u32 | BIT_OUTBOUND,
            ..Default::default()
        };
        assert_eq!(a.layer(), LAYER_SOCKET);
        assert_eq!(a.event(), EVENT_SOCKET_CONNECT);
        assert!(a.outbound());
        assert!(a.flow().is_none());
        assert!(a.socket().is_some());
    }

    #[test]
    fn socket_data_decodes_mapped_ipv4() {
        let raw = RawEndpoint {
            endpoint_id: 1,
            parent_endpoint_id: 2,
            process_id: 1234,
            local_addr: ipv4_to_words(Ipv4Addr::new(192, 168, 1, 5)),
            remote_addr: ipv4_to_words(Ipv4Addr::new(1, 1, 1, 1)),
            local_port: 50000,
            remote_port: 80,
            protocol: 6,
        };
        let mut a = Address {
            bits: LAYER_SOCKET as u32,
            ..Default::default()
        };
        // SAFETY: RawEndpoint fits in the 64-byte data area (asserted);
        // write_unaligned has no alignment requirement.
        unsafe { ptr::write_unaligned(a.data.as_mut_ptr().cast(), raw) };
        let s = a.socket().unwrap();
        assert_eq!(s.pid, 1234);
        assert_eq!(s.local, "192.168.1.5:50000".parse().unwrap());
        assert_eq!(s.remote, "1.1.1.1:80".parse().unwrap());
        assert_eq!(s.protocol, 6);
    }

    #[test]
    fn ipv6_decodes() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v = u128::from(ip);
        let words = [
            v as u32,
            (v >> 32) as u32,
            (v >> 64) as u32,
            (v >> 96) as u32,
        ];
        assert_eq!(to_ip(&words), IpAddr::V6(ip));
    }
}
