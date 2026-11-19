//! Q2Route Windows service library: WinDivert FFI, Win32 helpers, flow table,
//! TCP NAT redirect, transparent relay and traffic stats.

pub mod classify;
pub mod conns;
pub mod dns_proxy;
pub mod engine;
pub mod flows;
pub mod geo;
pub mod ipc_server;
pub mod nat;
pub mod packet_loop;
pub mod proxy_servers;
pub mod relay;
pub mod stats;
#[cfg(test)]
mod test_util;
pub mod udp_packet;
pub mod udp_relay;
pub mod usage;
pub mod winapi;
pub mod windivert;
