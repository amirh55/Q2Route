//! Q2Route Windows service library: WinDivert FFI, Win32 helpers, flow table,
//! TCP NAT redirect, transparent relay and traffic stats.

pub mod classify;
pub mod engine;
pub mod flows;
pub mod ipc_server;
pub mod nat;
pub mod packet_loop;
pub mod relay;
pub mod stats;
pub mod winapi;
pub mod windivert;
