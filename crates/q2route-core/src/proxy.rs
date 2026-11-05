//! Proxy types and (Task 8) clients.

use serde::{Deserialize, Serialize};

/// Result of a proxy connectivity test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProxyTestResult {
    pub tcp_ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}
