//! Auto-detected proxy server names: the host names the local proxy client
//! (xray / v2ray / sing-box, usually started by v2rayN) connects to. Their
//! DNS queries are resolved directly ([`crate::dns_proxy::bootstrap_direct`]),
//! since resolving them through the proxy would need the proxy to be up.
//!
//! Only the engine's exclusion refresh reads files (off the packet path).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use serde_json::Value;

/// Nesting followed inside an outbound's `settings` (configs are shallow).
const MAX_DEPTH: usize = 16;
/// Larger files are not proxy client configs; never read them whole.
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// Host names (not IP literals) of every outbound's server in a v2ray /
/// xray / sing-box JSON config, lowercased and deduplicated (first-seen
/// order). Collected: string values of `address` / `server` keys anywhere
/// inside each outbound's `settings`, and sing-box's top-level `server`;
/// never SNI / host header values. Invalid JSON gives an empty list.
pub fn server_hostnames(json: &str) -> Vec<String> {
    let json = json.strip_prefix('\u{feff}').unwrap_or(json);
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return out;
    };
    let Some(outbounds) = v.get("outbounds").and_then(Value::as_array) else {
        return out;
    };
    for ob in outbounds {
        if let Some(settings) = ob.get("settings") {
            collect(settings, &mut out, 0);
        }
        if let Some(Value::String(s)) = ob.get("server") {
            push_host(s, &mut out);
        }
    }
    out
}

fn collect(v: &Value, out: &mut Vec<String>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x {
                    Value::String(s) if k == "address" || k == "server" => push_host(s, out),
                    _ => collect(x, out, depth + 1),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect(x, out, depth + 1)),
        _ => {}
    }
}

/// Adds `s` if it is a host name: not empty, not an IP literal, has a dot.
fn push_host(s: &str, out: &mut Vec<String>) {
    let h = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let literal = h.trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() || !h.contains('.') || literal.parse::<IpAddr>().is_ok() {
        return;
    }
    if !out.contains(&h) {
        out.push(h);
    }
}

/// `config.json` files a running proxy client may use: next to the exe and
/// in `binConfigs` of the exe's dir and up to 2 ancestors (v2rayN layout:
/// `C:\v2rayN\bin\xray\xray.exe` -> `C:\v2rayN\binConfigs\config.json`).
/// Existing files only, deduplicated.
pub fn find_configs(proxy_exes: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for exe in proxy_exes {
        let Some(dir) = exe.parent() else { continue };
        let candidates = std::iter::once(dir.join("config.json")).chain(
            dir.ancestors()
                .take(3)
                .map(|a| a.join("binConfigs").join("config.json")),
        );
        for c in candidates {
            if c.is_file() && !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// Server names per config file, re-read only when its mtime changes.
#[derive(Default)]
pub struct ServerCache {
    files: HashMap<PathBuf, (SystemTime, Vec<String>)>,
}

impl ServerCache {
    /// The server names of `configs` (sorted, deduplicated). A file is read
    /// only when its mtime changed since the last call; a file that cannot
    /// be read keeps its last result; files no longer listed are forgotten.
    ///
    /// `None` (keep the last detected list) when no config is listed, e.g.
    /// while the proxy client restarts and nothing listens, or none of them
    /// could be read: forgetting the servers then would send their lookups
    /// through the proxy that is coming up.
    pub fn refresh(&mut self, configs: &[PathBuf]) -> Option<Vec<String>> {
        if configs.is_empty() {
            return None;
        }
        self.files.retain(|p, _| configs.contains(p));
        for path in configs {
            let Ok(meta) = std::fs::metadata(path) else {
                continue;
            };
            let Ok(mtime) = meta.modified() else { continue };
            if self.files.get(path).is_some_and(|(t, _)| *t == mtime) {
                continue;
            }
            if meta.len() > MAX_CONFIG_BYTES {
                self.files.insert(path.clone(), (mtime, Vec::new()));
                continue;
            }
            match std::fs::read(path) {
                Ok(bytes) => {
                    let names = server_hostnames(&String::from_utf8_lossy(&bytes));
                    self.files.insert(path.clone(), (mtime, names));
                }
                Err(e) => tracing::debug!("cannot read {}: {e}", path.display()),
            }
        }
        if self.files.is_empty() {
            return None;
        }
        let mut all: Vec<String> = self.files.values().flat_map(|(_, n)| n.clone()).collect();
        all.sort();
        all.dedup();
        Some(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_v2rayn_shape() {
        let json = r#"{
          "log": {"loglevel": "warning"},
          "inbounds": [{"tag": "socks", "port": 10808, "listen": "127.0.0.1",
                        "protocol": "socks", "settings": {"address": "127.0.0.1"}}],
          "outbounds": [
            {"tag": "proxy", "protocol": "vless",
             "settings": {"address": "VPN.Example.com", "port": 443, "id": "x",
                          "encryption": "none"},
             "streamSettings": {"network": "ws", "security": "tls",
                                "tlsSettings": {"serverName": "fake.sni.com"},
                                "wsSettings": {"host": "fake.host.com", "path": "/"}}},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}}
          ]
        }"#;
        assert_eq!(server_hostnames(json), ["vpn.example.com"]);
    }

    #[test]
    fn vnext_form() {
        let json = r#"{"outbounds": [{"protocol": "vmess", "settings": {"vnext": [
            {"address": "a.example.com", "port": 443, "users": []},
            {"address": "b.example.com", "port": 443, "users": []},
            {"address": "a.example.com", "port": 8443, "users": []}
        ]}}]}"#;
        assert_eq!(server_hostnames(json), ["a.example.com", "b.example.com"]);
    }

    #[test]
    fn servers_form() {
        let json = r#"{"outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [
            {"address": "ss.example.net", "port": 8388, "method": "aes-256-gcm"}
        ]}}, {"protocol": "socks", "settings": {"servers": [{"address": "socks.example.org"}]}}]}"#;
        assert_eq!(
            server_hostnames(json),
            ["ss.example.net", "socks.example.org"]
        );
    }

    #[test]
    fn sing_box_form() {
        let json = r#"{"outbounds": [
            {"type": "vless", "tag": "proxy", "server": "sb.example.org", "server_port": 443,
             "tls": {"enabled": true, "server_name": "fake.sni.com"}},
            {"type": "direct", "tag": "direct"}
        ]}"#;
        assert_eq!(server_hostnames(json), ["sb.example.org"]);
    }

    #[test]
    fn ip_literals_and_junk_excluded() {
        let json = r#"{"outbounds": [{"settings": {"vnext": [
            {"address": "203.0.113.7"}, {"address": "2001:db8::1"}, {"address": "[2001:db8::2]"},
            {"address": ""}, {"address": "localhost"}, {"address": 5}, {"server": null},
            {"address": "ok.example.com."}
        ]}, "server": "198.51.100.1"}]}"#;
        assert_eq!(server_hostnames(json), ["ok.example.com"]);
    }

    #[test]
    fn bom_and_invalid_json() {
        let json = "\u{feff}{\"outbounds\": [{\"settings\": {\"address\": \"bom.example.com\"}}]}";
        assert_eq!(server_hostnames(json), ["bom.example.com"]);
        assert!(server_hostnames("\u{feff}{not json").is_empty());
        assert!(server_hostnames("").is_empty());
        assert!(server_hostnames(r#"{"outbounds": 5}"#).is_empty());
        assert!(server_hostnames(r#"[1, 2]"#).is_empty());
        assert!(server_hostnames(r#"{"outbounds": [{"settings": 7}, null, "x"]}"#).is_empty());
    }

    #[test]
    fn find_configs_v2rayn_layout() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("v2rayN");
        let xray_dir = root.join("bin").join("xray");
        std::fs::create_dir_all(&xray_dir).unwrap();
        std::fs::create_dir_all(root.join("binConfigs")).unwrap();
        let active = root.join("binConfigs").join("config.json");
        std::fs::write(&active, "{}").unwrap();
        let xray = xray_dir.join("xray.exe");
        let gui = root.join("v2rayN.exe");
        // Not a config location: two levels too far up.
        std::fs::create_dir_all(d.path().join("binConfigs")).unwrap();
        std::fs::write(d.path().join("binConfigs").join("config.json"), "{}").unwrap();
        assert_eq!(
            find_configs(std::slice::from_ref(&xray)),
            std::slice::from_ref(&active)
        );
        std::fs::remove_dir_all(d.path().join("binConfigs")).unwrap();
        // Same file from two exes: once.
        assert_eq!(
            find_configs(&[xray.clone(), gui.clone()]),
            std::slice::from_ref(&active)
        );
        // A config next to the exe.
        let local = xray_dir.join("config.json");
        std::fs::write(&local, "{}").unwrap();
        assert_eq!(find_configs(&[xray]), [local, active]);
        // Nothing there.
        assert!(find_configs(&[d.path().join("nowhere").join("x.exe")]).is_empty());
        assert!(find_configs(&[]).is_empty());
    }

    #[test]
    fn cache_rereads_only_on_mtime_change() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        let cfg =
            |host: &str| format!(r#"{{"outbounds": [{{"settings": {{"address": "{host}"}}}}]}}"#);
        let set_mtime = |t: SystemTime| {
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            f.set_modified(t).unwrap();
        };
        std::fs::write(&p, cfg("one.example.com")).unwrap();
        let t0 = std::fs::metadata(&p).unwrap().modified().unwrap();
        let mut c = ServerCache::default();
        let configs = vec![p.clone()];
        let one = Some(vec!["one.example.com".to_string()]);
        assert_eq!(c.refresh(&configs), one);
        // Same mtime: not re-read.
        std::fs::write(&p, cfg("two.example.com")).unwrap();
        set_mtime(t0);
        assert_eq!(c.refresh(&configs), one);
        // New mtime: re-read.
        set_mtime(t0 + std::time::Duration::from_secs(10));
        assert_eq!(
            c.refresh(&configs),
            Some(vec!["two.example.com".to_string()])
        );
        // Broken file: no names (a real replacement), no panic.
        std::fs::write(&p, "{broken").unwrap();
        set_mtime(t0 + std::time::Duration::from_secs(20));
        assert_eq!(c.refresh(&configs), Some(vec![]));
        // Nothing listed or nothing readable: keep the last list.
        assert_eq!(c.refresh(&[]), None);
        assert_eq!(c.refresh(&[d.path().join("missing.json")]), None);
    }

    /// The D7 scenario: the proxy client restarts (no listener for a while).
    #[test]
    fn cache_keeps_list_while_no_proxy_client_runs() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("v2rayN");
        let xray_dir = root.join("bin").join("xray");
        std::fs::create_dir_all(&xray_dir).unwrap();
        std::fs::create_dir_all(root.join("binConfigs")).unwrap();
        let p = root.join("binConfigs").join("config.json");
        let cfg =
            |host: &str| format!(r#"{{"outbounds": [{{"settings": {{"address": "{host}"}}}}]}}"#);
        std::fs::write(&p, cfg("vpn.example.com")).unwrap();
        let t0 = std::fs::metadata(&p).unwrap().modified().unwrap();
        let xray = vec![xray_dir.join("xray.exe")];
        let mut c = ServerCache::default();
        // 1. A config: its names.
        assert_eq!(
            c.refresh(&find_configs(&xray)),
            Some(vec!["vpn.example.com".to_string()])
        );
        // 2. No proxy client exe: the list is kept (no change).
        assert_eq!(c.refresh(&find_configs(&[])), None);
        // 3. The client is back with a changed config: the new names.
        std::fs::write(&p, cfg("new.example.com")).unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(t0 + std::time::Duration::from_secs(10))
            .unwrap();
        drop(f);
        assert_eq!(
            c.refresh(&find_configs(&xray)),
            Some(vec!["new.example.com".to_string()])
        );
    }
}
