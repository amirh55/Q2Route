//! Leak-check probes. Plain sockets (no proxy), so the capture engine routes
//! them like any other app; the verdict comes from `q2route_core::leak`.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use q2route_core::decide::Route;
use q2route_core::ipc::{ConnInfo, Request, Response};
use q2route_core::leak::{
    http_get, ip_api_path, parse_ip_api, parse_resolver_txt, verdict, IpInfo, LeakError,
    LeakInputs, Level, Probe, ProbeOutcome, ProbeRoute, Verdict, IPV6_HOST, IPV6_PATH, IP_API_HOST,
    RESOLVER_TXT_NAME,
};
use tokio::net::TcpStream;

use crate::client::Client;

const STEP_TIMEOUT: Duration = Duration::from_secs(8);
const LOOKUP_TRIES: u32 = 3;
const LOOKUP_GAP: Duration = Duration::from_millis(300);

/// A leak check running on its own thread; `poll` is non-blocking.
pub struct LeakCheck {
    result: Arc<Mutex<Option<Verdict>>>,
}

impl LeakCheck {
    pub fn start(client: &Client) -> LeakCheck {
        let result = Arc::new(Mutex::new(None));
        let (out, client) = (result.clone(), client.clone());
        let spawned = std::thread::Builder::new()
            .name("q2route-leak".into())
            .spawn(move || {
                let v = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(run(client)),
                    Err(e) => cant_tell(format!("Can't tell: {e}")),
                };
                *out.lock().expect("leak result lock") = Some(v);
            });
        if let Err(e) = spawned {
            *result.lock().expect("leak result lock") = Some(cant_tell(format!("Can't tell: {e}")));
        }
        LeakCheck { result }
    }

    /// `Some` once the check is done.
    pub fn poll(&self) -> Option<Verdict> {
        self.result.lock().expect("leak result lock").clone()
    }

    pub fn running(&self) -> bool {
        self.poll().is_none()
    }
}

fn cant_tell(headline: String) -> Verdict {
    Verdict {
        level: Level::CantTell,
        headline,
        lines: Vec::new(),
    }
}

/// Route of the connection `pid`/`local`, with its group's name.
/// `groups` are (id, name) pairs.
pub fn find_route(
    conns: &[ConnInfo],
    pid: u32,
    local: SocketAddr,
    groups: &[(String, String)],
) -> ProbeRoute {
    let Some(c) = conns.iter().find(|c| c.pid == pid && c.local == local) else {
        return ProbeRoute::Unknown;
    };
    let group = match &c.group_id {
        None => "no group".to_string(),
        Some(id) => groups
            .iter()
            .find(|(gid, _)| gid == id)
            .map_or_else(|| id.clone(), |(_, n)| n.clone()),
    };
    match c.route {
        Route::Proxy(_) => ProbeRoute::Proxy { group },
        Route::Block => ProbeRoute::Block { group },
        Route::Direct => ProbeRoute::Direct { group },
    }
}

/// What a probe needs to ask the service where its own socket went.
struct Ctx {
    client: Client,
    groups: Vec<(String, String)>,
}

impl Ctx {
    /// Looks the probe's socket up in the connection table; the service may
    /// list it slightly late, so retry.
    async fn route_of(&self, local: SocketAddr) -> ProbeRoute {
        for i in 0..LOOKUP_TRIES {
            if i > 0 {
                tokio::time::sleep(LOOKUP_GAP).await;
            }
            if let Ok(Response::Connections(conns)) =
                ask(&self.client, Request::GetConnections).await
            {
                let r = find_route(&conns, std::process::id(), local, &self.groups);
                if r != ProbeRoute::Unknown {
                    return r;
                }
            }
        }
        ProbeRoute::Unknown
    }
}

async fn step<T>(f: impl Future<Output = Result<T, LeakError>>) -> Result<T, LeakError> {
    tokio::time::timeout(STEP_TIMEOUT, f)
        .await
        .unwrap_or(Err(LeakError::Timeout))
}

async fn ask(client: &Client, r: Request) -> Result<Response, LeakError> {
    let rx = client.send(r);
    match step(async { rx.await.map_err(|e| LeakError::Io(e.to_string())) }).await? {
        Response::Error(e) => Err(LeakError::Io(e)),
        ok => Ok(ok),
    }
}

/// Result of one probe connection.
struct Fetch<T> {
    /// The TCP connect succeeded.
    connected: bool,
    route: ProbeRoute,
    body: Result<T, LeakError>,
}

/// Connects to `addr` (plain socket), GETs `path`, then (if `ctx` is given)
/// looks up how the service routed that very connection.
async fn fetch_text(addr: SocketAddr, host: &str, path: &str, ctx: Option<&Ctx>) -> Fetch<String> {
    let mut s = match step(async {
        TcpStream::connect(addr)
            .await
            .map_err(|e| LeakError::Io(e.to_string()))
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return Fetch {
                connected: false,
                route: ProbeRoute::Unknown,
                body: Err(e),
            }
        }
    };
    let local = s.local_addr().ok();
    let body = step(http_get(&mut s, host, path)).await;
    // `s` is still open here, so the connection is listed.
    let route = match (ctx, local) {
        (Some(c), Some(l)) => c.route_of(l).await,
        _ => ProbeRoute::Unknown,
    };
    Fetch {
        connected: true,
        route,
        body,
    }
}

async fn fetch_ip_info(
    addr: SocketAddr,
    host: &str,
    path: &str,
    ctx: Option<&Ctx>,
) -> Fetch<IpInfo> {
    let f = fetch_text(addr, host, path, ctx).await;
    Fetch {
        connected: f.connected,
        route: f.route,
        body: f.body.and_then(|b| parse_ip_api(&b)),
    }
}

async fn resolve(host: &str, v6: bool) -> Result<Vec<SocketAddr>, LeakError> {
    let addrs = step(async {
        tokio::net::lookup_host((host, 80))
            .await
            .map_err(|e| LeakError::Io(e.to_string()))
    })
    .await?;
    Ok(addrs.filter(|a| a.is_ipv6() == v6).collect())
}

fn probe_of(f: Fetch<IpInfo>) -> Probe {
    Probe {
        outcome: match f.body {
            Ok(i) => ProbeOutcome::Got(i),
            Err(e) => ProbeOutcome::Failed(e.to_string()),
        },
        route: f.route,
    }
}

fn failed(e: impl ToString) -> Probe {
    Probe {
        outcome: ProbeOutcome::Failed(e.to_string()),
        route: ProbeRoute::Unknown,
    }
}

/// Geolocates `ip` (or the caller when `None`) over a fresh IPv4 connection.
async fn geolocate(ip: Option<IpAddr>, ctx: &Ctx) -> Probe {
    match resolve(IP_API_HOST, false).await {
        Ok(a) if !a.is_empty() => {
            probe_of(fetch_ip_info(a[0], IP_API_HOST, &ip_api_path(ip), Some(ctx)).await)
        }
        Ok(_) => failed("no IPv4 address for ip-api.com"),
        Err(e) => failed(e),
    }
}

async fn dns_probe(ctx: &Ctx) -> Probe {
    let txt = match step(async {
        tokio::task::spawn_blocking(|| query_txt(RESOLVER_TXT_NAME))
            .await
            .map_err(|e| LeakError::Io(e.to_string()))?
            .map_err(LeakError::Io)
    })
    .await
    {
        Ok(t) => t,
        Err(e) => return failed(e),
    };
    match parse_resolver_txt(&txt).0 {
        Some(ip) => geolocate(Some(ip), ctx).await,
        None => failed("resolver address not found in TXT answer"),
    }
}

async fn ipv6_probe(ctx: &Ctx) -> Probe {
    let none = Probe {
        outcome: ProbeOutcome::NoIpv6,
        route: ProbeRoute::Unknown,
    };
    let Some(addr) = resolve(IPV6_HOST, true)
        .await
        .ok()
        .and_then(|a| a.into_iter().next())
    else {
        return none;
    };
    let f = fetch_text(addr, IPV6_HOST, IPV6_PATH, Some(ctx)).await;
    if !f.connected {
        return none;
    }
    let route = f.route;
    let parsed = f.body.and_then(|b| {
        b.trim()
            .parse::<IpAddr>()
            .map_err(|e| LeakError::Parse(e.to_string()))
    });
    match parsed {
        Ok(ip) => Probe {
            // The route that matters is the one of the IPv6 connection itself.
            outcome: geolocate(Some(ip), ctx).await.outcome,
            route,
        },
        // Connected but no answer: only a Direct route makes that a failure.
        Err(e) if matches!(route, ProbeRoute::Direct { .. }) => Probe {
            outcome: ProbeOutcome::Failed(e.to_string()),
            route,
        },
        Err(_) => Probe {
            outcome: ProbeOutcome::NoIpv6,
            route,
        },
    }
}

async fn run(client: Client) -> Verdict {
    let snap = match ask(&client, Request::GetState).await {
        Ok(Response::State(s)) => s,
        _ => return cant_tell("Can't tell: Q2Route service not reachable".into()),
    };
    let groups = snap
        .config
        .groups
        .iter()
        .map(|g| (g.id.clone(), g.name.clone()))
        .collect();
    let ctx = Ctx { client, groups };
    let _ = ask(&ctx.client, Request::FlushDns).await;
    let ipv4 = geolocate(None, &ctx).await;
    let dns = dns_probe(&ctx).await;
    let ipv6 = ipv6_probe(&ctx).await;
    verdict(&LeakInputs {
        running: snap.running,
        ipv4,
        dns,
        ipv6,
    })
}

/// Every string of every TXT record for `name`, bypassing the DNS cache.
#[cfg(windows)]
fn query_txt(name: &str) -> Result<Vec<String>, String> {
    use windows_sys::Win32::NetworkManagement::Dns::{
        DnsFree, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_BYPASS_CACHE, DNS_RECORDW, DNS_TYPE_TEXT,
    };
    let wname: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut list: *mut DNS_RECORDW = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated name; `list` receives an allocation that is
    // only read while alive and released with DnsFree below.
    let status = unsafe {
        DnsQuery_W(
            wname.as_ptr(),
            DNS_TYPE_TEXT,
            DNS_QUERY_BYPASS_CACHE,
            std::ptr::null_mut(),
            &mut list as *mut *mut DNS_RECORDW as *mut _,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("DnsQuery failed ({status})"));
    }
    let mut out = Vec::new();
    let mut rec = list;
    // SAFETY: walking the linked list DnsQuery returned; the TXT payload is
    // valid for records of type DNS_TYPE_TEXT, with `dwStringCount` wide strings.
    unsafe {
        while !rec.is_null() {
            let r = &*rec;
            if r.wType == DNS_TYPE_TEXT {
                let txt = &r.Data.TXT;
                let strings = txt.pStringArray.as_ptr();
                for i in 0..txt.dwStringCount as usize {
                    let p = *strings.add(i);
                    if p.is_null() {
                        continue;
                    }
                    let mut n = 0;
                    while *p.add(n) != 0 {
                        n += 1;
                    }
                    out.push(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
                }
            }
            rec = r.pNext;
        }
        DnsFree(list as *const _, DnsFreeRecordList);
    }
    Ok(out)
}

#[cfg(not(windows))]
fn query_txt(_name: &str) -> Result<Vec<String>, String> {
    Err("DNS TXT query is Windows-only".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use q2route_core::config::Protocol;
    use q2route_core::decide::Route;
    use q2route_core::ipc::ConnInfo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn conn(pid: u32, local: &str, route: Route, group: Option<&str>) -> ConnInfo {
        ConnInfo {
            id: 1,
            proto: Protocol::Tcp,
            pid,
            exe: "q2route.exe".into(),
            local: local.parse().unwrap(),
            dst: "1.2.3.4:80".parse().unwrap(),
            domain: None,
            route,
            group_id: group.map(Into::into),
            reason: "own".into(),
            started_ms: 0,
            ended_ms: None,
            up: None,
            down: None,
        }
    }

    #[test]
    fn route_lookup_matches_own_pid_and_local() {
        let groups = vec![("g1".to_string(), "Work".to_string())];
        let local: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        let conns = vec![
            conn(1, "10.0.0.2:5555", Route::Direct, None),
            conn(7, "10.0.0.2:5556", Route::Direct, None),
            conn(7, "10.0.0.2:5555", Route::Proxy("p".into()), Some("g1")),
        ];
        assert_eq!(
            find_route(&conns, 7, local, &groups),
            ProbeRoute::Proxy {
                group: "Work".into()
            }
        );
        let b = vec![conn(7, "10.0.0.2:5555", Route::Block, Some("zz"))];
        assert_eq!(
            find_route(&b, 7, local, &groups),
            ProbeRoute::Block { group: "zz".into() }
        );
        let d = vec![conn(7, "10.0.0.2:5555", Route::Direct, None)];
        assert_eq!(
            find_route(&d, 7, local, &groups),
            ProbeRoute::Direct {
                group: "no group".into()
            }
        );
        assert_eq!(find_route(&d, 8, local, &groups), ProbeRoute::Unknown);
        assert_eq!(find_route(&[], 7, local, &groups), ProbeRoute::Unknown);
    }

    #[tokio::test]
    async fn probe_against_local_http_server() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b).await;
            let body = r#"{"status":"success","country":"Germany","countryCode":"DE","isp":"Hetzner","query":"5.6.7.8"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        });
        let f = fetch_ip_info(addr, "ip-api.com", "/json/", None).await;
        assert!(f.connected);
        let info = f.body.unwrap();
        assert_eq!(info.ip, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(info.country_code, "DE");
    }

    #[tokio::test]
    async fn refused_connect_is_not_connected() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let f = fetch_ip_info(addr, "ip-api.com", "/json/", None).await;
        assert!(!f.connected);
        assert!(f.body.is_err());
        assert_eq!(f.route, ProbeRoute::Unknown);
    }
}
