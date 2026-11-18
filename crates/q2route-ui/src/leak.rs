//! Leak-check probes. Plain sockets (no proxy), so the capture engine routes
//! them like any other app; the verdict comes from `q2route_core::leak`.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use q2route_core::decide::Route;
use q2route_core::ipc::{ConnInfo, Request, Response, StateSnapshot};
use q2route_core::leak::{
    http_get, ip_api_path, parse_ip_api, parse_resolver_txt, verdict, IpInfo, LeakError,
    LeakInputs, Level, Probe, ProbeOutcome, ProbeRoute, Verdict, IPV6_HOST, IPV6_PATH, IP_API_HOST,
    RESOLVER_TXT_NAME,
};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::client::Client;

const STEP_TIMEOUT: Duration = Duration::from_secs(8);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Every probe is cut off this long after the check starts, so a verdict is
/// built from what finished well before `OVERALL_TIMEOUT`.
const PROBE_BUDGET: Duration = Duration::from_secs(25);
const LOOKUP_TRIES: u32 = 3;
const LOOKUP_GAP: Duration = Duration::from_millis(300);

/// A leak check running on its own thread; `poll` is non-blocking.
pub struct LeakCheck {
    result: Arc<Mutex<Option<Verdict>>>,
}

impl LeakCheck {
    pub fn start(client: &Client) -> LeakCheck {
        let client = client.clone();
        Self::start_with(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return cant_tell(format!("Can't tell: {e}")),
            };
            let v = rt
                .block_on(tokio::time::timeout(OVERALL_TIMEOUT, run(&client)))
                .unwrap_or_else(|_| cant_tell("Can't tell: the check timed out".into()));
            // A hung blocking DNS call must not delay delivery of `v`.
            rt.shutdown_background();
            v
        })
    }

    fn start_with(runner: impl FnOnce() -> Verdict + Send + 'static) -> LeakCheck {
        let result = Arc::new(Mutex::new(None));
        let out = result.clone();
        let spawned = std::thread::Builder::new()
            .name("q2route-leak".into())
            .spawn(move || {
                let v = std::panic::catch_unwind(std::panic::AssertUnwindSafe(runner))
                    .unwrap_or_else(|_| {
                        cant_tell("Can't tell: the check failed unexpectedly".into())
                    });
                *lock(&out) = Some(v);
            });
        if let Err(e) = spawned {
            *lock(&result) = Some(cant_tell(format!("Can't tell: {e}")));
        }
        LeakCheck { result }
    }

    /// `Some` once the check is done.
    pub fn poll(&self) -> Option<Verdict> {
        lock(&self.result).clone()
    }

    pub fn running(&self) -> bool {
        self.poll().is_none()
    }
}

fn lock(m: &Mutex<Option<Verdict>>) -> std::sync::MutexGuard<'_, Option<Verdict>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn cant_tell(headline: String) -> Verdict {
    Verdict {
        level: Level::CantTell,
        headline,
        lines: Vec::new(),
    }
}

/// Route of this process's connection from local port `local.port()` to
/// `remote`, with its group's name. `groups` are (id, name) pairs.
///
/// Relayed (proxied) connections are recorded with `local = remote_ip:port`
/// (the NAT reflects the packet), packet-layer Direct/Block decisions with the
/// real local address, so only the local port is compared.
pub fn find_route(
    conns: &[ConnInfo],
    pid: u32,
    local: SocketAddr,
    remote: SocketAddr,
    groups: &[(String, String)],
) -> ProbeRoute {
    // Prefer a live entry, then the most recently started one.
    let best = conns
        .iter()
        .filter(|c| c.pid == pid && c.dst == remote && c.local.port() == local.port())
        .max_by_key(|c| (c.ended_ms.is_none(), c.started_ms));
    let Some(c) = best else {
        return ProbeRoute::Unknown;
    };
    let name = c.group_id.as_ref().map(|id| {
        groups
            .iter()
            .find(|(gid, _)| gid == id)
            .map_or_else(|| id.clone(), |(_, n)| n.clone())
    });
    match c.route {
        Route::Proxy(_) => ProbeRoute::Proxy {
            group: name.unwrap_or_else(|| "no group".into()),
        },
        Route::Block => ProbeRoute::Block {
            group: name.unwrap_or_else(|| "no group".into()),
        },
        Route::Direct => ProbeRoute::Direct { group: name },
    }
}

/// The three probes' results.
struct Probes {
    ipv4: Probe,
    dns: Probe,
    dns_subnet: Option<(IpAddr, Probe)>,
    ipv6: Probe,
}

/// What `run` needs from the outside world, so tests can run it offline.
trait Env {
    async fn state(&self) -> Option<StateSnapshot>;
    async fn flush_dns(&self);
    /// Sends the probes: the check's only internet traffic.
    async fn probe(&self, groups: Vec<(String, String)>, deadline: Instant) -> Probes;
}

impl Env for Client {
    async fn state(&self) -> Option<StateSnapshot> {
        match ask(self, Request::GetState).await {
            Ok(Response::State(s)) => Some(s),
            _ => None,
        }
    }

    async fn flush_dns(&self) {
        let _ = ask(self, Request::FlushDns).await;
    }

    async fn probe(&self, groups: Vec<(String, String)>, deadline: Instant) -> Probes {
        let ctx = Ctx {
            client: self.clone(),
            groups,
        };
        // Each probe is capped, so one hung probe keeps the others' results.
        let (ipv4, (dns, dns_subnet), ipv6) = tokio::join!(
            capped(deadline, failed("timed out"), geolocate(None, &ctx)),
            capped(deadline, (failed("timed out"), None), dns_probe(&ctx)),
            capped(deadline, failed("timed out"), ipv6_probe(&ctx)),
        );
        Probes {
            ipv4,
            dns,
            dns_subnet,
            ipv6,
        }
    }
}

async fn capped<T>(deadline: Instant, timed_out: T, f: impl Future<Output = T>) -> T {
    tokio::time::timeout_at(deadline, f)
        .await
        .unwrap_or(timed_out)
}

/// What a probe needs to ask the service where its own socket went.
struct Ctx {
    client: Client,
    groups: Vec<(String, String)>,
}

impl Ctx {
    /// Looks the probe's socket up in the connection table; the service may
    /// list it slightly late, so retry.
    async fn route_of(&self, local: SocketAddr, remote: SocketAddr) -> ProbeRoute {
        for i in 0..LOOKUP_TRIES {
            if i > 0 {
                tokio::time::sleep(LOOKUP_GAP).await;
            }
            if let Ok(Response::Connections(conns)) =
                ask(&self.client, Request::GetConnections).await
            {
                let r = find_route(&conns, std::process::id(), local, remote, &self.groups);
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
        (Some(c), Some(l)) => c.route_of(l, addr).await,
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
            Err(e) => ProbeOutcome::from_error(&e),
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

/// The resolver's geolocation, and the ECS subnet's when the answer has one.
async fn dns_probe(ctx: &Ctx) -> (Probe, Option<(IpAddr, Probe)>) {
    let txt = match step(async {
        tokio::task::spawn_blocking(|| query_txt(RESOLVER_TXT_NAME))
            .await
            .map_err(|e| LeakError::Io(e.to_string()))?
            .map_err(LeakError::Io)
    })
    .await
    {
        Ok(t) => t,
        Err(e) => return (failed(e), None),
    };
    let (ip, ecs) = parse_resolver_txt(&txt);
    let resolver = async {
        match ip {
            Some(ip) => geolocate(Some(ip), ctx).await,
            None => failed("resolver address not found in TXT answer"),
        }
    };
    let subnet = async {
        match ecs {
            Some(net) => Some((net, geolocate(Some(net), ctx).await)),
            None => None,
        }
    };
    tokio::join!(resolver, subnet)
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

async fn run(env: &impl Env) -> Verdict {
    let deadline = Instant::now() + PROBE_BUDGET;
    let Some(snap) = env.state().await else {
        return cant_tell("Can't tell: Q2Route service not reachable".into());
    };
    if !snap.running {
        // Everything would go direct: send nothing, show nothing.
        return cant_tell("Can't tell: Q2Route is stopped (everything goes direct)".into());
    }
    let groups = snap
        .config
        .groups
        .iter()
        .map(|g| (g.id.clone(), g.name.clone()))
        .collect();
    env.flush_dns().await;
    // All three run concurrently; when IPv4 is routed Direct, `verdict`
    // drops the DNS/IPv6 lines.
    let p = env.probe(groups, deadline).await;
    verdict(&LeakInputs {
        running: snap.running,
        ipv4: p.ipv4,
        dns: p.dns,
        dns_subnet: p.dns_subnet,
        ipv6: p.ipv6,
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
    let mut out = Vec::new();
    if status == 0 {
        let mut rec = list;
        // SAFETY: walking the linked list DnsQuery returned; the TXT payload is
        // valid for records of type DNS_TYPE_TEXT, with `dwStringCount` wide
        // strings. The string array is a trailing variable-length array, so
        // its pointer is derived from the raw record pointer, not a reference.
        unsafe {
            while !rec.is_null() {
                if (*rec).wType == DNS_TYPE_TEXT {
                    let count = (*rec).Data.TXT.dwStringCount as usize;
                    let strings =
                        std::ptr::addr_of!((*rec).Data.TXT.pStringArray) as *const *mut u16;
                    for i in 0..count {
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
                rec = (*rec).pNext;
            }
        }
    }
    if !list.is_null() {
        // SAFETY: `list` came from DnsQuery_W and is freed exactly once.
        unsafe { DnsFree(list as *const _, DnsFreeRecordList) };
    }
    if status != 0 {
        return Err(format!("DnsQuery failed ({status})"));
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
    use q2route_core::config::{Config, Protocol};
    use q2route_core::decide::Route;
    use q2route_core::ipc::ConnInfo;
    use std::cell::Cell;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DST: &str = "1.2.3.4:80";

    fn conn_to(pid: u32, local: &str, dst: &str, route: Route, group: Option<&str>) -> ConnInfo {
        ConnInfo {
            id: 1,
            proto: Protocol::Tcp,
            pid,
            exe: "q2route.exe".into(),
            local: local.parse().unwrap(),
            dst: dst.parse().unwrap(),
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

    fn conn(pid: u32, local: &str, route: Route, group: Option<&str>) -> ConnInfo {
        conn_to(pid, local, DST, route, group)
    }

    fn dst() -> SocketAddr {
        DST.parse().unwrap()
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
            find_route(&conns, 7, local, dst(), &groups),
            ProbeRoute::Proxy {
                group: "Work".into()
            }
        );
        let b = vec![conn(7, "10.0.0.2:5555", Route::Block, Some("zz"))];
        assert_eq!(
            find_route(&b, 7, local, dst(), &groups),
            ProbeRoute::Block { group: "zz".into() }
        );
        let d = vec![conn(7, "10.0.0.2:5555", Route::Direct, None)];
        assert_eq!(
            find_route(&d, 7, local, dst(), &groups),
            ProbeRoute::Direct { group: None }
        );
        assert_eq!(
            find_route(&d, 8, local, dst(), &groups),
            ProbeRoute::Unknown
        );
        assert_eq!(
            find_route(&[], 7, local, dst(), &groups),
            ProbeRoute::Unknown
        );
    }

    #[test]
    fn route_lookup_finds_relayed_entry() {
        // The relay records `local = dst_ip:app_port`.
        let groups = vec![("g1".to_string(), "Work".to_string())];
        let local: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        let conns = vec![conn(
            7,
            "1.2.3.4:5555",
            Route::Proxy("p".into()),
            Some("g1"),
        )];
        assert_eq!(
            find_route(&conns, 7, local, dst(), &groups),
            ProbeRoute::Proxy {
                group: "Work".into()
            }
        );
    }

    #[test]
    fn route_lookup_finds_packet_layer_direct() {
        let groups = vec![("g2".to_string(), "Home".to_string())];
        let local: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        let conns = vec![conn(7, "10.0.0.2:5555", Route::Direct, Some("g2"))];
        assert_eq!(
            find_route(&conns, 7, local, dst(), &groups),
            ProbeRoute::Direct {
                group: Some("Home".into())
            }
        );
    }

    #[test]
    fn route_lookup_ignores_same_port_other_destination() {
        let local: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        let conns = vec![
            conn_to(7, "10.0.0.2:5555", "9.9.9.9:80", Route::Direct, None),
            conn_to(7, "9.9.9.9:5555", "9.9.9.9:80", Route::Direct, None),
            conn_to(7, "10.0.0.2:5555", "1.2.3.4:443", Route::Direct, None),
        ];
        assert_eq!(
            find_route(&conns, 7, local, dst(), &[]),
            ProbeRoute::Unknown
        );
    }

    #[test]
    fn route_lookup_prefers_live_then_newest() {
        let local: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        let mut old_live = conn(7, "10.0.0.2:5555", Route::Direct, None);
        old_live.started_ms = 1;
        let mut new_ended = conn(7, "10.0.0.2:5555", Route::Block, None);
        new_ended.started_ms = 9;
        new_ended.ended_ms = Some(10);
        let mut newer_live = conn(7, "1.2.3.4:5555", Route::Proxy("p".into()), None);
        newer_live.started_ms = 5;
        let r = find_route(&[old_live.clone(), new_ended.clone()], 7, local, dst(), &[]);
        assert!(matches!(r, ProbeRoute::Direct { .. }));
        let r = find_route(&[old_live, new_ended, newer_live], 7, local, dst(), &[]);
        assert!(matches!(r, ProbeRoute::Proxy { .. }));
    }

    /// Offline `Env`: counts the calls that would touch the service or the network.
    struct FakeEnv {
        running: Option<bool>,
        probes: fn() -> Probes,
        flushes: Cell<u32>,
        probe_calls: Cell<u32>,
    }

    impl FakeEnv {
        fn new(running: Option<bool>, probes: fn() -> Probes) -> FakeEnv {
            FakeEnv {
                running,
                probes,
                flushes: Cell::new(0),
                probe_calls: Cell::new(0),
            }
        }
    }

    impl Env for FakeEnv {
        async fn state(&self) -> Option<StateSnapshot> {
            self.running.map(|running| StateSnapshot {
                running,
                config: Config::seed(),
                groups: HashMap::new(),
                proxy_up: HashMap::new(),
                total_up_bps: 0,
                total_down_bps: 0,
                proxy_servers: Vec::new(),
            })
        }
        async fn flush_dns(&self) {
            self.flushes.set(self.flushes.get() + 1);
        }
        async fn probe(&self, _: Vec<(String, String)>, _: Instant) -> Probes {
            self.probe_calls.set(self.probe_calls.get() + 1);
            (self.probes)()
        }
    }

    fn ir_info(ip: &str) -> IpInfo {
        IpInfo {
            ip: ip.parse().unwrap(),
            country: "Iran".into(),
            country_code: "IR".into(),
            isp: "Irancell".into(),
        }
    }

    fn direct_probes() -> Probes {
        let direct = ProbeRoute::Direct {
            group: Some("Home".into()),
        };
        Probes {
            ipv4: Probe {
                outcome: ProbeOutcome::Got(ir_info("5.200.1.1")),
                route: direct.clone(),
            },
            dns: Probe {
                outcome: ProbeOutcome::Got(ir_info("5.200.9.9")),
                route: direct.clone(),
            },
            dns_subnet: None,
            ipv6: Probe {
                outcome: ProbeOutcome::Got(ir_info("2a00::1")),
                route: direct,
            },
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn stopped_sends_nothing_and_shows_nothing() {
        let env = FakeEnv::new(Some(false), direct_probes);
        let v = block_on(run(&env));
        assert_eq!(v.level, Level::CantTell);
        assert_eq!(
            v.headline,
            "Can't tell: Q2Route is stopped (everything goes direct)"
        );
        assert!(v.lines.is_empty());
        assert_eq!(env.probe_calls.get(), 0);
        assert_eq!(env.flushes.get(), 0);
    }

    #[test]
    fn unreachable_service_sends_nothing() {
        let env = FakeEnv::new(None, direct_probes);
        let v = block_on(run(&env));
        assert_eq!(v.headline, "Can't tell: Q2Route service not reachable");
        assert_eq!(env.probe_calls.get(), 0);
    }

    #[test]
    fn direct_ipv4_hides_address_and_other_lines() {
        let env = FakeEnv::new(Some(true), direct_probes);
        let v = block_on(run(&env));
        assert_eq!(env.probe_calls.get(), 1);
        assert_eq!(v.level, Level::CantTell);
        assert_eq!(
            v.headline,
            "Can't tell: this check was routed Direct by \"Home\""
        );
        assert_eq!(v.lines.len(), 1);
        assert!(!v.lines[0].contains("5.200.1.1"));
    }

    #[test]
    fn panicking_runner_ends_with_cant_tell() {
        let c = LeakCheck::start_with(|| panic!("boom"));
        for _ in 0..200 {
            if !c.running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!c.running());
        let v = c.poll().unwrap();
        assert_eq!(v.level, Level::CantTell);
        assert!(v.headline.contains("failed unexpectedly"));
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
    async fn rate_limited_answer_is_refused() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b).await;
            s.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let p = probe_of(fetch_ip_info(addr, "ip-api.com", "/json/", None).await);
        assert!(matches!(p.outcome, ProbeOutcome::Refused(_)), "{p:?}");
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
        let p = probe_of(f);
        assert!(matches!(p.outcome, ProbeOutcome::Failed(_)));
    }
}
