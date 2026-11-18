# Q2Route M8: Leak check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A "Leak check" button on the Settings page that shows, in one click, what a proxied app looks like to the outside world: its public IPv4 and country, the DNS resolver that answers its lookups, and its IPv6 — with a clear verdict ("No leak" / "LEAK" / "Can't tell") against the anti-goal "a proxied site or app must never see the real Iranian IP".

**Architecture:** The check runs **inside the UI process (`q2route.exe`) with plain sockets and the normal Windows resolver**, so its traffic goes through the real capture engine exactly like any other app (it is not in `always_direct`). After each probe connection the UI asks the service for its connection list (`GetConnections`) and finds its own entry (own pid + local address) to report which route and group the engine actually used. A new core module holds the HTTP/1.1 GET client, the response parsers and the pure verdict function; a UI module runs the probes on a background thread.

**Tech Stack:** Rust; tokio (existing); `windows-sys` (existing dependency, add the `Win32_NetworkManagement_Dns` feature for `DnsQuery_W`).

**Spec:** `docs/specs/2026-11-05-q2route-design.md` — §3 anti-goals; §6 Settings row ("a Leak check button"); "Leak check: a button that, through a proxied path, fetches the public IP and checks DNS resolver identity and IPv6. It shows 'Proxied apps appear as X (country)'."

## Global Constraints

- **The check itself must not reveal the real IP to a foreign service.** No "direct baseline" request is made: nothing is sent around the engine, and the verdict is based on the country the outside world reports (`IR` = leak), not on comparing with the real IP.
- A probe whose own connection the engine routed **Direct** (or when Q2Route is stopped) gives **"Can't tell"** with the reason — never "No leak", never "LEAK".
- A probe that fails while routed to Proxy/Block means the proxy path is down: report **"No leak — but proxied traffic isn't getting through"** (fail-closed is working), not a leak.
- Each probe has an 8 s timeout; the whole check finishes within ~30 s and never blocks the UI thread.
- Endpoints (plain HTTP / DNS, fixed constants in one place):
  - IPv4 + country: `http://ip-api.com/json/?fields=status,message,country,countryCode,isp,query`
  - Country of a given IP: `http://ip-api.com/json/<ip>?fields=status,message,country,countryCode,isp,query`
  - IPv6: `http://api6.ipify.org/` (plain-text address; only has AAAA records)
  - DNS resolver identity: TXT `o-o.myaddr.l.google.com` via the Windows resolver (`DnsQuery_W`, `DNS_TYPE_TEXT`, after the service's `FlushDns`). Each TXT string is an IP (the resolver's egress) or `edns0-client-subnet <cidr>`; geolocate the first IP (and the subnet's network address when present) with the country endpoint.
- No new crates. `cargo clippy --workspace --all-targets` clean, `cargo fmt --all`, all tests pass; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made in this plan (builder's calls)

- **Home country is `IR`**, a constant (`HOME_COUNTRY`). Any probe result whose country code is `IR` is a leak. (Not configurable in this milestone.)
- **Why the UI process:** it tests the whole engine path (capture, DNS routing by name, SNI/Host peek, relay, proxy) instead of only v2ray. If the user routes `q2route.exe` Direct with their own rule, the report says so ("This check was routed Direct by group …") and the verdict is "Can't tell".
- **Verdict levels:** `Leak` (red) if any of IPv4 / DNS / IPv6 shows `IR`; `NoLeak` (green) if every probe that produced an address shows a non-`IR` country; `CantTell` (grey) when Q2Route is stopped, a probe was routed Direct, or nothing produced an address. A proxied path that fails is `NoLeak` with the "not getting through" note.
- **IPv6 "no route"** (lookup or connect fails with the probe not routed Direct) is reported as "IPv6: none (nothing to leak)", not as a failure.
- **HTTP client:** HTTP/1.1, `Connection: close`, reads the body by `Content-Length`, else until EOF; `Transfer-Encoding: chunked` is decoded (small, needed for robustness). Response size cap 64 KiB. Non-200 is an error.

## Review Focus

1. Q2Route stopped (everything Direct): the check must say "Can't tell — Q2Route is stopped", never "No leak", and must not present the Iranian IP as a proxied result. Test: `verdict_stopped_is_cant_tell` (Task 1).
2. The proxy is down: probes time out; verdict "No leak — proxied traffic isn't getting through". Test: `verdict_proxy_down_is_no_leak_with_note` (Task 1).
3. The probe's own connection matched a Direct group: "Can't tell", naming the group. Test: `verdict_direct_route_is_cant_tell` (Task 1).
4. ip-api answers `{"status":"fail","message":"private range"}` or a garbage/oversized body: a clear per-probe error, no panic. Tests: `parse_ip_api_fail`, `http_body_cap` (Task 1).
5. DNS answered by an Iranian resolver (TXT IP geolocates to IR) while IPv4 looks fine: verdict `Leak` with "DNS" named. Test: `verdict_dns_leak` (Task 1).

---

### Task 1: Core leak-check logic (`crates/q2route-core/src/leak.rs`)

**Files:**
- Create: `crates/q2route-core/src/leak.rs`; Modify: `crates/q2route-core/src/lib.rs`
- Test: `crates/q2route-core/tests/leak.rs`

**Interfaces — Produces:**
- `pub const HOME_COUNTRY: &str = "IR";` and the endpoint constants above.
- `pub async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(s: S, host: &str, path: &str) -> Result<String, LeakError>` (request with `Host`, `User-Agent: q2route-leak-check`, `Connection: close`).
- `#[derive(Clone, Debug, PartialEq, Deserialize)] pub struct IpInfo { pub ip: IpAddr, pub country: String, pub country_code: String, pub isp: String }` and `pub fn parse_ip_api(body: &str) -> Result<IpInfo, LeakError>` (maps `query`→`ip`, `countryCode`→`country_code`; `status != "success"` → error with `message`).
- `pub fn parse_resolver_txt(strings: &[String]) -> (Option<IpAddr>, Option<IpAddr>)` → (resolver egress IP, ECS network address).
- `#[derive(Clone, Debug, PartialEq)] pub enum ProbeRoute { Proxy { group: String }, Block { group: String }, Direct { group: String }, Unknown }`
- `#[derive(Clone, Debug, PartialEq)] pub enum ProbeOutcome { Got(IpInfo), Failed(String), NoIpv6 }`
- `#[derive(Clone, Debug, PartialEq)] pub struct Probe { pub outcome: ProbeOutcome, pub route: ProbeRoute }`
- `#[derive(Clone, Debug, PartialEq)] pub struct LeakInputs { pub running: bool, pub ipv4: Probe, pub dns: Probe, pub ipv6: Probe }` (DNS's `Got` is the resolver's geolocation)
- `#[derive(Clone, Debug, PartialEq)] pub enum Level { NoLeak, Leak, CantTell }` and `pub struct Verdict { pub level: Level, pub headline: String, pub lines: Vec<String> }`
- `pub fn verdict(i: &LeakInputs) -> Verdict`
- `#[derive(Debug, thiserror::Error)] pub enum LeakError { Io(String), Http(String), Parse(String), Timeout }`

Headline texts (exact): NoLeak → `No leak: proxied apps appear as {ip} ({country}, {isp})`; NoLeak with failed IPv4 → `No leak, but proxied traffic isn't getting through`; Leak → `LEAK: {parts} show your Iranian IP` where parts is a comma list of `IPv4`, `DNS`, `IPv6`; CantTell stopped → `Can't tell: Q2Route is stopped (everything goes direct)`; CantTell direct → `Can't tell: this check was routed Direct by "{group}"`. `lines` has one line per probe: `IPv4: …`, `DNS: resolver {ip} ({country}, {isp})`, `IPv6: …` / `IPv6: none (nothing to leak)`, each with ` — via {group}` when the route is known.

- [ ] **Step 1: Failing tests** (`tests/leak.rs`, using `tokio::io::duplex` for HTTP): `http_get_content_length`, `http_get_chunked`, `http_get_until_eof`, `http_non_200_is_error`, `http_body_cap` (65 KiB body → error); `parse_ip_api_ok`, `parse_ip_api_fail`; `parse_resolver_txt_ip_and_ecs` (`["2400:cb00::1", "edns0-client-subnet 141.98.7.0/24"]` → both), `parse_resolver_txt_garbage`; verdicts: `verdict_all_foreign_is_no_leak`, `verdict_ipv4_ir_is_leak`, `verdict_dns_leak`, `verdict_ipv6_ir_is_leak`, `verdict_stopped_is_cant_tell`, `verdict_direct_route_is_cant_tell`, `verdict_proxy_down_is_no_leak_with_note`, `verdict_no_ipv6_line`. Assert headlines verbatim.
- [ ] **Step 2:** Run → fail (module missing).
- [ ] **Step 3:** Implement. Leak takes precedence over CantTell only when the leaking probe's route is not Direct (a Direct-routed `IR` result is CantTell).
- [ ] **Step 4:** Tests pass; clippy clean.
- [ ] **Step 5:** Commit `feat(core): leak-check client, parsers and verdict`.

### Task 2: Probes in the UI (`crates/q2route-ui/src/leak.rs`)

**Files:**
- Create: `crates/q2route-ui/src/leak.rs`; Modify: `crates/q2route-ui/src/main.rs` (module), `crates/q2route-ui/Cargo.toml` (`windows-sys` feature `Win32_NetworkManagement_Dns`)
- Test: in-module tests

**Interfaces:**
- Consumes: Task 1; `Client::send(Request) -> oneshot::Receiver<Response>`; `Request::{GetState, GetConnections, FlushDns}`; `ConnInfo { pid, local, route, group_id, .. }`; group names from `StateSnapshot.config.groups`.
- Produces: `pub struct LeakCheck` with `pub fn start(client: &Client) -> LeakCheck` (spawns a thread with a current-thread tokio runtime) and `pub fn poll(&self) -> Option<Verdict>` (non-blocking; `Some` once done), plus `pub fn running(&self) -> bool`.

Flow: GetState (running?) → FlushDns → IPv4 probe (resolve `ip-api.com` with `tokio::net::lookup_host`, connect to the first IPv4, note `local_addr`, `http_get`) → route lookup (GetConnections, entry with `pid == std::process::id()` and `local ==` the probe's local address; retry up to 3× at 300 ms since the service may list it slightly later; else `ProbeRoute::Unknown`) → DNS probe (`DnsQuery_W` TXT on a blocking task, then geolocate via the country endpoint on a new connection, whose route is the DNS probe's route) → IPv6 probe (resolve `api6.ipify.org` to an IPv6, connect, `http_get`, then geolocate via the country endpoint; lookup/connect failure with a non-Direct route → `NoIpv6`) → `verdict`.

Keep the Windows-specific `DnsQuery_W` call in one small function returning `Vec<String>`; the rest is testable.

- [ ] **Step 1: Failing tests:** `route_lookup_matches_own_pid_and_local` (pure fn `find_route(conns: &[ConnInfo], pid, local, groups) -> ProbeRoute`: Proxy/Block/Direct with group name, Unknown when absent); `probe_against_local_http_server` (a tokio TCP listener on 127.0.0.1 serving an ip-api JSON; the probe helper `fetch_ip_info(addr, host, path)` returns the parsed `IpInfo`).
- [ ] **Step 2:** Run → fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt.
- [ ] **Step 5:** Commit `feat(ui): run leak-check probes through the engine`.

### Task 3: Settings page section; smoke rows

**Files:**
- Modify: `crates/q2route-ui/src/views/settings.rs` (and its caller in `app.rs` to own a `Option<LeakCheck>` and the last `Verdict`)
- Modify: `docs/SMOKE_TEST.md` ("M8" section)

UI: a "Leak check" heading under the existing settings, a `Run leak check` button (disabled while running, with a spinner and "Checking… (up to 30 s)"), then the headline coloured by level (green `dashboard::DIRECT`, red `dashboard::BLOCK`, grey for CantTell) and the `lines` below it. Request a repaint every 250 ms while running.

- [ ] **Step 1:** Test: a pure `level_color(Level) -> Color32` helper (green/red/grey) and that `settings::show` compiles with the new state (an egui test harness is not required).
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** SMOKE rows (M8): L1 normal run → green "No leak: proxied apps appear as <German IP> (Germany, …)", DNS resolver not Iranian; L2 stop v2ray → "No leak, but proxied traffic isn't getting through"; L3 Stop Q2Route → "Can't tell: Q2Route is stopped"; L4 add `q2route.exe` to a Direct group → "Can't tell: this check was routed Direct by …", then remove it; L5 IPv6 line matches the M6 smoke result.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt.
- [ ] **Step 5:** Commit `feat(ui): leak check on the Settings page; smoke steps`.
