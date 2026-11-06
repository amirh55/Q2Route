# Q2Route M3: UDP through the proxy (SOCKS5 UDP ASSOCIATE) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** UDP from apps routed to a SOCKS5 proxy (filtered online games) is relayed through SOCKS5 UDP ASSOCIATE instead of being blocked; if the proxy can't carry UDP the traffic stays blocked, never direct.

**Architecture:** The Network layer already captures every outbound UDP packet. For a flow decided `Proxy`, `classify` returns a new `Action::UdpProxy`; the packet loop hands the datagram to a `UdpRelay` (tokio) and drops the original. The relay keeps one SOCKS5 UDP association per app socket (local ip:port): a TCP control connection plus a UDP socket to the proxy's relay address. Outgoing datagrams get the SOCKS5 UDP header with the real destination; replies are rebuilt as IPv4/UDP packets from the real remote to the app and injected *inbound* through the same WinDivert handle (the RST-to-app path already does inbound injection).

**Tech Stack:** Rust, tokio, WinDivert (existing), etherparse (dev-dep, tests only).

**Spec:** `docs/specs/2026-11-05-q2route-design.md` — §2 goal 1 (TCP and UDP), goal 5 (SOCKS5 incl. UDP ASSOCIATE, test shows UDP support), §3 anti-goals ("No QUIC/UDP bypass. UDP from proxied apps goes through SOCKS5 UDP ASSOCIATE or is blocked."; "No fail-open"), §5.2 "Proxied UDP".

## Global Constraints

- **Fail closed:** a proxied UDP datagram is only ever sent through the proxy association. Association failure, a non-SOCKS5 profile, a queue overflow or any error drops it. Nothing in this milestone may turn a non-Direct UDP flow into a passed packet.
- IPv6 UDP from proxied flows stays blocked (IPv6 is a later milestone).
- **Decision (builder's call): proxied UDP to destination port 443 stays blocked** (QUIC). Browsers fall back to TCP, where the SNI peek keeps domain rules working; this keeps smoke test L5 (`h2`) passing. Games don't use UDP/443.
- DNS (port 53) and NTP (UDP 123) stay always-Direct exactly as today (DNS is the next milestone).
- The service's own sockets are never captured into a loop: its UDP socket to the proxy is owned by the service pid (already always Direct, Ruling R13) and usually loopback.
- Only SOCKS5 profiles can carry UDP. Proxied UDP whose profile is SOCKS4/HTTP is dropped and logged once per app socket.
- IPC: `ProxyTestResult` gains `udp_ok: Option<bool>` with `#[serde(default)]` (older peers still decode).
- `cargo clippy --workspace --all-targets` clean, `cargo fmt --all`, all tests pass; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made in this plan (builder's calls)

- **Session key:** the app's local socket address (IPv4 ip:port). One association carries every destination that socket talks to (SOCKS5 UDP puts the destination in each datagram), so a game socket talking to several servers works ("full cone").
- **Session idle timeout:** 300 s without datagrams in either direction (matches `UDP_CACHE_IDLE`). A Socket-layer CLOSE for the app socket ends it at once.
- **Pending queue:** up to 64 datagrams per session are queued while the association is being set up; more are dropped.
- **Failure backoff:** after an association fails, datagrams for that session are dropped for 10 s before retrying (no hammering a dead proxy).
- **Replies from any remote are delivered** with that remote as the source (games/STUN expect it). Replies with SOCKS5 `FRAG != 0` or a domain address type are dropped.
- **Proxy test:** for SOCKS5 profiles, after the TCP check, associate and send one DNS query (A `example.com`) to `1.1.1.1:53` through it; a reply within 2 s → `udp_ok = Some(true)`, else `Some(false)`. Non-SOCKS5 → `None` ("not supported").

## Review Focus

1. Proxy has UDP disabled (v2ray socks inbound `"udp": false`) or the profile is HTTP: game UDP must be dropped, never direct, with one log line saying why. Test: `udp_association_refused_drops_and_logs` (Task 3).
2. A burst of datagrams before the association is ready: first 64 are delivered in order after setup, the rest dropped — none passed. Test: `queues_until_associated_then_flushes` (Task 3).
3. A reply from a server the app never sent to (game relay / STUN): delivered with that server as the source. Test: `reply_from_other_remote_is_delivered` (Task 3).
4. v2ray restarts mid-game (control TCP closes): the session is torn down and the next datagram re-associates; nothing leaks meanwhile. Test: `control_close_tears_down_and_reassociates` (Task 3).
5. A 1400-byte payload survives the round trip intact, with correct IPv4/UDP checksums on the injected packet. Test: `inbound_packet_roundtrip_1400` (Task 2).

---

### Task 1: Core — SOCKS5 UDP client, UDP proxy test, decision change

**Files:**
- Modify: `crates/q2route-core/src/proxy.rs`
- Modify: `crates/q2route-core/src/decide.rs` (`finalize`)
- Test: `crates/q2route-core/tests/proxy.rs`, `crates/q2route-core/tests/decide.rs`, `crates/q2route-core/tests/ipc.rs`

**Interfaces:**
- Produces (proxy.rs):
  ```rust
  /// A live SOCKS5 UDP association. Dropping `control` ends it (RFC 1928 §7).
  pub struct UdpAssociation { pub control: TcpStream, pub relay: SocketAddr }
  /// Open a UDP association through a SOCKS5 profile (user/pass supported).
  /// Non-SOCKS5 -> Err(Protocol("UDP needs a SOCKS5 proxy")). Bounded by `timeout`,
  /// same error mapping as connect_via (Unreachable / Timeout / TargetTimeout / Refused).
  /// A BND.ADDR of 0.0.0.0 / :: is replaced by the proxy's own host IP.
  pub async fn udp_associate(p: &ProxyProfile, timeout: Duration) -> Result<UdpAssociation, ProxyError>;
  /// SOCKS5 UDP request header (RSV=0, FRAG=0, ATYP IPv4/IPv6) + payload.
  pub fn encode_udp(dst: SocketAddr, payload: &[u8]) -> Vec<u8>;
  /// Parses a SOCKS5 UDP reply; None if too short, FRAG != 0, or ATYP is a domain.
  pub fn decode_udp(d: &[u8]) -> Option<(SocketAddr, &[u8])>;
  ```
  `ProxyTestResult` gets `#[serde(default)] pub udp_ok: Option<bool>`; `test_proxy` fills it per the decision above (only when `tcp_ok`).
- Produces (decide.rs `finalize`): `Action::Proxy` + UDP → `Route::Proxy(id)` when the destination is IPv4 and its port ≠ 443; IPv6 (TCP or UDP) → `Route::Block`; UDP/443 → `Route::Block`.

- [ ] **Step 1: Failing tests**
  - `encode_decode_roundtrip`: IPv4 `1.2.3.4:27015` and IPv6 `[2001:db8::1]:5000` with a 3-byte payload; `decode_udp(&encode_udp(..))` returns the same addr and payload; header bytes for IPv4 are exactly `[0,0,0,1,1,2,3,4,0x69,0x87]`.
  - `decode_rejects_frag_domain_short`: FRAG=1 → None; ATYP=3 → None; 5-byte input → None.
  - `udp_associate_against_mock`: a mock SOCKS5 server in the test (TCP listener that answers method 0, then a UDP ASSOCIATE reply with BND `127.0.0.1:<its UDP socket port>`, then echoes each UDP datagram back unchanged); assert `relay` is that address, send `encode_udp(1.1.1.1:53, b"hi")` to it, receive and `decode_udp` → `(1.1.1.1:53, b"hi")`.
  - `udp_associate_bnd_unspecified_uses_proxy_host`: mock replies BND `0.0.0.0:<port>` → `relay.ip()` is `127.0.0.1`.
  - `udp_associate_refused`: mock replies REP=7 → `Err(ProxyError::Refused)`; HTTP profile → `Err(Protocol(..))` without connecting.
  - decide.rs: update the existing tests that expected proxied UDP → Block; add `udp_proxy_ipv4_routes_to_proxy` (UDP to `5.6.7.8:27015` from a proxied app → `Route::Proxy("v2ray")`), `udp_443_and_ipv6_stay_blocked`.
  - ipc.rs: a `ProxyTestResult` JSON without `udp_ok` still decodes (`udp_ok == None`).
- [ ] **Step 2: Run** `cargo test -p q2route-core` — FAIL (missing items).
- [ ] **Step 3: Implement.** Share the SOCKS5 greeting/auth code between `socks5` (CONNECT) and `udp_associate` (one helper, no copy).
- [ ] **Step 4: Run** `cargo test --workspace` — PASS (fix the service/UI compile for the new `udp_ok` field: construct with `udp_ok: None` where needed).
- [ ] **Step 5: Commit** — `feat(core): SOCKS5 UDP associate, UDP proxy test, proxied IPv4 UDP routed to proxy`

---

### Task 2: Service — flow cache route, classify action, inbound UDP packet builder

**Files:**
- Modify: `crates/q2route-service/src/classify.rs`
- Modify: `crates/q2route-service/src/nat.rs` or create `crates/q2route-service/src/udp_packet.rs` (builder; pick a new file `udp_packet.rs` + `pub mod udp_packet;`)
- Test: unit tests in both files

**Interfaces:**
- Consumes: Task 1 `Route::Proxy` for UDP.
- Produces (classify.rs):
  - The cache stores a route, not a bool: `pub enum Cached { Direct, Other, UdpProxy(ProfileId, Option<GroupId>) }` (`Other` = Block or TCP-proxied). `FlowCache::get(&id) -> Option<Cached>`, `put_at(id, Cached, generation)`. All TCP rules stay exactly as they are (TCP uses Direct vs not-Direct only); keep the existing tests passing unchanged in meaning.
  - New `Action::UdpProxy { pid: u32, profile: ProfileId, group_id: Option<GroupId> }` returned for a UDP packet whose (cached or fresh) decision is `Route::Proxy(profile)` and whose remote is IPv4. Proxied IPv6 UDP is never `UdpProxy` (Task 1 already blocks it; keep a defensive `Drop`).
  - Invariant doc on `classify` updated: `Pass` still only for Direct / own sockets.
- Produces (udp_packet.rs):
  ```rust
  /// IPv4 + UDP packet from `src` to `dst` carrying `payload`, checksums filled,
  /// TTL 64, DF clear, IP id from a process-wide counter. Err if payload > 65507.
  pub fn build_inbound_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> io::Result<Vec<u8>>;
  ```

- [ ] **Step 1: Failing tests**
  - classify.rs: `udp_proxy_decision_returns_udp_proxy` (fresh decide → `Final(Route::Proxy("v2ray"))` → `Action::UdpProxy{pid, profile:"v2ray", group_id}` (group_id from the decision's MatchInfo; on a cache hit the cache must return it too, so `Cached::UdpProxy` holds `(ProfileId, Option<GroupId>)`); second packet uses the cache, decide not called); `udp_block_still_drops`; `udp_direct_still_passes`; `rules_change_redecides_udp_proxy` (generation bump → decide called again).
  - udp_packet.rs: `inbound_packet_roundtrip_1400` — build from `8.8.4.4:3478` to `192.168.1.10:50000` with 1400 bytes of `i as u8`; parse with `etherparse::SlicedPacket::from_ip`; assert addresses, ports, payload, and that both checksums verify (recompute with etherparse and compare); `oversized_payload_errors` (65508 bytes → Err).
- [ ] **Step 2: Run** `cargo test -p q2route-service classify udp_packet` — FAIL.
- [ ] **Step 3: Implement.** The packet loop (`route_packet`) must compile: map `Action::UdpProxy` to `Out::Drop` for now (Task 3 wires the relay). That keeps behaviour fail-closed between tasks.
- [ ] **Step 4: Run** `cargo test --workspace` — PASS.
- [ ] **Step 5: Commit** — `feat(service): cached UDP proxy route, UdpProxy action, inbound UDP packet builder`

---

### Task 3: Service — UDP relay sessions and wiring

**Files:**
- Create: `crates/q2route-service/src/udp_relay.rs` (+ `pub mod udp_relay;`)
- Modify: `crates/q2route-service/src/packet_loop.rs` (hand off `UdpProxy`; Socket CLOSE → `udp.close(local)`)
- Modify: `crates/q2route-service/src/engine.rs` (create on start, cancel on stop)
- Test: unit/integration tests in `udp_relay.rs` (mock SOCKS5 UDP proxy + fake inbound sink)

**Interfaces:**
- Consumes: Task 1 `udp_associate`, `encode_udp`, `decode_udp`; Task 2 `Action::UdpProxy`, `build_inbound_udp`; existing `RelayCtx` (`cfg` for profiles, `stats`, `conns`, `events`, `proxy_down`).
- Produces:
  ```rust
  /// Delivers a rebuilt inbound packet to the app (production: WinDivert send with the
  /// first outbound packet's Address, outbound=false, checksums recalculated).
  pub trait InboundSink: Send + Sync + 'static { fn inject(&self, pkt: Vec<u8>, addr: &Address); }
  pub struct Datagram { pub pid: u32, pub profile: ProfileId, pub group_id: Option<GroupId>,
                        pub local: SocketAddrV4, pub remote: SocketAddrV4,
                        pub payload: Vec<u8>, pub addr: Address /* crate::windivert::Address */ }
  pub struct UdpRelay { .. }
  impl UdpRelay {
      pub fn new(ctx: Arc<RelayCtx>, sink: Arc<dyn InboundSink>, cancel: CancellationToken) -> Arc<UdpRelay>;
      /// Called from packet threads; never blocks (bounded channel, try_send; full = drop).
      pub fn submit(&self, d: Datagram);
      /// App socket closed: end its session now.
      pub fn close(&self, local: SocketAddrV4);
  }
  pub const SESSION_IDLE: Duration = Duration::from_secs(300);
  pub const PENDING_MAX: usize = 64;
  pub const FAIL_BACKOFF: Duration = Duration::from_secs(10);
  ```
- Behaviour:
  - One tokio task owns the session map (fed by an mpsc from `submit`/`close`); each session has its own task: associate (5 s timeout) → UDP socket bound `0.0.0.0:0` → flush pending → loop { app datagram → `send_to(relay, encode_udp(remote, payload))`; proxy datagram → `decode_udp` → `build_inbound_udp(src_remote, local, payload)` → `sink.inject` } until idle `SESSION_IDLE`, control TCP EOF/error, `close`, or cancel.
  - Datagrams on a session whose association failed within `FAIL_BACKOFF` are dropped.
  - Profile missing or not SOCKS5 → drop; log once per session at info: `udp pid=<pid> exe=<exe> local=<l> dst=<r> profile=<id>: dropped (<reason>, no direct fallback)`.
  - Association result logged once per session: `udp pid=.. exe=.. local=.. dst=<first remote> via '<id>': associated` / `association failed: <err> (dropped, no direct fallback)`.
  - `ProxyError::is_proxy_down()` failures insert into `ctx.proxy_down` and emit `Event::ProxyDown` (same rule as the TCP relay); the first successful association after that removes it and emits `Event::ProxyUp`.
  - Stats: bytes go to `ctx.stats.add(group, up, down)` and `ctx.stats.open(group)` guards for the session's lifetime; the group is `Datagram.group_id` (from the decision; `Action::UdpProxy` therefore also carries `group_id: Option<GroupId>` — Task 3 adds that field to the Task 2 action). ConnLog: one entry per (local, remote) pair on its first datagram (`proto: Udp`, `route: Proxy(profile)`, live bytes), closed when the session ends.
  - Engine: `UdpRelay::new` on start with a sink wrapping the Network `Handle`; stop cancels it before the handles close. `route_packet`: `Action::UdpProxy` → build `Datagram` from the parsed packet (IPv4 only, payload slice after the UDP header) → `submit` → `Out::Drop`. `socket_loop` CLOSE for UDP → `udp.close(local)` (unspecified-IP CLOSE closes every session on that port, same rule as `ConnLog::close_local`).

- [ ] **Step 1: Failing tests** (tokio tests with a mock SOCKS5 UDP proxy that relays to a local echo UDP server, and a `Vec`-collecting `InboundSink`):
  - `relays_datagram_and_injects_reply`: submit one datagram to the echo server → sink receives one packet, parsed: src = echo server addr, dst = app local, payload equal.
  - `queues_until_associated_then_flushes`: mock delays the ASSOCIATE reply 300 ms; submit 70 datagrams with distinct payloads; after setup the echo server saw exactly the first 64, in order.
  - `reply_from_other_remote_is_delivered`: the mock proxy also sends one unsolicited datagram from a second remote → injected with that remote as src.
  - `udp_association_refused_drops_and_logs`: mock REP=7 → nothing reaches the echo server, nothing injected, a second datagram within 10 s causes no new ASSOCIATE attempt (mock counts attempts == 1).
  - `non_socks5_profile_drops`: HTTP profile → no connection attempt to anything, nothing injected.
  - `control_close_tears_down_and_reassociates`: mock closes the control TCP after the first reply; the next datagram triggers a second ASSOCIATE (attempts == 2) and is delivered.
  - `close_ends_session`: `close(local)` → session task ends (ConnLog entry has `ended_ms`).
  - `proxy_unreachable_emits_proxy_down_then_up`: profile pointing at a closed port → `Event::ProxyDown`; repoint cfg to the mock, wait out `FAIL_BACKOFF` (make it a field overridable in tests, like `RelayCtx::idle_timeout`), next datagram → `Event::ProxyUp`.
- [ ] **Step 2: Run** `cargo test -p q2route-service udp_relay` — FAIL.
- [ ] **Step 3: Implement** `udp_relay.rs`, then wire packet loop + engine.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy — PASS/clean.
- [ ] **Step 5: Commit** — `feat(service): SOCKS5 UDP relay for proxied UDP flows`

---

### Task 4: UI, docs, package

**Files:**
- Modify: `crates/q2route-ui/src/views/proxies.rs` (test result line)
- Modify: `docs/SMOKE_TEST.md` (new section "M3: UDP through the proxy")
- Test: unit test for the result text in `proxies.rs`

- [ ] **Step 1: Failing test** `outcome_shows_udp`: `ProxyTest{tcp_ok:true, latency_ms:Some(42), udp_ok:Some(true)}` → `"TCP OK, 42 ms · UDP OK"`; `udp_ok:Some(false)` → `"TCP OK, 42 ms · UDP not working (enable UDP in the proxy's SOCKS inbound)"`; `None` → `"TCP OK, 42 ms · UDP not supported (SOCKS5 only)"`.
- [ ] **Step 2: Implement**, run `cargo test --workspace`, clippy, fmt.
- [ ] **Step 3: SMOKE_TEST.md** rows (same table style; install via `dist\Q2Route-update\Update.cmd`):
  - U1 Proxies → Test on v2ray shows "UDP OK" (v2rayN's SOCKS inbound has UDP on by default).
  - U2 Put a filtered game's exe in a Proxy (v2ray) group; play online; the game connects; Connections shows its UDP rows with route Proxy (v2ray) and growing ↑/↓; log has `udp ... via 'v2ray': associated`.
  - U3 Same game with v2ray stopped: the game can't connect; log shows `association failed ... (dropped, no direct fallback)`; browserleaks/game never sees the real IP.
  - U4 `https://cloudflare-quic.com` still reports `h2` (proxied UDP/443 stays blocked).
  - U5 A Direct game (e.g. in "Games") is unaffected: still direct, ping unchanged.
- [ ] **Step 4: Package** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1` → "update packaged" (service running).
- [ ] **Step 5: Commit** — `feat(ui): show UDP proxy test result; docs: M3 smoke steps`
