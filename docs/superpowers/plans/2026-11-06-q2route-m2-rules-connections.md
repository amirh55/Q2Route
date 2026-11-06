# Q2Route M2: Groups & rules editor and Connections view — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user can create, edit, reorder and delete groups and rules in the UI, and see every live/recent connection with a right-click "add this app / domain / IP to a group".

**Architecture:** Config editing stays in the service (the UI sends small IPC requests; the service validates, compiles, saves, swaps). The service keeps a bounded in-memory connection log fed from the two places that already decide flows (packet layer for Direct/Block, relay for relayed flows); the UI polls it once per second while the Connections page is open. Rule suggestions for the right-click menu are pure functions in core.

**Tech Stack:** Rust stable, egui/eframe 0.37, tokio, serde/JSON IPC (existing), WinDivert (existing).

**Spec:** `docs/specs/2026-11-05-q2route-design.md` (§2 goals 2, 4, 6; §5.3; §6 "Connections" and "Groups & rules" rows). Earlier rulings: `docs/superpowers/plans/2026-11-05-q2route-m1.md` and the M1 ledger (R1–R20).

## Global Constraints

- Windows 10/11 x64, Rust stable, English UI only.
- Every config change is saved immediately (spec §5.9) through the service's existing `mutate` path: validate, compile, save, swap; any failure leaves the running config untouched.
- The last group is the enabled catch-all "Everything else"; it cannot be disabled, deleted, renamed away from catch-all, or moved (Ruling R18). New groups are inserted before it.
- A rule with no conditions matches nothing (Ruling R6); the editor must refuse to save one.
- Rule conditions inside one rule are ANDed; rules inside a group are ORed (spec §5.3).
- "Include child processes" defaults to on when adding an app (spec §6).
- Never route anything Direct by accident: failed parses are errors, not silently dropped entries.
- IPC framing unchanged (u32-LE length + JSON, 16 MiB cap). New `Request`/`Response` variants are added at the end of each enum.
- `cargo clippy --workspace --all-targets` clean, `cargo fmt --all`, all tests pass, each commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made in this plan (builder's calls)

- **Reorder:** ▲/▼ buttons per group instead of drag-and-drop (egui drag-reorder is fiddly; same outcome).
- **Group id:** generated once from the name (slug), never changes on rename.
- **Rule form:** one text field per condition list, entries separated by commas or new lines.
- **"Add this app"** adds the exe *file name* (e.g. `game.exe`, matches wherever it is installed), with include children on. Disabled for pid 0/4 (`System`, `?`).
- **"Add *.parent":** drop the first label when the host has 3+ labels (`www.digikala.com` → `*.digikala.com`); with 2 labels offer `*.<host>`.
- **"Add this IP range":** exact IP, plus `/24` (IPv4) or `/64` (IPv6).
- **Right-click on an existing identical rule** is a no-op (no duplicates).
- **Connection log:** LAN/DNS/NTP flows (`AlwaysDirectDst`) are not recorded (noise). Byte counts exist only for relayed flows; packet-layer Direct flows show "—".

## Review Focus

1. Editing a group's rules while the dashboard/tray changes its action or enabled flag: the rule save must not overwrite the action/enabled change (rule edits replace `rules` only). Test: `set_group_rules_keeps_action_and_enabled` (Task 1).
2. Typing an invalid entry (`10.0.0.0/33`, `*`, `80-70`, `geoip:`) must be rejected with a readable error and nothing saved. Test: `set_group_rules_rejects_bad_entries` (Task 1).
3. Thousands of connections (torrent, Steam download): the log stays bounded and the UI stays responsive. Test: `log_is_bounded` (Task 2); UI uses `ScrollArea::show_rows` (Task 4).
4. Right-clicking "add" twice for the same thing must not create duplicate rules. Test: `add_rule_dedupes` (Task 1).
5. Connections owned by `System` (pid 4, e.g. under ESET web filtering) or unknown pid: "Add app" is not offered. Test: `app_rule_skips_system_and_unknown` (Task 1).

---

### Task 1: Core — group/rule editing, IPC types, rule suggestions

**Files:**
- Modify: `crates/q2route-core/src/config.rs`
- Modify: `crates/q2route-core/src/ipc.rs`
- Modify: `crates/q2route-core/src/decide.rs` (derive `Serialize, Deserialize` on `Route`)
- Create: `crates/q2route-core/src/suggest.rs` (+ `pub mod suggest;` in `lib.rs`)
- Test: `crates/q2route-core/tests/config.rs`, `crates/q2route-core/tests/suggest.rs`, `crates/q2route-core/tests/ipc.rs`

**Interfaces:**
- Produces (config.rs, all on `Config`, all through the existing `mutate` helper, all `Result<_, ConfigError>`):
  - `fn add_group(&mut self, name: &str, action: Action) -> Result<GroupId, ConfigError>` — enabled, no rules, inserted just before the catch-all; id = `slug(name)` made unique with `-2`, `-3`…; empty/blank name → `Invalid`.
  - `fn rename_group(&mut self, id: &str, name: &str) -> Result<(), ConfigError>` — blank name → `Invalid`; id unchanged.
  - `fn delete_group(&mut self, id: &str) -> Result<(), ConfigError>` — catch-all or unknown → `Invalid`.
  - `fn move_group(&mut self, id: &str, to: usize) -> Result<(), ConfigError>` — `to` is the final index; catch-all can't move and nothing can land at/after its index → `Invalid`.
  - `fn set_group_rules(&mut self, id: &str, rules: Vec<Rule>) -> Result<(), ConfigError>` — replaces `rules` only; every rule must pass `Rule::check`.
  - `fn add_rule(&mut self, id: &str, rule: Rule) -> Result<bool, ConfigError>` — `Ok(false)` if an equal rule already exists (nothing changed), else pushes; rule must pass `Rule::check`. Adding to the catch-all → `Invalid` (it has no rules).
  - `impl Rule { pub fn is_empty(&self) -> bool; pub fn check(&self) -> Result<(), ConfigError> }` — `check` = not empty, and every entry parses with `AppMatcher::parse` / `DomainPattern::parse` / `IpMatcher::parse` / `PortRange::parse`; error text names the entry, e.g. `invalid ip/cidr '10.0.0.0/33'`.
  - `pub fn slug(name: &str) -> String` — lowercase ASCII alnum, other runs → single `-`, trimmed of `-`; empty → `"group"`.
- Produces (ipc.rs), appended to `Request`:
  `AddGroup { name: String, action: Action }`, `RenameGroup { group_id: GroupId, name: String }`, `DeleteGroup { group_id: GroupId }`, `MoveGroup { group_id: GroupId, to: usize }`, `SetGroupRules { group_id: GroupId, rules: Vec<Rule> }`, `AddRule { group_id: GroupId, rule: Rule }`, `GetConnections`, `ListProcesses`.
  Appended to `Response`: `Connections(Vec<ConnInfo>)`, `Processes(Vec<ProcEntry>)`.
  ```rust
  pub struct ConnInfo {
      pub id: u64,
      pub proto: Protocol,
      pub pid: u32,
      pub exe: String,             // file name, "System" / "?" when unknown
      pub local: SocketAddr,
      pub dst: SocketAddr,
      pub domain: Option<String>,
      pub route: Route,
      pub group_id: Option<GroupId>,
      pub reason: String,          // "own", "inherited from steam.exe", "catch-all", "always-direct app", "excluded", "no match"
      pub started_ms: u64,         // unix ms
      pub ended_ms: Option<u64>,   // None while active
      pub up: Option<u64>,         // bytes; None when not relayed
      pub down: Option<u64>,
  }
  pub struct ProcEntry { pub pid: u32, pub name: String, pub path: String }
  ```
  (both `Serialize, Deserialize, Clone, Debug, PartialEq`)
- Produces (suggest.rs):
  - `pub fn app_rule(exe: &str) -> Option<Rule>` — `None` for `""`, `"?"`, `"System"`, `"Idle"` (case-insensitive); else `Rule { apps: [exe], include_children: true, .. }`.
  - `pub fn domain_patterns(host: &str) -> Vec<String>` — `[host]` plus the `*.parent` per the decision above; empty host → empty vec. Lowercased, trailing dot removed.
  - `pub fn ip_patterns(ip: IpAddr) -> Vec<String>` — `["1.2.3.4", "1.2.3.0/24"]` / `["2001:db8::1", "2001:db8::/64"]`.
  - `pub fn reason_text(reason: &MatchReason, tree: &ProcessTree) -> String` — the strings listed in `ConnInfo::reason`; `Inherited { from_pid }` → `"inherited from <exe of from_pid>"` (or `"inherited"` if unknown).

- [ ] **Step 1: Write the failing tests**

`tests/config.rs`:
```rust
#[test]
fn add_group_inserts_before_catch_all_with_unique_id() {
    let mut c = Config::seed();
    assert_eq!(c.add_group("My Games!", Action::Direct).unwrap(), "my-games");
    assert_eq!(c.add_group("my games", Action::Block).unwrap(), "my-games-2");
    let ids: Vec<_> = c.groups.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids, ["iranian-sites", "steam", "games", "my-games", "my-games-2", "everything-else"]);
    assert!(c.add_group("   ", Action::Direct).is_err());
}

#[test]
fn delete_rename_move_respect_catch_all() {
    let mut c = Config::seed();
    assert!(c.delete_group("everything-else").is_err());
    assert!(c.move_group("everything-else", 0).is_err());
    assert!(c.move_group("games", 3).is_err()); // catch-all's index
    c.move_group("games", 0).unwrap();
    assert_eq!(c.groups[0].id, "games");
    c.rename_group("games", "Online games").unwrap();
    assert_eq!((c.groups[0].id.as_str(), c.groups[0].name.as_str()), ("games", "Online games"));
    c.delete_group("games").unwrap();
    assert!(c.groups.iter().all(|g| g.id != "games"));
    assert!(c.delete_group("games").is_err());
}

#[test]
fn set_group_rules_keeps_action_and_enabled() {
    let mut c = Config::seed();
    c.set_group_action("steam", Action::Proxy("v2ray".into())).unwrap();
    let rules = vec![Rule { apps: vec!["steam.exe".into(), "steamwebhelper.exe".into()], ..Rule::default() }];
    c.set_group_rules("steam", rules.clone()).unwrap();
    let g = c.groups.iter().find(|g| g.id == "steam").unwrap();
    assert_eq!(g.rules, rules);
    assert_eq!(g.action, Action::Proxy("v2ray".into()));
    assert!(!g.enabled);
}

#[test]
fn set_group_rules_rejects_bad_entries() {
    let mut c = Config::seed();
    let before = c.clone();
    for bad in [
        Rule { ips: vec!["10.0.0.0/33".into()], ..Rule::default() },
        Rule { domains: vec!["*".into()], ..Rule::default() },
        Rule { ports: vec!["80-70".into()], ..Rule::default() },
        Rule { ips: vec!["geoip:".into()], ..Rule::default() },
        Rule::default(), // no conditions
    ] {
        assert!(c.set_group_rules("games", vec![bad]).is_err());
    }
    assert_eq!(c, before);
    let e = c.set_group_rules("games", vec![Rule { ips: vec!["10.0.0.0/33".into()], ..Rule::default() }]).unwrap_err();
    assert!(e.to_string().contains("10.0.0.0/33"), "{e}");
}

#[test]
fn add_rule_dedupes() {
    let mut c = Config::seed();
    let r = Rule { apps: vec!["game.exe".into()], ..Rule::default() };
    assert!(c.add_rule("games", r.clone()).unwrap());
    assert!(!c.add_rule("games", r).unwrap());
    assert_eq!(c.groups.iter().find(|g| g.id == "games").unwrap().rules.len(), 1);
    assert!(c.add_rule("everything-else", Rule { apps: vec!["x.exe".into()], ..Rule::default() }).is_err());
}

#[test]
fn slug_cases() {
    assert_eq!(slug("Online  Games (UDP)"), "online-games-udp");
    assert_eq!(slug("بازی"), "group");
}
```

`tests/suggest.rs`:
```rust
use q2route_core::suggest::*;

#[test]
fn app_rule_skips_system_and_unknown() {
    for x in ["", "?", "System", "system", "Idle"] {
        assert!(app_rule(x).is_none(), "{x}");
    }
    let r = app_rule("game.exe").unwrap();
    assert_eq!(r.apps, ["game.exe"]);
    assert!(r.include_children);
}

#[test]
fn domain_and_ip_patterns() {
    assert_eq!(domain_patterns("www.Digikala.com."), ["www.digikala.com", "*.digikala.com"]);
    assert_eq!(domain_patterns("digikala.com"), ["digikala.com", "*.digikala.com"]);
    assert!(domain_patterns("").is_empty());
    assert_eq!(ip_patterns("185.188.107.12".parse().unwrap()), ["185.188.107.12", "185.188.107.0/24"]);
    assert_eq!(ip_patterns("2001:db8::1".parse().unwrap()), ["2001:db8::1", "2001:db8::/64"]);
}
```
Plus a `reason_text` test with a two-process tree (`Inherited { from_pid: 10 }` where pid 10 is `C:\Steam\steam.exe` → `"inherited from steam.exe"`), and in `tests/ipc.rs` a JSON round-trip of every new `Request` variant and of `Response::Connections(vec![ConnInfo{..}])` / `Response::Processes(..)`.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p q2route-core`
Expected: compile errors (functions/variants not defined).

- [ ] **Step 3: Implement the Interfaces above**

`Rule::check` lives in config.rs and calls the matchers (core-internal dependency is fine). `MatchError` → `ConfigError::Invalid(e.to_string())`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p q2route-core` — Expected: all pass. Then `cargo build --workspace` (the service/UI `match`es on `Request` must still compile: add the new arms in the service as `Response::Error("not implemented".into())` for now; Task 2 replaces them).

- [ ] **Step 5: Commit** — `feat(core): group/rule editing, connection IPC types, rule suggestions`

---

### Task 2: Service — connection log and new requests

**Files:**
- Create: `crates/q2route-service/src/conns.rs` (+ `pub mod conns;` in `lib.rs`)
- Modify: `crates/q2route-service/src/relay.rs` (`RelayCtx` gets `pub conns: Arc<ConnLog>`; record in `handle`)
- Modify: `crates/q2route-service/src/packet_loop.rs` (record in `decide_flow`; end on Socket CLOSE in `socket_loop`)
- Modify: `crates/q2route-service/src/engine.rs` (handle the new requests)
- Test: unit tests in `conns.rs`; `crates/q2route-service/tests/relay.rs` (one new test)

**Interfaces:**
- Consumes: Task 1's `ConnInfo`, `ProcEntry`, `suggest::reason_text`, `Config` editing methods.
- Produces (`conns.rs`):
  ```rust
  pub const RECENT_CAP: usize = 500;   // ended connections kept
  pub const ACTIVE_CAP: usize = 5000;  // active entries kept (oldest dropped beyond)
  pub struct ConnLog { .. }            // thread-safe, &self methods
  pub struct ConnBytes { pub up: AtomicU64, pub down: AtomicU64 }
  impl ConnLog {
      /// Records a new connection, returns its id. `bytes` = Some for relayed flows.
      pub fn open(&self, info: NewConn, bytes: Option<Arc<ConnBytes>>) -> u64;
      /// Marks the connection ended (relay: when `handle` returns).
      pub fn close(&self, id: u64);
      /// Marks every active connection with this protocol + local address ended
      /// (Socket-layer CLOSE; packet-layer flows only know their local addr).
      pub fn close_local(&self, proto: Protocol, local: SocketAddr);
      /// Active first (newest first), then ended (newest first).
      pub fn list(&self) -> Vec<ConnInfo>;
  }
  pub struct NewConn { pub proto: Protocol, pub pid: u32, pub exe: String, pub local: SocketAddr,
                       pub dst: SocketAddr, pub domain: Option<String>, pub route: Route,
                       pub group_id: Option<GroupId>, pub reason: String }
  ```
- Recording rules:
  - `decide_flow` (packet layer): record only `Decision::Final` with route `Direct` or `Block` and reason ≠ `AlwaysDirectDst`, with `bytes: None`. (Proxy / NeedDomain flows are redirected and recorded by the relay instead, so nothing is listed twice.)
  - relay `handle`: record once the final decision is known (after any peek), with `bytes: Some(..)`; the copy loop adds to the same counters it already adds to `Stats`; `close(id)` when `handle` returns (also on cancel — use a drop guard like `Hold`).
  - `socket_loop` on `EVENT_SOCKET_CLOSE`: `conns.close_local(proto, s.local)`.
- Engine: `AddGroup`→`apply(|c| c.add_group(..).map(|_| ()))`, the other edit requests likewise via `apply`; `AddRule` → `Response::Ok` either way; `GetConnections` → `Response::Connections(relay.conns.list())`; `ListProcesses` → `winapi::list_processes()` filtered to entries with an absolute exe path, sorted by name, deduped by path, as `ProcEntry`.

- [ ] **Step 1: Write failing unit tests in `conns.rs`**

```rust
#[test]
fn open_close_and_order() { /* open a, b; close a; list() == [b (active), a (ended, ended_ms Some)] */ }

#[test]
fn close_local_ends_matching_active_only() { /* two TCP on different local ports + one UDP on same port; close_local(Tcp, port1) ends only the first */ }

#[test]
fn log_is_bounded() {
    let log = ConnLog::default();
    for i in 0..(ACTIVE_CAP + RECENT_CAP + 100) { let id = log.open(conn(i), None); if i % 2 == 0 { log.close(id) } }
    let l = log.list();
    assert!(l.iter().filter(|c| c.ended_ms.is_none()).count() <= ACTIVE_CAP);
    assert!(l.iter().filter(|c| c.ended_ms.is_some()).count() <= RECENT_CAP);
}

#[test]
fn bytes_are_live() { /* open with Some(bytes); bytes.up.fetch_add(10); list()[0].up == Some(10) */ }
```

- [ ] **Step 2: Run** `cargo test -p q2route-service conns` — Expected: FAIL (module missing).

- [ ] **Step 3: Implement `ConnLog`** — one `Mutex<State>` with `active: IndexMap`-like `VecDeque<(u64, Entry)>` + `ended: VecDeque<ConnInfo>`; plain std types, no new dependency.

- [ ] **Step 4: Wire it in** (relay, packet loop, engine) per the recording rules.

- [ ] **Step 5: Relay test** in `tests/relay.rs`: `relayed_connection_is_listed_with_bytes` — relay a proxied flow through the existing mock proxy, then assert `ctx.conns.list()` has one entry with `route == Route::Proxy("mock")`, `domain == Some("example.com")` (or whatever the test's existing peek fixture uses), `up > 0`, and `ended_ms.is_some()` after the client closes.

- [ ] **Step 6: Run** `cargo test --workspace` — Expected: all pass.

- [ ] **Step 7: Commit** — `feat(service): connection log, group/rule edit and process list requests`

---

### Task 3: UI — Groups & rules page

**Files:**
- Create: `crates/q2route-ui/src/views/groups.rs`
- Modify: `crates/q2route-ui/src/views/mod.rs`, `crates/q2route-ui/src/app.rs` (route `Page::Groups`)
- Test: unit tests in `groups.rs`

**Interfaces:**
- Consumes: Task 1 requests; existing `Requests::send`, `Client::send`, `StateSnapshot.config`.
- Produces: `pub struct GroupsView` with `pub fn show(&mut self, ui, snap: Option<&StateSnapshot>, client: &Client, req: &mut Requests)`; pure helpers `pub fn split_entries(text: &str) -> Vec<String>` and `pub fn join_entries(v: &[String]) -> String` (`"\n"`-joined), `pub fn rule_from_form(f: &RuleForm) -> Rule`.

Layout (my calls, spec §6 "Groups & rules"):
- Left: ordered group list. Each row: ▲ ▼ (disabled at the edges and for the catch-all; ▼ disabled on the row just above the catch-all), enabled checkbox (hidden for the catch-all), name, action badge. Click selects. Bottom: name field + "Add group" (action Direct) → `AddGroup`.
- Right (selected group): name field + "Rename"; action picker (Direct / Block / Proxy + profile combo, same widget as the dashboard card; sends `SetGroupAction`); "Delete group" with a confirm step (hidden for the catch-all); the rule list, each rule summarised like the dashboard (`dashboard::summary` logic, one line per rule) with Edit / Remove.
- Rule form (add or edit): multi-line fields Apps, Domains, IPs, Ports; protocol combo (Any / TCP / UDP); "Include child processes" checkbox (default on); "Pick running app…" opens a filterable list from `ListProcesses` (adds the file name to Apps); Save sends `SetGroupRules` with the whole edited list; Cancel. Save is disabled while the form is empty. On `Response::Error(e)` the form stays open and shows `e` in red; on `Ok` it closes.
- Catch-all selected: shows "Everything not matched above goes here." and only the action picker.
- Hint under the fields: "One per line. Apps: steam.exe, C:\Games\x.exe or a folder ending in \. Domains: example.com, *.ir, keyword:steam. IPs: 1.2.3.4, 5.0.0.0/8, geoip:ir. Ports: 443 or 27000-27100."

- [ ] **Step 1: Failing tests** for the pure helpers:
```rust
#[test] fn split_entries_commas_and_lines() { assert_eq!(split_entries(" a.com, b.com\n\n*.ir \r\n"), ["a.com", "b.com", "*.ir"]); }
#[test] fn form_roundtrip() { /* RuleForm from a Rule with every field set -> rule_from_form gives the same Rule */ }
#[test] fn empty_form_is_empty_rule() { assert!(rule_from_form(&RuleForm::default()).is_empty()); }
```
- [ ] **Step 2: Run** `cargo test -p q2route-ui groups` — FAIL.
- [ ] **Step 3: Implement** the helpers and the view.
- [ ] **Step 4: Run** `cargo test --workspace`, `cargo clippy --workspace --all-targets` — clean.
- [ ] **Step 5: Manual check** — `cargo run -p q2route-ui` against the installed service: add a group, add a rule with a bad IP (error shown, nothing saved), fix it, reorder, delete. Record what you saw in the task report.
- [ ] **Step 6: Commit** — `feat(ui): Groups & rules editor`

---

### Task 4: UI — Connections page

**Files:**
- Create: `crates/q2route-ui/src/views/connections.rs`
- Modify: `crates/q2route-ui/src/views/mod.rs`, `crates/q2route-ui/src/app.rs` (route `Page::Connections`)
- Test: unit tests in `connections.rs`

**Interfaces:**
- Consumes: `Request::GetConnections` / `Response::Connections`, `Request::AddRule`, Task 1 `suggest::*`.
- Produces: `pub struct ConnectionsView` with `show(&mut self, ui, snap, client, req)`; pure `pub fn filter(conns: &[ConnInfo], f: &Filter) -> Vec<&ConnInfo>` where `Filter { text: String, active_only: bool }` matches `text` case-insensitively against exe, domain, dst ip, group id; `pub fn route_label(r: &Route) -> String` (`"Direct"`, `"Block"`, `"Proxy (v2ray)"`); `pub fn human_bytes(n: Option<u64>) -> String` (`None` → `"—"`, `1536` → `"1.5 KB"`).

Behaviour:
- While the page is visible, send `GetConnections` at most once per second (keep the pending receiver; don't stack requests).
- Top bar: search box, "Active only" checkbox (default on), count "N shown".
- Table (`egui_extras` is NOT added; use `egui::Grid` inside `ScrollArea::vertical().show_rows` with a fixed row height): App (`exe`), PID, Destination (`domain` when known, then `ip:port`; e.g. `www.digikala.com 185.188.107.12:443`), Proto, Route, Group, Why (`reason`), ↑, ↓, Duration (`ended_ms or now` − `started_ms`, as `1m 05s`; pure helper `pub fn duration_label(ms: u64) -> String`, tested: `999`→`"0s"`, `65_000`→`"1m 05s"`, `3_726_000`→`"1h 02m"`). Ended rows greyed.
- Right-click a row (`response.context_menu`): submenus "Add app to group ▸", "Add domain to group ▸" (one item per `domain_patterns` entry), "Add IP to group ▸" (per `ip_patterns`); each lists non-catch-all groups by name. Picking one sends `AddRule { group_id, rule }` (rule built from the suggestion; apps rule from `app_rule`, domain/IP rules with that single entry). Menus are omitted when the suggestion is `None`/empty.
- A one-line note under the table: "Changing a rule applies to new connections; open ones keep their route."

- [ ] **Step 1: Failing tests** for `filter` (text match on each field; active_only hides ended), `route_label`, `human_bytes` (`None`, `0`→`"0 B"`, `1536`→`"1.5 KB"`, `5_000_000`→`"4.8 MB"`).
- [ ] **Step 2: Run** `cargo test -p q2route-ui connections` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace`, clippy, fmt — clean.
- [ ] **Step 5: Manual check** against the installed service: open a few sites, confirm rows appear with route/group/why; right-click a `.com` site → add `*.parent` to "Iranian sites"; it shows up on the Groups page. Record in the task report.
- [ ] **Step 6: Commit** — `feat(ui): live Connections view with add-to-group menu`

---

### Task 5: Package and smoke-test additions

**Files:**
- Modify: `docs/SMOKE_TEST.md` (new section "M2: rules editor and connections")

- [ ] **Step 1:** Add rows (Expected / Result columns, same style):
  - E1 Add group "Filtered games" with action Proxy (v2ray), add the game's exe via "Pick running app…"; the dashboard shows the new card above "Everything else".
  - E2 Bad entry (`10.0.0.0/33`) shows an error and nothing changes; `config.toml` unchanged.
  - E3 Reorder and delete a group; restart the service (`sc.exe stop Q2Route`, `sc.exe start Q2Route`); the order persists.
  - C1 Connections page lists browser connections with route, group and why; LAN/DNS are not listed.
  - C2 Right-click a site → "Add domain to group ▸ Iranian sites" with `*.parent`; new connections to it go Direct (log `group=iranian-sites`).
  - C3 Leave a Steam download running 10 min: the page stays responsive, list length bounded.
- [ ] **Step 2:** Run `powershell -ExecutionPolicy Bypass -File scripts\package.ps1` (service running → `dist\Q2Route-update`). Expected: "update packaged".
- [ ] **Step 3: Commit** — `docs: M2 smoke-test steps`
