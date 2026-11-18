# Q2Route M9: Data usage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A "Data usage" page that shows how much **proxied** traffic (what uses the VPN's quota) each group, app and proxy used, for this session, today, this month and the last 90 days, with a Reset button. It has an on/off switch, **off by default**. When off, nothing is counted or written to disk.

**Architecture:** A service-side `Usage` store sits next to the existing `Stats` (`crates/q2route-service/src/stats.rs`). The relay (TCP) and UDP relay already call `ctx.stats.add(group, up, down)` for every relayed byte. Next to those calls they also call `ctx.usage.add(&UsageKey { group, app, proxy }, up, down)`. That call returns at once when counting is off, after one atomic load. Totals are kept per local calendar day, saved to `%ProgramData%\Q2Route\usage.json` every 60 s and on Stop or exit, and loaded on start. The UI reads them over IPC.

**Tech Stack:** Rust. Uses existing crates only: serde/serde_json, dashmap and the `windows` crate. For the local date, add the `windows` feature `Win32_System_SystemInformation` (`GetLocalTime`).

**Spec:** `docs/specs/2026-11-05-q2route-design.md` §6, the "Data usage" row: "Per group, app and proxy; session and history; reset."

## Global Constraints

- **Off by default.** The setting is `settings.data_usage: bool`, which defaults to `false` and is added with serde default. Existing configs therefore load with it off.
- **When off:**
  - `Usage::add` does nothing beyond one `AtomicBool` load.
  - No file is created or written.
  - The page shows only the switch and one line explaining it.
- **Turning it off** keeps the saved history on disk until the user presses Reset.
- **Only relayed (proxied) traffic is counted.** This is TCP through the relay and UDP through the UDP relay. Direct traffic is not counted: its download packets are never captured, and capturing them would cost speed. The page says so in one line: `Counts traffic sent through a proxy (what uses your VPN data). Direct traffic is not counted.`
- **History.** Daily rows are kept for the last 90 local days, and older days are dropped when saving. A day is the local date from `GetLocalTime`, stored as `"YYYY-MM-DD"`.
- **Saving.** Writes are atomic: write `usage.json.tmp`, then rename it. A missing file means empty history. A corrupt file is logged at warn and then treated as empty; the corrupt file is renamed to `usage.json.bad` rather than overwritten silently.
- **Housekeeping.** `cargo clippy --workspace --all-targets` must be clean, `cargo fmt --all` must be run, and all tests must pass. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made in this plan (builder's calls)

- **Key.** `UsageKey { group: GroupId, app: String, proxy: ProfileId }`.
  - `app` is the lowercase exe file name, for example `chrome.exe`, or `"?"` when unknown. It comes from the same place the Connections list gets `exe`.
  - `proxy` is the profile id the flow was sent to.
- **In memory.**
  - `DashMap<(day: String, UsageKey), Counters{up, down}>` holds the days.
  - A separate `session` map (same key without the day) is reset on every service start and on Reset.
- **Wire types** (in `q2route_core::ipc`):
  - `UsageRow { group, app, proxy, up: u64, down: u64 }`.
  - `UsageReport { enabled: bool, session: Vec<UsageRow>, days: Vec<(String, Vec<UsageRow>)> }`. Days are sorted oldest first.
  - The UI does all grouping: by group, app, proxy, and Today / This month / 90 days.
- **New IPC requests:** `GetUsage` returns `Response::Usage(UsageReport)`. `SetDataUsage { enabled }` goes through the normal config apply/save path. `ResetUsage` clears session and days and deletes the file.
- **Load and save timing.**
  - Load on service start whenever the file exists, even with counting off, so that switching it on continues the history.
  - Save every 60 s only while enabled and changed.
  - Also save on Stop, on service shutdown and when the user turns counting off.

## Review Focus

1. **Counting off.** No `usage.json` is created after traffic flows, and `add` doesn't allocate. Test: `disabled_counts_nothing_and_writes_nothing` (Task 1).
2. **Corrupt or partial `usage.json`.** The service still starts, the bad file is kept as `usage.json.bad`, and counting continues from empty. Test: `corrupt_file_is_set_aside` (Task 1).
3. **More than 90 days of history.** Older days are dropped on save, and today's row is never dropped. Test: `keeps_90_days` (Task 1).
4. **Concurrency.** Many relay tasks add at once and no bytes are lost. Test: `concurrent_adds_sum` (Task 1), which uses 8 threads × 10,000 adds.
5. **Turning counting off and on.** Session totals restart only on a service restart or Reset, not on the toggle. History survives the toggle. Test: `toggle_keeps_history` (Task 2).

---

### Task 1: Usage store (`crates/q2route-service/src/usage.rs`) and wire types

**Files:**
- Create: `crates/q2route-service/src/usage.rs`.
- Modify: `crates/q2route-service/src/lib.rs`.
- Modify: `crates/q2route-core/src/ipc.rs` (types only, plus the three new `Request` variants and `Response::Usage`).
- Modify: `crates/q2route-service/Cargo.toml` (the windows feature).
- Test: in-module tests.

**Interfaces — Produces:**
- `pub struct Usage`:
  - `pub fn new(path: PathBuf, enabled: bool) -> Usage`. It loads the file if present.
  - `pub fn set_enabled(&self, on: bool)`.
  - `pub fn enabled(&self) -> bool`.
  - `pub fn add(&self, key: &UsageKey, up: u64, down: u64)`.
  - `pub fn report(&self) -> UsageReport`.
  - `pub fn reset(&self) -> std::io::Result<()>`.
  - `pub fn save_if_dirty(&self) -> std::io::Result<()>`.
  - `pub fn add_on(&self, day: &str, key: &UsageKey, up: u64, down: u64)`. This is the test seam for dates; `add` calls it with today's date.
- `pub fn today() -> String`, which uses `GetLocalTime`.
- `pub struct UsageKey { pub group: GroupId, pub app: String, pub proxy: ProfileId }`. It derives Hash, Eq, Clone and Debug.

Steps:
- [ ] **Step 1: Failing tests.**
  - `disabled_counts_nothing_and_writes_nothing`.
  - `adds_go_to_session_and_today`.
  - `report_roundtrips_through_file`: add, save, then a new `Usage` on the same path reports the same days. The session is empty after the reload.
  - `corrupt_file_is_set_aside`.
  - `keeps_90_days`: uses `add_on` across 100 dates.
  - `concurrent_adds_sum`.
  - `reset_clears_and_deletes_file`.
  - `today_format`: matches `^\d{4}-\d{2}-\d{2}$`. Check it by hand; there is no regex crate.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass and clippy is clean.
- [ ] **Step 5:** Commit `feat(service): data usage store`.

### Task 2: Count relayed traffic; setting; IPC

**Files:**
- Modify: `crates/q2route-core/src/config.rs` (`settings.data_usage`, default false, with a `set_data_usage` helper like `set_dns`).
- Modify: `crates/q2route-service/src/relay.rs` and `udp_relay.rs` (next to each `ctx.stats.add`).
- Modify: the relay context struct, to hold `usage: Arc<Usage>`.
- Modify: `engine.rs`:
  - Create the store at `%ProgramData%\Q2Route\usage.json` (the same dir as config and geo).
  - Run a 60 s save tick.
  - Save on Stop and shutdown.
  - Handle the IPC requests, and apply `set_enabled` when config changes.
- Modify: `crates/q2route-service/src/test_util.rs` (the context constructor).
- Test: service tests.

**Interfaces:**
- Consumes: `Usage` and `UsageKey` from Task 1.
- At each `stats.add` site, build the `UsageKey` from data already at hand:
  - The group id.
  - The profile id the flow was proxied through.
  - The app, which is the exe name the Connections entry uses, lowercased.
- If a site lacks the exe or profile id, pass it into that function from its caller. Don't look it up per packet.
- Build the key once per connection or UDP session, not per chunk.

Steps:
- [ ] **Step 1: Failing tests.**
  - `relayed_tcp_bytes_are_counted`: uses the existing relay test harness with a mock SOCKS5 proxy. With counting on, a proxied connection that moves N bytes up and M bytes down shows up as one `UsageRow` with the right group, app and proxy, and up/down ≥ N/M. With counting off, it shows nothing.
  - `relayed_udp_bytes_are_counted`: the same, with the UDP relay test harness.
  - `toggle_keeps_history`.
  - config: `data_usage_defaults_off` (the seed is off, and an old config without the field loads as off). Also `set_data_usage` round-trips.
  - IPC: `GetUsage` returns `enabled` plus the rows. `ResetUsage` clears them.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt.
- [ ] **Step 5:** Commit `feat(service): count proxied traffic per group, app and proxy`.

### Task 3: Data usage page; smoke rows

**Files:**
- Create: `crates/q2route-ui/src/views/usage.rs`.
- Modify: `crates/q2route-ui/src/views/mod.rs` and `app.rs`, to route `Page::DataUsage` to the new view instead of the placeholder.
- Modify: `docs/SMOKE_TEST.md`, adding an "M9" section.

**UI:**
- Heading "Data usage".
- A checkbox "Count data usage", bound to `SetDataUsage`.
- The one-line explanation from the Global Constraints.
- When off, nothing else is shown.
- When on:
  - A period selector with four options: `Session` / `Today` / `This month` / `Last 90 days`.
  - Three tables, "By group", "By app" and "By proxy". Columns are Name, Up, Down and Total, sorted by Total descending, with sizes formatted as `12.3 MB` / `1.20 GB`.
  - A "Reset" button that asks "Delete all data usage history?" with Yes/No.
- Refresh with `GetUsage` every 2 s while the page is visible. Never block the UI thread; use the existing `Client::send` receiver pattern other views use.
- Group names come from the config snapshot. A deleted group shows its id.

**Pure helpers, tested:**
- `pub fn aggregate(report: &UsageReport, period: Period, today: &str, by: By) -> Vec<(String, u64, u64)>`.
  - `Period`: Session, Today, Month, All.
  - `By`: Group, App, Proxy.
  - `Month` means the days whose `YYYY-MM` matches today's.
- `pub fn fmt_bytes(n: u64) -> String`.

Steps:
- [ ] **Step 1: Failing tests.**
  - `aggregate_by_group_today`.
  - `aggregate_month_spans_days`.
  - `aggregate_session`.
  - `aggregate_sorted_by_total`.
  - `fmt_bytes_units`: covers 0 B, 999 B, 1.0 KB, 12.3 MB and 1.20 GB, using 1000-based units.
- [ ] **Step 2:** Implement the helpers and the view.
- [ ] **Step 3: Smoke rows (M9).**
  - **U1:** a fresh install shows the switch off, and no `usage.json` exists after browsing.
  - **U2:** switch it on and browse a proxied site; "By app" shows the browser and "By proxy" shows v2ray, and the numbers grow.
  - **U3:** a Direct site, such as an Iranian one, doesn't increase the totals.
  - **U4:** restart the service. Session resets, and Today keeps its value.
  - **U5:** Reset clears everything.
  - **U6:** switch it off. The numbers stop growing, and history is kept.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt.
- [ ] **Step 5:** Commit `feat(ui): data usage page; smoke steps`.
