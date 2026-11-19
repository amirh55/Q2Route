# Q2Route M11: Log page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The "Log" page (now a placeholder) shows the service's log live. It has:
- a level filter (Errors / Warnings / Info)
- a text search
- Pause
- Copy
- "Open log folder"

The log files on disk also stop growing forever.

**Architecture:**
- **Service.** A small in-memory ring (`crates/q2route-service/src/log_ring.rs`) is a `tracing_subscriber::Layer`. It sits next to the existing file layer in `main.rs`'s `init_logging` and keeps the last 2000 events. Each event gets a sequence number.
- **IPC.** A new `GetLog { after: u64 }` request returns the entries newer than `after`.
- **UI.** The UI polls `GetLog` every 1 s, but only while the Log page is visible. It appends to its own copy, capped at 2000.

**Tech Stack:** Rust. Existing crates only: tracing 0.1, tracing-subscriber 0.3 (Layer), tracing-appender 0.2.5 (`Builder::max_log_files`), and egui 0.37.

**Spec:** `docs/specs/2026-11-05-q2route-design.md`:
- §6, Log: "Live log with level filter."
- §123: "Logs use rotating files in `%ProgramData%\Q2Route\logs`."

## Global Constraints

- **The ring.**
  - Capacity is 2000 entries. The oldest entry is dropped first.
  - The ring captures exactly what the file captures. The global `EnvFilter` defaults to `info`, so this plan adds no new debug output.
  - Each message is capped at 1000 chars, cut on a char boundary with `…` appended.
- **The hot path.** `on_event` takes one short `Mutex` lock and formats one string. The relay must never `await` while holding the lock; the layer has no async code at all.
- **File retention.** Daily files are now built with `tracing_appender::rolling::Builder` (`.rotation(DAILY).filename_prefix("q2route").filename_suffix("log").max_log_files(14)`), which keeps 14 days.
  - New files are named like `q2route.2026-11-19.log`. Old `q2route.log.YYYY-MM-DD` files from before this change are not deleted by the appender. Leave them alone; don't write cleanup code for them.
- **What the UI shows.** No IPs are masked. This is the user's own log, and it already contains what the file has.
- **Housekeeping.** `cargo clippy --workspace --all-targets` is clean, `cargo fmt --all` has been run, and all tests pass. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Subagents must not:**
  - stop, start or install the Q2Route service;
  - run `.cmd` scripts;
  - launch or kill `q2route.exe`;
  - run `#[ignore]` tests;
  - touch the real `%ProgramData%`;
  - open `C:\ProgramData\Q2Route\config.toml` or the v2rayN config.

## Decisions (builder's calls)

- **Wire type** in `q2route_core::ipc`:
  ```rust
  pub struct LogEntry { pub seq: u64, pub ms: u64, pub level: LogLevel, pub target: String, pub msg: String }
  pub enum LogLevel { Error, Warn, Info, Debug, Trace }
  ```
  - `ms` is Unix ms.
  - `target` is the tracing target, for example `q2route_service::relay`.
  - `msg` is the `message` field followed by any other fields as ` key=value`, the way `fmt` prints them.
- **`GetLog { after: u64 }` returns `Response::Log(Vec<LogEntry>)`**, holding the entries with `seq > after`, oldest first.
  - `after = 0` returns the whole ring.
  - If the service restarted, the UI sees a first entry whose `seq` ≤ its last seq. In that case it clears its copy and starts over.
- **The ring is process-wide:** `pub fn global() -> &'static LogRing` (a `OnceLock`). `main.rs` adds `global().layer()`, and the engine answers `GetLog` from `global()`.
  - Tests build their own `LogRing::new(cap)` and a local subscriber with `tracing::subscriber::with_default`.
- **UI level filter.** Three options, each including the more severe levels:
  - **Errors** shows errors.
  - **Warnings** shows warnings and errors.
  - **Info** (the default) shows everything.
- **UI search.** A case-insensitive substring match on `target + msg`.
- **UI layout.**
  - One row per entry, newest at the bottom, in a virtualised `ScrollArea::show_rows`.
  - Each row has a monospace `HH:MM:SS` local time, the level shown as text in its colour (`ERROR` red, `WARN` yellow, `INFO` default), the short target (after the last `::`) and the message.
  - It sticks to the bottom unless the user scrolls up or Pause is on.
- **Buttons.**
  - **Pause / Resume.** While paused, polling continues into the buffer but the view is frozen.
  - **Copy.** Copies the shown (filtered) rows as text lines.
  - **Clear.** Clears the UI copy only; the next poll continues from the last seq.
  - **Open log folder.** Runs `explorer.exe %ProgramData%\Q2Route\logs`.
- **Local time in the UI.** The UI has no timezone crate. It uses `GetTimeZoneInformation` / `SystemTimeToTzSpecificLocalTime` from `windows-sys`, which the UI already depends on. Add the needed feature if one is missing. A pure helper takes the offset in minutes, so it can be tested.

## Review Focus

1. **A flood of events,** for example a relay logging per connection under load. Memory stays bounded at 2000 entries plus 1000-char messages. Test: `ring_drops_oldest`.
2. **A huge or multi-byte message.** Cutting it never panics. Test: `long_message_cut_on_char_boundary`, using Persian text over 1000 chars.
3. **A service restart while the page is open.** The UI doesn't show duplicates and doesn't stall. Test: `merge_resets_on_seq_going_back`.
4. **The service is not running.** The page shows "Service not connected" and no error spam in the status bar. A failed `GetLog` is ignored, not shown in `last_error`.
5. **The filter and search combined.** Test: `filter_levels_and_search`.

---

### Task 1: Log ring, retention, IPC (service + core)

**Files:**
- Create: `crates/q2route-service/src/log_ring.rs`.
- Modify: `crates/q2route-service/src/lib.rs`, `crates/q2route-service/src/main.rs` (`init_logging`) and `crates/q2route-service/src/engine.rs` (the `GetLog` arm).
- Modify: `crates/q2route-core/src/ipc.rs`, adding `LogEntry`, `LogLevel`, `Request::GetLog { after: u64 }` and `Response::Log(Vec<LogEntry>)`.
- Modify: `crates/q2route-service/Cargo.toml`, if the tracing-subscriber `registry` feature or tracing-appender features are needed.

**Interfaces — Produces:**
- `pub struct LogRing`, with:
  - `pub fn new(cap: usize) -> LogRing`
  - `pub fn since(&self, after: u64) -> Vec<LogEntry>`
  - `pub fn layer(&'static self) -> impl Layer<S>`. Alternatively, implement `Layer` on a small `RingLayer(&'static LogRing)`, plus a test seam that works with a non-static ring (an `Arc<LogRing>`). Either is fine.
- `pub fn global() -> &'static LogRing`, with capacity 2000.
- `pub const MAX_MSG_CHARS: usize = 1000;`

Steps:
- [ ] **Step 1: Failing tests,** in-module, using a local subscriber:
  - `captures_level_target_message_and_fields`: `tracing::warn!(target: "q2route_service::relay", peer = 5, "boom")` produces one entry with `level == Warn`, that target, and a `msg` that contains `boom` and `peer=5`.
  - `seq_increases_and_since_filters`: three events; `since(0)` returns all 3, and `since(seq_of_first)` returns 2.
  - `ring_drops_oldest`: with cap 5 and 12 events, `since(0)` returns 5 entries, the last 5 by seq.
  - `long_message_cut_on_char_boundary`: a 1500-char Persian message is cut to `MAX_MSG_CHARS` chars plus `…`, with no panic.
  - In `crates/q2route-service/tests/engine.rs`: `get_log_answers`. `handle(GetLog { after: u64::MAX })` returns `Response::Log(v)` with `v` empty.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
  - The ring is a `Mutex<VecDeque<LogEntry>>` plus an `AtomicU64` next-seq.
  - Use a field visitor that records `message` first and then ` k=v` for the rest.
  - In `main.rs`, switch to `rolling::Builder` with `max_log_files(14)` as in the Global Constraints. If the builder fails, keep the existing `eprintln!` fallback.
  - Add `.with(log_ring::global().layer())`.
- [ ] **Step 4:** Tests pass, and clippy and fmt are clean.
- [ ] **Step 5:** Commit `feat(service): in-memory log ring, GetLog, 14-day log retention`.

### Task 2: Log page (UI)

**Files:**
- Create: `crates/q2route-ui/src/views/log.rs`.
- Modify:
  - `crates/q2route-ui/src/views/mod.rs`.
  - `crates/q2route-ui/src/app.rs`. Route `Page::Log` to `LogView`. Like Connections, it is drawn outside the shared `ScrollArea` because it has its own virtualised one. Remove `placeholder` if nothing else uses it.
  - `docs/SMOKE_TEST.md`, adding an "M11" section.

**Interfaces — Consumes:** `Request::GetLog { after }`, `Response::Log(Vec<LogEntry>)`, `LogLevel` (Task 1), and `Client::send` (returns a `oneshot::Receiver<Response>`). Use the same poll pattern as `views/usage.rs`: one pending receiver, then the next request sent when it is due.

**Pure helpers, tested:**
- `pub struct LogBuf { entries: VecDeque<LogEntry>, last_seq: u64 }`, with `pub fn merge(&mut self, new: Vec<LogEntry>)`.
  - It appends and caps at 2000.
  - If `new` is non-empty and `new[0].seq <= last_seq`, it clears first (the service restarted).
  - It sets `last_seq` to the max seq.
- `pub enum LevelFilter { Errors, Warnings, Info }`, with `fn shows(self, l: LogLevel) -> bool`.
- `pub fn visible<'a>(buf: &'a LogBuf, f: LevelFilter, search: &str) -> Vec<&'a LogEntry>`.
- `pub fn hms(ms: u64, offset_min: i32) -> String`, which returns `HH:MM:SS`.
- `pub fn short_target(t: &str) -> &str`.

Steps:
- [ ] **Step 1: Failing tests.**
  - `merge_appends_and_caps`.
  - `merge_resets_on_seq_going_back`.
  - `filter_levels_and_search`: Errors shows only Error; Warnings shows Error and Warn; Info shows all; the search `"RELAY"` matches target `q2route_service::relay`.
  - `hms_applies_offset`: `hms(0, 210) == "03:30:00"` (Iran is +03:30), and `hms(0, -60) == "23:00:00"`.
  - `short_target_takes_last_segment`.
- [ ] **Step 2:** Implement the helpers and the view.
  - When not connected, show nothing besides the global banner and don't send.
  - Ignore `Response::Error` from `GetLog`; don't put it in `requests.last_error`.
  - Re-read the timezone offset at most once a minute.
- [ ] **Step 3: Smoke rows (M11).**
  - **L1:** open Log, and recent service lines appear within 1 s.
  - **L2:** Start/Stop routing from the dashboard, and the lines appear live.
  - **L3:** the Errors filter hides info lines.
  - **L4:** search narrows the rows.
  - **L5:** Pause freezes the view; Resume catches up.
  - **L6:** Copy, then paste into Notepad.
  - **L7:** "Open log folder" opens the logs folder.
  - **L8:** restart the service with the page open; it shows fresh lines without duplicates.
- [ ] **Step 4:** Run `cargo test --workspace`, clippy and fmt.
- [ ] **Step 5:** Commit `feat(ui): live Log page with level filter; smoke steps`.
