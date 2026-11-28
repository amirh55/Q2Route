# Q2Route M14 App Rules Implementation Plan

> **For agentic workers:** Use executing-plans / test-driven-development; complete each task with focused tests and small commits.

**Goal:** Add per-app routing and connection context-menu internet controls without direct fallback.

**Architecture:** Config owns ordered AppRule entries. RuleSet compiles enabled patterns using AppMatcher; the first matching own-process rule wins before groups. IPC replaces the list through Engine::apply. UI edits the snapshot list and sends SetAppRules.

**Tech Stack:** Rust, serde/TOML, egui 0.37, windows-sys native dialogs.

**Spec:** User-supplied M14 specification in this session.

## Global constraints
- Work on m14 from main; no merge or push. English UI; plain text glyphs.
- Never run service lifecycle commands, application binaries, .cmd scripts, installer/package scripts, ignored tests, or network tests. Never read live ProgramData or v2rayN configuration.
- Use temporary test paths. Missing proxy is Block, never Direct.
- Every commit ends with Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>.

## Decisions and review focus
- App rules apply only to the process's own exe; child processes are NOT included.
- First enabled matching app rule wins, preserving list order. Existing infrastructure exclusions stay intact; groups otherwise run unchanged.
- Deleted proxy references remain loadable/editable and compile as Block.
- Duplicate UI entries compare normalized Windows paths case-insensitively, respecting folder trailing backslash.
- Exact-path context-menu rules must outrank broader folder/name rules.
- Existing direct/UDP flows are re-evaluated via the same cache invalidation as group action changes. Inspect proxied TCP cancellation; implement safe termination if feasible, otherwise report the exact limitation.

## Task 1: Core config and decision rules
**Files:** core/src/config.rs, ruleset.rs, decide.rs, ipc.rs; core/tests/config.rs, decide.rs, ipc.rs.
**Interfaces:** AppRule { app: String, action: Action, enabled: bool }; Config.app_rules: Vec<AppRule> (serde empty default); Request::SetAppRules(Vec<AppRule>).
- [x] Add failing tests for precedence, disabled, recursive folder, own process only, missing proxy, old config and invalid pattern, IPC round-trip.
- [x] Run focused core tests to observe missing feature.
- [x] Implement config validation, enabled matcher compilation, fail-closed routes, and decision priority (including DNS path).
- [x] Run core tests and commit.

## Task 2: Engine live apply and existing flows
**Files:** service/src/engine.rs, classify.rs / relay.rs as needed; service/tests/engine.rs.
**Interfaces:** SetAppRules delegates to existing apply mutation path; compile/save/swap/cache invalidation remain atomic on failure.
- [x] Add failing engine tests for replacement, persistence, rollback, and live compiled behavior without starting capture or networking.
- [x] Implement request handling and feasible existing-flow termination using group-change machinery.
- [x] Test synthetic flows/cancellation without network; document any surviving proxied-flow limitation.
- [x] Run focused service tests and commit.

## Task 3: UI and native pickers
**Files:** ui/src/views/app_rules.rs (new), groups.rs, connections.rs, views/mod.rs, app.rs, file_dialog.rs, ui/Cargo.toml if Windows features required.
**Interfaces:** shared process picker using ListProcesses; pure duplicate/add/block/allow helpers; SetAppRules replacement requests.
- [x] Add failing pure helper tests for normalized duplicates, exact context-menu block upsert/allow disable and priority.
- [x] Reuse running-process picker; add exe-filtered open dialog and native folder picker, with no new crate.
- [x] Add App rules nav after Groups & rules, enabled/app/route/remove table, full-path tooltip, red proxy deleted state.
- [x] Add connection-row Block internet / Allow internet actions using exact exe paths; surface errors, never invent Direct restore.
- [x] Run UI tests and commit.

## Task 4: Documentation and verification
**Files:** docs/SMOKE_TEST.md; .superpowers/sdd/m14/report.md.
- [x] Add M14 table covering all pickers, duplicates, routes, deleted proxy, checkbox restore, context-menu block/allow, existing flows and no blocked traffic.
- [x] Run cargo fmt --all, cargo test --workspace, cargo clippy --workspace --all-targets (no warnings); confirm formatting with --check.
- [x] Graphify update skipped per the explicit continuation request.
- [x] Review diff and branch, record commit SHAs and unverified manual/live behavior in report; commit documentation. No push/merge.
