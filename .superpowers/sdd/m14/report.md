# M14: App rules — implementation report

Status: implemented and verified on m14. No merge or push. Live manual acceptance remains unverified.

## Built
- Backward-compatible AppRule config model, ordered own-process matchers, validation, SetAppRules IPC and atomic engine apply.
- App rules table after Groups & rules: shared running process picker, native exe/folder pickers, enabled toggle, named route selector, removal, duplicate feedback and deleted-proxy warning.
- Exact executable paths in connection IPC; context-menu Block upserts and prioritizes an exact-path rule, Allow disables it without forcing Direct.
- Cache invalidation and rule-change notification cancel newly blocked TCP relay tasks and UDP sessions without direct fallback.
- M14 smoke-test table added; live manual checks remain pending.

## Decisions
- First enabled matching app rule wins before groups; only process's own executable is matched, never children.
- Routing infrastructure exclusions remain authoritative.
- Missing proxy references remain valid configuration and compile as Block.
- Paths compare case-insensitively with normalized separators. Context block prepends the exact-path rule to outrank broad folder/name rules.
- Cancellation is asynchronous; transmitted/kernel-buffered bytes cannot be recalled. Existing proxy flows never downgrade to Direct.
- Domain-only group changes yielding NeedDomain are not proactively cancelled by the domain-less relay cancellation check; own-exe AppRule Block is definitive.
- Graphify update skipped per explicit continuation instruction.

## Tests and final evidence
- Core focused tests: config 38, decide 55, IPC 11, matchers 9, ruleset 4, suggest 4 passed.
- UI: five pure app-rule helpers and three dialog-buffer tests passed.
- Engine internal test covers replacement, persistence, compiled live policy, deleted proxy, validation/save rollback and cache notification behavior.
- Service/tests/engine.rs adds SetAppRules replacement/snapshot/persistence/rollback/empty-list test; passed.
- Three synthetic relay-policy tests cover TCP/UDP cancellation and unrelated rules.
- cargo check --workspace --offline passed.
- cargo clippy --workspace --all-targets --offline -- -D warnings passed without warnings.
- cargo fmt --all --check passed.
- Final cargo test --workspace --offline: 545 passed, 0 failed, 2 ignored. Existing suite uses local loopback fixtures under the previously granted loopback permission; no internet tests intentionally run. Log: C:/Users/Marketing-369/AppData/Local/hermes/cache/scratch/q2route-m14-final-tests.log (ephemeral).
- Four pure coordinator regressions cover rapid blocks, stale snapshots, failed write recovery and cross-page supersession; service UDP/TCP DNS regressions preserve bootstrap precedence.

## Commits
- 7d73509 — preserve connection executable paths.
- 8df603a — native executable/folder pickers.
- 2c0b625 — core app routing.
- adceb4c — service apply and relay cancellation.
- cb6ea24 — UI page and exact-path controls.
- d4b2f93 — engine IPC integration test.
- f1e01d2 — process-aware service DNS.
- 4eb9acf — shared cross-page UI app-rule writer and race regressions.

The following documentation commit records this report; its SHA is available via git log (the file cannot embed its own content-dependent commit SHA).

## Unverified / remaining
- No live service capture, real application traffic, native dialogs, installer or service lifecycle exercised.
- Manual smoke rows are intentionally blank; no claim that real blocked-app traffic was observed.
- Process-aware DNS integration fixed in f1e01d2 for UDP and TCP, preserving bootstrap exclusions; synthetic regression tests passed.
- Independent review found missing DNS integration and snapshot-derived whole-list lost updates. Both were fixed with regression tests followed by the final workspace run. No deferred findings.
- Shared Requests coordinator serializes writes across both pages and waits for acknowledgment plus ordered GetState; stale cached snapshots do not undo edits or freeze the page.
- A UI subagent mistakenly invoked graphify despite the skip instruction, creating untracked artifacts. These were removed and not committed; this deviation is disclosed.
- Cancellation requires owning process identification to remain available in ProcessTree; real socket/NAT teardown is not independently verified on live capture.
- No merge or push performed.
