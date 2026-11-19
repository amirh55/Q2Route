# Q2Route M12: Remaining settings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Settings page from spec §6:
- geo data status and an "Update now" button
- export and import of the configuration
- a theme choice
- a switch for the tray's traffic graph

The kill switch is dropped; the user said so on 2026-11-07.

**Architecture:**
- **Geo data and import** are handled by the service. The service owns `%ProgramData%\Q2Route\` and applies rules live.
- **Export** happens in the UI. It serialises the config it already has in `StateSnapshot.config`.
- **Theme and tray graph** are UI-only settings in `UiSettings` (`%APPDATA%\Q2Route\ui.toml`).
- **File pickers** use the Windows common dialogs from `windows-sys` (`GetOpenFileNameW` / `GetSaveFileNameW`, feature `Win32_UI_Controls_Dialogs`). No new crate is added.

**Tech Stack:** Rust. Existing crates: serde, toml 0.9, windows-sys 0.61 and egui 0.37.

**Spec:** `docs/specs/2026-11-05-q2route-design.md` §6, Settings: "Start with Windows, minimize/close to tray, tray traffic icon on or off, kill switch, geo data update, theme, export/import, a 'Leak check' button."

## Global Constraints

- **Secrets.**
  - Export leaves out proxy passwords by default. A checkbox, "Include proxy passwords", is off by default. When it's on, a warning line appears: `The file will contain your proxy passwords in plain text.`
  - On import, a profile whose `password` is missing keeps the current password of the profile with the same id, if there is one.
- **Import is all or nothing.**
  - The file is parsed, migrated (`Config::migrate`) and validated (`Config::validate`) first. Nothing changes unless all three pass. On failure, the error says why, for example `Import failed: line 12: ...` or a validation error.
  - On success, the current `config.toml` is copied to `config.toml.bak` (overwriting it), and then the new config is applied live through the normal `apply` path.
  - The import file is at most 1 MiB. A bigger file is refused before parsing.
- **Geo update.**
  - "Update now" does exactly what Start does today: `GeoCache::reload(&winapi::list_processes())`, then recompile and apply the rules if routing is running.
  - It doesn't download anything. If no proxy program with geo files is running, it says `No newer geo files found (v2rayN, xray, v2ray or sing-box must be running).`
- **Theme.** Three options: `Dark` (the default, as now), `Light` and `Follow Windows`. Follow Windows maps to `egui::ThemePreference::System`. The choice applies immediately and is saved to `ui.toml`.
- **Tray graph.** `tray_graph: bool` defaults to `true` with serde default, so the current behaviour stays. When it's off, the tray shows the plain running/stopped icon with no traffic bars. The tooltip and menu don't change.
- **Old files.** An existing `ui.toml` without the new fields loads with the defaults.
- **Housekeeping.** clippy is clean (`--workspace --all-targets`), fmt has been run, and all tests pass. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Subagents must not:**
  - stop, start or install the Q2Route service;
  - run `.cmd` scripts;
  - launch or kill `q2route.exe` or any other process;
  - run `#[ignore]` tests;
  - touch the real `%ProgramData%` or `%APPDATA%`;
  - open `C:\ProgramData\Q2Route\config.toml` or any v2rayN config;
  - open file dialogs from tests.

## Decisions (builder's calls)

- **IPC** (`q2route_core::ipc`):
  - `Request::GetGeoStatus` returns `Response::Geo(GeoStatus)`.
  - `Request::UpdateGeo` returns `Response::Geo(GeoStatus)`, with `updated` set.
  - `Request::ImportConfig(Config)` returns `Response::Ok` or `Response::Error(..)`.
  - `GeoStatus { geoip: Option<GeoFile>, geosite: Option<GeoFile>, updated: Vec<String> }`. Here `GeoFile { modified_ms: u64, size: u64 }`, and `updated` lists the file names that were copied in this call.
- **Parsing in core.** Add `Config::parse(s: &str) -> Result<Config, ConfigError>` to `config.rs`. It parses, migrates and validates. `Config::load` reuses it, so the two paths can't drift apart. The UI parses the chosen file with `Config::parse` too, which means errors are shown before anything is sent.
- **Export.** Use `toml::to_string_pretty(&cfg)` with passwords set to `None` unless the box is ticked. The suggested file name is `q2route-config.toml`.
- **Dialogs** (`crates/q2route-ui/src/file_dialog.rs`):
  - `pub fn pick_open(filter: &str) -> Option<PathBuf>`
  - `pub fn pick_save(default_name: &str) -> Option<PathBuf>`
  - Each is a modal call on the UI thread, owned by the main window's HWND (the one `dpi_guard` already takes from the frame), with the filter `TOML files (*.toml)`.
  - This is the only unsafe code. It isn't unit tested; it's covered by the smoke rows.
- **Settings page sections,** in order:
  1. the existing General section
  2. Appearance (theme, tray graph)
  3. Geo data
  4. Backup (Export, Import)
  5. the existing Leak check
- **The Geo data section** shows `geoip.dat: 2026-11-15 (4.1 MB)` and the same for geosite, or `missing`, plus the "Update now" button. After an update, it shows `Updated: geosite.dat` or the no-newer-files line.
- **Import confirmation.** Before sending, show `Replace all groups, rules and proxies with this file? A backup is kept as config.toml.bak.` with Yes and No.

## Review Focus

1. **A malformed or hostile import file** (bad TOML, a binary file, or a 50 MB file). It is refused with a message, nothing changes, and there's no panic. Tests: `parse_rejects_bad_toml` and `import_too_big_refused`.
2. **An export without passwords, then an import on the same machine.** The proxies keep working, because the passwords are kept by profile id. Test: `import_keeps_password_when_missing`.
3. **An import from an older config version** (`seed_version` 1). It is migrated like `Config::load` would migrate it. Test: `parse_migrates_old_version`.
4. **Geo update while routing is stopped.** The files are copied and nothing starts. Test: `update_geo_when_stopped_does_not_start`.
5. **An old `ui.toml`.** It loads with `theme = Dark` and `tray_graph = true`. Test: `ui_settings_defaults_for_old_file`.

---

### Task 1: Service and core: `Config::parse`, geo status/update, import

**Files:**
- Modify: `crates/q2route-core/src/config.rs` (add `parse`, and make `load` use it).
- Modify: `crates/q2route-core/src/ipc.rs`.
- Modify: `crates/q2route-service/src/geo.rs`. Add `pub fn status(&self) -> GeoStatus`, and make `reload` return the copied file names as a `Vec<String>`. Keep its existing caller working.
- Modify: `crates/q2route-service/src/engine.rs`. Add the three arms. For `ImportConfig`:
  1. Copy `config.toml` to `config.toml.bak`.
  2. Fill the missing passwords from the current config.
  3. Run `apply(|c| { *c = new; Ok(()) })`.
- Test: in-module tests in `config.rs` and `geo.rs`, plus `crates/q2route-service/tests/engine.rs`.

Steps:
- [ ] **Step 1: Failing tests.**
  - `parse_rejects_bad_toml`.
  - `parse_migrates_old_version`: a v1 config with a `geosite:` entry in `direct_names` comes out at `seed_version` 2, the same way `load` does it.
  - `load_and_parse_agree`.
  - `geo_status_reports_files` (uses a temp dir).
  - Engine tests:
    - `import_replaces_config_and_keeps_backup`.
    - `import_keeps_password_when_missing`.
    - `import_invalid_changes_nothing`.
    - `update_geo_when_stopped_does_not_start`.
  - Use the existing engine test setup with a temp dir; never `%ProgramData%`.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests, clippy and fmt pass.
- [ ] **Step 5:** Commit `feat(service): geo status/update and config import`.

### Task 2: UI: Appearance, Geo data, Backup sections; smoke rows

**Files:**
- Create: `crates/q2route-ui/src/file_dialog.rs`.
- Modify:
  - `crates/q2route-ui/src/settings.rs`: `theme: Theme` (`Dark` | `Light` | `System`, default `Dark`) and `tray_graph: bool` (default `true`).
  - `crates/q2route-ui/src/views/settings.rs` (the new sections).
  - `crates/q2route-ui/src/app.rs`: apply the theme at start and on change, and pass `tray_graph` to the tray.
  - `crates/q2route-ui/src/tray.rs`: a plain icon when the graph is off.
  - `crates/q2route-ui/Cargo.toml`: the `Win32_UI_Controls_Dialogs` feature.
  - `docs/SMOKE_TEST.md`: an "M12" section.

**Interfaces — Consumes:** `Request::{GetGeoStatus, UpdateGeo, ImportConfig}`, `Response::Geo(GeoStatus)` and `Config::parse` (Task 1). Requests use the single-pending-receiver pattern from `views/usage.rs`. Send `GetGeoStatus` once when the Settings page opens, and again after `UpdateGeo`.

**Pure helpers, tested:**
- `pub fn export_text(cfg: &Config, with_passwords: bool) -> String`.
- `pub fn read_import(path: &Path) -> Result<Config, String>`. It checks the 1 MiB size limit, then reads and calls `Config::parse`.
- `pub fn fmt_geo(f: Option<&GeoFile>, offset_min: i32) -> String`, which returns `2026-11-15 (4.1 MB)` or `missing`. Reuse `views/usage::fmt_bytes`, and the timezone offset helper from `views/log.rs` (make it `pub(crate)` if needed).

Steps:
- [ ] **Step 1: Failing tests.**
  - `export_strips_passwords`.
  - `export_with_passwords_keeps_them`.
  - `export_then_parse_roundtrips`.
  - `import_too_big_refused` (a temp file over 1 MiB).
  - `fmt_geo_formats`.
  - `ui_settings_defaults_for_old_file`.
- [ ] **Step 2:** Implement the helpers, the dialogs, the sections, the theme and the tray switch.
- [ ] **Step 3: Smoke rows (M12).**
  - **S1:** Light, then Follow Windows, then Dark switches the theme immediately, and the choice is still there after reopening the UI.
  - **S2:** turn off the tray graph, and the tray icon becomes plain.
  - **S3:** the Geo data section shows dates. With v2rayN running after its geo update, Update now copies and shows `Updated: ...`. Without newer files, it shows the no-newer-files line.
  - **S4:** Export without passwords; the file has no `password` lines.
  - **S5:** change a group, then Import the exported file. The confirmation appears, the group comes back, `config.toml.bak` exists and the proxies still connect.
  - **S6:** importing a random `.txt` renamed to `.toml` shows an error, and nothing changes.
- [ ] **Step 4:** Run `cargo test --workspace`, clippy and fmt.
- [ ] **Step 5:** Commit `feat(ui): theme, tray graph switch, geo update, export/import`.
