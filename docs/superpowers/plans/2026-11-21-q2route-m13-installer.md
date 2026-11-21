# Q2Route M13: Installer and update check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- **One setup file.** A single `Q2Route-Setup-<version>.exe` installs Q2Route and also updates an existing install, including one made from the old zip, in place. Settings are kept.
- **Update check.** The app checks GitHub for a newer release and offers "Install update": it downloads the new setup and runs it.

**Architecture:**
- **Installer.** It is built with Inno Setup 6 from `installer/q2route.iss` and does the same steps `Install.cmd` / `Uninstall.cmd` do today. Before copying files, it stops and removes the service by name, which also takes care of a service registered from a zip folder. The UI is closed through Inno's `CloseApplications`, with `taskkill` as a fallback.
- **Packaging.** `scripts/package.ps1` gains a `-Setup` switch that runs `ISCC.exe` with `/DAppVersion=<workspace version>`.
- **Update check.** It lives in the UI (`crates/q2route-ui/src/update.rs`) and uses WinHTTP from `windows-sys`, which handles TLS and redirects without a new crate.

**Tech Stack:**
- Inno Setup 6, installed on the build machine with `winget install -e --id JRSoftware.InnoSetup`. The user approved the download.
- Rust: windows-sys 0.61, adding the features `Win32_Networking_WinHttp` and `Win32_Security_Cryptography` (BCrypt SHA-256).
- serde_json, which the UI already uses.

**Spec:** `docs/specs/2026-11-05-q2route-design.md`. A real installer and easy updates were requested by the user on 2026-11-21.

## Global Constraints

- **Version.** The workspace version becomes `0.2.0`. From now on, releases are tagged `v<version>` and are **not** pre-releases, so `/releases/latest` returns them.
  - The update check compares the latest tag, minus its `v`, against `env!("CARGO_PKG_VERSION")` as numeric `major.minor.patch`.
  - Older `v0.1.0-mN` tags are ignored.
- **The update source** is one constant: `pub const UPDATE_REPO: &str = "amirh55/Q2Route";`. Its releases must be public.
- **Install location.** The app goes to `{autopf}\Q2Route` (Program Files). The installer needs admin rights (`PrivilegesRequired=admin`).
  - Data stays where it is: `%ProgramData%\Q2Route` (config, geo, usage, logs) and `%APPDATA%\Q2Route\ui.toml`.
  - Uninstall asks `Also delete Q2Route's settings, rules and logs?`, default **No**.
- **Setup steps, in order** (`[Code]` `PrepareToInstall`):
  1. If `Proxifier.exe` is running, abort with `Proxifier is running. Exit it fully (tray icon too), then run Setup again.`
  2. Close `q2route.exe`.
  3. If service `Q2Route` exists, run `q2route-service.exe uninstall`. Use the new exe extracted to `{tmp}`; it works by service name, so it doesn't matter where the old copy lives.
  4. Copy the files.
  5. Run `{app}\q2route-service.exe install`. If it fails, show its output and stop.
  6. Launch `q2route.exe` as the original, non-elevated user (`runasoriginaluser`), unless `/SILENT` was given together with `/NOLAUNCH`.
- **Files installed:** `q2route.exe`, `q2route-service.exe`, `WinDivert.dll`, `WinDivert64.sys`, `WinDivert-LICENSE.txt`, plus a Start menu shortcut "Q2Route". An optional desktop shortcut is unticked by default. `Install.cmd`, `Uninstall.cmd` and `OpenLog.cmd` are not installed.
- **Autostart path.** "Start with Windows" stores the exe path. On every start with `start_with_windows = true`, the UI rewrites the Run value with its current exe path, so moving from a zip folder to Program Files keeps autostart working.
- **Update check behaviour.**
  - Settings > Updates has "Check for updates automatically", on by default (`check_updates: bool`, serde default `true`), and a "Check now" button.
  - Automatic checks happen 10 s after start and then every 24 h while running, with at most one request in flight.
  - Request: GET `https://api.github.com/repos/{UPDATE_REPO}/releases/latest` with `User-Agent: Q2Route/<version>` and `Accept: application/vnd.github+json`.
  - A timeout (15 s), a 404 or a parse error is silent for automatic checks. For "Check now" it shows `Could not check for updates: <reason>`.
- **When a newer version exists:**
  - A banner shows above the page: `Q2Route <v> is available.` with the buttons `Install update`, `Release notes` (opens `html_url` in the browser) and `Later` (hides it until the next start).
  - **Install update:**
    1. Download the asset whose name matches `Q2Route-Setup-*.exe` to `%TEMP%\Q2Route-Setup-<v>.exe`, with progress shown as text (`Downloading… 3.1 / 6.0 MB`).
    2. Check that the size equals the asset `size`.
    3. If the asset has a `digest` of the form `sha256:<hex>`, the SHA-256 must match. On a mismatch, delete the file and show `Update download is damaged, try again.`
    4. Run the setup with `/SILENT /SUPPRESSMSGBOXES /NORESTART` through `ShellExecuteW` with the verb `open` (Windows shows the UAC prompt).
    5. Then exit the UI. The setup relaunches it.
  - Response and download caps: the JSON at most 1 MiB, the setup at most 100 MB.
- **Housekeeping.**
  - clippy is clean, fmt has been run, and tests pass.
  - Tests never touch the network. Pure parsing and comparison are tested; WinHTTP is covered by smoke rows.
  - Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Subagents must not:**
  - stop, start or install the Q2Route service;
  - run `.cmd` scripts or the built setup;
  - launch or kill `q2route.exe`;
  - run `#[ignore]` tests;
  - touch the real `%ProgramData%` or `%APPDATA%`;
  - open `config.toml` or any v2rayN config.

## Review Focus

1. **Old zip install, then setup.** The service ends up registered from Program Files, not the Downloads folder, and the config and rules are unchanged. This is covered by smoke row I2.
2. **Setup running while the service is routing.** The files are not locked (the service is removed before copying), and the setup doesn't fail half way. This is covered by smoke row I3.
3. **A damaged or partial download.** It is never run. Tests: `digest_mismatch_rejected` and `size_mismatch_rejected`.
4. **Pre-release and odd tags** (`v0.1.0-m12`, `nightly`). They never count as newer. Test: `version_compare`.
5. **GitHub unreachable, or rate limited (403).** Nothing is shown for automatic checks, and there's no repeated hammering: one try per 24 h. Test: `schedule_backs_off`.

---

### Task 1: Inno Setup script and packaging

**Files:**
- Create: `installer/q2route.iss`.
- Modify: `scripts/package.ps1`: add `-Setup`, which builds the release and then runs `ISCC.exe` (looked up in `${env:ProgramFiles(x86)}\Inno Setup 6`, `$env:ProgramFiles\Inno Setup 6` and `$env:LOCALAPPDATA\Programs\Inno Setup 6`) to write `dist\Q2Route-Setup-<version>.exe`. It also still writes the portable zip `dist\Q2Route-<version>-win-x64.zip`.
- Modify: the root `Cargo.toml`, setting the workspace version to `0.2.0`.
- Modify: `docs/SMOKE_TEST.md`, adding an "M13 installer" section with rows I1–I6.

Inno details:
- `AppId={{8E3C2F4A-6B1D-4F7E-9A52-Q2ROUTE00001}`. Replace this with a real fixed GUID you generate once, and never change it.
- `AppName=Q2Route`, `AppVersion={#AppVersion}`, `AppPublisher=Q2Route`, `DefaultDirName={autopf}\Q2Route`, `DisableProgramGroupPage=yes`, `ArchitecturesAllowed=x64compatible`, `ArchitecturesInstallIn64BitMode=x64compatible`, `CloseApplications=yes`, `RestartApplications=no`, `UninstallDisplayIcon={app}\q2route.exe`, `OutputBaseFilename=Q2Route-Setup-{#AppVersion}`, `SolidCompression=yes`, `WizardStyle=modern`.
- `[UninstallRun]`: `taskkill /IM q2route.exe /F`, then `{app}\q2route-service.exe uninstall`, both with `runhidden`.
- `[Code]`: `PrepareToInstall` as in the Global Constraints, and the uninstall data question in `CurUninstallStepChanged(usPostUninstall)`.
- A `/NOLAUNCH` command-line switch is read with `ExpandConstant('{param:NOLAUNCH|0}')` or by scanning `ParamStr`.

Steps:
- [ ] **Step 1:** Write the script and the package switch.
- [ ] **Step 2:** Build it: `powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Setup`. Expected: `dist\Q2Route-Setup-0.2.0.exe` exists. Do **not** run the setup.
- [ ] **Step 3:** Add smoke rows:
  - **I1:** fresh install on a PC without Q2Route.
  - **I2:** install over the old zip install; afterwards the service path is in Program Files (`sc qc Q2Route`) and the groups are unchanged.
  - **I3:** run the setup while routing is on.
  - **I4:** "Start with Windows" still works after moving from the zip.
  - **I5:** uninstall with No keeps `%ProgramData%\Q2Route`; with Yes it removes it.
  - **I6:** Proxifier running aborts with the message.
- [ ] **Step 4:** Commit `feat: Inno Setup installer (setup.exe) and packaging`.

### Task 2: Update check and in-app update (UI)

**Files:**
- Create: `crates/q2route-ui/src/update.rs`.
- Modify:
  - `crates/q2route-ui/src/settings.rs`: add `check_updates`, and rewrite the Run value on start when autostart is on.
  - `crates/q2route-ui/src/app.rs`: the banner and the schedule tick.
  - `crates/q2route-ui/src/views/settings.rs`: the Updates section.
  - `crates/q2route-ui/Cargo.toml`: the features.
  - `docs/SMOKE_TEST.md`: rows U7–U9 in the M13 section.

**Interfaces — Produces** (pure, tested):
- `pub struct Release { tag: String, html_url: String, setup: Option<Asset> }`, where `Asset { name, url (browser_download_url), size: u64, sha256: Option<String> }`.
- `pub fn parse_release(json: &str) -> Result<Release, String>`.
- `pub fn newer(tag: &str, current: &str) -> bool`.
  - `newer("v0.2.1", "0.2.0") == true`, `newer("v0.2.0", "0.2.0") == false`, `newer("v0.10.0", "0.9.9") == true`.
  - `newer("v0.1.0-m12", "0.0.1") == false`, because a pre-release suffix never counts. `newer("nightly", "0.2.0") == false`.
- `pub fn verify(bytes_len: u64, sha256_hex: Option<&str>, expected: &Asset, actual_sha256: &str) -> Result<(), String>`.
- `pub struct Schedule`, with `fn due(&self, now: Instant) -> bool` and `fn mark(&mut self, now: Instant)`. The first check is due 10 s after start, the next ones every 24 h, whether the check succeeded or failed.
- The WinHTTP functions are not unit tested and run on a background `std::thread`:
  - `fn http_get(url: &str, cap: usize) -> Result<Vec<u8>, String>`
  - `fn download(url, path, cap, progress: impl Fn(u64, u64))`
  - Results come back to the UI through `std::sync::mpsc` and are polled each frame.

Steps:
- [ ] **Step 1: Failing tests.**
  - `parse_release_picks_setup_asset`: uses a trimmed real-shaped GitHub JSON with the zip and the setup assets, and a `digest` field.
  - `version_compare`.
  - `digest_mismatch_rejected`.
  - `size_mismatch_rejected`.
  - `schedule_backs_off`.
  - `check_updates_defaults_on_for_old_file`.
- [ ] **Step 2:** Implement the helpers, the WinHTTP calls, the banner and the Settings > Updates section.
  - The banner uses plain ASCII text and the default font. The `…` that is already used elsewhere is fine.
- [ ] **Step 3:** Smoke rows.
  - **U7:** with release v0.2.1 published (the next one), a 0.2.0 install shows the banner within about 10 s of start.
  - **U8:** Install update shows the UAC prompt, the setup runs silently, Q2Route reopens, and Settings shows the new version.
  - **U9:** with no network, "Check now" shows the error line, and automatic checks show nothing.
- [ ] **Step 4:** `cargo test --workspace`, clippy and fmt.
- [ ] **Step 5:** Commit `feat(ui): update check and one-click update`.
