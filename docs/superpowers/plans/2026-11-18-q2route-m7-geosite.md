# Q2Route M7: `geosite:` domain lists — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Domain rules accept v2ray `geosite:<code>` (for example `geosite:ir`, `geosite:steam`, `geosite:category-ads-all`), read from the same `geosite.dat` v2rayN uses, so Iranian sites on `.com`/`.net` (digikala.com, aparat.com, …) go Direct without listing them one by one.

**Architecture:** A new core reader `geosite.rs` decodes only the wanted codes from `geosite.dat` into a `DomainSet` (exact names, root-domain suffixes, keywords). `DomainPattern` gains a `Geo` variant that holds the set; `RuleSet::compile_with` receives it next to the `GeoIp`. The service's `GeoCache` copies and loads `geosite.dat` exactly as it already does `geoip.dat`. Because routing by name already covers SNI/Host peeks, the DNS proxy and DomainMap, `geosite:` works everywhere `*.ir` works with no change to the decision engine.

**Tech Stack:** Rust (existing crates only; no new dependencies).

**Spec:** `docs/specs/2026-11-05-q2route-design.md` — line 22 (domains include `geosite:` categories), line 32 (seed groups), line 81 (geo data read from v2ray-format files).

## Global Constraints

- **Never a leak:** a `geosite:` code with no data (file missing, unreadable, malformed, or code absent) matches nothing, so that traffic follows later groups (normally the proxy). Logged once at warn, like `geoip:`.
- No new dependencies. Reuse the protobuf `Reader` from `geoip.rs` (make it `pub(crate)`).
- Only the wanted codes are decoded; other entries are skipped by length. Loading `geosite:ir` (62,828 entries) from the 7.6 MB file must not slow Start noticeably (target well under 1 s in release).
- Matching cost per name is O(number of labels) hash lookups plus the keyword list; no linear scan of the set.
- Existing behaviour of `*.x`, exact and `keyword:` patterns is unchanged.
- `cargo clippy --workspace --all-targets` clean, `cargo fmt --all`, all tests pass; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions made in this plan (builder's calls)

- **Format:** `GeoSiteList { repeated GeoSite entry = 1; }`, `GeoSite { string country_code = 1; repeated Domain domain = 2; }`, `Domain { Type type = 1; string value = 2; repeated Attribute attribute = 3; }`, `Attribute { string key = 1; oneof { bool bool_value = 2; int64 int_value = 3; } }`. Types: `0 Plain` (keyword: substring), `1 Regex`, `2 RootDomain` (the name and its subdomains), `3 Full` (exact). Codes compare case-insensitively (the file stores `IR`, rules write `ir`).
- **Regex entries are skipped** (counted and logged at info). They are a handful in the whole file (1 in `category-ads`, 1 in `private`, none in `ir` or `steam`); skipping one only means that name follows later groups. Revisit if a list the user relies on uses them.
- **Attributes:** `geosite:<code>@<attr>` keeps only entries carrying that attribute (v2ray syntax, e.g. `geosite:category-ads@ads`). Without `@`, all entries. The wanted key is `code@attr` lowercased.
- **Seed (`SEED_VERSION` 2):** "Iranian sites" rule 1 becomes `domains = ["*.ir", "geosite:ir"]`; "Steam" rule gains a second rule `domains = ["geosite:steam"]`. We use `geosite:ir` rather than the spec's `geosite:category-ir` because in v2rayN's file `ir` is a strict superset (62,828 vs 41,618 names, every `category-ir` name included). Migration (run once, gated by `seed_version` like `geoip:ir`) adds each to an existing config only if that group id exists and no domain entry in it already equals the code (case-insensitive); `geosite:ir` goes into the rule that holds `*.ir` if there is one, else into a new rule.
- **Updates:** like `geoip.dat`, a newer `geosite.dat` next to a running v2rayN/xray/v2ray/sing-box is copied to `%ProgramData%\Q2Route` on Start. The spec's "Update geo data" download button is **not** in this milestone.
- **`direct_names` (DNS settings)** keep accepting only plain patterns: `geosite:` there is rejected by validation with a clear message, since that list is matched without geo data.

## Review Focus

1. `geosite.dat` missing or corrupt with `geosite:ir` in a Direct group: Iranian `.com` sites go to the proxy (not Direct, not blocked), the service starts, and the log says why. Test: `missing_geosite_matches_nothing` (Task 3) and `malformed_geosite_is_error` (Task 1).
2. Suffix boundary: `geosite:ir` containing `digikala.com` must match `www.digikala.com` and `digikala.com` but not `notdigikala.com` or `digikala.com.evil.net`. Test: `root_domain_matches_label_boundary` (Task 1).
3. Case and trailing dot: `WWW.Digikala.COM.` matches; a rule written `geosite:IR` loads the file's `IR` entry. Test: `codes_and_names_case_insensitive` (Task 1).
4. A rule mixing `geosite:ir` with an app condition or port: conditions still AND as before. Test: `geosite_and_port_anded` (Task 2).
5. A flow whose name is unknown on 443 with a `geosite:` rule: same `NeedDomain` peek as `*.ir` (no regression to Direct). Test: `geosite_rule_needs_domain_like_suffix` (Task 2).

---

### Task 1: `geosite.dat` reader (`crates/q2route-core/src/geosite.rs`)

**Files:**
- Create: `crates/q2route-core/src/geosite.rs`
- Modify: `crates/q2route-core/src/geoip.rs` (make `Reader`, `Field`, the error type usable from `geosite.rs`: `pub(crate)`)
- Modify: `crates/q2route-core/src/lib.rs` (`pub mod geosite;`)
- Test: `crates/q2route-core/tests/geosite.rs`

**Interfaces — Produces:**
- `pub struct DomainSet` with `pub fn contains(&self, host: &str) -> bool`, `pub fn len(&self) -> usize`, `pub fn is_empty(&self) -> bool`, `pub fn from_entries(full: &[&str], roots: &[&str], keywords: &[&str]) -> DomainSet` (for tests elsewhere).
- `pub struct GeoSite` (`Default`, `Clone`) with `pub fn parse(data: &[u8], wanted: &[String]) -> Result<GeoSite, GeoSiteError>` and `pub fn get(&self, key: &str) -> Option<Arc<DomainSet>>`; `key` is `code` or `code@attr`, lowercase. `pub fn skipped_regex(&self, key: &str) -> usize`.
- `#[derive(Debug, thiserror::Error)] #[error("malformed geosite.dat: {0}")] pub struct GeoSiteError(&'static str);`

`contains` lowercases and strips one trailing dot, then: exact set hit; else for each suffix starting at a label boundary (the whole name, then after each `.`) a root-set hit; else any keyword is a substring.

- [ ] **Step 1: Write failing tests** in `tests/geosite.rs`, building a fixture with a small hand-written protobuf encoder in the test (varint + length-delimited helpers) holding codes `IR` (root `digikala.com`, root `ir`, full `exact.example`, plain `snapp`, regex `^ads\d+\.com$`), `STEAM` (root `steampowered.com`) and `ADS` (root `a.com` with attribute `ads`, root `b.com` without):
  - `root_domain_matches_label_boundary`: `www.digikala.com`, `digikala.com`, `x.y.ir` match; `notdigikala.com`, `digikala.com.evil.net`, `iran.com` don't.
  - `full_and_keyword`: `exact.example` matches, `a.exact.example` doesn't; `mysnapp.net` matches (keyword).
  - `codes_and_names_case_insensitive`: wanted `["ir"]` loads `IR`; `WWW.Digikala.COM.` matches.
  - `only_wanted_codes_decoded`: wanted `["ir"]` → `get("steam")` is `None`; `get("ir")` has 4 entries (regex skipped) and `skipped_regex("ir") == 1`.
  - `attribute_filter`: wanted `["ads@ads"]` → set contains `a.com`, not `b.com`; wanted `["ads"]` contains both.
  - `malformed_geosite_is_error`: truncated buffer → `Err`.
  - `real_file_smoke` (`#[ignore]`, reads `C:\v2rayN\bin\geosite.dat` if present): `ir` contains `digikala.com`, loads in under 1 s in release.
- [ ] **Step 2:** `cargo test -p q2route-core --test geosite` → fails (module missing).
- [ ] **Step 3:** Implement as specified above. Unknown domain types are skipped like regex (counted together).
- [ ] **Step 4:** Tests pass; `cargo clippy -p q2route-core --all-targets` clean.
- [ ] **Step 5:** Commit `feat(core): read geosite.dat domain lists`.

### Task 2: `geosite:` in rules and the seed

**Files:**
- Modify: `crates/q2route-core/src/matchers.rs` (`DomainPattern::Geo`, `parse_with`, `geosite_codes`)
- Modify: `crates/q2route-core/src/ruleset.rs` (`wanted_geosite`, `compile_with(cfg, geo, sites)`)
- Modify: `crates/q2route-core/src/config.rs` (seed, `SEED_VERSION = 2`, migration, `direct_names` validation)
- Modify callers of `compile_with` (service `geo.rs` only; keep `RuleSet::compile` as the no-data form)
- Test: `crates/q2route-core/tests/{matchers,decide,config}.rs`

**Interfaces:**
- Consumes: `GeoSite`, `DomainSet` (Task 1).
- Produces: `DomainPattern::Geo { key: String, set: Option<Arc<DomainSet>> }`; `DomainPattern::parse_with(s: &str, sites: &GeoSite) -> Result<Self, MatchError>` (`parse` = `parse_with(s, &GeoSite::default())`); `pub fn geosite_codes<'a>(domains: impl IntoIterator<Item = &'a String>) -> Vec<String>` (sorted, deduped, lowercase keys incl. `@attr`); `RuleSet::wanted_geosite(cfg: &Config) -> Vec<String>`; `RuleSet::compile_with(cfg: &Config, geo: &GeoIp, sites: &GeoSite) -> Result<RuleSet, MatchError>`.

`geosite:` with an empty code, or `@` with an empty attribute, is `MatchError::Domain`.

- [ ] **Step 1: Failing tests:**
  - matchers: `geosite_matcher` — with data, `geosite:ir` matches `www.digikala.com`; without data it parses and matches nothing; `geosite:` and `geosite:ir@` are errors; `geosite_codes(["geosite:IR", "*.ir", "geosite:ir", "geosite:ads@Ads"]) == ["ads@ads", "ir"]`.
  - decide: `geosite_ir_direct` (browser to `www.digikala.com:443` with the seed + data → Direct via "iranian-sites"); `geosite_missing_data_goes_to_proxy` (same flow, no data → Proxy "everything-else"); `geosite_rule_needs_domain_like_suffix` (domain unknown, TCP 443, foreign IP → `NeedDomain`); `geosite_and_port_anded` (rule `domains=["geosite:ir"], ports=["8443"]` doesn't match on 443).
  - config: `seed_has_geosite` (Iranian sites rule 1 is `["*.ir", "geosite:ir"]`, Steam has a `geosite:steam` rule); `migrate_adds_geosite_once` (a `seed_version = 1` config gains both, a second migrate changes nothing, an existing `GEOSITE:IR` isn't duplicated, a config without the `steam` group gets only the Iranian one); `direct_names_reject_geosite`.
- [ ] **Step 2:** Run, confirm failures.
- [ ] **Step 3:** Implement. Migration from 0 applies both the version-1 and version-2 additions.
- [ ] **Step 4:** `cargo test --workspace` passes (update any test that pinned `SEED_VERSION == 1` or the seed's exact domains).
- [ ] **Step 5:** Commit `feat(core): geosite: domain rules; seed geosite:ir and geosite:steam`.

### Task 3: Load `geosite.dat` in the service; UI text; smoke rows

**Files:**
- Modify: `crates/q2route-service/src/geo.rs` (both files), `crates/q2route-service/src/engine.rs` only if a call changes
- Modify: `crates/q2route-ui/src/views/groups.rs` (HINT), `crates/q2route-ui/src/views/dashboard.rs` (`rule_summary`)
- Modify: `scripts/package.ps1` only if it copies `geoip.dat` (copy `geosite.dat` the same way)
- Modify: `docs/SMOKE_TEST.md` (new "M7" section)

**Interfaces:** Consumes `GeoSite::parse`, `RuleSet::wanted_geosite`, `RuleSet::compile_with` (Tasks 1–2).

Generalise `GeoCache` so the copy-newer-from-proxy-program and load-only-wanted-codes logic serves both `geoip.dat` and `geosite.dat` (one helper parameterised by file name, not two copies). The cache key becomes (wanted geoip, wanted geosite); each file reloads only when its own codes change or on `reload`. Logs: `geosite:<key>: <n> names` (info), `geosite:<key>: <n> regex entries skipped` (info, only when n > 0), `geosite:<key>: no data, so these rules match nothing (that traffic follows later groups)` (warn).

UI: HINT domains part becomes `Domains: example.com, *.ir, keyword:steam, geosite:ir.`; `rule_summary` shows `geosite:ir` as `GeoSite IR` (and `geosite:ads@ads` as `GeoSite ADS@ADS`).

- [ ] **Step 1: Failing tests** in `geo.rs`: `finds_and_copies_geosite_like_geoip` (v2rayN layout with both files; both copied when newer); `missing_geosite_matches_nothing` (seed config, no file → `www.digikala.com` doesn't match rule 1's `geosite:ir`, `*.ir` still works); `loads_geosite_codes` (fixture file with `IR` → `geosite:ir` matches); UI: `rule_summary_geosite`.
- [ ] **Step 2:** Run, confirm failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt.
- [ ] **Step 5:** SMOKE rows (M7): G1 log shows `geosite:ir: <n> names` after Start; G2 `digikala.com` and `aparat.com` show Direct / "Iranian sites" on Connections and the Iranian IP on a what-is-my-IP page hosted in Iran; G3 `ifconfig.me` still shows the German IP; G4 rename `%ProgramData%\Q2Route\geosite.dat`, Restart → warn line, digikala.com now via proxy, restore; G5 Groups page summary reads `*.ir + GeoSite IR`.
- [ ] **Step 6:** Commit `feat(service): load geosite.dat; UI and smoke steps for geosite`.
