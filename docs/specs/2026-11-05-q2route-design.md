# Q2Route: Design

Date: 2026-11-05
Status: draft, waiting for approval

## 1. What this is, and why

Q2Route is a Windows desktop app, written in Rust, that decides for **every network connection on the machine** whether it goes **direct**, through a **proxy** (usually a local v2ray/Xray SOCKS5 inbound such as `127.0.0.1:10808`), or gets **blocked**. It combines the strongest parts of two tools the user knows:

- **Proxifier**: fast, always on, reliably catches the whole system, and has a live traffic indicator in the tray. Its weakness is rules that are awkward to write. The user's `*.ir → Direct` rule in Proxifier **does not actually work**, so they still have to fall back to v2ray's own routing.
- **OpenNetRoute** (`D:\Q2Route\OpenNetRoute-v0.1.0-beta.1-win-x64`, <https://github.com/soheilsoufiani/OpenNetRoute>): shows what is using the network and lets you route it, using WinDivert. It has a multi-section UI, proxy profiles with testing, a DNS relay with leak protection, DoH detection, WebRTC/STUN protection, data usage and tray integration. Its weaknesses are that it is slow (a .NET/WPF build of about 160 MB), it is TCP/IPv4-only for general traffic, and every rule covers one item only. There is no way to say "all of Steam, including its child processes" or "every `.ir` domain".

**The user's own situation:** the app stays open all the time. Most traffic should go through v2ray. Iranian sites should go direct. Sometimes Steam should go direct for downloads. Most online games should go direct for ping and to save proxy data, but some games are filtered and must go through the proxy, and those use UDP. The user sometimes runs other proxy programs on other local ports.

**What success looks like:** the user replaces Proxifier with Q2Route and never needs v2ray's own routing for the `.ir` case again. Changing Steam or a game between Direct and Proxy is a single click on the dashboard or in the tray, and the setting stays saved.

## 2. Goals

1. **System-wide capture** at least as dependable as Proxifier: TCP **and UDP**, IPv4 **and IPv6**, every process.
2. **Group-based rules**, so one rule covers many things:
   - **Apps:** match by process name (with wildcards), exe path or folder. **Child processes inherit the group**: anything Steam or a game launcher starts gets Steam's route.
   - **Domains:** exact names, wildcard suffixes (`*.ir`, `*.steampowered.com`), keywords, and v2ray `geosite:` categories (for example `geosite:category-ir`, `geosite:steam`).
   - **IPs:** single addresses, CIDR ranges, and v2ray `geoip:` categories (for example `geoip:ir`).
   - **Ports and protocols** (TCP/UDP) as extra conditions.
3. **Domain rules must work even when the app connects by IP** (because of DoH, cached DNS and so on). This is exactly where Proxifier fails the user today.
4. **One-click group toggles** on the dashboard and in the tray menu. A group's action is Direct, Block, or Proxy using a chosen profile. Changes are saved immediately and survive restarts.
5. **Multiple proxy profiles**: SOCKS5 (including UDP ASSOCIATE), HTTP CONNECT and SOCKS4/4a, with optional username/password and a test button (TCP reachability, UDP support, latency).
6. **Live Connections view**: app, PID, destination domain and IP, port, protocol, the group and rule that matched, the route taken, bytes and duration. Right-clicking a connection offers "Add this app to group…", "Add this domain / `*.parent` to group…" and "Add this IP range…".
7. **Tray icon with live traffic bars** like Proxifier's, a speed tooltip, and a right-click menu with Start/Stop, group toggles and Open.
8. **Data usage**: upload, download and total per group, per app and per proxy, for the current session and as history, with reset.
9. **Fast and light**: direct traffic should see no noticeable slowdown, and the build should be a few MB instead of about 160 MB.
10. **Ready-made groups on first run**: "Iranian sites" (`*.ir`, `geosite:category-ir`, `geoip:ir` → Direct), "Steam" (steam.exe and children, `geosite:steam` → Direct, off by default), "Games" (empty, Direct), and "Everything else" (→ the default proxy).

## 3. Anti-goals (failure even if everything else works)

**Leaking the user's real Iranian IP or location from traffic that is meant to go through the proxy is the worst possible outcome.** If a site or app that is routed to the proxy can see the user's real IP, the product has failed. Concretely:

- **No fail-open.** If the proxy is down, refuses a connection, or does not support UDP, proxied traffic is **blocked**, never sent direct. The user gets a visible tray and dashboard warning.
- **No DNS leaks** for names that resolve to proxied destinations.
- **No IPv6 bypass.** IPv6 from proxied apps or destinations is proxied or blocked, never sent direct.
- **No QUIC/UDP bypass.** UDP from proxied apps goes through SOCKS5 UDP ASSOCIATE or is blocked. Blocking UDP/443 makes browsers fall back to TCP.
- **No WebRTC leak** of the real IP for proxied browsers. STUN from a proxied app goes through the proxy or is dropped.
- **No gaps at start, stop or crash.** Nothing proxied leaks while the service is starting, after the UI crashes, or after a config reload. If the engine itself dies, the default is to block proxied apps until it is back (a kill switch, on by default).

Other failures to avoid: routing loops that cut off the internet (see 5.6); being slower than Proxifier; making games lag when they are set to Direct.

## 4. Non-goals for the first version

- Proxy chains (proxy → proxy).
- A built-in v2ray/Xray core. Q2Route only talks to proxies that already run.
- Timed toggles ("direct for 30 minutes"). The user wants toggles that persist.
- Importing Proxifier `.ppx` profiles. This is a good later addition.
- Hiding non-network location signals such as browser timezone or language. That is outside a network router's reach; mention it in the docs.
- TLS interception or DoH relaying.
- Platforms other than Windows 10/11 x64. UI languages other than English.

## 5. How it works (decided)

### 5.1 Process layout

- **`q2route-service`**: a Windows service running as LocalSystem that starts automatically. It owns WinDivert, the rule engine, the proxy clients, DNS handling, connection tracking and statistics. It keeps running when the UI is closed. Installing it needs admin rights once; after that the UI does not need "Run as administrator".
- **`q2route` (UI)**: a normal user-level desktop app, using **egui/eframe** with a tray icon. It talks to the service over a **named pipe**, protected by an ACL that allows the interactive user and admins. It is used for config changes, live connection and stats streams, and commands. One UI instance at a time. "Start with Windows" launches the UI minimized to the tray.
- Both are built from one Cargo workspace. Shared types (config, IPC messages) live in a common crate.

### 5.2 Traffic capture

**WinDivert 2.x**, the signed driver that ships with the app, the same approach OpenNetRoute uses.

- **Who owns a connection:** the SOCKET/FLOW layers (sniff mode) report the owning PID when a connection is created, so there is no polling of `GetExtendedTcpTable`. A **process tree** (PID → parent, exe path, start time) is maintained from process-creation events (ETW or an equivalent) so that "include children" works. Children launched while Q2Route was not running are also resolved from the parent PID.
- **Direct traffic** goes on the normal path, untouched, with as little processing as possible.
- **Proxied TCP** is redirected to a local transparent listener inside the service. That listener knows the original destination and opens the upstream connection through the chosen proxy.
- **Proxied UDP** is captured and relayed through SOCKS5 UDP ASSOCIATE. Replies are reinjected as if they came from the real remote end. If the proxy does not support UDP, the traffic is **blocked**.
- **Blocked** traffic is dropped, with a TCP RST where that makes sense so apps fail fast.
- The service's own upstream sockets, and the proxy program itself, are always excluded (see 5.6).

### 5.3 Rule matching

- **Groups are kept in a user-defined order.** For each new connection or UDP flow, the first enabled group with a matching rule decides. The last group is "Everything else" and acts as the default.
- **A rule matches** on any combination of: app (name glob, path or folder, plus children), domain (exact, `*.suffix`, keyword, `geosite:`), IP (address, CIDR, `geoip:`), port or port range, and protocol. Conditions inside one rule are ANDed; the rules inside a group are ORed.
- **Decisions are cached per flow.** Toggling a group applies to **new** connections. Existing connections keep their route. A "Reconnect" button closes affected connections so they reconnect on the new route.
- **Geo data:** the app reads v2ray-format `geosite.dat` and `geoip.dat`. It ships with a copy and has an "Update geo data" button that downloads from a configurable URL (default: Loyalsoldier/v2ray-rules-dat or an Iran-specific list such as chocolate4u/Iran-v2ray-rules).

### 5.4 Knowing the domain when the app only uses an IP

This is the key to `*.ir` working. Use these together:

1. **DNS-answer mapping.** The service sees the plaintext DNS answers it handles (5.5) and keeps an IP → domain(s) map for each process. That map is used when the connection starts.
2. **SNI/Host peek.** For TCP 443/80, when the IP → domain map has no answer and the result could depend on a domain rule, the decision is delayed until the first client bytes arrive. The service reads the TLS SNI or HTTP `Host` header, then decides. On the direct path this costs a little time per connection, and only on that first connection.
3. **`geoip:ir` as a backstop**, so Iranian IPs go direct even when no name is known.

The builder decides exactly how the peek is done (for example, redirect to the local listener and then either proxy upstream or open a direct upstream). The requirement: domain rules must reliably match browser traffic that uses DoH, and direct connections that did not need a peek must not slow down.

### 5.5 DNS

- Plaintext DNS (UDP/TCP 53, IPv4/IPv6) is intercepted system-wide.
- **Each DNS query is routed by the same rules, using the name being asked about.** A name whose group is Direct (such as `*.ir`) is resolved directly through a configurable direct resolver (default: the system resolver), so Iranian CDNs return local answers. A name whose group is Proxy is resolved **through that proxy**: UDP ASSOCIATE first, falling back to DNS-over-TCP through CONNECT, with a TC=1 reply to force TCP when UDP is not available, the same as OpenNetRoute. The resolver used through the proxy is configurable (default `1.1.1.1`).
- **Fail-closed:** a query that should go through the proxy and cannot is dropped, never sent direct.
- The Windows DNS cache is flushed on start and stop.
- **DoH/DoT detection**, as OpenNetRoute does it: read the SNI on 443 and 853 and log which app is using which encrypted resolver. **There is also an optional setting**, on by default, that blocks well-known DoH and DoT endpoints for proxied apps, so browsers fall back to the plaintext DNS that Q2Route controls.

### 5.6 Loop and self-protection

- Automatic exclusion: the process that listens on each configured proxy's host and port (for example `v2ray.exe` or `xray.exe`) is found and its traffic is always sent direct. The same applies to Q2Route's own upstream sockets.
- **A manual "Always direct" list** for proxy programs, prefilled with v2ray, xray, sing-box, v2rayN, nekoray, hiddify and clash.
- A proxy address on a loopback or LAN IP is never itself proxied.

### 5.7 Kill switch (my call, after review)

- WinDivert filters disappear when the service process dies. So the kill switch uses **persistent WFP filters**, installed by the service, that survive both a crash and a reboot. While a filter is active it **blocks all traffic except** loopback, LAN/private ranges, DHCP, and the "Always direct" list (proxy programs). During that window Q2Route cannot evaluate domain rules, so it blocks everything instead of guessing.
- A **boot-time block** is active from Windows start until the service has its capture running. Once capture is running, the service removes or relaxes the WFP block. If the service crashes, it is not removed, so the block stays.
- **Deliberate Stop or Exit (the user's decision): the internet keeps working directly, as when Proxifier is closed.** The service flushes the DNS cache, closes proxied connections so apps cannot keep using a half-open proxied path, and removes the WFP block. The tray and dashboard clearly show "Stopped: all traffic direct". The kill switch covers only unexpected loss of the engine (a crash, or the boot window), never a deliberate Stop.

### 5.8 Matching details (my calls, after review)

- **An app's own match beats an inherited one.** If a process matches an app rule directly, that group wins, whatever the group order. Inheritance from the parent process is used only when nothing matches the process itself. Example: a filtered game launched by Steam goes through the proxy even though Steam is Direct. The Connections view shows whether a match was "own" or "inherited from steam.exe".
- **DNS is routed by the queried name only.** Most lookups go through Windows' DNS Client service, so the requesting app is usually unknown. A name that matches a domain rule follows that group. A name that matches no domain rule follows the action of the last group ("Everything else"), which is normally the proxy, so DNS does not leak. Dnscache is not disabled. The IP → domain map is global, not per process.
- **An IP that maps to domains in several groups:** for TCP, use the SNI/Host peek. Where nothing can be peeked, the **more protective route wins**, in the order Proxy > Block > Direct. Parsing the SNI from QUIC Initial packets is left to the builder. Games are normally matched by app, so this rarely affects them.

### 5.9 Configuration and storage

- **One TOML file** at `%ProgramData%\Q2Route\config.toml` holds proxies, groups and rules, and settings. The service owns it, and the UI edits it through IPC. Every change is saved immediately. There is "Export" and "Import" of the file.
- Usage history is stored in a small local database (SQLite or an append-only file; the builder chooses).
- Logs use rotating files in `%ProgramData%\Q2Route\logs`.
- Proxy passwords are stored protected with DPAPI, not in plain text.

## 6. UI (decided with the user)

A multi-section app with a left navigation bar and a dark theme by default. The dashboard is the layout the user picked (option B):

| Section | Contents |
|---|---|
| **Dashboard** | Running/stopped and kill-switch status, the default proxy, live up/down speed. Large **group cards**, each showing its name, a short summary (for example "12 processes" or "*.ir + GeoIP IR"), its live speed and a **one-click Direct / Proxy / Block switch**, plus a proxy picker when the action is Proxy. Warning banner when a proxy is down. |
| **Connections** | Live table (see goal 6) with filter and search, a choice between active only and recent, and the right-click "build a rule" actions. |
| **Groups & rules** | Ordered list of groups (drag to reorder, enable/disable). Editing a group means editing its action and rule list. When adding an app, pick from running processes, an exe or a folder. "Include child processes" is on by default. |
| **Proxies** | Profiles (type, host, port, auth), "Test" (TCP, UDP, latency), default proxy selection. |
| **DNS** | Direct resolver, proxy resolver, DoH blocking, DoH detections, flush cache. WebRTC/STUN handling. |
| **Data usage** | Per group, app and proxy; session and history; reset. |
| **Log** | Live log with level filter. |
| **Settings** | Start with Windows, minimize/close to tray, tray traffic icon on or off, kill switch, geo data update, theme, export/import, **a "Leak check" button** (see below). |

**Tray:** the icon is drawn live as **traffic bars** (upload and download, Proxifier style), updated a few times per second. The tooltip shows speed. The right-click menu offers Open, Start/Stop, one item per group to switch Direct/Proxy, and Exit.

**Leak check:** a button that, through a proxied path, fetches the public IP and checks DNS resolver identity and IPv6. It shows "Proxied apps appear as X (country)". It is a quick sanity test for the anti-goal.

## 7. Constraints

- Rust (stable), Windows 10/11 x64 only.
- WinDivert ships with the app (`WinDivert.dll` and `WinDivert64.sys`, signed). Mind its LGPLv3/GPLv2 licence terms when distributing.
- Installing the service needs admin rights once. Provide an installer (MSI or Inno Setup; the builder chooses) and a portable "install service" path from the UI.
- It must coexist with v2ray/Xray, which are already running on the machine.

## 8. Left to the builder

- Crate choices (async runtime, WinDivert bindings or FFI, the tray crate, the IPC framing, the SQLite crate).
- The exact NAT and redirect technique for TCP and UDP, and how the SNI peek is wired, within the requirements in 5.2–5.4.
- How the process tree is fed (ETW versus WinDivert events with lookup).
- How geosite/geoip data is parsed and stored.
- Visual styling details beyond the layout above.
- How the work is split into milestones. A sensible first milestone: the service with TCP capture, app and domain groups, a SOCKS5 profile, fail-closed behaviour and a minimal UI with dashboard toggles and the tray. After that: UDP, DNS, the Connections view, usage data and polish.
