# Q2Route M1 smoke test

Manual end-to-end checks on the target machine, using the portable build in
`dist\Q2Route`. Fill in the **Result** column (pass / fail plus what you saw)
and commit with the message `docs: m1 smoke test results`.

## Get the build

Build it from the repo root (stop the service first if it is running, because
its exe and `WinDivert.dll` are locked while it runs):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package.ps1
```

This creates `dist\Q2Route` with `q2route.exe` (UI), `q2route-service.exe`,
`WinDivert.dll`, `WinDivert64.sys` and three scripts:

- **Install.cmd**: asks for admin, refuses while Proxifier runs, installs (or
  reinstalls) the service with its firewall rule, starts it, and opens the UI.
- **OpenLog.cmd**: shows the live service log. Run it after Install; it waits
  until the log folder exists.
- **Uninstall.cmd**: closes the UI, stops and removes the service and its
  firewall rule.

The service runs from wherever `Install.cmd` was run, so do not move or delete
the folder while it is installed (run Uninstall first).

**Updating a running install:** while the service runs, `package.ps1` writes to
`dist\Q2Route-update` instead and adds **Update.cmd**. Double-click it: it
stops the service, copies the new files into `dist\Q2Route`, and starts the
service and the UI again. Settings are kept.

Logs: `%ProgramData%\Q2Route\logs\q2route.<date>.log` (the last 14 days
are kept; the Log page shows them live). Each decided flow logs
one `flow ...` line (packet layer) and, for relayed flows, one `relay ...`
line with domain, route, group, reason and outcome.

## Preconditions

| # | Check | Result |
|---|---|---|
| P1 | Proxifier is fully exited (tray icon gone, no `Proxifier.exe` in Task Manager). It redirects connections and breaks Q2Route (Ruling R10). | pass |
| P2 | OpenNetRoute and any other WinDivert-based app (other routers, packet sniffers) are closed. | pass |
| P3 | v2rayN: system proxy is cleared and TUN mode is off. v2ray/xray is running with its SOCKS inbound on `127.0.0.1:10808`. | pass |
| P4 | Windows Firewall is ON for all profiles. | |
| P5 | After `Install.cmd`, the firewall rule exists. | |

P4 and P5:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-NetFirewallRule -DisplayName "Q2Route relay" | Select-Object DisplayName, Enabled, Direction, Action
```

## Task 16 checklist

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | Iranian sites. Dashboard shows Running, "Everything else" set to v2ray. Open `https://ifconfig.me` and `https://www.digikala.ir`. | ifconfig.me shows the **v2ray exit IP**; digikala.ir loads; log shows `group=iranian-sites` `route=Direct` for digikala.ir and `group=everything-else` `route=Proxy(v2ray)` for ifconfig.me. | pass (2026-11-06). ifconfig.me showed the German v2ray exit IP. `ipmyp.ir` (used instead of digikala.ir) showed the Iranian IP, log `group=iranian-sites route=Direct`. Note: `www.digikala.com` is not `.ir`, so it goes through the proxy until geoip:ir exists. |
| 1b | GeoIP IR. The "Iranian sites" card reads `*.ir; GeoIP IR`. Open `https://www.digikala.com`, then stop v2ray and reload it. | Loads both times; log shows `geoip:ir: <N> ranges` at start and `domain=www.digikala.com route=Direct group=iranian-sites` per flow. | pass (2026-11-06): digikala.com loads with v2ray closed; log `geoip:ir: 2537 ranges`, `dst=185.188.106.12:443 route=Direct group=iranian-sites` (no peek needed, so no domain in the flow line). |
| 2 | Steam. Enable "Steam" with Direct, start Steam. | Log shows `exe=steamwebhelper.exe ... route=Direct group=steam reason=Inherited(from_pid=...)`. | |
| 2b | Launch a game from Steam that has its own rule in a lower group (e.g. add its exe to "Games" with a different action). | Log shows the game exe with its own group and `reason=Own`. | |
| 3 | Proxy down. Stop v2ray. Reload `https://ifconfig.me` and `https://www.digikala.ir`. | ifconfig.me **fails to load and never shows the real IP**; red banner appears; digikala.ir still loads; log shows `proxy failed: ... (closed, no direct fallback)`. | pass for `.ir` (2026-11-06). With a dead config, foreign sites failed and `.ir` sites loaded; with v2ray closed, log shows `proxy unreachable (closed, no direct fallback)`. The "Iranian site" that failed with v2ray closed was `www.digikala.com` (proxied, not `.ir`): correct per the rules, fixed by geoip:ir. Banner not recorded. |
| 3b | Restart v2ray and browse a proxied site. | The banner clears by itself (no Test click needed). | |
| 4 | Deliberate Stop. Press Stop. | ifconfig.me shows the real IP; status reads "Stopped: all traffic direct". Press Start again afterwards. | |
| 5 | UI loss. Kill `q2route.exe` in Task Manager while Running. | Browsing continues through v2ray; relaunched UI reconnects. | |
| 6 | Toggle persistence. Set Steam to Proxy, then restart the service. | Steam is still Proxy. | |
| 7 | Loop protection. With v2ray running. | v2ray has internet access (its traffic is not looped into the proxy). | |

Step 6:

```powershell
sc.exe stop Q2Route
sc.exe start Q2Route
```

## M2: rules editor and connections

Install this update with `dist\Q2Route-update\Update.cmd` (see "Updating a running install" above).

| # | Step | Expected | Result |
|---|---|---|---|
| E1 | Add group "Filtered games" with action Proxy (v2ray). Add the game's exe via "Pick running app…". | The dashboard shows the new card above "Everything else". | |
| E2 | Enter the bad entry `10.0.0.0/33`. | An error shows and nothing changes; `config.toml` is unchanged. | |
| E3 | Reorder and delete a group, then restart the service (`sc.exe stop Q2Route`, `sc.exe start Q2Route`). | The order persists after the restart. | |
| C1 | Open the Connections page. | Lists browser connections with route, group and why; LAN and DNS are not listed. | |
| C2 | Right-click a site → "Add domain to group → Iranian sites" with `*.parent`. Open a new connection to it. | The connection goes Direct; log shows `group=iranian-sites`. | |
| C3 | Leave a Steam download running for 10 min. | The page stays responsive; the list length stays bounded. | |
| C4 | Right-click an `explorer.exe` (or `svchost.exe`) row. | The menu names the exe without "(and apps it starts)". After adding it to a Direct group, a browser started afterwards from the Start menu still shows `route=Proxy(v2ray)` in the Connections page. Remove the rule afterwards. | |

## M3: UDP through the proxy

Install this update with `dist\Q2Route-update\Update.cmd`.

| # | Step | Expected | Result |
|---|---|---|---|
| U1 | Proxies → Test on v2ray. | Shows "UDP OK" (v2rayN's SOCKS inbound has UDP on by default). | |
| U2 | Put a filtered game's exe in a Proxy (v2ray) group; play online. | The game connects; Connections shows its UDP rows with route Proxy (v2ray) and growing ↑/↓; log has `udp ... via 'v2ray': associated`. | |
| U3 | Same game with v2ray stopped. | The game can't connect; log shows `association failed ... (dropped, no direct fallback)`; browserleaks/game never sees the real IP. | |
| U3b | With Windows Firewall turned off for the test, play a proxied game, then quit it mid-session; capture outbound ICMP (`pktmon start --capture --comp nics` / Wireshark filter `icmp`) for 60 s. Turn the firewall back on. | No ICMP port-unreachable toward the game server. | |
| U4 | Open `https://cloudflare-quic.com`. | Still reports `h2` (proxied UDP/443 stays blocked). | |
| U5 | Use a Direct game (e.g. in "Games"). | Unaffected: still direct, ping unchanged. | |
| U6 | Re-run L4 (browserleaks WebRTC). | The srflx candidate shows the v2ray exit IP, never the real IP. | |

## M4: DNS through the proxy

Install this update with `dist\Q2Route-update\Update.cmd`.

| # | Step | Expected | Result |
|---|---|---|---|
| D1 | Browser: `https://www.dnsleaktest.com` (extended test). | Only resolvers of the proxy's network (e.g. Cloudflare), no ISP resolver. (Replaces the M1 L6 gap.) | |
| D2 | `nslookup example.com` (Windows' resolver). | It resolves; the log (enable debug) or the Connections page shows the query routed via the proxy (check the TCP row if a TC fallback happened). | |
| D3 | `nslookup digikala.ir`. | It resolves through the normal (ISP) resolver; `.ir` sites still load with v2ray stopped. | |
| D4 | Stop v2ray, then `nslookup example.com`. | It fails (no fallback to the ISP). | |
| D5 | Chrome with Secure DNS on: browse proxied sites and a Direct `.ir` site. | Proxied browsing still works (DoH is blocked, Chrome falls back to system DNS); the Direct `.ir` site is unaffected. | |
| D6 | DNS page: change the proxy resolver to `9.9.9.9:53`, Save, then repeat D1. | dnsleaktest shows Quad9. | |
| D7 | With v2rayN using a server *hostname*, restart v2ray while Q2Route runs (and `ipconfig /flushdns`). | v2ray reconnects; the log shows `proxy servers resolved directly: <your server>`; the DNS page lists it as detected. | |
| D8 | Switch v2rayN to a server with a different hostname. | It connects within ~15 s; the log shows the new name in `proxy servers resolved directly`. | |
| D9 | Update a v2rayN subscription while the current server is unreachable; if it fails, add the subscription host to "Names always resolved directly" and retry. | The subscription updates. | |

## M6: IPv6 through the proxy

Install this update with `dist\Q2Route-update\Update.cmd`. On IPv6 the relay port can be reached from the internet (there is no NAT, and the firewall rule is scoped to the program, not the port); connections without a NAT entry are closed immediately, so nothing is exposed.

| # | Step | Expected | Result |
|---|---|---|---|
| V1 | `curl.exe -6 https://ifconfig.co` | Shows the proxy exit's IPv6, or fails if the server has no IPv6 — never your real IPv6. | |
| V2 | Browser: `https://test-ipv6.com` (or browserleaks/ip). | No real IPv6 shown. | |
| V3 | Check the service log after start. | The log shows `relay listening on <port> (IPv4+IPv6)`; on a machine without IPv6 it shows IPv4 only and nothing breaks. | |
| V4 | `nslookup -vc example.com <your IPv6 DNS server>` (forces TCP). | It resolves; Connections shows the TCP/53 row routed via the proxy. | |
| V5 | A proxied game over IPv6 (if available). | Connections shows its UDP rows with route Proxy. | |
| V6 | With a VPN server that has no IPv6: browse a site that has IPv6 and use a non-web proxied app (e.g. a game or SSH to an IPv6-capable host). | Works. If it doesn't, turn off "Proxy IPv6 traffic" on the Proxies page → it works over IPv4. | |

## M7: geosite domain lists

`geosite:ir` (Iranian sites) is in the seed's "Iranian sites" rule. `geosite.dat` is copied from the running v2rayN into `%ProgramData%\Q2Route\` on Start, like `geoip.dat`.

| # | Step | Expected | Result |
|---|---|---|---|
| G1 | Click Start, then open the log. | A line `geosite:ir: <n> names` (n in the thousands). | |
| G2 | Open `digikala.com` and `aparat.com`, then check the Connections page. Also open a what-is-my-IP page hosted in Iran. | Both domains show Direct / "Iranian sites"; the Iran-hosted page shows your Iranian IP. | |
| G3 | `curl.exe https://ifconfig.me` | Still shows the proxy exit IP (the German one). | |
| G4 | Stop the service, rename `%ProgramData%\Q2Route\geosite.dat`, then Start (not Restart: Start re-copies from v2rayN, so also close v2rayN or rename its copy). | The log shows a warn line `geosite:ir: no data, so these rules match nothing`; `digikala.com` now goes via the proxy. Restore the file and Restart afterwards. | |
| G5 | Open the Groups page. | The "Iranian sites" summary reads `*.ir + GeoSite IR`. | |

## M8: leak check

Settings page, "Leak check" section, button "Run leak check" (takes up to 30 s).

| # | Step | Expected | Result |
|---|---|---|---|
| M8-L1 | Normal run: service Running, v2ray up, click "Run leak check". | Green "No leak: proxied apps appear as <IP> (<country>, ...)", where the country is the v2ray server's country, not Iran. The DNS line shows a resolver (and, if listed, a client subnet) that is not Iranian. | |
| M8-L2 | Stop v2ray, then click "Run leak check". | "No leak, but proxied traffic isn't getting through". Start v2ray again afterwards. | |
| M8-L3 | Click Stop on the dashboard, then "Run leak check". | Grey "Can't tell: Q2Route is stopped (everything goes direct)", with no result lines and no IP shown. Click Start afterwards. | |
| M8-L4 | Add `q2route.exe` to a Direct group, Restart, then "Run leak check". | Grey "Can't tell: this check was routed Direct by ..." (or "... routed Direct (always-direct app or no group)"); one IPv4 line reading "address not shown (routed Direct)", no IP shown. Remove it from the group and Restart afterwards. | |
| M8-L5 | Run the check and read the IPv6 line. | It matches the M6 smoke result (V1-V3) for this machine. | |
| M8-L6 | v2ray running, but its server unreachable (e.g. point the v2rayN profile at a dead address, or block the server IP in the firewall), then "Run leak check". | "No leak, but proxied traffic isn't getting through", shown within 30 s. Restore the profile afterwards. | |

Limit of the method: the DNS probe sees the resolver that answers this process's query and the client subnet it forwards. A direct DNS query to a foreign anycast resolver that sends no client subnet (EDNS Client Subnet) shows a foreign resolver, so the check can't detect it; such a query still reveals your real IP to that resolver.

## M9: data usage

Data usage page. Counts only proxied traffic (TCP through the relay, UDP through the UDP relay); Direct traffic is not counted. The history is `%ProgramData%\Q2Route\usage.json`.

| # | Step | Expected | Result |
|---|---|---|---|
| M9-U1 | Fresh install (or no `usage.json`, `data_usage` not set in `config.toml`). Open the Data usage page, then browse. | The "Count data usage" switch is off, with the one-line explanation and nothing else; no `usage.json` exists after browsing. | |
| M9-U2 | Switch it on and browse a proxied site. | "By app" shows the browser, "By proxy" shows v2ray, and the numbers grow (refresh every 2 s). | |
| M9-U3 | Browse a Direct site, such as an Iranian one. | The totals do not increase. | |
| M9-U4 | Restart the service. | Session resets to empty; Today keeps its value. | |
| M9-U5 | Press Reset and answer Yes. | Everything is cleared and `usage.json` is deleted. | |
| M9-U6 | Switch it off. | The numbers stop growing; the history is kept in `usage.json` (and shows again when switched back on). | |

## M11: log page

Log page. Shows the service's last 2000 log lines, polled every second while the page is open. Files are in `%ProgramData%\Q2Route\logs` (14 days kept).

| # | Step | Expected | Result |
|---|---|---|---|
| L1 | Open the Log page. | Recent service lines appear within 1 s. | |
| L2 | Start/Stop routing from the dashboard, then return to Log. | The new lines appear live. | |
| L3 | Choose the Errors filter. | Info lines are hidden (Warnings shows warnings and errors). | |
| L4 | Type part of a module name or message in Search. | The rows narrow to the matches. | |
| L5 | Press Pause, wait for new lines to be logged, then Resume. | Pause freezes the view; Resume catches up. | |
| L6 | Press Copy, then paste into Notepad. | The shown rows are pasted as text lines. | |
| L7 | Press "Open log folder". | Explorer opens `%ProgramData%\Q2Route\logs`. | |
| L8 | Restart the service with the page open. | Fresh lines appear without duplicates; the page does not stall. | |

## M12: settings

Settings page: theme, tray graph, geo data update, export and import. The file dialogs are the Windows pickers and are not covered by unit tests.

| # | Step | Expected | Result |
|---|---|---|---|
| S1 | Settings > Appearance: choose Light, then Follow Windows, then Dark. Close and reopen the UI. | Each choice applies immediately; the last choice is still selected after reopening. | |
| S2 | Untick "Traffic graph in the tray icon". | The tray icon becomes plain (no traffic bars); the tooltip and menu are unchanged. Ticking it brings the bars back. | |
| S3 | Open Settings > Geo data. With v2rayN running after its own geo update, press Update now. Press it again, or press it with no proxy program running. | The section shows dates such as `geoip.dat: 2026-11-15 (4.1 MB)`. The first press shows `Updated: ...`; without newer files it shows `No newer geo files found (v2rayN, xray, v2ray or sing-box must be running).` | |
| S4 | Backup: leave "Include proxy passwords" off, press Export and save `q2route-config.toml`. | The file has no `password` lines. Ticking the box shows `The file will contain your proxy passwords in plain text.` | |
| S5 | Change a group (for example rename it), then Import the exported file. | The confirmation `Replace all groups, rules and proxies with this file? A backup is kept as config.toml.bak.` appears. After Yes the group is back, `config.toml.bak` exists next to `config.toml` and the proxies still connect. | |
| S6 | Rename a random `.txt` file to `.toml` and Import it. | A red `Import failed: ...` line appears and nothing changes. A file over 1 MiB gives `Import failed: the file is bigger than 1 MiB.` | |

## Leak checks

| # | Check | Expected | Result |
|---|---|---|---|
| L1 | `curl -6 https://ifconfig.co` | Fails, or never shows the real IPv6 / IPv4. Since M6 see V1 (proxied IPv6 goes through the proxy). | pass: `Could not resolve host`, no IPv6 exposure. |
| L2 | `curl -4 https://ifconfig.co` | Shows the v2ray exit IP. | inconclusive: log shows curl proxied via v2ray, but TLS failed (`CRYPT_E_REVOCATION_OFFLINE`). Retry with `curl.exe --ssl-no-revoke -4 https://ifconfig.co`. No real IP shown. |
| L3 | Browser: `https://browserleaks.com/ip` | Only the v2ray exit IP; no real IPv4/IPv6. | pass |
| L4 | Browser: `https://browserleaks.com/webrtc` | No real public IP in the WebRTC candidates (local/LAN addresses are fine). | pass |
| L5 | Browser: `https://cloudflare-quic.com` | Page reports HTTP/2 (`h2`), not HTTP/3 (`h3`): proxied UDP/QUIC is blocked. | pass (h2) |
| L6 | Browser: `https://www.dnsleaktest.com` (extended test) | Shows the ISP resolver: **known M1 gap**, closed by M4 (see D1). Record what it shows. | German and Belgian resolvers, no Iranian ISP resolver (Chrome secure DNS goes through the proxy). Other apps still use the ISP resolver directly (R3). |

```powershell
curl.exe -6 https://ifconfig.co
curl.exe -4 https://ifconfig.co
```

## Robustness

| # | Check | Expected | Result |
|---|---|---|---|
| R1 | Unchecking "Everything else". | Impossible: the card has no Enabled checkbox and the tray never shows it "(off)". | |
| R2 | Idle connection: open an SSH (or telnet) session to a proxied host, leave it idle 3+ minutes, then type. | Session still works (the NAT entry is held by the relay, not swept after 120 s). | pass: Termius SSH stable for 20 min. |
| R3 | Service handles and memory over 1 hour of normal use. | Handle count and private bytes stay flat (no steady growth). Record start/end values. | |
| R4 | Restart v2ray several times while Q2Route runs, then count connections to the SOCKS port. | Count stays bounded (no leaked relay upstream sockets). | |
| R5 | Toggle Steam Direct/Proxy during a download. | Existing connections on the old route are reset and Steam reconnects on the new route; the download resumes. Record how long it stalls. | |
| R6 | Speed test (e.g. speedtest.net) with the service stopped vs running; watch the service CPU in Task Manager. | Record both speeds and the CPU. | speed good while running; stopped-vs-running numbers and CPU not recorded. |
| R7 | Router admin page (e.g. `http://192.168.1.1`). | Loads (LAN is always direct). | |
| R8 | Windows Update: Settings > Windows Update > Check for updates. | Connects. | |
| R9 | Inbound from the internet to a local server: run `python -m http.server 8000`, forward port 8000 on the router (or use a public-IP machine), and open `http://<your public IP>:8000` from a phone on **mobile data** (not Wi-Fi: LAN peers are always direct and prove nothing). | Loads (accepted inbound connections are direct). Remove the port forward afterwards. | |
| R10 | Kill `q2route-service.exe` in Task Manager while Running. | Traffic goes direct: **known M1 gap**, there is no kill switch until M2. The service restarts or is restarted manually. | |
| R11 | Reboot with the service Running. | After login, routing resumes (dashboard shows Running, ifconfig.me shows the v2ray IP). | |

R3, run at the start and after one hour:

```powershell
Get-Process q2route-service | Select-Object Id, HandleCount, PrivateMemorySize64, CPU
```

R4, run after each v2ray restart:

```powershell
netstat -ano | find /c ":10808"
```

R10, kill the service process:

```powershell
taskkill /F /IM q2route-service.exe
```

## Uninstall

| # | Check | Expected | Result |
|---|---|---|---|
| U1 | Run `Uninstall.cmd`. | Service removed; `Get-NetFirewallRule -DisplayName "Q2Route relay"` finds nothing. | |

```powershell
Get-NetFirewallRule -DisplayName "Q2Route relay"
```

## M14: app rules

Manual checks below are pending; they were not run against the live installation during development.

| # | Step | Expected | Result |
|---|---|---|---|
| A1 | Open App rules in the left navigation. | Immediately after Groups & rules; English table with On, App, Route and Remove. | |
| A2 | Click Add running process…; filter and select a running app. | Exact executable path added; filename displayed with full-path tooltip; processes with the same name in different folders are distinct. | |
| A3 | Click Add exe…; select an exe, then repeat and cancel. | Native exe-filtered picker; selected app added; cancel changes nothing. | |
| A4 | Click Add folder…; select a folder containing executables in subfolders. | Folder rule ends in a backslash and matches executables below it, not adjacent similarly named folders. Cancel changes nothing. | |
| A5 | Add the same executable or folder again using different path case. | Short duplicate message; list unchanged. | |
| A6 | Choose Direct, each named proxy, and Block on an app that matches a group. | Enabled app rule wins before groups; proxy failure never falls back to Direct. | |
| A7 | Set Block then turn its checkbox off. | App resumes normal group routing, not forced Direct; child processes are unaffected by the app rule. | |
| A8 | Remove a proxy referenced by an app rule. | Row is red, reads proxy deleted, and routes Block. Selecting a valid route repairs it. | |
| A9 | Right-click a Connections row and choose Block internet for the exe. | Exact-path Block rule created/enabled at highest app-rule priority; same-named executables elsewhere unaffected. Unknown full paths cannot be targeted. | |
| A10 | Block an app with established direct TCP, proxied TCP and UDP traffic. | Verify existing flows stop, not only new connections; with Active only enabled, no continuing traffic for that app. Any retained history has no increasing byte counts. | |
| A11 | Right-click and choose Allow internet for the exe. | Exact-path app rule disabled; normal routing resumes on new connections. No Direct rule is invented. | |
| A12 | Click Remove on an app rule. | Rule removed and normal group routing restored. | |
| A13 | Settings > Backup: export then import a configuration containing enabled/disabled app rules. | Patterns, routes, enabled flags and order survive; old backups without app_rules load with an empty list. | |

## M13 installer

Build with `powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Setup`; the setup is `dist\Q2Route-Setup-0.2.0.exe`.

| # | Step | Expected | Result |
|---|---|---|---|
| I1 | Run the setup on a PC without Q2Route. | Installs to `C:\Program Files\Q2Route`, service `Q2Route` is registered from there, Start menu shortcut exists, the UI opens. | |
| I2 | Install over an old zip install (service registered from the zip folder). | `sc qc Q2Route` shows a path in Program Files; groups, rules and settings are unchanged. | |
| I3 | Run the setup while routing is on. | Setup removes the service before copying, finishes without file-in-use errors, and routing can be started again afterwards. | |
| I4 | Turn on "Start with Windows" in the zip build, then move to the installed build. | After the update to the installed build, autostart still launches Q2Route at login. | |
| I5 | Uninstall from Apps, once answering No and once Yes to "Also delete Q2Route's settings, rules and logs?". | No keeps `%ProgramData%\Q2Route`; Yes removes it (and `%APPDATA%\Q2Route`). The service and firewall rule are gone either way. | |
| I6 | Start Proxifier, then run the setup. | Setup stops with "Proxifier is running. Exit it fully (tray icon too), then run Setup again." and installs nothing. | |

```powershell
sc qc Q2Route
```
| U7 | With release v0.2.1 published (the next one), start a 0.2.0 install. | The banner "Q2Route 0.2.1 is available." with Install update, Release notes and Later shows within about 10 s of start. Later hides it until the next start. | |
| U8 | Click Install update. | Progress text "Downloading… x / y MB", then the UAC prompt; the setup runs silently, Q2Route reopens, and Settings shows `Version 0.2.1`. | |
| U9 | Disconnect the network. Click "Check now" in Settings > Updates; restart with automatic checks on. | "Check now" shows `Could not check for updates: <reason>`; the automatic check shows nothing. | |
