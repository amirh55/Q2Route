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

Logs: `%ProgramData%\Q2Route\logs\q2route.log.<date>`. Each decided flow logs
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
| U4 | Open `https://cloudflare-quic.com`. | Still reports `h2` (proxied UDP/443 stays blocked). | |
| U5 | Use a Direct game (e.g. in "Games"). | Unaffected: still direct, ping unchanged. | |

## Leak checks

| # | Check | Expected | Result |
|---|---|---|---|
| L1 | `curl -6 https://ifconfig.co` | Fails, or never shows the real IPv6 / IPv4 (proxied IPv6 is blocked in M1). | pass: `Could not resolve host`, no IPv6 exposure. |
| L2 | `curl -4 https://ifconfig.co` | Shows the v2ray exit IP. | inconclusive: log shows curl proxied via v2ray, but TLS failed (`CRYPT_E_REVOCATION_OFFLINE`). Retry with `curl.exe --ssl-no-revoke -4 https://ifconfig.co`. No real IP shown. |
| L3 | Browser: `https://browserleaks.com/ip` | Only the v2ray exit IP; no real IPv4/IPv6. | pass |
| L4 | Browser: `https://browserleaks.com/webrtc` | No real public IP in the WebRTC candidates (local/LAN addresses are fine). | pass |
| L5 | Browser: `https://cloudflare-quic.com` | Page reports HTTP/2 (`h2`), not HTTP/3 (`h3`): proxied UDP/QUIC is blocked. | pass (h2) |
| L6 | Browser: `https://www.dnsleaktest.com` (extended test) | Shows the ISP resolver: **known M1 gap** (Ruling R3, DNS is always direct until the M2 DNS relay). Record what it shows. | German and Belgian resolvers, no Iranian ISP resolver (Chrome secure DNS goes through the proxy). Other apps still use the ISP resolver directly (R3). |

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
