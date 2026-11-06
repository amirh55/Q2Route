# Q2Route M1 smoke test

Manual end-to-end checks, run as administrator on the target machine. Fill in
the **Result** column (pass / fail plus what you saw) and commit with the
message `docs: m1 smoke test results`.

Logs: `%ProgramData%\Q2Route\logs\q2route.log.<date>`. Each decided flow logs
one `flow ...` line (packet layer) and, for relayed flows, one `relay ...`
line with domain, route, group, reason and outcome.

Open the latest log in a second window:

```powershell
Get-ChildItem "$env:ProgramData\Q2Route\logs" | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content -Wait -Tail 50
```

## Preconditions

| # | Check | Result |
|---|---|---|
| P1 | Proxifier is fully exited (tray icon gone, no `Proxifier.exe` in Task Manager). It redirects connections and breaks Q2Route (Ruling R10). | |
| P2 | OpenNetRoute and any other WinDivert-based app (other routers, packet sniffers) are closed. | |
| P3 | v2rayN: system proxy is cleared and TUN mode is off. v2ray/xray is running with its SOCKS inbound on `127.0.0.1:10808`. | |
| P4 | The service is stopped before every rebuild (the exe and `WinDivert.dll` are locked while it runs). | |
| P5 | After the build, `WinDivert.dll` and `WinDivert64.sys` are next to `target\release\q2route-service.exe`. | |
| P6 | Windows Firewall is ON for all profiles. | |
| P7 | After `install`, the firewall rule exists. | |

P4, stop the service before rebuilding:

```powershell
sc.exe stop Q2Route
cargo build --release --workspace
```

P5:

```powershell
Get-ChildItem target\release\WinDivert.dll, target\release\WinDivert64.sys, target\release\q2route-service.exe
```

Install and start (admin), then launch the UI:

```powershell
target\release\q2route-service.exe install
target\release\q2route.exe
```

P6 and P7:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-NetFirewallRule -DisplayName "Q2Route relay" | Select-Object DisplayName, Enabled, Direction, Action
```

## Task 16 checklist

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | Iranian sites. Dashboard shows Running, "Everything else" set to v2ray. Open `https://ifconfig.me` and `https://www.digikala.ir`. | ifconfig.me shows the **v2ray exit IP**; digikala.ir loads; log shows `group=iranian-sites` `route=Direct` for digikala.ir and `group=everything-else` `route=Proxy(v2ray)` for ifconfig.me. | |
| 2 | Steam. Enable "Steam" with Direct, start Steam. | Log shows `exe=steamwebhelper.exe ... route=Direct group=steam reason=Inherited(from_pid=...)`. | |
| 2b | Launch a game from Steam that has its own rule in a lower group (e.g. add its exe to "Games" with a different action). | Log shows the game exe with its own group and `reason=Own`. | |
| 3 | Proxy down. Stop v2ray. Reload `https://ifconfig.me` and `https://www.digikala.ir`. | ifconfig.me **fails to load and never shows the real IP**; red banner appears; digikala.ir still loads; log shows `proxy failed: ... (closed, no direct fallback)`. | |
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

## Leak checks

| # | Check | Expected | Result |
|---|---|---|---|
| L1 | `curl -6 https://ifconfig.co` | Fails, or never shows the real IPv6 / IPv4 (proxied IPv6 is blocked in M1). | |
| L2 | `curl -4 https://ifconfig.co` | Shows the v2ray exit IP. | |
| L3 | Browser: `https://browserleaks.com/ip` | Only the v2ray exit IP; no real IPv4/IPv6. | |
| L4 | Browser: `https://browserleaks.com/webrtc` | No real public IP in the WebRTC candidates (local/LAN addresses are fine). | |
| L5 | Browser: `https://cloudflare-quic.com` | Page reports HTTP/2 (`h2`), not HTTP/3 (`h3`): proxied UDP/QUIC is blocked. | |
| L6 | Browser: `https://www.dnsleaktest.com` (extended test) | Shows the ISP resolver: **known M1 gap** (Ruling R3, DNS is always direct until the M2 DNS relay). Record what it shows. | |

```powershell
curl.exe -6 https://ifconfig.co
curl.exe -4 https://ifconfig.co
```

## Robustness

| # | Check | Expected | Result |
|---|---|---|---|
| R1 | Unchecking "Everything else". | Impossible: the card has no Enabled checkbox and the tray never shows it "(off)". | |
| R2 | Idle connection: open an SSH (or telnet) session to a proxied host, leave it idle 3+ minutes, then type. | Session still works (the NAT entry is held by the relay, not swept after 120 s). | |
| R3 | Service handles and memory over 1 hour of normal use. | Handle count and private bytes stay flat (no steady growth). Record start/end values. | |
| R4 | Restart v2ray several times while Q2Route runs, then count connections to the SOCKS port. | Count stays bounded (no leaked relay upstream sockets). | |
| R5 | Toggle Steam Direct/Proxy during a download. | Record what happens (existing connections keep their route; new ones use the new route). | |
| R6 | Speed test (e.g. speedtest.net) with the service stopped vs running; watch the service CPU in Task Manager. | Record both speeds and the CPU. | |
| R7 | Router admin page (e.g. `http://192.168.1.1`). | Loads (LAN is always direct). | |
| R8 | Windows Update: Settings > Windows Update > Check for updates. | Connects. | |
| R9 | Inbound to a local server: run `python -m http.server 8000` and open it from another LAN device. | Loads (accepted inbound connections are direct). | |
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
| U1 | `target\release\q2route-service.exe uninstall` | Service removed; `Get-NetFirewallRule -DisplayName "Q2Route relay"` finds nothing. | |

```powershell
target\release\q2route-service.exe uninstall
Get-NetFirewallRule -DisplayName "Q2Route relay"
```
