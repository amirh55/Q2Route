@echo off
rem Replaces the installed Q2Route in ..\Q2Route with the files in this folder,
rem then restarts the service and the UI. Settings are kept.
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
set "SRC=%~dp0"
set "DST=%~dp0..\Q2Route\"
if not exist "%DST%q2route-service.exe" (
    echo No installed Q2Route found in "%DST%". Run Install.cmd there instead.
    pause
    exit /b 1
)

taskkill /IM q2route.exe >nul 2>&1
echo Stopping the Q2Route service...
sc.exe stop Q2Route >nul 2>&1
powershell -NoProfile -Command "$s = Get-Service Q2Route -ErrorAction SilentlyContinue; if ($s) { $s.WaitForStatus('Stopped', '00:00:20') }"
rem The exe stays locked for a moment after the service reports Stopped.
timeout /t 2 /nobreak >nul

for %%f in (q2route.exe q2route-service.exe WinDivert.dll WinDivert64.sys WinDivert-LICENSE.txt Install.cmd Uninstall.cmd OpenLog.cmd) do (
    copy /Y "%SRC%%%f" "%DST%%%f" >nul || (
        echo Could not replace %%f. Close Q2Route and try again.
        sc.exe start Q2Route >nul 2>&1
        pause
        exit /b 1
    )
)

sc.exe start Q2Route >nul
explorer.exe "%DST%q2route.exe"
echo.
echo Updated. The Q2Route window should open now.
timeout /t 5
