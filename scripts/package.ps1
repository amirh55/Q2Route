# Builds a release and assembles a portable folder at dist\Q2Route.
# Usage (from the repo root): powershell -ExecutionPolicy Bypass -File scripts\package.ps1
#
# The service locks its exe and WinDivert.dll while running, so when it is
# running the build goes to dist\Q2Route-update instead, with Update.cmd,
# which swaps the files into dist\Q2Route and restarts the service.
#
# With -Setup it also builds dist\Q2Route-Setup-<version>.exe (Inno Setup) and the
# portable zip dist\Q2Route-<version>-win-x64.zip, both from a fresh dist\setup-stage
# folder, so files locked by a running service are not needed.
param([switch]$Setup)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$svc = Get-Service Q2Route -ErrorAction SilentlyContinue
$update = $svc -and $svc.Status -ne 'Stopped'

cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$out = Join-Path $root $(if ($update) { 'dist\Q2Route-update' } else { 'dist\Q2Route' })
New-Item -ItemType Directory -Force $out | Out-Null
$files = 'q2route.exe', 'q2route-service.exe', 'WinDivert.dll', 'WinDivert64.sys'
foreach ($f in $files) { Copy-Item (Join-Path $root "target\release\$f") $out -Force }
Copy-Item (Join-Path $root 'vendor\windivert\LICENSE') (Join-Path $out 'WinDivert-LICENSE.txt') -Force
Copy-Item (Join-Path $root 'scripts\dist\*') $out -Force

if ($update) {
    Copy-Item (Join-Path $root 'scripts\update\Update.cmd') $out -Force
    Write-Host "Service is running: update packaged to $out. Run Update.cmd there."
} else {
    Write-Host "Packaged to $out"
}

if ($Setup) {
    $m = Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $m) { throw "workspace version not found in Cargo.toml" }
    $ver = $m.Matches[0].Groups[1].Value

    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6", "$env:ProgramFiles\Inno Setup 6", "$env:LOCALAPPDATA\Programs\Inno Setup 6") |
        ForEach-Object { Join-Path $_ 'ISCC.exe' } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw "ISCC.exe not found. Install Inno Setup 6: winget install -e --id JRSoftware.InnoSetup" }

    $stage = Join-Path $root 'dist\setup-stage'
    $zipDir = Join-Path $root 'dist\setup-zip'
    foreach ($d in $stage, $zipDir) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
    $inner = Join-Path $zipDir 'Q2Route'
    New-Item -ItemType Directory -Force $stage, $inner | Out-Null
    foreach ($f in $files) { Copy-Item (Join-Path $root "target\release\$f") $stage -Force }
    Copy-Item (Join-Path $root 'vendor\windivert\LICENSE') (Join-Path $stage 'WinDivert-LICENSE.txt') -Force

    & $iscc "/DAppVersion=$ver" (Join-Path $root 'installer\q2route.iss')
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

    Copy-Item (Join-Path $stage '*') $inner -Force
    Copy-Item (Join-Path $root 'scripts\dist\*') $inner -Force
    $zip = Join-Path $root "dist\Q2Route-$ver-win-x64.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    for ($i = 1; $i -le 5; $i++) {
        try { Compress-Archive -Path $inner -DestinationPath $zip -Force -ErrorAction Stop; break }
        catch { if ($i -eq 5) { throw }; Start-Sleep -Seconds 2 }
    }
    Remove-Item $zipDir -Recurse -Force
    Write-Host "Setup: dist\Q2Route-Setup-$ver.exe"
    Write-Host "Zip:   $zip"
}
