# Builds a release and assembles a portable folder at dist\Q2Route.
# Usage (from the repo root): powershell -ExecutionPolicy Bypass -File scripts\package.ps1
#
# The service locks its exe and WinDivert.dll while running, so when it is
# running the build goes to dist\Q2Route-update instead, with Update.cmd,
# which swaps the files into dist\Q2Route and restarts the service.
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
