# Builds a release and assembles a portable folder at dist\Q2Route.
# Usage (from the repo root): powershell -ExecutionPolicy Bypass -File scripts\package.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# The service locks its exe and WinDivert.dll while running.
$svc = Get-Service Q2Route -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    throw "Q2Route service is running. Run dist\Q2Route\Uninstall.cmd (or 'sc.exe stop Q2Route' as admin) first."
}

cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$out = Join-Path $root 'dist\Q2Route'
New-Item -ItemType Directory -Force $out | Out-Null
$files = 'q2route.exe', 'q2route-service.exe', 'WinDivert.dll', 'WinDivert64.sys'
foreach ($f in $files) { Copy-Item (Join-Path $root "target\release\$f") $out -Force }
Copy-Item (Join-Path $root 'vendor\windivert\LICENSE') (Join-Path $out 'WinDivert-LICENSE.txt') -Force
Copy-Item (Join-Path $root 'scripts\dist\*') $out -Force

Write-Host "Packaged to $out"
