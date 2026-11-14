# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Termina el re-vendor APROVECHANDO el 'vendor-new' que ya escribió
# revendorizar-egui.ps1 (no re-descarga). Copia la dep git mirilla, verifica,
# intercambia y compila offline. Correr con `!`:
#   ! powershell -ExecutionPolicy Bypass -File Z:\chuspa\terminar-revendor.ps1

$ErrorActionPreference = 'Stop'
$env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' + [Environment]::GetEnvironmentVariable('Path','Machine')
Set-Location Z:\chuspa

if (-not (Test-Path vendor-new\eframe)) { Write-Host "No hay vendor-new con eframe; corré primero revendorizar-egui.ps1" -ForegroundColor Red; exit 1 }

Write-Host "1. Copiando mirilla (dep git) del vendor viejo a vendor-new..." -ForegroundColor Cyan
if (Test-Path vendor\mirilla) { Copy-Item vendor\mirilla vendor-new\mirilla -Recurse -Force }
else { Write-Host "No existe vendor\mirilla" -ForegroundColor Red; exit 1 }

$n = (Get-ChildItem vendor-new -Directory).Count
$okm = Test-Path vendor-new\mirilla
$oke = Test-Path vendor-new\eframe
Write-Host "   vendor-new: $n crates | mirilla: $okm | eframe: $oke"
if (-not ($okm -and $oke) -or $n -lt 500) { Write-Host "vendor-new incompleto; NO intercambio." -ForegroundColor Red; exit 1 }

Write-Host "2. Intercambiando vendor <- vendor-new..." -ForegroundColor Cyan
Remove-Item vendor-old -Recurse -Force -ErrorAction SilentlyContinue
Rename-Item vendor vendor-old
Rename-Item vendor-new vendor

# El config ya quedó restaurado por el script anterior (replace-with vendored, dir=vendor).
Write-Host "3. Build OFFLINE de chuspa-egui (control solo-local)..." -ForegroundColor Cyan
cargo build --release --bin chuspa-egui --offline 2>&1 | Select-Object -Last 20
$ok = $LASTEXITCODE -eq 0

Write-Host ""
if ($ok) {
    Write-Host "LISTO. Re-vendor completo ($n crates) y chuspa-egui compiló OFFLINE." -ForegroundColor Green
    Write-Host "Borra el vendor viejo cuando confíes:  Remove-Item vendor-old -Recurse -Force" -ForegroundColor Green
} else {
    Write-Host "Vendor OK pero el bin no compiló: es ajuste de código en chuspa-egui.rs." -ForegroundColor Yellow
    Write-Host "Pégale a Claude las últimas líneas de error y lo corrige." -ForegroundColor Yellow
}
