# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Re-vendoriza chuspa AÑADIENDO uds_windows (AF_UNIX en Windows para el enlace con
# el navegador — passkeys, 2026-10-04). Mismo patrón que revendorizar-egui.ps1.
# Correr A MANO desde una terminal de verdad (en Claude Code: con `!`), porque el
# sandbox bloquea borrar/renombrar dentro de Z:\chuspa.
#
#   ! powershell -ExecutionPolicy Bypass -File Z:\chuspa\revendorizar-uds.ps1
#
# Qué hace, y por qué es seguro:
#  - Respalda .cargo\config.toml antes de tocar nada.
#  - Desactiva SOLO la sustitución de crates-io (mirilla sigue del vendor viejo).
#  - cargo vendor a vendor-new; el viejo queda intacto por si algo falla.
#  - Verifica que vendor-new tenga mirilla + eframe + uds_windows antes de cambiar.
#  - Intercambia, restaura el config, y prueba el build egui OFFLINE.
#  - Si algo falla antes del intercambio, restaura el config y deja el vendor viejo.

$ErrorActionPreference = 'Stop'
$env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' + [Environment]::GetEnvironmentVariable('Path','Machine')
Set-Location Z:\chuspa

$cfg  = ".cargo\config.toml"
$orig = ".cargo\config.toml.orig"

function Restaurar-Config { if (Test-Path $orig) { Copy-Item $orig $cfg -Force; Write-Host "  config restaurada" -ForegroundColor Yellow } }

try {
    Write-Host "1. Respaldo del config..." -ForegroundColor Cyan
    Copy-Item $cfg $orig -Force

    Write-Host "2. Desactivando la sustitución de crates-io (mirilla se queda replace-with)..." -ForegroundColor Cyan
    $c = Get-Content $cfg -Raw
    $c2 = $c -replace '(\[source\.crates-io\]\s*\r?\n)replace-with = "vendored-sources"', '$1# replace-with = "vendored-sources"   # TEMP re-vendor uds'
    if ($c2 -eq $c) { throw "No se encontró el replace-with de crates-io; aborto sin tocar nada." }
    Set-Content $cfg $c2 -NoNewline

    Write-Host "3. cargo vendor -> vendor-new (fetch crates.io + mirilla del vendor viejo). Tarda..." -ForegroundColor Cyan
    Remove-Item vendor-new -Recurse -Force -ErrorAction SilentlyContinue
    cargo vendor vendor-new | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cargo vendor falló (exit $LASTEXITCODE)" }

    Write-Host "3b. Copiando la dep GIT (mirilla) del vendor viejo..." -ForegroundColor Cyan
    if (Test-Path vendor\mirilla) { Copy-Item vendor\mirilla vendor-new\mirilla -Recurse -Force }
    else { throw "no existe vendor\mirilla para copiar" }

    Write-Host "4. Verificando vendor-new..." -ForegroundColor Cyan
    $n = (Get-ChildItem vendor-new -Directory).Count
    $tieneMirilla = Test-Path vendor-new\mirilla
    $tieneEframe  = Test-Path vendor-new\eframe
    $tieneUds     = Test-Path vendor-new\uds_windows
    Write-Host "   crates: $n | mirilla: $tieneMirilla | eframe: $tieneEframe | uds_windows: $tieneUds"
    if (-not ($tieneMirilla -and $tieneEframe -and $tieneUds) -or $n -lt 515) {
        throw "vendor-new incompleto (falta mirilla/eframe/uds_windows o pocos crates). NO intercambio."
    }

    Write-Host "5. Intercambiando vendor <- vendor-new..." -ForegroundColor Cyan
    Remove-Item vendor-old -Recurse -Force -ErrorAction SilentlyContinue
    Rename-Item vendor vendor-old
    Rename-Item vendor-new vendor

    Write-Host "6. Restaurando config (re-activa replace-with de crates-io)..." -ForegroundColor Cyan
    Copy-Item $orig $cfg -Force

    Write-Host "7. Build OFFLINE de prueba (control del protocolo solo-local)..." -ForegroundColor Cyan
    # OJO: cargo escribe su progreso ("Compiling ...") a STDERR. Con
    # $ErrorActionPreference='Stop' + 2>&1, PowerShell trata esa primera línea de
    # stderr como error TERMINANTE y salta al catch ANTES de que el build acabe
    # —un falso fallo—. Se baja a 'Continue' solo para el build y se mira el exit code.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    cargo build --release --bin chuspa-egui --offline 2>&1 | Select-Object -Last 8
    $ok = $LASTEXITCODE -eq 0
    $ErrorActionPreference = $prev

    Write-Host ""
    if ($ok) {
        Write-Host "LISTO. vendor re-vendorizado ($n crates) con uds_windows, build egui OFFLINE en verde." -ForegroundColor Green
        Write-Host "El vendor viejo quedó en 'vendor-old'; bórralo cuando confíes: Remove-Item vendor-old -Recurse -Force" -ForegroundColor Green
    } else {
        Write-Host "El re-vendor terminó pero el build egui NO compiló. El vendor YA está actualizado;" -ForegroundColor Yellow
        Write-Host "dile a Claude que siga (abstraer el transporte usa uds_windows, no el bin egui)." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    Restaurar-Config
    Write-Host "Nada se intercambió si el error fue antes del paso 5. Revisa y reintenta." -ForegroundColor Red
    exit 1
}
