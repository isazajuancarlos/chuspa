# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Re-vendoriza chuspa AÑADIENDO el árbol de egui/eframe (migración a egui, 2026-10-04).
# Correr A MANO desde una terminal de verdad (en Claude Code: con `!`), porque el
# sandbox bloquea borrar/renombrar dentro de Z:\chuspa.
#
#   ! powershell -ExecutionPolicy Bypass -File Z:\chuspa\revendorizar-egui.ps1
#
# Qué hace, y por qué es seguro:
#  - Respalda .cargo\config.toml antes de tocar nada.
#  - Desactiva SOLO la sustitución de crates-io (mirilla sigue saliendo del vendor
#    viejo, así NO se toca su URL git Linux → el build del .deb no se rompe).
#  - cargo vendor a un dir NUEVO (vendor-new); el viejo queda intacto por si algo falla.
#  - Verifica que vendor-new tenga mirilla + eframe antes de intercambiar.
#  - Intercambia, restaura el config, y prueba el build OFFLINE.
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
    # Comenta SOLO el replace-with que va bajo [source.crates-io] (el primero).
    $c2 = $c -replace '(\[source\.crates-io\]\s*\r?\n)replace-with = "vendored-sources"', '$1# replace-with = "vendored-sources"   # TEMP re-vendor egui'
    if ($c2 -eq $c) { throw "No se encontró el replace-with de crates-io; aborto sin tocar nada." }
    Set-Content $cfg $c2 -NoNewline

    Write-Host "3. cargo vendor -> vendor-new (fetch crates.io + mirilla del vendor viejo). Tarda..." -ForegroundColor Cyan
    Remove-Item vendor-new -Recurse -Force -ErrorAction SilentlyContinue
    cargo vendor vendor-new | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cargo vendor falló (exit $LASTEXITCODE)" }

    Write-Host "3b. Copiando la dep GIT (mirilla) del vendor viejo..." -ForegroundColor Cyan
    # cargo vendor NO re-emite mirilla: su fuente git sigue replace-with=vendored-sources
    # apuntando al vendor viejo, así que la copiamos a mano (es una dep git, no de crates.io).
    if (Test-Path vendor\mirilla) { Copy-Item vendor\mirilla vendor-new\mirilla -Recurse -Force }
    else { throw "no existe vendor\mirilla para copiar" }

    Write-Host "4. Verificando vendor-new..." -ForegroundColor Cyan
    $n = (Get-ChildItem vendor-new -Directory).Count
    $tieneMirilla = Test-Path vendor-new\mirilla
    $tieneEframe  = Test-Path vendor-new\eframe
    Write-Host "   crates: $n | mirilla: $tieneMirilla | eframe: $tieneEframe"
    if (-not ($tieneMirilla -and $tieneEframe) -or $n -lt 490) {
        throw "vendor-new incompleto (mirilla/eframe ausente o pocos crates). NO intercambio."
    }

    Write-Host "5. Intercambiando vendor <- vendor-new..." -ForegroundColor Cyan
    Remove-Item vendor-old -Recurse -Force -ErrorAction SilentlyContinue
    Rename-Item vendor vendor-old
    Rename-Item vendor-new vendor

    Write-Host "6. Restaurando config (re-activa replace-with de crates-io)..." -ForegroundColor Cyan
    Copy-Item $orig $cfg -Force

    Write-Host "7. Build OFFLINE de prueba (control del protocolo solo-local)..." -ForegroundColor Cyan
    cargo build --release --bin chuspa-egui --offline 2>&1 | Select-Object -Last 8
    $ok = $LASTEXITCODE -eq 0

    Write-Host ""
    if ($ok) {
        Write-Host "LISTO. vendor re-vendorizado ($n crates), build egui OFFLINE en verde." -ForegroundColor Green
        Write-Host "El vendor viejo quedó en 'vendor-old' por si acaso; bórralo cuando confíes:" -ForegroundColor Green
        Write-Host "   Remove-Item vendor-old -Recurse -Force" -ForegroundColor Green
    } else {
        Write-Host "El re-vendor terminó pero el build egui NO compiló (probable ajuste de código en chuspa-egui.rs)." -ForegroundColor Yellow
        Write-Host "El vendor YA está actualizado; dile a Claude que corrija el bin y recompile." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    Restaurar-Config
    Write-Host "Nada se intercambió si el error fue antes del paso 5. Revisa y reintenta." -ForegroundColor Red
    exit 1
}
