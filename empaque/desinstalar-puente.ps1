# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Juan Carlos Isaza
#
# Quita el registro del puente de Chuspa en Windows (lo que escribió
# instalar-puente.ps1): las tres claves del registro y los manifiestos.

$ErrorActionPreference = "Stop"
$Nombre = "com.xiliux.chuspa"

$claves = @(
    "HKCU:\Software\Mozilla\NativeMessagingHosts\$Nombre",
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$Nombre",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$Nombre"
)
foreach ($c in $claves) {
    if (Test-Path $c) {
        Remove-Item -Path $c -Force
        Write-Host "quitada  $c"
    } else {
        Write-Host "no estaba  $c"
    }
}

$destino = Join-Path $env:LOCALAPPDATA "chuspa"
foreach ($m in @("$Nombre.json", "$Nombre.chrome.json")) {
    $ruta = Join-Path $destino $m
    if (Test-Path $ruta) {
        Remove-Item -Path $ruta -Force
        Write-Host "borrado  $ruta"
    }
}
Write-Host ""
Write-Host "Puente desregistrado. El socket del agente y la bóveda no se tocan." -ForegroundColor Green
