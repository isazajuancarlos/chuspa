# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Juan Carlos Isaza
#
# Registra el puente de Chuspa en Firefox, Chrome y Brave EN WINDOWS (Fase B).
#
# En Linux el manifiesto de native-messaging es un archivo JSON en un directorio
# conocido (`instalar-puente.sh`). En Windows el navegador NO mira un directorio:
# lee una CLAVE DEL REGISTRO cuyo valor por defecto apunta al archivo JSON. Por eso
# aquí se hacen dos cosas por navegador: escribir el manifiesto y apuntar la clave
# del registro a él.
#
# El manifiesto declara QUÉ programa puede lanzar el navegador (`path`) y QUÉ
# extensión puede hablar con él. Esa restricción es la parte que importa:
#   - Firefox usa `allowed_extensions` (el id del complemento).
#   - Chrome/Brave usan `allowed_origins` (`chrome-extension://<id>/`).
# Sin ellas, cualquier extensión instalada podría pedirle firmas al agente.
#
# Todo va en HKEY_CURRENT_USER: es por-usuario y no necesita administrador, igual
# que el `.sh` escribe en $HOME. El puente NO abre la bóveda ni ve la frase; lo
# único que hace es reenviar al socket del agente (`%LOCALAPPDATA%\chuspa\agente.sock`).

[CmdletBinding()]
param(
    # Ruta al ejecutable del puente. Si se omite, se busca `chuspa-puente.exe`
    # junto a este script y, si no, junto a `chuspa-egui.exe` instalado.
    [string]$Puente,
    # El id del complemento de Firefox y el de Chrome/Brave. Por defecto los de
    # producción; se dejan como parámetro para pruebas con una compilación propia.
    [string]$IdFirefox = "chuspa@xiliux.com",
    [string]$IdChrome = "gnnfdpkaghhjdfjjbmpknkifmicljbll"
)

$ErrorActionPreference = "Stop"
$Nombre = "com.xiliux.chuspa"

# ── Resolver la ruta del puente ──────────────────────────────────────────────
if (-not $Puente) {
    $aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidatos = @(
        (Join-Path $aqui "chuspa-puente.exe"),
        (Join-Path (Split-Path -Parent $aqui) "chuspa-puente.exe"),
        (Join-Path (Split-Path -Parent $aqui) "target\release\chuspa-puente.exe")
    )
    $Puente = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Puente -or -not (Test-Path $Puente)) {
    Write-Error "No encuentro chuspa-puente.exe. Pásalo con -Puente <ruta al .exe>."
    exit 2
}
# El navegador exige ruta ABSOLUTA y no expande variables ni rutas relativas.
$Puente = (Resolve-Path $Puente).Path
if (-not $Puente.EndsWith(".exe")) {
    Write-Warning "«$Puente» no termina en .exe; comprueba que es el ejecutable del puente."
}

# ── Carpeta de manifiestos ───────────────────────────────────────────────────
$destino = Join-Path $env:LOCALAPPDATA "chuspa"
New-Item -ItemType Directory -Force -Path $destino | Out-Null

# Escribe un JSON en UTF-8 SIN BOM: Firefox rechaza el manifiesto si lleva BOM.
function Escribir-Json($ruta, $objeto) {
    $json = $objeto | ConvertTo-Json -Depth 5
    $utf8SinBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ruta, $json, $utf8SinBom)
}

$manifiestoFirefox = Join-Path $destino "$Nombre.json"
$manifiestoChrome = Join-Path $destino "$Nombre.chrome.json"

Escribir-Json $manifiestoFirefox ([ordered]@{
    name = $Nombre
    description = "Puente entre Firefox y la aplicación Chuspa"
    path = $Puente
    type = "stdio"
    allowed_extensions = @($IdFirefox)
})

Escribir-Json $manifiestoChrome ([ordered]@{
    name = $Nombre
    description = "Puente entre el navegador y la aplicación Chuspa"
    path = $Puente
    type = "stdio"
    allowed_origins = @("chrome-extension://$IdChrome/")
})

# ── Claves del registro (HKCU) ───────────────────────────────────────────────
# El valor POR DEFECTO de la clave es la ruta del manifiesto. Cada navegador
# Chromium lee su PROPIA rama: Chrome bajo Google\Chrome, Brave bajo
# BraveSoftware\Brave-Browser. Firefox bajo Mozilla.
function Registrar($claveBase, $manifiesto) {
    $clave = "$claveBase\$Nombre"
    New-Item -Path $clave -Force | Out-Null
    # `(default)` = Set-Item -Value sobre la clave.
    Set-Item -Path $clave -Value $manifiesto
}

Registrar "HKCU:\Software\Mozilla\NativeMessagingHosts" $manifiestoFirefox
Registrar "HKCU:\Software\Google\Chrome\NativeMessagingHosts" $manifiestoChrome
Registrar "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts" $manifiestoChrome

# ── Resumen ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Puente registrado para Firefox, Chrome y Brave (usuario actual)." -ForegroundColor Green
Write-Host "  programa          : $Puente"
Write-Host "  manifiesto FF     : $manifiestoFirefox  (extensión $IdFirefox)"
Write-Host "  manifiesto Chrome : $manifiestoChrome  (chrome-extension://$IdChrome/)"
Write-Host ""
Write-Host "Claves del registro escritas:"
Write-Host "  HKCU\Software\Mozilla\NativeMessagingHosts\$Nombre"
Write-Host "  HKCU\Software\Google\Chrome\NativeMessagingHosts\$Nombre"
Write-Host "  HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$Nombre"
Write-Host ""
Write-Host "La bóveda se abre en la ventana (chuspa-egui). El enlace con el navegador"
Write-Host "vive DENTRO de la aplicación: el cerrojo del archivo impide abrir la misma"
Write-Host "bóveda dos veces, así que no hay proceso agente aparte."
Write-Host ""
Write-Host "Cargar la extensión sin firmar:"
Write-Host "  Firefox: about:debugging -> Este Firefox -> Cargar complemento temporal"
Write-Host "           -> elige extension\manifest.json"
Write-Host "  Brave  : brave://extensions -> Modo de desarrollador -> Cargar"
Write-Host "           descomprimida -> elige la carpeta extension\"
Write-Host ""
Write-Host "Para QUITAR el registro: desinstalar-puente.ps1"
