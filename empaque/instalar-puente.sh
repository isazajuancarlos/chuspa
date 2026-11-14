#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Registra el puente de Chuspa en Firefox.
#
# El manifiesto declara QUÉ programa puede lanzar Firefox y QUÉ extensión puede
# hablar con él. `allowed_extensions` es la parte que importa: sin ella,
# cualquier extensión instalada podría pedirle credenciales al agente.
set -euo pipefail

NOMBRE="com.xiliux.chuspa"
EXTENSION_ID="chuspa@xiliux.com"
DESTINO="$HOME/.mozilla/native-messaging-hosts"

PUENTE="${1:-}"
if [[ -z "$PUENTE" ]]; then
  echo "uso: $0 /ruta/absoluta/a/chuspa-puente" >&2
  exit 2
fi
if [[ ! -x "$PUENTE" ]]; then
  echo "«$PUENTE» no existe o no es ejecutable" >&2
  exit 2
fi
# Firefox exige ruta absoluta y no expande ~ ni variables.
PUENTE="$(readlink -f "$PUENTE")"

mkdir -p "$DESTINO"
cat > "$DESTINO/$NOMBRE.json" <<JSON
{
  "name": "$NOMBRE",
  "description": "Puente entre Firefox y la aplicación Chuspa",
  "path": "$PUENTE",
  "type": "stdio",
  "allowed_extensions": ["$EXTENSION_ID"]
}
JSON
chmod 600 "$DESTINO/$NOMBRE.json"

echo "Manifiesto escrito en $DESTINO/$NOMBRE.json"
echo "  programa   : $PUENTE"
echo "  extensión  : $EXTENSION_ID (y ninguna otra)"
echo
echo "Ahora, en Firefox: about:debugging → Este Firefox → Cargar complemento"
echo "temporal → elige $PWD/extension/manifest.json"
echo
echo "La bóveda se abre en la ventana: chuspa-gtk. No hay proceso aparte —el"
echo "enlace con el navegador vive DENTRO de la aplicación, porque el cerrojo"
echo "del archivo impide abrir la misma bóveda dos veces."
echo
echo "Para Brave, Chrome o Chromium: empaque/instalar-extension-chrome.sh"
