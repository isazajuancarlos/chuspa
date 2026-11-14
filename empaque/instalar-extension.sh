#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Instala el .xpi FIRMADO de Chuspa para todo el sistema.
#
# Comprueba la firma antes de instalar: un paquete sin firmar se copiaría igual
# y Firefox lo ignoraría en silencio, que es la peor forma de fallar —parece
# instalado y no lo está—.
set -euo pipefail

XPI="${1:-}"
if [[ -z "$XPI" || ! -f "$XPI" ]]; then
  echo "uso: $0 /ruta/al/complemento-firmado.xpi" >&2
  echo >&2
  echo "Se descarga del Centro de Desarrolladores de AMO:" >&2
  echo "  Administrar estado y versiones -> Version 0.1.0 -> el archivo .xpi" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
if ! python3 empaque/comprobar-firma.py "$XPI"; then
  echo >&2
  echo "No se instala: Firefox ignoraría un paquete sin firmar y parecería" >&2
  echo "que está puesto cuando no lo está." >&2
  exit 1
fi

# Ese identificador entre llaves es el de Firefox como aplicación, no el de la
# extensión. El nombre del archivo SÍ tiene que ser el id de la extensión.
DESTINO="/usr/lib/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/chuspa@xiliux.com.xpi"

echo
echo "Instalando en $DESTINO"
sudo install -Dm644 "$XPI" "$DESTINO"
echo
echo "Hecho. Reinicia Firefox: pedirá permiso para activar «Chuspa»."
echo "Después, abre la aplicación con  chuspa-gtk  y desbloquea la bóveda."
