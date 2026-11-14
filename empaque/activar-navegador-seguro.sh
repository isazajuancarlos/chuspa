#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Juan Carlos Isaza
#
# Activa (o desactiva) chuspa-navegar como NAVEGADOR POR DEFECTO del usuario, de
# modo que todo enlace del sistema (/login, xdg-open, clic en otra app) abra el
# perfil cifrado del navegador seguro y NO el Firefox estándar.
#
# Se corre COMO USUARIO, no root: cambia la configuración de ESTE usuario. Por eso
# NO va en el %post del paquete —ahí correría como root, sin el $HOME del usuario,
# y además imponer el navegador por defecto a todos sería invasivo—.
#
#   chuspa-navegador-predeterminado activar [RUTA_DEL_VOLUMEN]
#   chuspa-navegador-predeterminado desactivar
#
# RUTA_DEL_VOLUMEN (opcional): dónde vive el perfil cifrado. Si se da, se fija
# CHUSPA_NAVEGADOR_DIR en el lanzador (p. ej. /mnt/data/navegador-seguro, un disco
# que sobreviva a reinstalar); si no, chuspa-navegar usa el directorio XDG.

set -euo pipefail

APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
FF="org.mozilla.firefox.desktop"

activar() {
  local vol="${1:-}"
  mkdir -p "$APPS"
  local exec_line="chuspa-navegar %u"
  [ -n "$vol" ] && exec_line="env CHUSPA_NAVEGADOR_DIR=$vol chuspa-navegar %u"

  cat > "$APPS/chuspa-navegar.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Navegador seguro (Chuspa)
GenericName=Secure browser
Comment=Abre enlaces en el perfil cifrado de Chuspa
Exec=$exec_line
Icon=chuspa
Terminal=false
Categories=Network;WebBrowser;
MimeType=x-scheme-handler/http;x-scheme-handler/https;text/html;
StartupNotify=true
EOF

  # Ocultar el lanzador de Firefox del menú y de "abrir con". El binario
  # /usr/bin/firefox SIGUE existiendo —chuspa lo usa para el perfil cifrado—.
  cat > "$APPS/$FF" <<EOF
[Desktop Entry]
Type=Application
Name=Firefox
Exec=firefox %u
Hidden=true
NoDisplay=true
EOF

  xdg-settings set default-web-browser chuspa-navegar.desktop
  xdg-mime default chuspa-navegar.desktop x-scheme-handler/http x-scheme-handler/https text/html
  update-desktop-database "$APPS" 2>/dev/null || true
  echo "Activado: chuspa-navegar es el navegador por defecto; Firefox oculto del menú."
  echo "Recuerda tener el navegador seguro abierto (chuspa → «Abrir y navegar») para navegar."
}

desactivar() {
  rm -f "$APPS/chuspa-navegar.desktop" "$APPS/$FF"
  xdg-settings set default-web-browser "$FF" 2>/dev/null || true
  update-desktop-database "$APPS" 2>/dev/null || true
  echo "Desactivado: Firefox vuelve a ser el navegador por defecto."
}

case "${1:-}" in
  activar)    activar "${2:-}";;
  desactivar) desactivar;;
  *) echo "uso: $(basename "$0") activar [RUTA_DEL_VOLUMEN] | desactivar" >&2; exit 2;;
esac
