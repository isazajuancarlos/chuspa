#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Prepara la extensión para Chrome/Brave/Chromium y registra el puente.
#
# Hace dos cosas que en Firefox son una sola:
#
#   1. Arma `target/extension-chrome/` — los mismos archivos de `extension/`,
#      pero con `manifest.chrome.json` puesto como `manifest.json`. Chrome no
#      admite `background.scripts` y Firefox no admite `service_worker`, así que
#      los dos manifiestos no se pueden fundir en uno. El resto de archivos es
#      EL MISMO: se copian, no se duplican en el repositorio.
#
#   2. Escribe el manifiesto del puente en las rutas donde miran Brave, Chrome y
#      Chromium. Cada uno tiene la suya y ninguno mira las de los otros.
#
# El identificador de la extensión NO se pide: el manifiesto lleva una clave
# pública fija (`key`), y Chrome deriva el identificador de ella. Sin esa clave
# el identificador saldría del CAMINO en disco, así que mover la carpeta lo
# cambiaría y el puente dejaría de estar autorizado sin que nada lo dijera.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOMBRE="com.xiliux.chuspa"
DESTINO_EXT="$RAIZ/target/extension-chrome"

# El puente que el navegador va a usar. POR DEFECTO, EL INSTALADO — y no es
# una comodidad, es la corrección de un defecto medido el 2026-08-15:
#
#   Brave/Chrome/Chromium  ->  /mnt/data/chuspa/target/release/chuspa-puente
#   Firefox                ->  /usr/bin/chuspa-puente
#
# Los manifiestos de $HOME los escribió este guion el 2026-08-10 con la ruta del
# ÁRBOL DE CONSTRUCCIÓN, y en Chrome los de $HOME TAPAN a los que instala el RPM
# en /etc. Resultado: dos navegadores hablando con dos puentes distintos contra
# la misma aplicación, y el del árbol es lo que dejó el último `cargo build` —
# puede ir por delante, por detrás o estar sucio. Aquel día coincidían byte a
# byte, así que no se veía: es «misma versión, distinto contenido» otra vez, una
# capa más abajo, y sin nada que lo delate.
PUENTE_INSTALADO="/usr/bin/chuspa-puente"
PUENTE="${1:-}"
if [[ -z "$PUENTE" ]]; then
  if [[ -x "$PUENTE_INSTALADO" ]]; then
    PUENTE="$PUENTE_INSTALADO"
    echo "puente: el INSTALADO, $PUENTE_INSTALADO"
  else
    echo "uso: $0 /ruta/absoluta/a/chuspa-puente" >&2
    echo "(sin argumento se usaría $PUENTE_INSTALADO, que aquí no existe:" >&2
    echo " instala el RPM, o pasa la ruta del que quieras registrar)" >&2
    exit 2
  fi
fi
if [[ ! -x "$PUENTE" ]]; then
  echo "«$PUENTE» no existe o no es ejecutable" >&2
  exit 2
fi
# Chrome, igual que Firefox, exige ruta absoluta y no expande ~ ni variables.
PUENTE="$(readlink -f "$PUENTE")"

# Registrar OTRO puente sigue siendo legítimo —probar uno sin publicar es
# trabajo normal—, pero se dice en voz alta: callarlo es lo que dejó la
# divergencia viva cinco días sin que nadie la viera.
if [[ -x "$PUENTE_INSTALADO" && "$PUENTE" != "$(readlink -f "$PUENTE_INSTALADO")" ]]; then
  echo
  echo "AVISO: el navegador va a usar un puente DISTINTO del instalado."
  echo "  navegador : $PUENTE"
  echo "  instalado : $PUENTE_INSTALADO   ($($PUENTE_INSTALADO --version 2>/dev/null || echo '?'))"
  echo "  Firefox usa SIEMPRE el instalado, así que los dos navegadores"
  echo "  quedarán hablando con programas distintos."
  echo "  Para volver al instalado: $0   (sin argumento)"
  echo
fi

# --- 1. La carpeta que se carga en el navegador ---------------------------
rm -rf "$DESTINO_EXT"
mkdir -p "$DESTINO_EXT"
for f in "$RAIZ"/extension/*; do
  nombre="$(basename "$f")"
  # El manifiesto de Firefox y el directorio del banco de pruebas no van dentro.
  case "$nombre" in
    manifest.json|manifest.chrome.json|banco) continue ;;
  esac
  cp -r "$f" "$DESTINO_EXT/"
done
cp "$RAIZ/extension/manifest.chrome.json" "$DESTINO_EXT/manifest.json"

# El identificador se calcula a partir de la clave pública del manifiesto: son
# los 128 primeros bits de su SHA-256, con cada dígito hexadecimal traducido de
# «0-f» a «a-p». Se calcula aquí en vez de escribirlo a mano para que no pueda
# desmentir a la clave que hay al lado.
ID="$(python3 - "$DESTINO_EXT/manifest.json" <<'PY'
import base64, hashlib, json, sys
clave = json.load(open(sys.argv[1]))["key"]
h = hashlib.sha256(base64.b64decode(clave)).hexdigest()[:32]
print("".join(chr(ord("a") + int(c, 16)) for c in h))
PY
)"

# --- 2. El manifiesto del puente, en las tres rutas -----------------------
rutas=(
  "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "$HOME/.config/google-chrome/NativeMessagingHosts"
  "$HOME/.config/chromium/NativeMessagingHosts"
)
escritas=0
for destino in "${rutas[@]}"; do
  # Solo donde el navegador está instalado: crear la carpeta de perfil de un
  # navegador que no existe deja basura y no habilita nada.
  perfil="$(dirname "$destino")"
  [[ -d "$perfil" ]] || continue
  mkdir -p "$destino"
  cat > "$destino/$NOMBRE.json" <<JSON
{
  "name": "$NOMBRE",
  "description": "Puente entre el navegador y la aplicación Chuspa",
  "path": "$PUENTE",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$ID/"]
}
JSON
  chmod 600 "$destino/$NOMBRE.json"
  echo "  manifiesto en $destino/$NOMBRE.json"
  escritas=$((escritas + 1))
done

if [[ $escritas -eq 0 ]]; then
  # Directiva: ante la ausencia de un dato, fallar ruidosamente. Un «listo» sin
  # haber escrito nada es peor que un error: se descubre el día que la llave no
  # funciona y ya nadie recuerda este paso.
  echo "No hay ningún perfil de Brave, Chrome ni Chromium en \$HOME." >&2
  echo "Abre el navegador una vez para que lo cree, y vuelve a ejecutar esto." >&2
  exit 1
fi

echo
echo "  extensión  : $DESTINO_EXT"
echo "  identidad  : $ID (fijada por la clave del manifiesto)"
echo "  programa   : $PUENTE"
echo
echo "Ahora, en el navegador:"
echo "  brave://extensions  (o chrome://extensions)"
echo "  → Modo de desarrollador → Cargar descomprimida → elige"
echo "    $DESTINO_EXT"
echo
echo "Comprueba que el identificador que muestra la página es $ID."
echo "Si es otro, el puente NO lo autorizará: la clave del manifiesto no llegó."
