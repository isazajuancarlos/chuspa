#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Juan Carlos Isaza
"""Empaqueta la extensión como .xpi listo para firmar en AMO.

Un `.xpi` es un zip. Firefox **exige** que esté firmado por Mozilla para poder
instalarlo de forma permanente, así que este archivo no se instala tal cual: se
sube a addons.mozilla.org en modo «unlisted» (autodistribuido) y Mozilla
devuelve el mismo paquete firmado.

Se empaqueta con Python y no con `zip` porque `zip` no viene en una instalación
mínima de Tumbleweed, y un script de empaquetado que solo funciona en la máquina
de quien lo escribió no sirve de nada.
"""

import json
import os
import sys
import zipfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUENTE = os.path.join(RAIZ, "extension")

manifiesto = json.load(open(os.path.join(FUENTE, "manifest.json"), encoding="utf-8"))
version = manifiesto["version"]
extension_id = manifiesto["browser_specific_settings"]["gecko"]["id"]

os.makedirs(os.path.join(RAIZ, "target"), exist_ok=True)
salida = os.path.join(RAIZ, "target", f"chuspa-{version}.xpi")
if os.path.exists(salida):
    os.remove(salida)

# Lo que NO viaja a Mozilla. Un `.xpi` es lo que se le sube a un revisor: el
# banco de pruebas son servidores de mentira que no pintan nada dentro de un
# complemento firmado, y el manifiesto de Chrome es literalmente el de otro
# navegador. Ninguno de los dos rompe nada al colarse, y por eso hay que
# excluirlos a propósito: nadie se daría cuenta.
FUERA_ARCHIVOS = {"manifest.chrome.json"}
FUERA_CARPETAS = {"banco"}

with zipfile.ZipFile(salida, "w", zipfile.ZIP_DEFLATED) as z:
    for base, carpetas, archivos in os.walk(FUENTE):
        carpetas[:] = [c for c in carpetas if c not in FUERA_CARPETAS]
        for nombre in sorted(archivos):
            if nombre.startswith(".") or nombre in FUERA_ARCHIVOS:
                continue
            ruta = os.path.join(base, nombre)
            # El manifest.json va en la RAÍZ del zip, no bajo `extension/`: es
            # el error que hace que AMO rechace el paquete antes de mirar una
            # sola línea de código.
            z.write(ruta, os.path.relpath(ruta, FUENTE))
    contenido = sorted(z.namelist())

if "manifest.json" not in contenido:
    print("ERROR: manifest.json no quedó en la raíz del paquete", file=sys.stderr)
    sys.exit(1)

print(f"Paquete: {salida}")
for nombre in contenido:
    print("  ", nombre)

print(
    f"""
Firefox EXIGE firma de Mozilla para instalar una extensión de forma permanente.
Este .xpi todavía NO está firmado, así que solo sirve para:

  · probarlo temporalmente en about:debugging (se pierde al cerrar Firefox), o
  · subirlo a AMO para que lo firmen.

Para dejarlo instalado de verdad (lo hace Juan: subir algo es publicar):

  1. addons.mozilla.org -> Submit a New Add-on
  2. En «How to distribute this version?» elegir «On your own».
     (La otra opcion, «On this site», lo PUBLICA en el catalogo. «On your own»
      es la autodistribuida: Mozilla la firma y no la publica.)
  3. Subir este archivo y descargar el .xpi FIRMADO.
  4. Instalarlo para todo el sistema:

     sudo install -Dm644 firmado.xpi \\
       '/usr/lib/mozilla/extensions/{{ec8030f7-c20a-464f-9b0e-13a3a9e97384}}/{extension_id}.xpi'

     (ese identificador entre llaves es el de Firefox, no el de la extensión)
"""
)
