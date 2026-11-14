#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Juan Carlos Isaza
"""¿Está firmado este .xpi por Mozilla?

Es la única comprobación que no depende de lo que diga una pantalla: un paquete
firmado lleva dentro `META-INF/mozilla.rsa`, que es la firma. Si está, Firefox lo
instalará de forma permanente; si no está, solo sirve para `about:debugging`.
"""
import sys
import zipfile

if len(sys.argv) != 2:
    print("uso: comprobar-firma.py <archivo.xpi>", file=sys.stderr)
    sys.exit(2)

ruta = sys.argv[1]
try:
    with zipfile.ZipFile(ruta) as z:
        nombres = z.namelist()
except Exception as e:
    print(f"no se pudo leer «{ruta}»: {e}", file=sys.stderr)
    sys.exit(2)

firma = [n for n in nombres if n.startswith("META-INF/")]
if firma:
    print(f"FIRMADO ✓  «{ruta}»")
    for n in sorted(firma):
        print("   ", n)
    print("\nSe puede instalar de forma permanente en Firefox.")
else:
    print(f"SIN FIRMAR ✗  «{ruta}»")
    print("\nSolo sirve para about:debugging (temporal). Para instalarlo de")
    print("verdad hay que subirlo a AMO y descargar el paquete que devuelven.")
    sys.exit(1)
