<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Banco del puente de passkeys

Prueba la cadena **página → puente → fondo → aplicación** en un Firefox de
verdad. Existe porque el fallo que lo justificó no lo veía ninguna prueba de las
otras: la extensión se inyectaba bien, la aplicación firmaba bien, y la respuesta
se perdía **entre los dos mundos** de la extensión.

## Qué mide

- `sustituida`: si el content script del mundo principal llegó a sustituir
  `navigator.credentials.get`.
- `respondio`: si el puente contestó. **Esta es la que importa**: con el
  mecanismo anterior daba `false` sin ningún error a la vista.

## Cómo se corre

```bash
python3 extension/banco/banco.py &          # sirve la página en :8932
cp -r extension /tmp/ext-banco               # copia que también corre en localhost
# en /tmp/ext-banco/manifest.json: añadir "http://localhost/*" a los `matches`
MOZ_HEADLESS=1 npx web-ext run --source-dir /tmp/ext-banco \
  --start-url http://localhost:8932/ --no-input --no-reload
```

El veredicto sale por la salida del servidor, en una línea `VEREDICTO {...}`.

## El resultado que lo justifica

Medido el 2026-08-01 en Firefox 153, mismo agente y misma página, cada versión
con el protocolo que entiende:

| Versión | `sustituida` | `respondio` |
|---|---|---|
| `CustomEvent` (anterior) | true | **false** — «sin respuesta en 6 s» |
| `postMessage` (actual) | true | **true** |

Sin el segundo caso, el primero no probaría nada: un rojo puede venir de que el
banco esté mal montado. Con los dos, la diferencia solo puede ser el mecanismo.

## En Brave, `respondio` NO es la medida

Medido el 2026-08-03 en Brave 151 (Chromium 151), con la extensión de
`manifest.chrome.json` y el agente del arnés `socket_de_prueba`:

| fondo | `respondio` | `detalle` | peticiones al agente |
|---|---|---|---|
| `sendResponse` + `return true` | true | la respuesta del agente | 1 |
| `async` que devuelve la promesa | true | la respuesta del agente | 1 |
| **control**: no contesta nunca | **true** | **ausente** | **0** |

Dos cosas, y las dos cambian cómo se lee este banco:

1. **La forma `async` funciona en Brave.** Se había escrito que Chrome la ignora
   y es falso al menos desde Chromium 151. Lo que justifica `sendResponse` es que
   el manifiesto admite desde la 111, no una limitación de hoy.
2. **`respondio` no discrimina aquí.** En Chrome, `runtime.sendMessage` resuelve
   igual cuando nadie contesta, así que el content script devuelve un mensaje
   vacío y la página lo cuenta como respuesta. Con el control —un fondo que no
   contesta nada— sale `respondio: true`. **La medida es `detalle`**, y de apoyo,
   cuántas peticiones llegaron al agente (`CHUSPA_BITACORA`).

En Firefox `respondio` sí discriminaba, porque con `CustomEvent` la página no
recibía NADA. El mismo indicador mide cosas distintas en cada navegador.

## Cómo se corre en Brave

**Perfil nuevo en cada corrida.** Dos `--load-extension` seguidos contra el mismo
`--user-data-dir` no recargan la extensión: el segundo le entrega la URL a la
instancia que ya corre, que tiene la anterior. Medido así, un veneno sale verde
porque lo contesta el proceso viejo — pasó, y dio la conclusión al revés.

```bash
XDG_RUNTIME_DIR=$AISLADO brave-browser \
  --user-data-dir="$PERFIL_NUEVO" --load-extension="$COPIA" \
  --no-first-run --headless=new http://localhost:8932/
```

El `XDG_RUNTIME_DIR` aparte no es cosmético: sin él, la extensión de prueba habla
con el `chuspa-gui` de verdad que uno tenga abierto, y el banco acaba pidiéndole
credenciales a la bóveda real.

---

# Banco de la mediación condicional

`banco-mediacion.py` (puerto 8934). Llama a `navigator.credentials.get` de las
dos formas y cuenta cuántas veces la extensión pregunta al agente, observando los
`postMessage` que cruzan la página.

Con `mediation: "conditional"` el sitio **no está pidiendo entrar**: prepara el
autocompletado, y lo hace nada más cargar la página. Atender esas peticiones era
lo que hacía que Gmail entrara solo, con la primera cuenta, sin que nadie hubiera
pedido nada.

Medido el 2026-08-01 en Firefox 153:

| Versión | condicional | explícita |
|---|---|---|
| sin el filtro | **1 consulta** — firmaba sin que nadie pidiera nada | 1 |
| con el filtro | **0** | 1 |

Las llamadas van con plazo: sin autenticador, la promesa de WebAuthn puede no
volver nunca, y entonces el banco no reporta — un silencio que se lee como «no se
pudo medir» cuando en realidad no se midió.

---

# Banco de los marcos anidados

`banco-iframe.py` (puerto 8935) y `banco-iframe-ajeno.py` (8936). La página crea
un iframe que llama a WebAuthn y se cuenta si la extensión consulta al agente
desde dentro.

`all_frames` es **false** por defecto: los content scripts solo corren en el marco
principal. Si el sitio pide la llave desde un iframe suyo —como hace Google en su
flujo—, ahí no hay nadie que intercepte, y el navegador acaba pidiendo una llave
física.

Pero encenderlo sin más abre una puerta: un iframe de un tercero solo puede usar
WebAuthn si la página que lo aloja se lo permite con `Permissions-Policy:
publickey-credentials-get`, y esa comprobación la hace el navegador. Interceptar
ahí se la saltaría. Por eso el script se retira en los marcos de otro origen.

Medido el 2026-08-01 en Firefox 153:

| Caso | script presente | consulta al agente |
|---|---|---|
| sin `all_frames`, iframe propio | **no** | 0 — la llave no se ofrecía |
| con `all_frames`, iframe propio | sí | **1** |
| con `all_frames`, iframe **ajeno** | sí | **0** — se devuelve al navegador |

La tercera fila es la que impide que el arreglo se convierta en un agujero: sin
ella, un anuncio incrustado pediría firmas que el navegador le habría negado.
