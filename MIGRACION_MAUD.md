# Migración de la interfaz: Angular 22 → maud + htmx (directiva 26)

Rama `migra/maud-htmx`. Este documento es el diseño de ingeniería de la
migración: el análisis está hecho, el enfoque está confirmado, y los checkpoints
están ordenados de menor a mayor riesgo. **chuspa es un gestor de contraseñas: la
migración se hace por checkpoints compilables y con las pruebas guardián
envenenadas, no de un tirón** — una chapuza en la UI aquí es una vulnerabilidad.

## Lo que ya se hizo (checkpoint 0 — análisis + andamiaje iniciado)

- **htmx y boi vendorizados** en `src/estaticos/` — byte a byte los de
  informes/medico/nexus (`md5 19a5737…`), como exige la directiva 26 (misma
  versión de htmx en todos los proyectos).
- Mapeado completo del contrato y la UI (abajo).
- **Confirmada la incógnita técnica y su solución** (ver «El puente del cuerpo»).
- Entorno verificado: `webkit2gtk-4.1` presente, display activo, quipu hermana,
  `interfaz/dist` compilado → la migración es verificable en la webview real aquí.

## Checkpoint 1 — HECHO (2026-08-09). El spike salió verde, y encontró un fallo

**Medido en la ventana WebKitGTK de verdad**, con `examples/ventana_de_prueba.rs`
y la bitácora como instrumento. Lo que quedó montado:

- `maud = "0.27"` (la misma versión que nexus, inventario, medico y chasqui).
- `src/vista.rs` — armazón + la primera pantalla (`/nuevo`) y su fragmento.
- `src/estaticos.rs` + `src/estaticos/{puente,estilo}` — htmx, boi, el puente y
  la hoja, servidos en `/estaticos/…` desde dentro del binario por
  **`include_str!`**, no por `rust-embed`: así cargo los sigue solo y no hace
  falta la declaración de `build.rs` que ya envejeció una vez.
- `gui::atender` **sale del binario y baja a la librería**, para que el arnés
  mida el camino real y no una copia (directiva 33).
- `src/bitacora.rs` — la bitácora, compartida por las dos fronteras.

Lo medido, con su control al lado:

| | resultado |
|---|---|
| htmx cargó y disparó `hx-trigger="load"` | `GET /nuevo/estado -> 200` en la bitácora |
| el fragmento cayó **dentro** de su destino | `fragmento=en-su-sitio` (no solo «llegó») |
| `boi.js` (módulo ES) se ejecutó | `data-boi=listo` |
| el puente del cuerpo | `POST /api/abrir cuerpo=59 -> 401` |
| **el control, sin puente** | `POST /api/abrir cuerpo=0 -> 400` |

### El fallo que apareció: la «ñ» rompía la ventana, y ya estaba roto

`setRequestHeader` **lanza `TypeError` con cualquier byte ≥ 0x80**, y
`JSON.stringify` no escapa lo que no es ASCII. No es un problema nuevo del stack
nuevo: **el interceptor de Angular tenía el mismo fallo desde siempre**, o sea
que en el producto que se instala hoy una frase de paso con «ñ», una entrada con
tilde o una ruta como `~/Imágenes/copia.chuspa` fallaban — y el error no
mencionaba nunca la causa.

Los dos puentes escapan ahora a `\uXXXX` (JSON válido y ASCII puro; `serde_json`
lo decodifica sin cambiar nada, pares subrogados incluidos). Angular se arregló
también, y se reconstruyó `dist`: sigue siendo la interfaz que se instala hasta
el checkpoint 6.

## Checkpoint 2 — HECHO (2026-08-09). Estado, crear, desbloquear y cerrar

Las tres pantallas de entrada, tejidas en el servidor y **decididas por él**: no
hay tres señales de cliente que mantener en sincronía, hay un `if` sobre el
estado de la bóveda. Todo lo que cambia ese estado contesta con la pantalla
entera y se intercambia en `#pantalla`.

Lo que se montó, además de las pantallas:

- `abrir_la_boveda` y `crear_la_boveda` salen de sus manejadores JSON: **una sola
  lógica, dos presentaciones**. Con dos copias, un arreglo en una se quedaría
  fuera de la otra y las dos seguirían abriendo bóvedas.
- Los avisos de importación viven ahora en la `Aplicacion` y se descartan **por
  su texto**. Antes solo viajaban en la respuesta de `crear`; con htmx eso los
  borraría en el intercambio siguiente, que es justo antes de leerlos.
- `comportamientos.js` — el primer uso de `boi`: devolver el foco al campo tras
  un intercambio. `autofocus` solo lo aplica el navegador al parsear, así que
  tras fallar al abrir la bóveda había que ir al ratón para reintentar.
- El campo «frase de la copia» aparece con `:has()` en CSS, sin JavaScript. La
  regla ESCONDE cuando no hay ruta de copia, no al revés: sin `:has()` la regla
  se descarta y el campo queda visible, en vez de invisible para siempre.

### Los errores contestan 200, y es a propósito

htmx no intercambia las respuestas 4xx. Un 401 con el mensaje dentro dejaría la
ventana idéntica y muda, y el usuario pensaría que el botón no funciona. Un
fragmento describe **la pantalla que toca ver**, y «esa frase no abre la bóveda»
es una pantalla legítima. La API de `/api/…`, que sí es un contrato, conserva sus
códigos.

### Dos fallos que solo se vieron DIBUJANDO la ventana

Los encontró el piloto de `examples/ventana_de_prueba.rs` en su primera corrida,
y ninguno de los dos daba error:

1. **Un formulario sin `method` se envía por GET, y el navegador escribe la
   frase de paso en la URL.** Con htmx cargado no pasa —él intercepta el envío—,
   pero si htmx todavía no ha procesado el formulario, el envío es el nativo. Se
   vio literalmente en la bitácora:
   `GET /nuevo?frase=ma%C3%B1ana-…`. Ahora **todo formulario lleva
   `method="post"` y su `action`**: el respaldo nativo manda el cuerpo en el
   cuerpo, que WebKitGTK descarta, en vez de escribirlo en la barra.
2. **`/nuevo?loquesea` no casaba con `/nuevo`**, se caía hasta el comodín
   estático y devolvía el `index.html` de **Angular**. Dos interfaces en la misma
   ventana, con 200 y sin un aviso. Las rutas de la pantalla nueva se despachan
   por la ruta sin consulta.

### Medido en la ventana real, el ciclo entero sin nadie delante

| paso | qué | resultado |
|---|---|---|
| 0 | la pantalla de bienvenida | `pantalla=crear foco=frase` |
| 1 | crear con `mañana-ñandú-Ω-😀` | `pantalla=abierta cuenta=0_entradas` |
| 2 | cerrar | `pantalla=abrir foco=frase` |
| 3 | abrir con una frase mala | `pantalla=abrir error=si` |
| 4 | abrir con la buena | `pantalla=abierta` |

Y en los cinco pasos: **`fugaFrase=no`** —la frase no aparece en el DOM en ningún
momento— y **`destinos=1`** —la pantalla nunca se anidó dentro de sí misma—. El
`foco=frase` de los pasos 2 y 3 es la prueba de que `boi` vuelve a escanear cada
fragmento: `autofocus` ahí ya no hace nada.

## Checkpoint 3 — HECHO (2026-08-09). Lista, filtro, detalle y generador

Dos columnas: la lista a la izquierda, el detalle a la derecha. Pulsar una
entrada intercambia **solo** `#detalle`, así que la lista no se vuelve a dibujar
y no pierde ni el filtro ni el sitio por donde iba.

**El filtro lo aplica el servidor.** Filtrar en el cliente exigiría mandarle la
lista entera —595 nombres de sitios donde el usuario tiene cuenta— y tenerla ahí
por si acaso. Es lo mismo que el índice cifrado de la bóveda evita.

### La contraseña se pide aparte, y por eso «ocultar» significa algo

El detalle **no lleva la contraseña dentro** (`Detalle` no tiene dónde meterla:
solo `tiene_clave`). Se pide con su propia ruta, y ocultarla vuelve a pedir el
fragmento tapado — la contraseña **se va del documento**, no se le pone un
`type=password` encima. Con la contraseña en el detalle quedaría escrita en el
DOM de todas las entradas que se hayan mirado, con la ventana abierta y el
usuario en la cocina.

Copiar al portapapeles va por la misma regla: el botón lleva la **ruta**, no el
valor. `boi` lo pide con `fetch` y lo pasa a `navigator.clipboard` sin que el
texto toque `innerHTML` en ningún momento — que además es lo que impide que una
contraseña que empiece por `<` se convierta en etiqueta dentro de la ventana que
enseña todas las demás.

### Dos fallos más, otra vez solo visibles DIBUJANDO

1. **El motor reutilizaba respuestas de `chuspa://` sin volver a pedirlas.** Tras
   abrir la bóveda, `GET /nuevo/lista` **no llegó al manejador**, y la lista se
   quedó con la respuesta de cuando la bóveda estaba vacía: se abría con sus
   entradas dentro y la pantalla enseñaba una lista vacía, sin un solo error.
   Medido con su control, misma corrida y mismo piloto: **sin `no-store` llegó 1
   petición a `/nuevo/lista` y el guion se atascó; con `no-store` llegaron 4 y
   los diez pasos terminaron.** Ahora toda respuesta lleva
   `cache-control: no-store`, que además impide que una contraseña acabe escrita
   en el disco de la caché del motor.

   **Lo que NO está medido**, y no se da por hecho: que a la interfaz de Angular
   le pasara lo mismo. Se probó lo que más dolería —dos `GET /api/generar?largo=20`
   seguidos, que devolverían la MISMA contraseña— y llegaron los dos, con
   contraseñas distintas. O sea que el motor no reutiliza todo por igual: lo
   reproducido es lo que hace htmx. La cabecera cubre los dos casos porque se
   pone en un solo sitio.
2. **La bitácora apuntaba la consulta**, y el filtro viaja ahí (`?filtro=banco`).
   Qué está buscando el usuario es exactamente lo que el índice cifrado existe
   para no revelar. Se anota la ruta sin consulta.

### El piloto ahora se dirige por lo que SE VE

Contar intercambios no servía: `htmx:afterSettle` **burbujea**, así que un
fragmento que trae otro dentro dispara dos y el guion se desincroniza sin que
nada falle —cada paso actúa sobre la pantalla equivocada y el informe parece un
fallo del producto—. Cada paso declara ahora la condición en la que le toca
actuar.

Y actúa con 120 ms de respiro: pulsar en el mismo tic en que aparece una
pantalla se adelanta a que htmx enganche el formulario recién insertado, y
entonces el envío es el nativo — el navegador NAVEGA y recibe un fragmento
suelto, sin `<html>` y sin scripts.

### Medido en la ventana real, dos corridas seguidas iguales

| paso | qué | resultado |
|---|---|---|
| 5 | tras abrir, la lista | `filas=1` |
| 6 | filtrar por algo que no existe | `filas=0` |
| 7 | quitar el filtro | `filas=1` |
| 8 | pulsar la entrada | `detalle=Banco_de_prueba` |
| 9 | «Ver» | `claveVisible=SI` |
| 10 | «Ocultar» | `claveVisible=no` |

`claveVisible` es `no` en todos los pasos salvo justo mientras se enseña, y
`fugaFrase=no` en los diez.

### Queda anotado, no resuelto

El **respaldo nativo de los formularios** cumple lo suyo —la frase no se escribe
en la URL— pero deja al usuario en un fragmento suelto si llega a dispararse. Lo
propio sería que una petición SIN `HX-Request` devolviera la página entera. Se
hará en el checkpoint 6, cuando `/nuevo` pase a `/` y `Peticion` se toque de
todas formas.

## Checkpoint 4 — HECHO (2026-08-09). Editar y crear, con TOTP y URIs

El checkpoint que tenía que reproducir las dos trampas peores del repositorio, y
resultó traer una tercera.

### En un `<form>` no existe el «ausente», y ahí está todo el problema

Un `<input>` **siempre se envía**. El modelo de la bóveda distingue tres cosas
—no tocar, poner, quitar— y esa distinción es lo único que impide que corregir el
nombre de una entrada le destruya el segundo factor. En JSON eso se decía con
`null`; en un formulario no hay forma.

La traducción vive en `tres_estados` y es el sitio donde mirar si algo se pierde:

| lo que llega | qué significa |
|---|---|
| campo vacío, casilla sin marcar | **no se toca** |
| campo con algo | se pone eso |
| casilla marcada | **se quita** |
| campo con algo **y** casilla marcada | contradicción: **se rechaza** |

La última fila es la directiva 20: ante dos órdenes incompatibles se falla
ruidosamente. Envenenado, se ve por qué — resolver la contradicción «a ojo»
borraba la contraseña que el usuario acababa de teclear.

Y el formulario **no devuelve ni la contraseña ni el secreto del segundo factor**
(el segundo no se puede: la bóveda solo entrega su código de seis dígitos). Sí
dice si LOS HAY, porque sin ese dato un campo vacío se lee como «esta entrada no
tiene contraseña» y quien teclee una nueva creería estar poniéndola cuando la
está sustituyendo.

### La tercera de la familia, que estaba viva en el producto instalado

Aplicando la regla del `CLAUDE.md` —«todo campo que el detalle no devuelva tal
cual se pierde al guardar»— a los campos que quedaban, apareció una que nadie
había mirado: **el detalle no devuelve la CARPETA**, y la interfaz de Angular no
la manda. O sea que **corregir el nombre de una entrada la sacaba de su
carpeta**, sin error. Comprobado con una prueba que salió roja antes de
arreglarlo.

Arreglado en `construir`, que es de las dos interfaces: `carpeta` y `clave`
siguen ahora la misma regla que el segundo factor —ausente = no se toca,
`""` = se quita—. Angular no se entera: manda siempre el campo.

### Borrar pregunta antes, y en la pantalla

No con un `confirm()` del navegador: un diálogo modal **bloquea el motor entero**,
y aquí el motor es el que atiende al navegador que está pidiendo una firma.
Además así se ve QUÉ se va a borrar.

### Medido en la ventana real

| paso | qué | resultado |
|---|---|---|
| 10 | abrir el editor | — |
| 11 | corregir **solo el nombre** y guardar | — |
| 12 | el detalle que queda | `detalle=Banco_renombrado`, `claveVisible=no` |
| 13 | pulsar «Ver» | `claveVisible=SI` |

O sea: el nombre cambió y **la contraseña sobrevivió**, con la contraseña fuera
del DOM en todo momento salvo cuando se pide.

## Checkpoint 5 — HECHO (2026-08-09). Firma, guardado propuesto y presencia

### El sondeo se lleva su regla dentro, y eso resuelve un fallo que no se ve

Un hueco que sondeara cada segundo pase lo que pase **borraría lo que el usuario
esté tecleando** en el panel de la propuesta —el nombre, el usuario— una vez por
segundo. En Angular eso no pasaba porque el panel vivía en señales del cliente.

La forma que lo cierra: el fragmento trae su propio comportamiento siguiente. Sin
nada pendiente vuelve un hueco **con** `hx-trigger="every 1s"`; con algo
pendiente vuelve el panel **sin sondeo**, y se intercambia con `outerHTML`, o sea
que el elemento se sustituye a sí mismo y con él su regla. Al decidir, vuelve el
hueco que sondea.

### Y NO cuenta como presencia

`GET /nuevo/pendientes` no sella presencia; `POST /nuevo/firma` y
`POST /nuevo/guardado` sí. Si el sondeo contara, el plazo del enlace con el
navegador no vencería jamás mientras la ventana estuviera abierta: la misma
defensa que solo lo parece que ya costó un fallo en agosto. Envenenado por los
dos lados.

### Lo que no se reimplementa

`ventana_decidir_firma` traduce el formulario y llama a `decidir_firma`. El `id`
que empareja la decisión con su petición, y la comprobación de que la candidata
está entre las ofrecidas, siguen viviendo en **un solo sitio**. Con dos caminos,
uno se quedaría sin la comprobación el día que se añadiera otra — y el camino
nuevo es exactamente por donde se rodean las reglas viejas. Envenenado: haciendo
que la pantalla nueva tomara el `id` de la firma en curso en vez del que mandó el
formulario, la prueba se pone roja con «una decisión de otra petición autorizó
ésta».

Los tres botones de la propuesta —nueva, actualizar una existente, descartar—
mandan **un solo campo** (`nueva`, `existente:{i}`, `no`) porque son
excluyentes: con tres campos sueltos habría combinaciones que no significan nada
y que alguien tendría que resolver a ojo.

### Medido en la ventana real

| paso | qué | resultado |
|---|---|---|
| — | con la bóveda abierta | 20 sondeos en ~20 s |
| 14 | plantar una firma esperando | `sondeando=si` |
| 15 | el panel aparece | `pendiente=Una_página_pide_entrar…`, **`sondeando=no`** |
| 16 | tras autorizar | panel fuera, **`sondeando=si`** |

O sea: sondea, aparece el panel, **el sondeo se para** mientras está en pantalla,
se decide, y el sondeo vuelve.

## Checkpoints 6, 7 y 8 — HECHOS (2026-08-09). Angular retirado

`/nuevo` pasa a `/`. Se borran `interfaz/` entera, el paso de `npm`, `rust-embed`
y la vigilancia de `dist` en `build.rs`.

### Lo que se trajo antes de borrar

`nombre.ts` decidía la letra y el color de cada entrada en la lista, con una
regla medida sobre una bóveda real —174 entradas empiezan por `www.`, y la
inicial cruda pintaba un tercio de la lista con la misma letra—. Se **tradujo** a
`src/nombre.rs` con sus casos, no se rehízo: traducir en vez de reinventar es lo
que impide que una migración pierda por el camino una decisión que costó medir.

### Lo que se retiró, con su lápida

Cada prueba que miraba Angular se fue con una nota que dice **qué la sustituye**,
para que nadie la eche de menos ni la reconstruya:

| prueba | por qué se va | qué queda vigilando lo suyo |
|---|---|---|
| `la_interfaz_llega_al_binario` | vigilaba que `build.rs` y el `#[folder]` apuntaran al mismo sitio | **nada, y está bien**: con `include_str!` no hay dos artefactos que puedan separarse (directiva 1) |
| `la_interfaz_no_llama_a_nadie` | buscaba cargas externas en el `dist` de Angular | la hoja y los scripts son nuestros y van dentro del binario; `el_armazon_carga_lo_suyo_y_nada_en_linea` |
| `la_lista_distingue` | corría `nombre.test.ts` | `src/nombre.rs`, con los mismos casos en `cargo test` |
| `la_interfaz_esta_dentro_del_binario` | comprobaba el `index.html` embebido | no hay index; `los_estaticos_propios_se_sirven_con_su_tipo` |
| `el_html_ya_no_lleva_ninguna_credencial_dentro` | buscaba el testigo en el index | `ninguna_respuesta_de_la_pantalla_lleva_la_frase` |
| `la_interfaz_no_manda_ninguna_credencial` | miraba el PAQUETE de Angular | ídem; y el artefacto ya **es** el fuente |
| `la_hoja_de_estilos_no_se_carga_solo_para_imprimir` | vigilaba el `inlineCritical` | `el_armazon_carga_lo_suyo_y_nada_en_linea` |
| `los_botones_de_copiar_son_todos_iguales` | miraba el HTML de Angular | `la_lista_y_el_detalle_no_llevan_ninguna_clave`, que es una regla más fuerte |
| `el_paquete_compilado_de_angular_lleva_el_escapado` | miraba el bundle | una sola implementación del puente, con su banco |

Y una se **adaptó**: `lo_que_no_existe_se_rechaza_sin_confundirlo_con_la_interfaz`
pasa a `una_ruta_de_api_que_no_existe_contesta_json`. Ya no hay interfaz con la
que confundirse; lo que sigue importando es que un error de API llegue como JSON.

### Lo que quedaba anotado del checkpoint 3, resuelto

Una petición **sin `HX-Request`** recibe ahora la **página entera** en vez de un
fragmento. Es el respaldo del respaldo: los formularios llevan `method="post"`
para que un envío nativo no escriba la frase en la URL, y ahora además ese envío
deja al usuario en una ventana con la que seguir en vez de en un trozo de HTML
sin estilos ni scripts.

### Medido

- **El binario de verdad** (`chuspa-gui`, no el arnés) sirve `/` y sus cinco
  estáticos: comprobado en la bitácora.
- El piloto recorre los **16 pasos** en la raíz: crear con frase acentuada,
  cerrar, fallar al abrir, abrir, listar, filtrar, abrir una entrada, ver y
  ocultar la clave, editar sin destruir nada, plantar una firma, autorizarla y
  ver volver el sondeo.
- **319 pruebas** en verde y `clippy` limpio. Bajan de 323 porque se fueron las
  nueve de Angular y llegaron las siete de `nombre`.

### Lo que NO se ha hecho, y hay que decirlo

- **La extensión no se ha vuelto a medir en Firefox ni en Brave.** No se tocó su
  código, y el enlace con el navegador tiene sus pruebas por el socket; pero la
  cadena entera —página → puente → fondo → aplicación— no se ha ejercitado desde
  la migración. Es lo primero que hay que correr antes de empaquetar.
- **No se ha subido la versión ni se ha construido el RPM.** El binario dice
  `0.2.11 (…-sucio)`, que es la respuesta honesta: el árbol tiene cambios sin
  commitear mientras se mide.

## La incógnita técnica, y cómo se resuelve — «El puente del cuerpo»

`chuspa-gui.rs` documenta que **WebKitGTK NO entrega el cuerpo de un POST a un
esquema propio** (`chuspa://`): llega con 0 bytes. Angular lo resuelve con un
interceptor (`interfaz/src/app/cuerpo-por-cabecera.ts`) que mueve el cuerpo a la
cabecera `X-Chuspa-Cuerpo`, que `gui::atender` lee cuando el body viene vacío.

**htmx necesita el mismo puente**, y se hace con su evento `htmx:configRequest`:

```js
// src/estaticos/puente.js  (vendorizado, servido por chuspa://, cargado con <script src>)
document.body.addEventListener('htmx:configRequest', (e) => {
  if (e.detail.verb === 'get') return;
  // WebKitGTK descarta el cuerpo del POST/PUT al esquema propio; va por cabecera.
  e.detail.headers['X-Chuspa-Cuerpo'] = JSON.stringify(e.detail.parameters);
});
```

Con eso, `gui::despachar` sigue leyendo JSON del cuerpo (por la cabecera) **sin
cambiar el parseo** — solo cambia que los manejadores devuelvan HTML (maud) en
vez de JSON. La CSP actual (`script-src 'self'`) ya permite scripts vendorizados
por `<script src>`; los atributos `hx-*` no son inline, así que no la violan.

**Corrección medida el 2026-08-09**: ese código de ejemplo estaba **incompleto**.
`JSON.stringify(e.detail.parameters)` falla por dos motivos que no se ven leyendo:

1. En htmx 2, `detail.parameters` es un **`Proxy` sobre un `FormData`**, no un
   objeto. Funciona de casualidad —el proxy trae una trampa `toJSON`—, y eso es
   depender de un detalle interno de la librería.
2. El valor resultante **no es ASCII**, y `setRequestHeader` lanza con cualquier
   byte ≥ 0x80. Ver arriba.

Lo que hay escrito en `src/estaticos/puente.js` cubre las dos cosas, con su banco
en `src/estaticos/puente.test.js`.

**SPIKE: hecho y verde** (ver «Checkpoint 1» arriba).

## El contrato actual (lo que hay que reproducir)

`gui::despachar` (un `match (método, ruta)`, NO axum) sirve, y Angular consume
desde `interfaz/src/app/api.ts`:

| ruta | qué hace |
|---|---|
| `GET /api/estado` | existe / abierta / ruta / avisos |
| `POST /api/abrir` `{frase}` | desbloquea |
| `POST /api/crear` `{frase,importar,restaurar,fraseCopia}` | crea la bóveda |
| `POST /api/cerrar` | suelta la bóveda |
| `GET /api/entradas` | lista (Resumen[]) |
| `GET/POST /api/entradas`, `PUT/DELETE /api/entradas/{i}` | CRUD de entrada |
| `GET /api/salud` | informe offline |
| `GET /api/generar?largo`, `GET /api/frase?palabras` | generador |
| `GET/POST /api/firma` | **firma WebAuthn pendiente** (autorizar/rechazar) |
| `GET/POST /api/guardado` | **credencial propuesta por el navegador** |

Estático: `gui::estatico` sirve `Estatico::get` (Angular embebido con rust-embed,
`#[folder = "interfaz/dist/interfaz/browser/"]`).

## Los flujos de la UI (de `interfaz/src/app/app.ts`, 429 líneas)

1. **Bóveda no existe** → crear (frase ×2, importar Bitwarden/CSV, restaurar copia).
2. **Cerrada** → desbloquear (frase).
3. **Abierta** → lista con filtro; ver, nueva.
4. **Detalle** → ver/ocultar clave, copiar campos, TOTP, URIs con su regla, editar, borrar.
5. **Editar/nueva** → nombre, usuario, clave, **TOTP (ausente≠vacío≠valor)**, uris, notas, quitar-totp (casilla), usar-generada.
6. **Generar** contraseña / frase.
7. **Salud** (informe con gravedad).
8. **Copias** (hacer / comprobar, con antigüedad).
9. **Firma pendiente** (polling 1 Hz, autorizar con candidata elegida o rechazar).
10. **Guardado propuesto** (polling; aprobar como nueva o sobre existente; editable antes de aceptar).
11. **Avisos** de importación (descartar).
12. **Presencia**: el sondeo de 1 Hz (`/api/firma`, `/api/guardado`) **NO cuenta como actividad** (`gui::es_de_una_persona`). Con htmx el polling debe seguir SIN contar — ya están excluidos por ruta.

## Checkpoints (orden de menor a mayor riesgo)

1. ~~**Spike**: andamiaje + validar htmx en la webview real.~~ **HECHO** (2026-08-09).
2. ~~**Página base + estado + desbloquear/crear/cerrar**.~~ **HECHO** (2026-08-09).
3. ~~**Lista + filtro + detalle + generar**.~~ **HECHO** (2026-08-09).
4. ~~**Editar/nueva con TOTP y URIs**.~~ **HECHO** (2026-08-09).
5. ~~**Firma WebAuthn + guardado propuesto + presencia**.~~ **HECHO** (2026-08-09).
6. ~~**Retirar Angular**.~~ **HECHO** (2026-08-09).
7. ~~**Adaptar las pruebas guardián**.~~ **HECHO** (2026-08-09), con lápida cada una.

## Invariantes que NO se pueden romper (del CLAUDE.md)

- La interfaz **no manda ninguna credencial** (no hay testigo de sesión).
- El **sondeo de 1 Hz no cuenta como presencia** (o la bóveda se cierra sola).
- **TOTP**: ausente/`null` = no tocar; `""` = quitar (pedido con casilla). El
  detalle devuelve el CÓDIGO, no el secreto — el formulario de edición sale con
  el TOTP **vacío** y vacío significa «no lo toques».
- **URIs**: la regla de coincidencia se conserva emparejando por texto; el
  detalle la ENSEÑA porque lo que no se ve no se conserva.
- **Nadie firma sin autorización explícita** en la ventana (id + caducidad 90 s).
- CSP sin `'unsafe-inline'`; devtools apagadas (la ventana muestra contraseñas).
