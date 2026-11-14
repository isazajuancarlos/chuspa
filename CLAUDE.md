# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Configuración general: `~/.claude/CLAUDE.md`** — directivas numeradas, reglas
> que no se rompen y máquinas montadas. Se carga en toda sesión y **no se copia
> aquí**.
>
> **Chuspa es parte de la familia Quipu**, cuyo contexto compartido —los cuatro
> repositorios, cómo dependen unos de otros y el modelo de ramas de Quipu— vive
> en **`/mnt/data/quipu/CLAUDE.md`**. Este archivo lleva SOLO lo propio de
> chuspa.

## Qué es

Gestor de contraseñas **offline**: un archivo de bóveda local cifrado, sin nube,
sin cuenta y sin ningún puerto abierto. AGPL-3.0-or-later, `publish = false`.
El README es largo y **está al día**: cada sección explica *por qué* algo es
como es. Antes de cambiar un mecanismo, leer su sección.

Depende de Quipu **por ruta**: `quipu = { path = "../quipu", features = ["escrow"] }`
y `quipu-nucleo` con `palabras`. `chuspa` tiene que ser **hermana de quipu** en
el disco, y compila contra el árbol de trabajo: un cambio en Quipu la rompe hoy,
sin esperar a una release.

No hay `origin` configurado ni CI: **el único verde es el local**.

## Comandos

**EL FRONTAL SE PARTE POR PLATAFORMA (decisión de Juan, 2026-10-11):**

- **Linux → `chuspa-gtk` (GTK4).** Es el producto que se empaqueta (`.deb`/`.rpm`)
  y el que prueba el CI. **Es el `default`**, así que en esta máquina Linux:

  ```bash
  cargo build --release                               # construye chuspa-gtk
  cargo test --release --no-fail-fast
  cargo clippy --all-targets --release -- -D warnings
  ```

- **Windows → `chuspa-egui` (egui/eframe sobre `huitaca`)**, por si en algún
  momento se crea un `.exe`. Compila en todas partes; se construye explícito:

  ```bash
  cargo build --release --no-default-features --features egui-ui
  ```

  El CI (en Linux) lo compila-chequea aparte (`Clippy (frontal Windows egui)`)
  para que no se pudra. **No hay "Fase 3 en que egui reemplaza a GTK": coexisten,
  uno por plataforma.** La verdad en código está en `[features]` de `Cargo.toml`.

> **Nota de deriva (pendiente):** lo que sigue en «Comandos» y «Arquitectura»
> sobre `maud` + htmx + `wry` describe una arquitectura RETIRADA — la pantalla se
> migró a **GTK4 nativo** (`cd15fbce`, «retirar el WebView entero») y luego a egui
> en Windows. Sección a reescribir en una pasada aparte.

**Ya no hay paso de `npm`.** Node sigue haciendo falta para **un** banco —el del
puente del cuerpo, que se prueba en su propio lenguaje— y para nada más.
(Histórico: hasta la migración a GTK la pantalla fue Angular y luego `maud`+htmx.)

```bash
cargo build --release

cargo test --release --no-fail-fast                # 325 pruebas, exit 0 (2026-08-10)
cargo clippy --all-targets --release -- -D warnings # exit 0 (2026-08-10)
```

Una prueba sola, o un archivo de pruebas:

```bash
cargo test --release --test la_firma_pide_permiso
cargo test --release --test la_firma_pide_permiso -- sin_autorizacion_no_se_firma
cargo test --release cifrado::pruebas::            # las unitarias de un módulo
```

**Para MEDIR el KDF, siempre `--release`.** Argon2id tarda **900 ms en release
y 12 s en debug** cuando se compila sin optimizar, y quien mida ahí acaba
bajando el coste del KDF por un número inflado 14×. Y `--no-fail-fast` siempre,
o las pruebas de los binarios que van después del primer fallo no se ejecutan.

**Lo que ya NO es cierto: que la suite entera en debug sea «minutos de espera».**
Lo decía esta misma línea y se midió el 2026-08-13, banco completo y el mismo
conteo en los dos —**325 pruebas en 21 suites**, que es el control de que la
rápida no lo es por hacer menos—:

| | segundos |
|---|---|
| `--release` | **36,0** |
| debug | **46,1** |

Diez segundos, no minutos. La causa es la línea de abajo: Argon2id vive en
`quipu`, o sea en una DEPENDENCIA, y `[profile.dev.package."*"] opt-level = 3`
la compila optimizada también en el perfil dev. Por eso el verde declarado corre
**los dos carriles** y no solo release.

Desde el 2026-08-09 el `Cargo.toml` lleva la línea del estándar de nacimiento
que le faltaba —`[profile.dev.package."*"] opt-level = 3`— y eso hace el debug
**usable**, no equivalente: medido aquí sobre la misma prueba de tres
derivaciones, **39,46 s → 4,66 s (8,5×)**. Sigue sin ser el sitio donde medir el
KDF; es el sitio donde depurar sin esperar.

**El VERDE de este repositorio está DECLARADO** desde el 2026-08-13, en
`.github/workflows/ci.yml`, y se corre así:

```bash
python3 /mnt/data/conocimiento/cupo/verde_local.py chuspa
```

No lo ejecuta GitHub —Actions está apagado en toda la cuenta desde el protocolo
solo-local—: el archivo existe porque `verde_local.py` saca de él los `run:` en
su orden y los ejecuta, para que «el comando exacto del CI» no sea una frase que
alguien copia a mano. Hasta ese día chuspa era el ÚNICO repositorio Rust de la
casa sin NINGÚN verde declarado —ni éste ni `deny.toml`—, y es el producto que
guarda contraseñas, passkeys y semillas TOTP.

**`deny.toml` nace el mismo día, y con ONCE excepciones documentadas una a una.**
`cargo deny check advisories` sale rojo en este árbol con 11 avisos, y los 11 son
`unmaintained`: **cero `vulnerability`, cero `unsound`**. Diez son las ligaduras
GTK3 de gtk-rs, archivadas al pasar a GTK4, y el undécimo es `proc-macro-error`.
Todos llegan por una sola raíz —`wry`/`tao`, cuya pila de Linux ES GTK3— y **no
se pueden quitar desde aquí**: comprobado que `wry 0.56` mantiene `dep:gtk`, así
que subir de línea no arregla nada.

Se enumeran los once por identificador **en vez de apagar la clase entera** con
`unmaintained = "workspace"`: eso silenciaría también el aviso de mañana sobre
una dependencia que sí podríamos arreglar (directiva 23). Validado con su pareja:
con la lista completa `cargo deny check` sale **verde**; quitando UN
identificador cualquiera vuelve a **rojo** nombrándolo. Y `licenses`, `bans` y
`sources` siguen midiendo — el agujero de que el `Cargo.lock` gane un registro o
un `git` desconocido no lo toca ninguna de esas once líneas.

**Lo que el verde NO mide, y no se da por medido**: la VENTANA (ninguna prueba
abre un `EventLoop` ni un `WebView` real — los demás productos con pantalla la
dibujan con `mirilla`, y chuspa no puede porque la suya no es un servidor HTTP
sino un `wry` empotrado) y la EXTENSIÓN (`npx addons-linter`, que necesita red y
npm, y se corre a mano antes de firmar en AMO).

Empaquetado y extensión:

```bash
cargo generate-rpm                        # toma target/release; el binario DEBE ser release
python3 empaque/empaquetar-extension.py   # target/chuspa-<version>.xpi, para firmar en AMO
bash empaque/instalar-puente.sh /ruta/absoluta/a/chuspa-puente   # registro por usuario
npx addons-linter extension/              # el filtro de Mozilla: errors 0 · notices 0
```

Los ejemplos son las herramientas de operación (respaldo, recuperación, reparto
k-de-n, informe de salud, verificación de un export real). Todos en `--release`
y con la frase por variable de entorno — ver sus cabeceras y el README.

## Arquitectura

**Tres procesos y un solo poder.** El reparto está documentado en
`src/navegador/protocolo.rs` y es la base de todo lo demás:

| Proceso | Qué puede | Qué no |
|---|---|---|
| `chuspa-gui` (la aplicación/agente) | tiene la bóveda abierta y la frase; decide qué passkey corresponde a qué página, y firma | — |
| `chuspa-puente` | traduce *native messaging* ↔ socket unix | no abre la bóveda, no ve la frase, no compara dominios |
| `extension/` (Firefox y Chrome/Brave) | pide firmar un reto de passkey | nunca recibe la bóveda ni ninguna contraseña |

**Desde 0.3.0 el agente es SOLO passkeys.** El protocolo (`Peticion`) se reduce a
`Estado`/`Bloquear`/`Autenticar`; se retiraron los mensajes de contraseña del
viejo autofill (`Buscar`/`Credencial`/`Generar`/`Proponer`) y todo su subsistema
(fichas, `GuardadoPendiente`, `proponer_guardado`, `decidir_guardado`,
`dialogo_guardado`). Lo único que devuelve un secreto es `Autenticar`, y **exige
aprobación por uso en la ventana** (`pedir_permiso` → `gui::decidir_firma`): no
basta con que la bóveda esté abierta. Por eso el enlace puede aguantar 12 h de
inactividad sin abrir una vía de exfiltración — una extensión comprometida ya no
tiene a quién pedirle contraseñas. Las contraseñas se manejan con el gestor
nativo del navegador, y se traen a la bóveda con el importador (botón
«Sincronizar desde los navegadores», `src/importar/navegadores/`: Chromium por
`os_crypt`+llavero y Firefox por NSS, todo Rust puro). Retirado el bloqueante del
concilio 2026-09-15; ver `tests/enlace_navegador.rs`
(`el_enlace_solo_hace_passkeys_y_no_entrega_contrasenas`).

**Un solo árbol de extensión para los dos navegadores.** Lo único que no se
puede fundir es el manifiesto (`service_worker` contra `scripts`); todo lo demás
lo vigila `tests/los_dos_manifiestos_no_se_separan.rs`. `browser` no existe en
Chrome, y el fondo contesta con `sendResponse`+`return true` porque el
manifiesto admite desde Chromium 111 — **no** porque Chrome ignore la promesa:
eso se escribió, se midió en Brave 151 y era falso (`extension/banco/README.md`).

**Al medir en Brave, perfil nuevo en cada corrida.** Dos `--load-extension`
seguidos contra el mismo `--user-data-dir` no recargan nada: la segunda llamada
le pasa la URL a la instancia viva, que tiene la extensión ANTERIOR. Un veneno
sale verde porque lo contesta el proceso viejo. Y el `respondio` del banco **no
discrimina en Chrome**: el content script contesta igual aunque el fondo calle.
La medida buena es `detalle`.

Que el puente no decida nada es deliberado: es el proceso que un navegador
comprometido alcanza primero.

**Un solo proceso para la ventana y el agente.** El enlace con Firefox vive
DENTRO de `chuspa-gui` (`navegador::escuchar_al_navegador`). Hubo un
`chuspa-agente` aparte y no podían coexistir: el cerrojo del archivo impide
abrir la misma bóveda dos veces. Si vuelve a aparecer esa idea, ya se probó y
falla.

**La interfaz no pasa por el navegador.** `maud` teje el HTML **en el servidor**
(`src/vista.rs`), htmx hace los intercambios parciales y `boi` cubre lo poco que
ocurre solo en el navegador; todo dentro de una ventana `tao`/`wry` (WebKitGTK)
servida por el esquema propio `chuspa://`. Cero puertos: por eso no hay testigo
de sesión, ni comprobación de `Host`, ni CORS. El «servidor» es
`gui::despachar`, un `match (método, ruta)`.

**El estado vive en el servidor, que es donde ya vivía**: la bóveda está en este
proceso. No hay un segundo modelo de los datos en el navegador que pueda
desincronizarse del primero — que era la familia de fallos más cara de este
repositorio (la regla de cada URI, el segundo factor, la carpeta).

`/api/…` sigue existiendo y es el mismo contrato de antes; hoy no lo consume
ninguna pantalla, y lo usa el arnés para sembrar. Toda ruta que no sea `/api/…`
ni `/estaticos/…` es la pantalla, y **una petición sin `HX-Request` recibe la
página entera** en vez de un fragmento: así un envío nativo —htmx que no cargó—
deja al usuario en una ventana con la que seguir, y no en un trozo de HTML sin
estilos.

### Mapa de módulos

| Archivo | Qué decide |
|---|---|
| `src/boveda.rs` | modelo interno único: una entrada es una lista de campos etiquetados; ningún dato se cae por no encajar |
| `src/cifrado.rs` | el formato: Argon2id → maestra → HKDF por entrada; el índice guarda el hash de cada bloque y lleva el contador en su AAD. **Aquí vive la integridad del conjunto** |
| `src/navegador/coincidencia.rs` | **el archivo más delicado**: a qué página le corresponde una credencial. Comparación por etiquetas de dominio, nunca por texto |
| `src/webauthn.rs` | firma ECDSA P-256 de las passkeys; comprueba el `rpId` contra el origen que puso el navegador, no contra el que dice la página |
| `src/gui.rs` | estado compartido (`Aplicacion`), rutas `/api/…`, y la firma pendiente que espera el visto bueno del usuario |
| `src/respaldo.rs` | hoja de papel (BIP-39 + Reed-Solomon), reparto Shamir, sobre a un destinatario |
| `src/copia.rs` | copia de seguridad del **contenido**: comprimir → Padmé → cifrar. El texto cifrado no se comprime, así que comprimir el `.chuspa` no ahorra nada; y el relleno va DESPUÉS de comprimir porque comprimir reintroduce la fuga de longitud |
| `src/importar/` | Bitwarden JSON y CSV, con `deny_unknown_fields` en todo el esquema |
| `src/fecha.rs` | la fecha de HOY en el formato de las importadas. Existe porque hasta ahora ninguna nacía aquí: todas venían del export. Solo se fecha lo que nace en la aplicación — a una entrada importada sin fecha no se le inventa una |
| `src/version.rs` | de qué commit sale este binario, no solo qué versión decía el `Cargo.toml`. Lo sella `build.rs` y lo enseña `--version` |
| `src/vista.rs` | **la pantalla**, tejida con `maud` en el servidor (directiva 26). El servidor decide qué pantalla toca; todo lo que cambia el estado contesta con la pantalla entera y se intercambia en `#pantalla` |
| `src/nombre.rs` | qué letra y qué color lleva cada entrada en la lista. Traído de `nombre.ts` al retirar Angular, con sus casos —salen de una bóveda real de 595 entradas, donde 174 empiezan por `www.` y la inicial cruda pintaba un tercio de la lista igual— |
| `src/estaticos.rs` + `src/estaticos/` | htmx 2.0.4, `boi.js` y `puente.js`, dentro del binario por `include_str!` — no por `rust-embed`, para que cargo los siga sin una declaración que envejezca |
| `src/bitacora.rs` | la bitácora de las **dos** fronteras —navegador y ventana—, `CHUSPA_BITACORA`. Nunca escribe un secreto |
| `src/salud.rs`, `src/generador.rs`, `src/totp.rs`, `src/memoria.rs` | informe offline, muestreo por rechazo, RFC 6238, detección de intercambio sin cifrar |

## Invariantes que no se negocian

- **`unsafe_code = "forbid"`.** Por eso no hay `mlock`, y la decisión está
  razonada en el README — no se reabre sin ese razonamiento delante.
- **El origen lo pone el navegador** (`sender.url` en el script de fondo), nunca
  la página, y nunca viaja en el mensaje entre mundos.
- **Nadie firma sin autorización explícita en la ventana**, con id de petición y
  caducidad de 90 s.
- **Las peticiones con `mediation: "conditional"` se devuelven enteras** al
  navegador. Atenderlas era lo que hacía que Gmail entrara solo.
- **La frase de paso no viaja por variables de entorno en la aplicación** (se
  heredan a los hijos). Los ejemplos sí usan `CHUSPA_FRASE`, y es una decisión
  distinta y consciente.
- **La bitácora no se enciende sola** (`CHUSPA_BITACORA=/ruta`) y **no puede
  anotar secretos**: `tests/la_bitacora_no_filtra.rs` falla al *escribir* una
  línea que mencione clave, reto o frase, así que cubre también las que se
  añadan mañana.

## Fallos que no dan error — cada uno tiene su prueba guardián

Esta es la parte que ahorra horas. Todos ocurrieron de verdad y todos salían
verdes:

| Trampa | Qué la vigila |
|---|---|
| ~~Cargo no sabe que `rust-embed` embebe `dist`~~ **RETIRADA (2026-08-09)**: la salvaguarda desapareció porque desapareció lo que la hacía falta (directiva 1). Con `maud` + `include_str!` no hay dos artefactos que puedan separarse — las plantillas las compila `rustc` y los estáticos los registra el propio compilador como dependencias del crate | ya no hace falta: `build.rs` no vigila ninguna carpeta |
| El RPM enumeraba la extensión archivo a archivo y se dejó tres fuera: passkeys muertas, sin un solo aviso | `tests/el_rpm_lleva_la_extension_entera.rs` (el `Cargo.toml` va por patrón) |
| Un andamio de pruebas (`with_initialization_script`, `with_devtools(true)`, `dbg!`) colado en un binario que se instala | `tests/sin_andamios_en_produccion.rs` |
| Firefox aísla los dos mundos de la extensión: con `CustomEvent` la respuesta llega ilegible y el sitio pide una llave física | `tests/el_puente_no_cruza_mundos_con_eventos.rs` (se usa `window.postMessage`) |
| `all_frames` apagado ⇒ los iframes propios no interceptan; encendido sin más ⇒ un iframe ajeno pediría firmas | `tests/las_llaves_llegan_a_los_marcos.rs` — las dos mitades, quitar cualquiera pone la suite roja |
| El agente atendía de una en una: una firma esperando permiso congelaba todo («Consultando…» eterno) | `tests/una_firma_lenta_no_congela_el_resto.rs`, con plazo y 120 peticiones desde 12 hilos |
| El `credentialId` viene como UUID en Bitwarden y como 16 bytes crudos del navegador: 0 de 19 casaban | normalización única en `Passkey::de_entrada` |
| Firefox trata los permisos de host de MV3 como **opcionales**: sin concederlos a mano los content scripts no se inyectan y nada avisa | el popup lo detecta y ofrece el botón (`about:addons` → Permisos) |
| Firefox busca el manifiesto del puente junto a donde está instalado: openSUSE/Fedora miran `/usr/lib64/mozilla` | el RPM lo instala en **las dos** rutas |
| La CSP no lleva `'unsafe-inline'` para scripts. Con Angular eso rompía su «CSS crítico» (`onload=`); **con `maud` la misma regla dice otra cosa igual de dura**: htmx, boi y el puente van por `<script src>` y jamás en línea — un script en línea aquí no falla, no se ejecuta, y no lo dice nadie | `vista::pruebas::el_armazon_carga_lo_suyo_y_nada_en_linea`, que comprueba las dos mitades (que estén por `src` y que no haya nada en línea) |
| Una defensa que sobrevive a lo que la hacía falta: el cliente siguió mandando el testigo de sesión después de que el lado Rust dejara de mirarlo — cabecera vacía, `meta` inexistente, y aspecto de protección | **La prueba se retiró con Angular** (miraba su paquete): en la pantalla nueva el artefacto ES el fuente. Lo que queda vivo de la regla lo vigila `gui::pruebas::ninguna_respuesta_de_la_pantalla_lleva_la_frase` |
| Un dato que la interfaz no sabe decir se pierde al ida y vuelta: la regla de coincidencia de cada URI volvía al defecto al editar, así que corregir un NOMBRE cambiaba a qué páginas sirve la entrada — y una URI `Nunca` empezaba a ofrecerse sola | `gui::pruebas::editar_una_entrada_no_le_cambia_a_que_paginas_sirve` + `el_detalle_dice_con_que_regla_sirve_cada_direccion`. La regla se empareja por texto, y el detalle la ENSEÑA: lo que no se ve no se conserva a propósito |
| La carpeta que Brave tiene **cargada descomprimida** (`target/extension-chrome/`) no se actualiza sola: llevaba un día atrasada, con el manifiesto en 0.2.5 contra un programa en 0.2.9. El navegador no vuelve a preguntar | `tests/lo_que_brave_tiene_cargado_no_se_queda_atras.rs` — compara archivo a archivo con `extension/` y exige que el manifiesto armado lleve la versión del programa |
| El paquete instalado se llamaba igual que el del árbol y no era el mismo: el RPM 0.2.9 se construyó ANTES de los tres últimos commits y nadie subió el número. Misma versión, distinto contenido; las pruebas verdes porque miran el árbol, no lo instalado | `build.rs` sella el commit en el binario (`--version` → `0.2.10 (422383b)`, con `-sucio` y `sin-git` como respuestas honestas) + `tests/el_binario_dice_de_que_commit_sale.rs`, que arranca el ejecutable de verdad |
| El mismo fallo de raíz, y peor: el detalle devuelve el CÓDIGO del segundo factor y no el secreto, así que la ventana mandaba el campo vacío — y vacío valía como «bórralo». Corregir el nombre destruía el TOTP | `gui::pruebas::editar_una_entrada_no_le_destruye_el_segundo_factor`. Ausente o `null` = no se toca; `""` = se quita, pedido con una casilla. La prueba se cae también con la SOBRECORRECCIÓN de conservarlo siempre |
| **La TERCERA de la familia, y estaba viva:** el detalle no devuelve la **carpeta** y la ventana no la manda, así que corregir el nombre de una entrada la sacaba de su carpeta, sin error. Salió aplicando a los campos que quedaban la regla que ya estaba escrita para el segundo factor | `construir` trata `carpeta` y `clave` como el TOTP —ausente = no se toca, `""` = se quita—; `gui::pruebas::editar_una_entrada_no_la_saca_de_su_carpeta` y `…no_le_borra_la_contrasena` |
| En un `<form>` **no existe el «ausente»**: un `<input>` siempre se envía, así que la distinción que salva al segundo factor desaparece al migrar a HTML | `tres_estados` traduce (vacío = no tocar; con valor = poner; CASILLA marcada = quitar; las dos cosas = se rechaza) y `guardar_desde_el_formulario_no_destruye_la_clave_ni_el_segundo_factor` lo envenena por los tres lados |
| **El motor reutiliza respuestas de `chuspa://` sin volver a pedirlas.** Medido con su control: de cuatro `GET /nuevo/lista` idénticos que hace htmx llegó UNO; con `no-store` llegan los cuatro. La bóveda se abría con sus entradas dentro y la pantalla enseñaba una lista vacía, sin un solo error. Y una respuesta guardada es una contraseña fuera de la bóveda cifrada. **No se generaliza**: dos `GET /api/generar` seguidos por `fetch` llegaron los dos, así que lo reproducido es lo de htmx, no «el motor cachea todo» | `cache-control: no-store` en `gui::atender`; `gui::pruebas::ninguna_respuesta_de_la_ventana_se_puede_cachear` |
| La bitácora apuntaba la CONSULTA, y el filtro de la lista viaja ahí (`?filtro=banco`): qué busca el usuario es justo lo que el índice cifrado existe para no revelar | se anota la ruta sin consulta, por `linea_de_entrada`/`linea_de_salida`; `gui::pruebas::la_bitacora_no_apunta_lo_que_se_busca` |
| **Un `<form>` sin `method` se envía por GET**, y el navegador escribe todos sus campos en la URL — la frase de paso, en claro, en `document.location`. Con htmx cargado no pasa (él intercepta el envío), pero si htmx aún no ha procesado el formulario el envío es el nativo, y la página se ve idéntica. Se vio literalmente: `GET /nuevo?frase=ma%C3%B1ana-…` | todo formulario lleva `method="post"` y su `action`, así el respaldo nativo manda el cuerpo en el CUERPO (que WebKitGTK descarta) y no en la barra; `vista::pruebas::ningun_formulario_puede_enviarse_por_get` |
| Una consulta pegada a la ruta (`/?frase=…`) no casaba con la ruta y se caía al comodín estático, que devolvía el `index.html` de **Angular**: dos interfaces en la misma ventana, con 200 y sin un aviso. El comodín ya no existe —no hay index— pero la lectura de la ruta se arregló por su cuenta | `la_ventana` despacha por la ruta SIN consulta; `gui::pruebas::una_consulta_pegada_no_se_cae_a_la_interfaz_vieja` |
| **`setRequestHeader` lanza `TypeError` con cualquier byte ≥ 0x80**, y `JSON.stringify` no escapa lo que no es ASCII: una frase de paso con «ñ» no abría la bóveda, una entrada con tilde no se guardaba y una ruta como `~/Imágenes/copia.chuspa` no servía. La petición moría DENTRO de la ventana; con htmx llegaba percent-encoded (reintenta con `encodeURIComponent`) y contestaba «petición mal formada», que habla de otra cosa | los dos puentes escapan a `\uXXXX`; `tests/el_puente_del_cuerpo_escapa_lo_que_no_es_ascii.rs` corre el banco de cada uno en su lenguaje, comprueba el escapado **en el paquete compilado** y fija que `serde_json` recompone el par subrogado |
| El plazo de inactividad del enlace medía la actividad **del navegador**, no la del usuario: una mañana trabajando en la ventana, con 598 entradas en pantalla, y Firefox y Brave diciendo «la bóveda está cerrada». Peor, era definitivo —la comprobación cortaba antes de refrescar el reloj, así que nada podía revivirlo salvo reiniciar— y las dos causas se contestaban igual, con un consejo imposible de seguir | el reloj vive en `Aplicacion` y lo sellan las dos mitades; `gui::es_de_una_persona` **enumera** lo que cuenta y deja fuera el sondeo de 1 Hz. `trabajar_en_la_ventana_mantiene_vivo_el_enlace` + `el_sondeo_de_la_ventana_no_cuenta_como_presencia` tiran de lados opuestos, y la pantalla nueva tiene su propia pareja (`trabajar_en_la_pantalla_nueva_…` + `pedir_la_pantalla_nueva_no_cuenta_…`) porque la presencia se enumera por RUTA y una interfaz nueva estrena rutas que nadie ha enumerado; `Razon::{SinBoveda,Inactividad}` hace que el aviso diga qué hacer |
| **La firma era impecable y el sitio la rechazaba.** El contador de firmas se calculaba (`guardado + 1`) y se tiraba al suelo: nadie lo escribía en la bóveda, así que todas las firmas de una misma passkey llevaban el MISMO número. El sitio guarda el último que recibió y rechaza el que no lo supere —es su detector de llaves clonadas, WebAuthn §7.2—, o sea que la passkey servía **exactamente una vez** y a partir de ahí era, para el servidor, una copia robada. Nada daba error: la aserción verifica con la clave pública, la bitácora dice «firma autorizada», y el rechazo llega del otro lado del mundo como «Something went wrong». Y como muchos sitios no comprueban el contador, parecía un problema **de npm** | `dos_firmas_seguidas_no_llevan_el_mismo_contador`, que lee el número del `authenticatorData` que sale hacia el navegador —el artefacto, no el campo de la bóveda— y relee el archivo del DISCO, porque subirlo solo en memoria se ve igual. Su pareja es `firmar_no_toca_las_otras_passkeys_ni_el_resto_de_la_entrada`: anotar un número reescribe la entrada entera, y eso aquí ya se llevó por delante el segundo factor, la carpeta y la regla de cada URI. Si el contador no se puede guardar, la aserción **no se entrega** |

**La regla que sale de los dos:** todo campo que el detalle no devuelva tal cual
es un campo que la ventana no puede conservar, y al guardar se pierde sin error.
Antes de añadir uno así, la pregunta es qué significa que llegue vacío — y
«ausente» y «vacío» tienen que ser cosas distintas.

Cuando una llave no funciona, el primer dato no es una hipótesis:
`CHUSPA_BITACORA=/tmp/chuspa.log chuspa-gui` dice **si la petición llega**. Desde
el 2026-08-09 cubre también la ventana (líneas `ventana MÉTODO /ruta cuerpo=N`),
que es lo que distingue «htmx no disparó» de «disparó y el cuerpo llegó vacío».

**Y una pantalla hay que DIBUJARLA** (directiva 28). El instrumento es
`examples/ventana_de_prueba.rs`, que abre la ventana WebKitGTK de verdad,
sirve por `gui::atender` —el mismo del producto, sin copias— y anota en la
bitácora. Su ruta `/spike` lleva la pareja dentro: el mismo POST a la misma ruta
real con puente y sin él, que tienen que contestar **401 y 400**. Un `assert`
sobre el HTML que devuelve `despachar` no mide nada de esto: un fragmento que se
inserta en el sitio equivocado devuelve el mismo 200 con el mismo cuerpo.

```bash
CHUSPA_BITACORA=/tmp/spike.log cargo run --release --example ventana_de_prueba -- /nuevo 8
```

## Cómo se prueba aquí

- Las pruebas se llaman como frases (`sin_autorizacion_no_se_firma`,
  `ninguna_anotacion_menciona_un_secreto`) y cada arreglo viene con la suya. Un `fix(...)` sin
  prueba guardián no está terminado.
- **Se envenena la salvaguarda para ver que discrimina**: quitar el hash del
  índice tumba 3 pruebas, quitar la normalización del `credentialId` baja de 19
  passkeys usables a 0, devolver el comportamiento anterior de la firma tumba 4
  de 5. Si romperlo a propósito no pone nada rojo, la prueba es un adorno.
- **Se cruza la frontera del programa** donde hay una: `tests/enlace_navegador.rs`
  y `una_firma_lenta_no_congela_el_resto.rs` hablan por el socket de verdad
  (arnés `examples/socket_de_prueba.rs`), y `extension/banco/` ejercita la cadena
  entera —página → puente → fondo → aplicación— en un **Firefox real** con
  `web-ext`, que es lo único que veía el fallo de los dos mundos.
- **`cargo test` ya NO depende de node.** Hubo una prueba que lanzaba `node
  --test src/estaticos/puente.test.js` (escapado de no-ASCII del puente JS); se
  retiró con el WebView y el puente JS en la migración a GTK4. Hoy ningún paso
  del verde toca node. Node solo haría falta para los chequeos MANUALES de la
  extensión (`npx addons-linter`, banco `extension/banco/` con `web-ext`), al
  (re)publicar en las tiendas — no para el verde ni para el `.deb`.
- **Y una pantalla hay que DIBUJARLA**: `examples/ventana_de_prueba.rs` abre la
  ventana WebKitGTK de verdad, la sirve por `gui::atender` —el mismo del
  producto, sin copias— y la recorre sola con un piloto dirigido por lo que ve
  en el DOM. Cuatro de los fallos de la migración solo se vieron ahí.

## Datos reales, nunca en el repositorio

El `.gitignore` es amplio a propósito: `*.csv`, `bitwarden_export*`,
`/boveda*.chuspa`, `/exports/`. La única excepción son los CSV **inventados** de
`tests/datos/`. Un export de Bitwarden es la bóveda entera en texto plano; las
mediciones que aparecen en el README (595 entradas, 19 passkeys) salen de
`examples/comprobar_export.rs` e `informe_salud.rs`, que están escritos para
**no poder imprimir un valor**.
