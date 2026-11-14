<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Migración de chuspa a GTK4 nativo (escritorio = GTK puro)

Decisión de Juan (2026-09-09): todos los programas de escritorio en **GTK puro,
sin WebView**. chuspa hoy es tao+wry (WebKitGTK) con la UI en maud. Esto NO es un
cambio de UI aislado: `gui.rs` (3912 líneas) es el NÚCLEO del app.

## El nudo, REMEDIDO en fase 1 (y la premisa que había estaba mal)
`navegador/mod.rs` (puente de la extensión Firefox/Chrome) depende de
`gui::{Aplicacion, Candidata, Existente, FirmaPendiente, crear_para_sitio,
proponer_guardado}` en su código de producción (los usos de `despachar`/`Peticion`
están dentro de `#[cfg(test)]`). El plan viejo suponía que había que extraer un
`src/app.rs` porque «gatear `gui` entero rompe la extensión» y porque el
despachador mezclaba `/api` con las páginas maud. **Lo primero es cierto; lo
segundo llevaba a la solución equivocada.** Medido:

- **`maud` NO es opcional** (`Cargo.toml`): es Rust puro, teje cadenas de HTML y
  **no arrastra ningún motor web**. Toda la UI maud (`vista.rs`, `la_ventana`,
  los `ventana_*`, `despachar`, `atender_ruta`) compila en el build por defecto.
- **La ÚNICA pieza que toca `wry` es `gui::atender`** (el traductor
  `wry::http::Request` → `Peticion`), más su prueba `ninguna_respuesta_de_la_
  ventana_se_puede_cachear` y el arnés `examples/ventana_de_prueba.rs`. Eso es
  la «capa wry», y es lo único que arrastra gtk3/webkit.

O sea que separar el núcleo de la **capa wry** (que es lo que pedía la memoria
`estandar-escritorio-gtk`) NO exigía mover 1500 líneas a `app.rs`: exigía aislar
`atender`. Extraer `app.rs` habría sido churn de alto riesgo sobre un gestor de
contraseñas, y habría sacado del banco por defecto las pruebas de la UI maud
(directivas 1 y 37).

## Fases
1. **HECHO (2026-09-09).** Des-gatear `gui` y `vista` en `lib.rs` (solo necesitan
   maud) y gatear tras `webview` **solo la capa wry**: `gui::atender`, su prueba de
   caché, el bin `chuspa-gui` (ya lo estaba) y el example `ventana_de_prueba`.
   Resultado: el build por defecto (**GTK puro, solo gtk4**) compila, y el banco
   del núcleo corre sin gtk3/webkit. El guardián del sello de commit
   (`el_binario_dice_de_que_commit_sale`) pasó a medir el binario POR DEFECTO
   (`chuspa-gtk`, que ganó `--version`); las pruebas de la ventana `chuspa-gui`
   quedaron tras `webview`.
2. **UI GTK4 nativa** sobre el núcleo (la semilla está en `src/bin/chuspa-gtk.rs`:
   desbloqueo + lista con filtro + detalle con revelar/copiar). Estado:
   - [x] **generar** contraseña/frase (diálogo sobre `chuspa::generador`).
   - [x] **crear/editar** entrada con los tres estados ausente/vacío/quitar,
     TOTP y carpeta. NO reinventa la fusión: reusa `chuspa::gui::{construir,
     EntradaEntrante}` (ahora públicos), así que las pruebas guardián de editar
     de `gui::` cubren las dos interfaces; la app añade sus propias pruebas que
     cruzan cifrado+disco (`entrada_del_formulario` + `guardar_entrada_gtk`).
   - [x] **TOTP con código en vivo**: el detalle muestra el código de 6 dígitos
     con cuenta atrás y copiar (refresco cada segundo, se corta al redibujar).
   - [x] **salud**: informe offline de `chuspa::salud` en un diálogo, por gravedad.
   - [x] **copia de seguridad**: crear (con verificación) y comprobar, sobre
     `chuspa::copia`. El papel BIP-39 + Shamir de `respaldo.rs` queda como
     herramienta de operación (tampoco está en el GUI web), así que la **paridad
     de la ventana standalone está ALCANZADA**.
   El núcleo que consume es `chuspa::{cifrado, boveda, gui, totp, salud, copia,
   generador}` reusando las funciones probadas, no la UI maud.

   **FASE 2 COMPLETA (2026-09-12).** El binario por defecto `chuspa-gtk` es un
   gestor de contraseñas de escritorio completo y 100% GTK para uso STANDALONE.
   Cada pieza se verificó cruzando la frontera del núcleo (cifrado+disco) con su
   pareja de caso rojo (directiva 33). Falta la verificación por PÍXELES (D28):
   la ventana de desbloqueo se dibujó y capturó (X11), pero los diálogos internos
   necesitan un arnés de dibujo — se hará en la fase 3, cuando la UI se reordene.
3. **FASE 3 COMPLETA (2026-09-12). Retirado wry/tao/maud/vista y la feature
   `webview`: chuspa es 100% GTK.** Lo que se hizo:
   - **3a** — la app GTK usa `Arc<Aplicacion>` como estado (el mismo núcleo que la
     ventana web), prerequisito para hospedar el agente sin reinventar el estado.
   - **3c** — el agente del navegador vive en la app GTK:
     `navegador::escuchar_al_navegador(Arc<Aplicacion>)` + un `glib::timeout` que
     sondea `firma`/`guardado` y abre los diálogos de autorización de **firma de
     passkeys (WebAuthn)** y de **guardado propuesto**. NO se reinventa la
     decisión: `aplicar_firma`/`aplicar_guardado` arman el JSON y llaman a
     `gui::{decidir_firma, decidir_guardado}` (ahora `pub`), la MISMA lógica
     validada. Cerrar la ventana suelta la bóveda; la presencia la sella la
     interacción real (no el sondeo).
   - **3d** — borrado el frontal viejo entero: `chuspa-gui`, `vista` (maud),
     `estaticos`, tao/wry/maud/mirilla, la feature `webview`, y ~1600 líneas de
     capa HTTP/HTML en `gui.rs` (que pasó de 3949 a ~700). Queda solo el núcleo
     que la ventana GTK y el agente reusan. Empaquetado (RPM, .desktop) y
     `deny.toml` (excepciones GTK3 vaciadas) apuntan a `chuspa-gtk`.
   - **Cierre: `concilio` de 4 modelos (haiku, sonnet, opus, fable) — CERO
     hallazgos ≥8.** La lógica de firma/guardado es byte-idéntica a la base (solo
     `pub`). Se atendieron dos observaciones convergentes: la presencia se sellaba
     por foco en el temporizador (se pasó a interacción real) y el aviso de firma
     no realzaba la ventana (ahora `ventana.present()` al detectar el pendiente).
   - **Pendiente menor:** instrumento de dibujo GTK4 (broadway/Xvfb) para probar
     los píxeles de los diálogos; hoy la lógica se verifica cruzando la frontera
     del núcleo (cifrado+disco) y el agente por su socket, no por píxeles.

## Lo que el banco por defecto NO cubre (queda tras `webview` o es ambiental)
- La **ventana wry** (`atender`, su caché, `ventana_de_prueba`) y las pruebas de
  versión de `chuspa-gui`: tras `webview`, que exige **`libgtk-3-dev` +
  `libwebkit2gtk-4.1-dev`** (hoy la máquina solo tiene `libgtk-4-dev`, así que
  `cargo build --features webview` no compila aquí — no se fuerza).
- `el_puente_de_htmx_pasa_su_banco` necesita **node ≥ 22** (ausente); falla
  ruidosamente, como está diseñado.

Cada fase cierra con `cargo test` verde y, por ser auth/secretos, **concilio**.
