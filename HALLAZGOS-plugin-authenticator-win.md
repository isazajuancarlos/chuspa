<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# chuspa como proveedor de passkeys en Windows — spikes de viabilidad

Rama `windows/passkey-provider`. De-riesgo de la vía **(C)**: que chuspa aparezca
**junto a** Windows Hello en el selector nativo de passkeys (como 1Password/
Bitwarden), vía el **Windows 11 WebAuthn plugin authenticator** (no
`webAuthenticationProxy`, que es escritorio remoto — ver `PENDIENTES.md`).

## Spike 1 — ¿el API existe aquí? ✔ VERDE
`src/main.rs` (bin `sonda-plugin-authenticator`). FFI crudo a kernel32
(`LoadLibraryW`/`GetProcAddress`), sin dependencias. Los 3 símbolos del plugin
resuelven en `webauthn.dll`. Discrimina: control + (baseline `WebAuthNGetApiVersionNumber`)
y control − (símbolo inventado = `no`). Medido en **Win11 LTSC 2024 build 26100.9457**
(≥ 26100.8524, KB5089573).

## Spike 2 — ¿se registra y aparece en Ajustes? ✔ VERDE (y limpiado)
`src/bin/registrar.rs`. Structs/firmas transcritas **verbatim** del header oficial
de Microsoft (`microsoft/webauthn`: `webauthnplugin.h`, `pluginauthenticator.idl`).

**Hallazgo pivotal:** `WebAuthNPluginAddAuthenticator` desde un `.exe` pelado da
**`0x80073D54` = APPMODEL_ERROR_NO_PACKAGE**. **El proceso del proveedor DEBE tener
identidad de paquete (MSIX).**

**Receta que funcionó (modo desarrollador ON, sin firmar — para el spike):**
1. `cargo build --release --bin registrar`, copiar el exe a `paquete-spike/`.
2. `paquete-spike/AppxManifest.xml` (en el repo): identidad + `runFullTrust` +
   `EntryPoint="Windows.FullTrustApplication"` + un **AppExecutionAlias**
   (`chuspa-registrar.exe`) que lanza el exe CON identidad de paquete.
3. `Add-AppxPackage -Register paquete-spike\AppxManifest.xml`.
4. `chuspa-registrar.exe agregar` (por el alias) → **`WebAuthNPluginAddAuthenticator`
   = S_OK**. No hizo falta servidor COM en el registro (el COM se invoca solo en las
   ceremonias).
5. **Verificado en la frontera real (D28):** Ajustes → Cuentas → Llaves de acceso →
   Opciones avanzadas → "Administradores de clave de paso" muestra **"Chuspa (spike)"
   / "Juan Carlos Isaza"**, junto a Windows Hello. Juan lo activó en su pantalla.
6. **Limpieza (reversible):** `chuspa-registrar.exe quitar`
   (`WebAuthNPluginRemoveAuthenticator` S_OK) + `Remove-AppxPackage` → desaparece de
   Ajustes. La máquina vuelve a su estado original.

## Datos del API para la construcción real
- **Interfaz COM `IPluginAuthenticator : IUnknown`** (UUID `d26bcf6f-b54c-43ff-9f06-d5bf148625f7`),
  4 métodos tras IUnknown: `MakeCredential`, `GetAssertion`, `CancelOperation`, `GetLockStatus`.
- Peticiones/respuestas CTAP2 **CBOR** (`WEBAUTHN_PLUGIN_OPERATION_REQUEST/RESPONSE`);
  la request trae firma verificable con la `pbOpSignPubKey` que devuelve AddAuthenticator.
- `authenticatorGetInfo` CBOR **requerido** en el registro (aquí uno mínimo: `{1:["FIDO_2_0"],3:aaguid}`).
- Tooling MSIX (build real): `makeappx`/`signtool` en `C:\Users\juan\tools\sdk-buildtools\bin\10.0.28000.0\x64\`.
- Cert de firma `CN=Juan Carlos Isaza` confiado en `CurrentUser\Root`.

## La construcción (sesión dedicada) — repo sensible, concilio D25 al cerrar

### Rebanada A ✔ HECHA 2026-10-08 — el corazón en `chuspa-gui` (crate núcleo, `forbid` intacto)

El flujo del plugin **NO es el del navegador**: Windows entrega un `clientDataHash`
YA calculado (CTAP2), no el reto ni el origen. El autenticador firma
`authenticatorData ‖ clientDataHash`; reconstruir el `clientDataJSON` es imposible
(preimagen de SHA-256). Así que el socket y `webauthn.rs` ganaron un camino basado
en hash, en paralelo al del navegador (sin tocar el flujo desplegado):

- **Protocolo** (`src/navegador/protocolo.rs`): `Peticion::AutenticarCtap` /
  `RegistrarCtap`; `Respuesta::AsercionCtap` / `CredencialCtap`. Llevan
  `client_data_hash` (b64url de 32) y `uv`, no `reto`/`origen`.
- **Firmado** (`src/webauthn.rs`): `Passkey::firmar_hash(rp_id, client_data_hash, uv)`
  y `registrar_ctap(rp_id, algoritmos, uv)` + `RegistroCtap`. El registro
  comparte el núcleo criptográfico con `registrar` (función `registrar_nucleo`).
- **Agente** (`src/navegador/mod.rs`): `autenticar_ctap` / `registrar_ctap`,
  gemelos de los del navegador. Reutilizan `pedir_permiso`/`pedir_permiso_registro`
  (aprobación en la ventana), `anotar_el_contador` (anti-clon) y el recorrido de
  candidatas, ahora extraído a `candidatas_para` (compartido).
- **Pruebas** (D33, mutante verificado por la vía real: re-hashear el
  `clientDataHash` pone rojas SOLO las 3 que verifican la firma): 8 unit nuevas de
  cripto + 5 del agente, cierre de lazo a través del agente+bóveda. Verde total:
  `cargo test --release` 149 lib + integración, `clippy -D warnings` limpio.

**DECISIÓN de diseño para el concilio (desplazamiento DELIBERADO del límite de
confianza):** en el flujo del navegador, el `rp_id` lo pone la PÁGINA, así que
`chuspa-gui` comprueba el origen (anti-phishing). En el flujo del plugin **no hay
origen** y la comprobación la hace la PLATAFORMA (Windows liga `rpId`↔origen dentro
del `clientDataHash` antes de llamarnos): es el modelo estándar del autenticador de
plataforma. Lo que se CONSERVA: la passkey no sale de la bóveda, la firma exige
aprobación en la ventana (invariante del producto), y el contador sube y se guarda.
`firmar_hash` mantiene la defensa en profundidad de que la passkey sea del `rp_id`
pedido.

### Rebanada 1 ✔ HECHA 2026-10-08 — el códec CTAP2 + despacho por socket (`src/navegador/proveedor_ctap.rs`)

Todo Rust **seguro** → va en el crate núcleo, `forbid` intacto; el crate COM será
una cáscara que marshaliza bytes y llama a `proveedor_ctap::procesar`.

- **Parseo** de `authenticatorMakeCredential`(0x01) / `GetAssertion`(0x02): lector
  CBOR propio que NUNCA entra en pánico ante entrada malformada (devuelve estado
  CTAP2, D20) y rechaza longitud indefinida/anchos reservados. Extrae lo que hace
  falta y **salta** lo que no (extensiones, pinUvAuth, `rk`) consumiéndolo entero.
- **Despacho:** arma `Peticion::{RegistrarCtap,AutenticarCtap}` y habla con
  `chuspa-gui` por el socket (cliente gemelo del puente, plazo 120 s por los 90 s
  de aprobación en ventana).
- **Respuesta:** compone el CBOR de `authenticatorMakeCredential`
  (`{1:"none",2:authData,3:{}}`) y `GetAssertion`
  (`{1:{id,type},2:authData,3:sig[,4:{id}]}`), con el byte de estado CTAP2 delante.
  Mapea los errores del agente a estados CTAP2 (NO_CREDENTIALS, CREDENTIAL_EXCLUDED,
  UNSUPPORTED_ALGORITHM, OPERATION_DENIED), cada rama fijada por prueba.
- **Pruebas:** 9 unit (parseo, respuestas decodificadas con el lector de
  producción, no-pánico ante basura, mapeo de estados) + **1 E2E que cruza el
  socket REAL**: MakeCredential+GetAssertion por `procesar_en` contra un `Agente`
  de verdad, con aprobador de fondo; la aserción la VERIFICA la clave pública de la
  passkey guardada (lo que hará el RP) y el contador queda en 1. Mutante D33
  (swap authData↔sig) verificado: pone rojas la estructura Y la E2E. Verde:
  `cargo test --release` 159 lib + integración; `clippy -D warnings` limpio.

**Supuesto a confirmar en la Rebanada 2 (con los headers MS):** el framing exacto
del `WEBAUTHN_PLUGIN_OPERATION_REQUEST/RESPONSE`. Aquí se asume que transporta el
mensaje CTAP2 crudo (`comando/estado ‖ CBOR`), que es el contrato estándar de un
autenticador; si el wrapper difiere, se ajusta en la cáscara COM (los bytes CBOR
de dentro no cambian).

### Rebanada 2 ✔ HECHA 2026-10-08 — el objeto COM `IPluginAuthenticator` (crate `proveedor-win/`)

Crate SEPARADO (`chuspa-proveedor-win`, Windows-only) con el `unsafe` del ABI de
COM; el núcleo `chuspa` sigue `forbid`. Es una **cáscara**: saca los bytes CTAP2 del
`WEBAUTHN_PLUGIN_OPERATION_REQUEST`, llama a `chuspa::navegador::proveedor_ctap::procesar`
y empaqueta el `WEBAUTHN_PLUGIN_OPERATION_RESPONSE` con `CoTaskMemAlloc`.

- **Contrato confirmado con los headers MS** (`webauthnplugin.h`, `pluginauthenticator.idl`
  de `microsoft/webauthn`, re-leídos): `IPluginAuthenticator` IID `d26bcf6f-…`, vtable
  tras IUnknown = MakeCredential/GetAssertion/CancelOperation/GetLockStatus.
  `WEBAUTHN_PLUGIN_OPERATION_REQUEST{hWnd, transactionId, cb/pbRequestSignature,
  requestType(=CTAP2_CBOR 0x01), cb/pbEncodedRequest}` → `…RESPONSE{cb/pbEncodedResponse}`.
  Structs transcritos `repr(C)`. **Confirma la Rebanada 1**: `pbEncodedRequest` es el
  mensaje CTAP2 (`comando ‖ CBOR`) → `procesar` encaja tal cual.
- **Implementado:** IUnknown (QueryInterface con los dos IID + E_NOINTERFACE, AddRef/
  Release con refcount atómico y drop del Box en 0), MakeCredential/GetAssertion
  (verifican `requestType`=CTAP2_CBOR, comprueban que el comando del mensaje case con el
  método, llaman a `procesar`, asignan la respuesta con CoTaskMemAlloc), CancelOperation
  (S_OK: nuestras ops son síncronas, nada de fondo que cancelar), GetLockStatus
  (Unlocked). Nulos → E_POINTER; tipo no soportado → E_INVALIDARG; sin memoria → E_OUTOFMEMORY.
- **Pruebas (5, verdes; clippy `-D warnings` limpio):** QI/refcount, GetLockStatus,
  marshalling (estado CTAP2 viaja por la cáscara; request nulo→E_POINTER; comando que no
  casa el método→INVALID_COMMAND; requestType ajeno→E_INVALIDARG), y **1 E2E por la vtable
  contra un Agente REAL**: MakeCredential+GetAssertion con aprobador de fondo → estado CTAP2
  0x00 y respuestas >64 B. Mutante D33 (ignorar los bytes del request) verificado: pone roja
  la E2E.

**DOS GAPS declarados (defensa en profundidad / plumbing), a cerrar con la ceremonia:**
- **No se verifica `pbRequestSignature`** (que Windows firma con la clave de `pbOpSignPubKey`
  de AddAuthenticator). Probaría que la llamada viene DE Windows, no de un proceso local.
  El gate REAL no es ése: cada firma/registro exige aprobación en la ventana de `chuspa-gui`
  (invariante), así que un proceso que llame al COM directo no obtiene firma silenciosa —a lo
  sumo un diálogo que el usuario rechaza—. Verificarla cierra esa molestia; el esquema exacto
  se confirma con el sample y en la ceremonia.
- **Falta el registro del servidor COM** (class factory / `CoCreateInstance`): va en la
  Rebanada 3 vía el manifiesto MSIX (`com:ExeServer`), inseparable del empaquetado.

### Rebanada 3 ✔ HECHA 2026-10-08 (lo construible) — class factory + servidor COM + MSIX firmado

En el crate `proveedor-win/`:
- **IClassFactory** (lib): lo que Windows pide ANTES de crear el objeto. `CreateInstance`
  crea el `Objeto` y le pide la interfaz (propaga E_NOINTERFACE si no la tiene), rechaza la
  agregación (`CLASS_E_NOAGGREGATION`). Singleton estático. **Probado** (CreateInstance da un
  IPluginAuthenticator usable; agregación e interfaz ajena rechazadas).
- **Servidor COM** (`servidor.rs`): MTA + `CoRegisterClassObject` (suspendido → `CoResumeClassObjects`)
  + espera del **evento de parada** que se señala cuando no quedan objetos vivos tras servir
  (conteo `VIVOS`/`HUBO_ACTIVIDAD`, con `LockServer`). MTA porque `MakeCredential` bloquea hasta
  90 s en la aprobación y no debe congelar al resto.
- **Registro** (`registro.rs`): `agregar`/`quitar`/`estado` = `WebAuthNPluginAddAuthenticator`/
  `…Remove`/`…GetState` con el **CLSID real** `9c067a63-…` (reusa el FFI probado del spike 2).
- **Binario** `chuspa-provider.exe`: `agregar|quitar|estado` o, por defecto (incl. `-Embedding`
  y `servidor`), corre el servidor COM.
- **MSIX**: `paquete/AppxManifest.xml` da identidad + `AppExecutionAlias` + **`com:ExeServer`**
  del CLSID (lo que faltaba: Windows ya puede activar el objeto). `empaque/empaquetar.ps1`
  construye el bin, arma el layout, `makeappx pack` y `signtool sign` con el cert
  `CN=Juan Carlos Isaza`. **CORRIDO 2026-10-08: `dist/chuspa-provider.msix` empaquetado,
  firmado y `signtool verify` VERDE.**

Suite del crate: **6 pruebas verdes** (objeto + fábrica), `clippy -D warnings` limpio. Todo lo
que NO exige que Windows sea el llamante está medido.

**UV:** nuestro modelo ya la satisface — la aprobación en la ventana de `chuspa-gui` (frase que
abre la bóveda + visto bueno por uso) ES verificación de usuario, y el bit UV ya viaja por el
protocolo (`uv`). Windows Hello (`WebAuthNPluginPerformUserVerification`) sería un pulido
opcional, no un requisito.

### LA CEREMONIA (la corre Juan; es la ÚNICA verificación que falta)

Lo único que no se puede probar sin que Windows active de verdad el CLSID. Pasos:

1. `pwsh -File proveedor-win\empaque\empaquetar.ps1`  → `dist\chuspa-provider.msix` (ya hecho; re-correr si cambia el código).
2. `Add-AppxPackage proveedor-win\dist\chuspa-provider.msix`  (la raíz del cert ya es de confianza; si no, confiar `CN=Juan Carlos Isaza` en LocalMachine\Root una vez).
3. Tener `chuspa-gui` abierto con la bóveda **abierta** (el proveedor habla con él por el socket).
4. `chuspa-provider.exe agregar`  → debe decir **S_OK** y aparecer **"Chuspa"** en Ajustes → Cuentas → Llaves de acceso → Opciones avanzadas, junto a Windows Hello.
5. En un navegador, en un sitio real o de prueba, disparar `navigator.credentials.create()` y luego `get()`; elegir **Chuspa** en el selector nativo. Debe salir el diálogo de aprobación de `chuspa-gui` y, al aceptar, el sitio recibe la credencial/aserción.
6. Limpiar: `chuspa-provider.exe quitar`  +  `Remove-AppxPackage Chuspa.PasskeyProvider_0.1.0.0_x64__<hash>`.

**Qué CONFIRMA la ceremonia** (hoy son supuestos): (a) que Windows pasa el mensaje CTAP2 crudo
en `pbEncodedRequest` (si fuera CBOR sin el byte de comando, saldría `INVALID_COMMAND` ruidoso →
arreglo de una línea); (b) si hace falta verificar `pbRequestSignature` (gap declarado en la
Rebanada 2; el gate real —la aprobación en ventana— ya está).

Ejemplo oficial de referencia: `microsoft/windows-classic-samples` → `Samples/PasskeyManager`.

### LA CEREMONIA — ✔ PASÓ (2026-10-09, en vivo en `webauthn.io`)

End-to-end verde en navegador real, los dos caminos CTAP2:
- **MakeCredential (create):** *«Success! Now try to authenticate…»* — credencial
  creada por Chuspa y aceptada por el RP.
- **GetAssertion (get):** *«You're logged in!»* — aserción verificada → el
  **contador anti-clon** también quedó probado en vivo (el RP la aceptó).
- Chuspa aparece en Ajustes → Cuentas → Llaves de acceso → Opciones avanzadas,
  *Activado*, junto a Windows Hello.

**Los dos supuestos quedaron CONFIRMADOS con la frontera cruzada (D28):** (a) Windows
pasa el CTAP2 crudo con byte de comando (el diálogo de chuspa mostró el `rp_id` y la
cuenta parseados — si fallara habría salido `INVALID_COMMAND`); (b) el proceso COM
empaquetado (MSIX) resuelve el mismo `%LOCALAPPDATA%\chuspa\agente.sock` que la GUI.

Dos aprendizajes de la corrida:
- El `.msix` firmado con cert autofirmado da `0x800B0109` al instalar si la raíz no
  está en `LocalMachine\Root`. La ceremonia se corrió por la vía de dev:
  `Add-AppxPackage -Register dist\layout\AppxManifest.xml` (modo desarrollador ON, sin
  firma). `chuspa-provider.exe agregar` se invoca por el **AppExecutionAlias** (nombre
  pelado, en el PATH), no por `target\release\…` (eso da `0x80073D54` = sin identidad).
- Trampa de foco (= la de bachue): usar el recorte de pantalla (Win+Shift+S) durante la
  ceremonia roba el foco al navegador y aborta el WebAuthn (`CredentialsContainer request
  is not allowed`). Hay que pulsar «Crear la passkey» sin cambiar de ventana.

### CIERRE (concilio D25) — ✔ 2026-10-09, MERGEADO a `desarrollo`

Concilio multi-modelo sobre `917c2fcd`: revisores **sonnet + fable + haiku** (3 ≠
coordinador Opus), verificados. **Sin hallazgos ≥8 de seguridad.** Invariantes (i–iv)
confirmados con mutante por la vía real por ≥2 modelos.

Convergencia ×3 en un punto <8 (DoS, pero incumplía el contrato D20 del módulo):
`Lector::saltar` recursaba sin tope → desbordamiento de pila del host del plugin
(~20 000 niveles, medido; abort, no pánico). Arreglado en `130eeb4b` + 3 fixes
fail-closed más (tope de 64 KiB, `entero` con `try_from`, `uv` consistente), 4 pruebas
pareadas D33. Paso 5: delta re-revisado por fable, 4 mutantes rojos por aserción +
control positivo del desbordamiento. Comentarios de `uv` alineados en `15a96f02` (D24).
`sin-caso-rojo` sobre `15a96f02`: sin huecos de cobertura reales.

Mergeado `--no-ff`: **`desarrollo 2286d89c`** (empujado al espejo). Verde: núcleo 163/0
+ clippy; proveedor-win 6/6 + clippy.

**Follow-ups (no bloqueantes, del concilio y la ceremonia):**
1. **AAGUID a ceros / `Name: (Unavailable)`** en el panel del RP — es el
   `authenticatorGetInfo` mínimo + attestation `none`; un AAGUID propio sería pulido.
2. **`lib.rs:6105-6107`**: el comentario («a lo sumo un diálogo que el usuario rechaza»)
   no se sostiene — el diálogo NO distingue al llamante, así que un proceso local del
   mismo usuario podría colar una petición en la ventana de 90 s (pre-existente, igual por
   `Peticion::Autenticar`). Reescribir el comentario y anotar el límite del modelo de
   amenaza. Verificar `pbRequestSignature` (gap declarado) lo mitigaría pero no lo cierra
   mientras el socket siga abierto a cualquier proceso del usuario.
3. **Coherencia de `uv` en el `authenticatorGetInfo`** que anuncie el plugin (fuera de
   este archivo).
