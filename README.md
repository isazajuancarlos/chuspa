<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Chuspa

Gestor de contraseñas **offline**, cifrado con [Quipu](https://github.com/isazajuancarlos/quipu).
Una bóveda local, sin nube y sin cuenta. Uso personal.

*Chuspa*: la bolsita andina donde se guarda lo que vale.

## Estado

En construcción. Lo que **funciona y está probado** hoy:

| Pieza | Estado |
|---|---|
| Modelo de bóveda (`src/boveda.rs`) | hecho |
| Importador de Bitwarden JSON (`src/importar/bitwarden.rs`) | hecho — 17 pruebas |
| Importador de Bitwarden CSV (`src/importar/bitwarden_csv.rs`) | hecho — 13 pruebas |
| Verificador de exports reales (`examples/comprobar_export.rs`) | hecho |
| Bóveda cifrada con Quipu (`src/cifrado.rs`) | hecho — 53 pruebas |
| Copia de seguridad del contenido (`src/copia.rs`) | hecho — 16 pruebas |
| Respaldo en papel y recuperación (`src/respaldo.rs`) | hecho — 20 pruebas |
| Comprobación de paginación (`src/memoria.rs`) | hecho — 9 pruebas |
| Enlace con el navegador (`src/navegador/`), Firefox y Chrome/Brave | hecho — 31 pruebas + 14 por el socket y la extensión |
| Passkeys (`src/webauthn.rs`) y su autorización en la ventana | hecho — 12 + 6 pruebas |
| Códigos TOTP (`src/totp.rs`) | hecho — 8 pruebas, vectores del RFC 6238 (+2 en el enlace) |
| Informe de salud (`src/salud.rs`) | hecho — 10 pruebas |
| Generador (`src/generador.rs`) | hecho — 6 pruebas |
| Fecha de lo que nace en la aplicación (`src/fecha.rs`) | hecho — 3 pruebas |
| Interfaz gráfica (`src/gui.rs` + `interfaz/`) | hecha — 22 pruebas, ventana propia |
| Puente del cuerpo por cabecera, en ASCII puro | hecho — 5 pruebas, que corren 9 casos en node |
| Interfaz en `maud` + htmx, servida por el binario | hecha — Angular retirado el 2026-08-09; banco de extremo a extremo en la ventana real |
| Sello del commit en el binario (`src/version.rs`) | hecho — 6 pruebas, `--version` |
| Que lo armado para Brave sea lo del repositorio | hecho — 2 pruebas |
| Empaquetado DEB y RPM con lanzador de escritorio | hecho |

En total, **319 pruebas en verde** y `clippy` sin avisos —
`cargo test --release --no-fail-fast` y `cargo clippy --all-targets --release --
-D warnings`, medidos el 2026-08-09—. No hay CI: el único verde es el local.

Lo pendiente está pendiente: nada de esto se anuncia como disponible hasta que
tenga pruebas que lo respalden.

## Qué garantiza el importador

La promesa es **ningún dato se pierde en silencio**, y no está escrita solo en
prosa: todos los tipos del esquema llevan `#[serde(deny_unknown_fields)]`. Si
Bitwarden añade un campo, la importación se detiene con su nombre en el error en
vez de descartarlo. Un tipo de ítem, un tipo de campo o un `reprompt` fuera de
los valores conocidos son errores, no valores a ignorar.

Se importan los cuatro tipos de ítem —acceso, nota, tarjeta, identidad— con
TOTP, passkeys (incluida su clave privada), campos personalizados de los cuatro
tipos, URIs con su regla de coincidencia, historial de contraseñas con su fecha,
carpetas y favoritos.

La prueba que sostiene todo esto no comprueba campos concretos: cuenta los datos
del JSON de origen y exige que salga el mismo número. Quitar el volcado de un
solo campo la pone roja aunque ninguna otra prueba lo nombre — verificado
inyectando el fallo a propósito (16 de 17 pruebas siguen verdes; esa se cae).

Importar bien no basta: hay que **no perderlo después**. La regla de
coincidencia de cada URI no viaja por la interfaz —allí una dirección es una
línea de texto— y al guardar volvía al defecto, así que **corregir el nombre de
una entrada le cambiaba a qué páginas sirve**. El caso grave no es el que
estrecha: una URI marcada `Nunca` —la que Bitwarden usa para «no ofrecer sola», y
donde acaban también las de expresión regular, que aquí no se admiten— pasaba a
ofrecerse en cualquier página del host. Una credencial apartada a propósito
volvía a salir sola, sin un aviso.

Ahora la regla se conserva emparejando por el texto de la URI, y una dirección
nueva no hereda ninguna: no se puede saber de cuál vendría, y suponerlo sería
inventar el dato. Además el detalle **enseña la regla** cuando no es la de por
defecto, porque una regla que no se ve no se puede conservar a propósito: era
exactamente igual de invisible antes y después de borrarla.

### Exporta en JSON, no en CSV

El CSV de Bitwarden tiene doce columnas fijas y **pierde datos de forma
irrecuperable**: no hay columna para tarjetas, identidades, passkeys, historial
de contraseñas ni identificadores de ítem, y aplana los campos personalizados
perdiendo su tipo.

No es una advertencia teórica. Comparando un export real en los dos formatos de
la misma bóveda: el JSON traía **595 ítems y el CSV 594**. El que faltaba era una
tarjeta, y el CSV no deja rastro de que existiera. Las 19 passkeys tampoco
viajaban.

Hay otra pérdida más sutil: el CSV separa varias URIs con comas y no escapa el
separador, así que una URI que contenga una coma es indistinguible de dos URIs.
En ese mismo export, una entrada con **una** URI en el JSON producía **dos** al
pasar por el CSV. El importador parte por coma —la lectura mayoritaria— y avisa
de cuántas entradas están afectadas, en vez de aplicar una heurística que
acertaría a veces sin decir en cuáles.

El importador CSV existe porque es lo que la gente tiene a mano. La recomendación
es el JSON.

### Comprobar un export real sin enseñarlo

```bash
cargo run --example comprobar_export -- /ruta/al/export.json
```

Importa el archivo y coteja **dato a dato** que nada se quedó fuera, imprimiendo
solo conteos y, si algo falla, el índice del ítem. Está escrito para no poder
mostrar un valor: es la bóveda entera en claro lo que se le pasa por la entrada.

### Lo que el formato de Bitwarden no permite importar

- **Adjuntos**: no viajan en el export JSON. Hay que descargarlos aparte. Chuspa
  lo avisa siempre, porque desde el archivo no se puede saber si había alguno.
- **Ítems en la papelera**: no entran, pero se cuentan y se avisan.
- **Colecciones de organización**: los ítems se importan; la estructura de
  colecciones no tiene equivalente en una bóveda personal.
- **Export cifrado** (`.encrypted_json`): no se admite, y el error dice qué
  exportar en su lugar.

Y un aviso que sale siempre: el archivo de export está **en texto plano** con
todas las contraseñas dentro. Hay que borrarlo en cuanto termine la importación.

## La bóveda

Un archivo. Argon2id deriva la clave maestra de la frase de paso —256 MiB y 4
iteraciones por defecto, **900 ms medidos** en release, cuatro veces el perfil
interactivo habitual— y de ahí HKDF deriva **una clave por entrada**.

Probado con una bóveda real de 595 entradas: ~900 ms de derivación más 7 ms para
cifrarlas y escribirlas todas, 561 KB de archivo (relleno incluido), permisos
0600, y ninguno de los 582 nombres, usuarios y contraseñas comprobados aparece
en claro en el archivo.

> En una compilación de depuración la misma derivación tarda 12 s. Es el modo de
> compilación, no el parámetro: no bajes el coste por una medición sin
> `--release`.

Abrir la bóveda descifra solo el índice. Abrir una entrada descifra solo esa (la
única excepción es migrar una bóveda de una versión anterior: una vez, al abrir,
se descifran sus entradas para derivar el usuario que distingue cuentas del mismo
sitio en la lista; una bóveda ya guardada con esta versión no vuelve a hacerlo).
Lo que no pides nunca llega a estar en claro en memoria — que es la diferencia
entre un volcado de memoria que expone una contraseña y uno que las expone todas.

El índice también va cifrado: el nombre de un sitio y su URL revelan dónde tienes
cuenta.

### Cómo se ata el conjunto

Cifrar por partes crea un problema: cada bloque es íntegro por separado, pero el
conjunto no. Alguien con acceso al archivo podría reordenar bloques, duplicar
uno, o devolver una entrada a una versión anterior con la contraseña que ya
rotaste — y todos los tags AEAD seguirían siendo válidos.

Lo cierra una sola pieza: **el índice guarda el hash de cada bloque cifrado**, y
el índice se cifra con el contador de versión dentro de su AAD. De ahí sale todo:

| Ataque | Qué lo detiene |
|---|---|
| Alterar un byte de una entrada | su hash no cuadra con el del índice |
| Reordenar o duplicar entradas | los hashes no cuadran en su posición |
| Revertir una entrada suelta | igual: el hash es del bloque cifrado |
| Pegar un índice viejo en un archivo nuevo | el contador va en el AAD del índice |
| Trasplantar una entrada de otra bóveda | su AAD lleva el salt y el id de origen |
| Reponer una copia de seguridad entera | `abrir_verificando` con el contador guardado aparte |
| Quitar la bandera de archivo llave | va en el AAD, del índice y de cada entrada |
| Falsear los parámetros del KDF para agotar memoria | se validan **antes** de derivar |
| Contar las entradas por la forma del archivo | desplazamientos y nonces viven en el índice cifrado |
| Distinguir la nota larga por el tamaño de su bloque | relleno Padmé por entrada y sobre el conjunto |
| Dos instancias pisándose los cambios | cerrojo entre procesos, con reclamo de huérfanos |

El contador **no** entra en el AAD de las entradas, y es deliberado: si entrara,
cada guardado obligaría a recifrar las 595 entradas, lo que exigiría tenerlas
todas descifradas a la vez — justo lo que este diseño evita.

Cada salvaguarda se verificó envenenándola por separado: quitar el hash del
índice tumba 3 pruebas, usar una subclave común tumba 1, y quitar el id del AAD
tumba otra distinta. Ninguna prueba tapa a otra.

### El archivo llave

Una frase de paso es lo que una persona puede recordar, y eso pone un techo a su
entropía. El archivo llave es un secreto de 256 bits que se guarda **aparte** —un
USB, otro equipo— y entra en la derivación junto a la frase.

Lo que cambia es el escenario realista de robo: la copia de seguridad que acabó
en la nube, el disco extraviado, el adjunto de un correo. Quien se lleve solo la
bóveda no puede probar frases contra ella, porque le falta un secreto que no está
ahí. **No** protege contra quien copia el equipo entero con la llave dentro, y
por eso la recomendación es que viva en otro soporte.

Es el *key file* de KeePassXC y la *Secret Key* de 1Password. No se inventa nada:
se implementa lo que funciona.

La bandera de «esta bóveda usa llave» va en claro a propósito. Saber que existe
no ayuda a nadie, y sin ese aviso quien se dejara el USB en casa recibiría
«contraseña incorrecta» y probaría frases durante una hora.

### Frase de paso: se avisa, no se bloquea

Solo se rechaza la frase **vacía**. Una frase débil produce un aviso y sigue
adelante, porque rechazarla sería cerrar por costumbre: una frase corta con
archivo llave es razonable, y quien recibe un rechazo suele responder añadiendo
un `1` al final. Se rechaza lo imposible, no lo inusual.

### Comparación honesta con el estado del arte

Dónde el formato de Chuspa está por delante:

| | Chuspa | KeePassXC | Bitwarden | 1Password |
|---|:--:|:--:|:--:|:--:|
| Cifrado por entrada (no se descifra todo al abrir) | sí | no | no | no |
| Integridad del **conjunto** (anti-reordenado/reversión) | sí | no | no | no |
| Detección de copia de seguridad repuesta | sí | no | no | no |
| Relleno de longitud de metadatos | sí | no | no | no |
| AEAD moderno | XChaCha20-Poly1305 | ChaCha20/AES | AES-CBC+HMAC | AES-GCM |
| Argon2id | sí | sí | opcional | no (PBKDF2) |
| Secreto de alta entropía aparte | sí | sí | no | sí |

Y dónde **no** lo está, que importa igual:

- **No hay auditoría externa.** 1Password y Bitwarden pagan auditorías y
  programas de recompensas. Aquí hay pruebas propias, envenenadas para comprobar
  que discriminan, pero eso no sustituye a que alguien de fuera intente romperlo.
- **No hay `mlock`.** KeePassXC fija la memoria y Chuspa no puede sin `unsafe`.
- **No hay sincronización, ni apps móviles, ni recuperación de cuenta.** Es un
  gestor local de una persona, no un servicio.
- **Es código nuevo.** Un formato de archivo de un día no ha tenido la
  oportunidad de fallar que tiene uno de quince años.

Dicho de una vez: el **formato** aguanta la comparación y en varios puntos la
gana; el **producto** no compite todavía con un gestor maduro, y decir lo
contrario sería vender humo.

### Respaldo en papel

Una bóveda bien hecha tiene un problema que no tiene una mal hecha: si olvidas la
frase, no hay quien la abra. No hay «recuperar contraseña» — el día que exista,
existe también para quien no eres tú. El precio es que un olvido lo borra todo.

```bash
CHUSPA_FRASE='...' cargo run --release --example hoja_de_respaldo -- boveda.chuspa
```

La hoja lleva **dos caminos independientes** a la misma clave:

1. **24 palabras BIP-39.** Se transcriben a mano, se dictan por teléfono y se
   entienden dentro de treinta años sin este programa. Llevan suma de
   verificación: una palabra mal copiada se **detecta** en vez de devolver una
   clave silenciosamente equivocada.
2. **11 símbolos con Reed-Solomon**, de los que se pueden perder **2** enteros —
   un roto, una mancha, una esquina quemada— y la clave sale igual.

Si el café cae sobre las palabras quedan los símbolos; si la impresora deja media
hoja sin tinta quedan las palabras. Por eso van los dos y no el mejor de los dos.

**Lo que se respalda es la clave, no la frase.** La maestra es aleatoria y va
envuelta por el acceso, así que **el papel sigue valiendo después de cambiar la
frase mil veces**. Respaldar la frase daría un papel que caduca en silencio la
próxima vez que la rotes, y un respaldo que crees tener y no tienes es peor que
ninguno.

Esa misma envoltura hace que rotar la frase cueste **48 bytes en vez de 595
entradas**: la maestra no cambia, así que ningún bloque se toca. La primera
versión recifraba la bóveda entera, lo que ponía todos los secretos en memoria a
la vez — justo lo que el cifrado por entrada existe para evitar.

Y el aviso que va impreso en la hoja: **ese papel abre la bóveda entera**, sin
frase y sin archivo llave. Se guarda como se guarda una escritura.

### Copia de seguridad cifrada y comprimida

```bash
CHUSPA_FRASE='...' cargo run --release --example copia_de_seguridad -- \
    crear boveda.chuspa copia.chuspacopia

# Comprobar que la copia del cajón SIGUE sirviendo. No toca nada.
CHUSPA_FRASE='...' cargo run --release --example copia_de_seguridad -- \
    comprobar copia.chuspacopia

# Restaurar en una bóveda NUEVA; se niega si el destino existe.
CHUSPA_FRASE='...' CHUSPA_NUEVA_FRASE='...' \
  cargo run --release --example copia_de_seguridad -- \
    restaurar copia.chuspacopia recuperada.chuspa
```

**El texto cifrado no se comprime**, así que comprimir el `.chuspa` no ahorra
nada: medido, `gzip -9` sobre una bóveda de 8 entradas la deja en 6 543 bytes
partiendo de 6 513 — *crece*. Comprimir solo significa algo antes de cifrar, y
por eso la copia se construye del **contenido**: se abren las entradas, se
serializan, se comprimen, y se cifra el resultado. Esa misma bóveda de 6 513
bytes produce una copia de **757**, ocho veces y media más pequeña.

El orden importa en la otra dirección también: se **rellena con Padmé después de
comprimir**, porque comprimir vuelve a introducir la fuga de longitud que la
bóveda evita rellenando cada entrada. Sin eso, el tamaño del archivo volvería a
ser una medida de cuánto hay dentro.

**La abre la frase de paso, y también la hoja de papel.** La copia lleva su
propia envoltura de la clave maestra, así que se restaura en otra máquina sin
tener el `.chuspa` original — y como lo envuelto es la maestra, los 24 símbolos
del respaldo abren la copia igual que abren la bóveda. Un respaldo que exigiera
recordar la frase caducaría el día que se olvida justo lo que hay que respaldar.

Se puede dar a la copia una **frase propia**, distinta de la de la bóveda, para
dejarla en manos de otro custodio sin darle la de uno.

**El precio, dicho antes de cobrarlo:** la bóveda presume de que abrirla no pone
las 595 contraseñas en claro en memoria, y una copia completa suspende eso por
definición — para copiarlo todo hay que tenerlo todo. Es una operación
explícita, nunca automática, y los búferes propios se borran al soltarlos; pero
ese es el minuto de mayor exposición de una bóveda y conviene saberlo. Cuesta
además **dos derivaciones Argon2id**: una para abrir la bóveda y otra para la
envoltura propia de la copia.

Y las mismas dos reglas que en el papel: **comprobar es lo que se hace por
defecto** y no toca ningún archivo, y **restaurar se niega a escribir sobre una
bóveda que ya existe**.

### Recuperación: tres caminos, y uno que se descartó

| Método | Cuándo | Qué hace falta |
|---|---|---|
| **Hoja de papel** | pérdida de la frase | una hoja, en un sitio seguro |
| **Reparto k-de-n** | no querer depender de un solo papel; herencia | `k` de `n` custodios |
| **Sobre a un destinatario** | dejarlo en manos de un tercero | su clave privada |

Y las dos operaciones que hacen que un respaldo sea algo en lo que confiar:

```bash
# Comprobar que la hoja del cajón SIGUE sirviendo. No toca la bóveda.
cargo run --release --example recuperar_boveda -- boveda.chuspa palabras

# Recuperar de verdad: abre con el respaldo y fija una frase nueva.
CHUSPA_NUEVA_FRASE='...' cargo run --release --example recuperar_boveda -- boveda.chuspa fragmentos f1.txt f2.txt f3.txt
```

**Comprobar es lo que hace por defecto**, y recuperar hay que pedirlo aparte:
recuperar sobrescribe el acceso, y eso no puede ser lo que ocurre cuando alguien
ejecuta el comando solo para ver si su respaldo sigue bien. Una copia de
seguridad que nunca se ha probado no es una copia: es una suposición, y se
descubre falsa el día que hace falta.

**Si un respaldo se pierde de vista**, cambiar la frase no lo invalida —la clave
maestra es la misma, y eso es justo lo que hace que el papel no caduque—. Para
eso está `rotar_maestra()`: genera una clave nueva, recifra todo y deja sin
efecto cualquier hoja, fragmento o sobre anterior. Es la operación cara, y ocurre
una vez y por un motivo grave.

**Reparto (Shamir k-de-n).** Una hoja falla de dos formas opuestas: que se
pierda, o que la encuentre quien no debe. Guardarla mejor empeora lo primero;
hacer copias empeora lo segundo. El reparto rompe la disyuntiva: cinco fragmentos
en cinco sitios, tres bastan. Pierdes dos sin consecuencias y quien robe dos no
obtiene **nada** — ni media clave, ni una pista. Es secreto perfecto, no
«difícil de romper». Cada fragmento lleva su propio Reed-Solomon, así que un
papel dañado se recupera solo sin ir a buscar a otro custodio.

```bash
CHUSPA_FRASE='...' cargo run --release --example repartir_clave -- boveda.chuspa 3 5
```

**Sobre a un destinatario.** La clave cifrada hacia la clave pública de alguien
—tu abogado, tu pareja, otro equipo tuyo— con X25519 + ML-KEM-1024. Puede viajar
por correo, por WhatsApp o impreso: **ninguno de esos canales puede abrirlo**. Y
sigue cerrado cuando existan ordenadores cuánticos, que es lo que se le pide a
algo que puede tardar veinte años en abrirse.

#### Por qué NO hay recuperación por correo electrónico

Es lo primero que se pide y no se sostiene:

1. **Es circular.** La contraseña del correo está *dentro* del gestor. El día que
   necesitas la recuperación, tampoco puedes entrar al correo. Y si la cuenta se
   recupera por SMS, quien custodia tus credenciales pasa a ser tu operadora.
2. **Chuspa es offline.** No hay servidor que envíe nada, y ponerlo cambia el
   producto.
3. Si el correo llevara la clave, la bóveda viviría en los servidores de tu
   proveedor. Si llevara un enlace a un servidor con material recuperable, **ese
   servidor podría abrir tu bóveda** — el diseño que le costó a LastPass la
   brecha de 2022.

Lo que sí puede hacer el correo es **transportar un sobre que no puede abrir**.
Eso está implementado; lo otro no lo va a estar.

### Memoria: por qué no se fija con `mlock`

KeePassXC llama a `mlock` para que sus secretos no se paginen al disco. Se evaluó
hacerlo con una dependencia que encapsule el `unsafe` y **se descartó**:

- `mlock` protege solo de la paginación. No impide leer la memoria con `ptrace`,
  por `/proc/pid/mem`, ni que un volcado de core la escriba entera.
- La respuesta correcta a la paginación no es fijar páginas: es no tener
  intercambio sin cifrar. Un swap cifrado protege la clave *y* todo lo demás —el
  portapapeles, el búfer del navegador, la contraseña a medio teclear—.

Lo que sí faltaba era **saber si el riesgo existe**, y eso no se supone:
`memoria::paginacion()` lo comprueba y avisa. Un dispositivo `dm-crypt` cuenta
como cifrado; un volumen LVM **no** (es `dm` y no cifra nada); un archivo de
intercambio queda como *no se sabe* en vez de darse por bueno. En el equipo donde
se desarrolla esto no hay intercambio activo, así que hoy `mlock` no compraría
nada. Si eso cambia, la decisión se revisa con este razonamiento delante.

### Lo que la bóveda NO protege

- **La memoria del proceso.** Una entrada abierta está en claro en RAM. No se
  puede fijar en memoria física (`mlock`) sin `unsafe`, y este crate lo prohíbe:
  si el equipo tiene swap, que esté cifrado.
- **El tamaño.** El archivo revela cuántas entradas hay y cómo de grande es cada
  una. No hay relleno.
- **`repreguntar`.** Es una barrera de la interfaz, no criptográfica: la clave
  maestra ya está en memoria mientras la bóveda esté abierta.
- **Un equipo ya desbloqueado.** Nada de esto ayuda ahí.

## Segundo factor y passkeys

**TOTP (códigos de seis dígitos)**: implementado según el RFC 6238 y comprobado
contra los 18 vectores del apéndice B del estándar, no contra sí mismo. Se
guarda pegando la URI `otpauth://` o el secreto a pelo, y la extensión entrega
el código ya calculado. Un secreto que no se entiende **se rechaza al guardarlo**,
no al usarlo: descubrir que no sale el código el día que hace falta entrar es
tarde.

Ese mismo diseño abrió un agujero que costó encontrar. El detalle devuelve el
**código**, no el secreto —pegar el código en esa casilla destruiría el segundo
factor—, así que la ventana no puede devolver lo que nunca recibió y mandaba el
campo vacío al guardar. Y vacío valía como «bórralo»: **corregir el nombre de una
entrada le destruía el segundo factor**, sin un error, sin nada raro a la vista,
y sin que se notara hasta el día de entrar. La casilla de la ventana ya prometía
lo correcto —«se deja vacío si no quieres cambiar el que ya tiene»— y era el
único sitio donde esa regla estaba escrita.

Ahora se distinguen las dos cosas, que es lo que el campo ya sabía decir y nadie
escuchaba: **ausente o `null` no se toca**; **`""` lo quita**, y eso se pide con
una casilla, no dejando un campo en blanco. La prueba se cae en las dos
direcciones: con el fallo de antes y con la sobrecorrección de conservarlo
siempre, que dejaría el segundo factor imposible de eliminar.

**Passkeys (llaves de acceso)**: se importan íntegras y **ya sirven para entrar**.
La extensión sustituye `navigator.credentials.get()`, la aplicación firma el reto
del sitio con la clave guardada y devuelve la aserción. Solo ECDSA P-256, que es
lo que usan las passkeys de Bitwarden —comprobado sobre las 19 reales— y la
inmensa mayoría de los sitios.

La prueba que lo sostiene no comprueba que el código sea consistente consigo
mismo: **verifica la firma con la clave pública**, que es lo que hará el servidor
del sitio.

Aquí decía *«si esa prueba pasa, el sitio la acepta»*, y **era falso**. Se cayó
el 2026-08-10 contra npm: la firma verificaba impecablemente y el servidor
contestaba «Something went wrong». Lo que faltaba no era criptografía sino el
**contador de firmas**, que es la otra mitad de una aserción — y verificar la
firma no dice nada de él, por construcción.

**El contador sube y se guarda en la bóveda.** El sitio recuerda el último
número que recibió y rechaza toda aserción que no lo supere: es su detector de
autenticadores clonados (WebAuthn §7.2). Chuspa calculaba `guardado + 1` y no
lo escribía en ninguna parte, así que todas las firmas de una misma passkey
llevaban el MISMO número: la primera entraba y todas las siguientes eran, para
el servidor, la copia de una llave robada. No daba error por ningún lado —la
bitácora decía «firma autorizada»— y solo se notaba en los sitios que de verdad
comprueban el contador, lo que lo disfrazaba de problema de ESE sitio.

Si el contador no se puede guardar, la aserción **no se entrega**: firmar sin
poder anotarlo es fabricar el mismo fallo, entrando hoy y dejando la cuenta sin
passkey mañana. Lo vigilan `dos_firmas_seguidas_no_llevan_el_mismo_contador`
—que lee el número del `authenticatorData` que sale hacia el navegador, no del
campo de la bóveda, y relee el archivo del disco— y su pareja
`firmar_no_toca_las_otras_passkeys_ni_el_resto_de_la_entrada`, porque anotar un
número reescribe la entrada entera y eso en este repositorio ya se ha llevado
por delante tres campos distintos.

Lo que hace que esto no sea un agujero de phishing es de dónde sale el origen:
lo pone **el navegador** (`sender.url` en el script de fondo), nunca la página. Un
sitio falso pidiendo una firma para tu banco recibe un rechazo — hay pruebas con
cuatro impostores distintos, incluido `banco.example@evil.test`. Tampoco se firma
por `http`, ni con una passkey registrada para otro dominio.

Si no hay passkey guardada para el sitio, la llamada sigue al navegador: nunca se
deja al usuario sin poder entrar por tener Chuspa instalado.

Falta **registrar** passkeys nuevas (`create()`). Las 19 que hay vienen de
Bitwarden y lo que hacía falta era poder usarlas.

## Guardar una cuenta nueva desde el navegador

Hasta ahora los secretos viajaban en **una sola dirección** —aplicación →
navegador— y el protocolo no tenía forma de meter nada en la bóveda: hay una
prueba, `no_existe_una_peticion_para_abrir_la_boveda`, que existe justo para eso.
Poder guardar abre el canal de vuelta, y el navegador es el proceso que un
atacante alcanza primero. Así que el canal se abrió partido en dos, según **de
dónde venga el dato**:

| Botón del popup | De dónde sale la contraseña | Qué pasa |
|---|---|---|
| **Crear contraseña y guardar** | la genera la aplicación | se guarda en el acto y se escribe en el formulario |
| **Guardar la que escribí** | la tecleaste en la página | queda **propuesta**; no se escribe nada hasta que la apruebas en la ventana |

La regla no es quién pulsa el botón —pulsas tú las dos veces— sino quién puso el
dato. En el primer caso el secreto **nace en la aplicación** y el navegador no
aporta nada que haya que creerse: lo peor que consigue un navegador comprometido
pidiendo esto son entradas nuevas con contraseñas que no abren nada. En el
segundo, el contenido lo pone una página, que es hostil por definición; sin el
paso de aprobación, visitar un sitio bastaría para meter entradas en la bóveda
—o para **pisar la contraseña del banco con otra**, que es un secuestro de cuenta
que no da ni un error—.

La ventana enseña qué se va a guardar, para qué sitio y encima de qué. Si ya
tienes credenciales para esa página aparecen para poder **actualizar** una en vez
de acabar con dos entradas iguales y sin saber cuál vale; y solo se puede
actualizar una de las ofrecidas, porque aceptar cualquier índice sería cambiarle
la contraseña al banco desde una tienda. La propuesta caduca a los cinco minutos:
mientras dura hay una contraseña en claro en memoria que nadie pidió guardar.

La respuesta que vuelve al navegador **no dice si el sitio ya estaba guardado**.
Decirlo convertiría esto en un oráculo: bastaría proponer una contraseña
cualquiera en cada dominio para averiguar dónde tienes cuenta.

Al actualizar, la contraseña anterior **no se tira**: pasa al historial con la
fecha en que dejó de servir. Perder la de ayer por corregir la de hoy no da
ningún error, y solo se descubre el día que hace falta la vieja.

### Chrome y Brave

La extensión es **la misma** para Firefox y para los navegadores de la familia
Chrome. Lo único que no se puede fundir es el manifiesto: Chrome exige
`background.service_worker` y Firefox exige `background.scripts`. De ahí
`manifest.chrome.json`, y una prueba —`los_dos_manifiestos_no_se_separan`— que
compara **todo lo demás** campo a campo sobre lo que hay, no contra una lista
esperada, porque una lista escrita a mano de algo que crece se queda vieja: es
exactamente la forma del fallo que ya mató las llaves de acceso una vez.

Dos diferencias de la API que no dan error cuando fallan:

- `browser` no existe en Chrome. Cada archivo que use la API pasa por
  `globalThis.browser ?? globalThis.chrome`; hacerlo en uno y olvidarlo en otro
  deja media extensión muerta en un navegador.
- Un escuchador `onMessage` **async que devuelve la promesa**. Se escribió aquí
  que Chrome lo ignora, y **al medirlo resultó falso**: en Brave 151 funciona
  igual (ver la tabla del banco). Lo que sostiene usar `sendResponse` y
  `return true` es que el manifiesto declara `minimum_chrome_version: 111`, y en
  el Chromium de entonces la promesa no se atendía. La forma con `sendResponse`
  vale en los dos navegadores y en todas las versiones que el manifiesto admite;
  la otra vale en la que uno tenga hoy delante.

Y una advertencia sobre cómo se mide esto, que costó una conclusión al revés:
**dos corridas seguidas contra el mismo `--user-data-dir` no recargan la
extensión**. La segunda le pasa la URL a la instancia que ya corre, con la
extensión anterior cargada, así que el «veneno» sale verde porque lo contesta el
proceso viejo. Perfil nuevo en cada corrida.

El identificador de la extensión es **fijo**, porque el manifiesto lleva su clave
pública: sin ella Chrome lo derivaría del camino en disco y mover la carpeta lo
cambiaría en silencio, dejando al puente sin autorizar a nadie. La clave privada
que lo genera **no está en el repositorio** (vive en `~/.chuspa-extension-chrome.pem`)
y solo hace falta para firmar un `.crx`; para cargar la extensión no se usa.

Y **no se firma todavía, a propósito** (decisión del 2026-08-03): se sigue
cargando descomprimida hasta que eso deje de servir —que Brave lo desactive
solo, o que el aviso de modo de desarrollador pase de molesto a bloqueante—, y
ese día se firma el `.crx` con la clave de arriba. El identificador no cambiará,
porque sale de la clave pública que el manifiesto ya lleva. Se escribe aquí para
que no se vuelva a proponer como si fuera un descuido: es una decisión con su
condición de salida, no un pendiente olvidado.

```bash
bash empaque/instalar-extension-chrome.sh "$PWD/target/release/chuspa-puente"
# arma target/extension-chrome/ y registra el puente en Brave, Chrome y Chromium
# → brave://extensions → Modo de desarrollador → Cargar descomprimida
```

**Esa carpeta no se actualiza sola, y el navegador no vuelve a preguntar.** Se
carga descomprimida una vez y se queda ahí; cambiar `extension/` en el
repositorio no mueve nada hasta que se rearma. El 2026-08-03 llevaba un día
atrasada —manifiesto en `0.2.5` con el programa en `0.2.9`, y sin el arreglo del
aviso en pestañas que no son páginas web—, sin un solo error por ninguna parte.
Es la misma trampa del paquete instalado, en otro artefacto: lo vigila
`tests/lo_que_brave_tiene_cargado_no_se_queda_atras.rs`, que compara archivo a
archivo y exige que el manifiesto armado lleve la versión del programa. Que la
carpeta **no exista** no es fallo —no hay nada cargado en ningún navegador—; lo
que no se admite es que exista y desmienta al repositorio.

Y ojo con **qué puente queda en juego**: hay dos manifiestos posibles, el del RPM
en `/etc/brave/native-messaging-hosts/` apuntando a `/usr/bin/chuspa-puente`, y
el que escribe este guion en `~/.config/…/NativeMessagingHosts/` apuntando a
donde se le diga. El puente solo transporta bytes; desde 0.3.0 el protocolo se
reduce a `Estado`/`Bloquear`/`Autenticar` (los mensajes de contraseña del viejo
autofill —`Buscar`/`Credencial`/`Generar`/`Proponer`— se retiraron), así que un
mensaje que no sea uno de esos tres no deserializa y el agente contesta error.

### La llave puede pedirse desde un marco anidado

`all_frames` es **false** por defecto: los content scripts solo corren en el marco
principal. Si el sitio pide la llave desde un iframe suyo —como hace Google—, ahí
no hay nadie que intercepte y el navegador acaba pidiendo una llave física.

Encenderlo sin más abriría una puerta: un iframe de un tercero solo puede usar
WebAuthn si la página que lo aloja se lo permite con `Permissions-Policy:
publickey-credentials-get`, y esa comprobación la hace el navegador.
Interceptarla se la saltaría, y un anuncio incrustado pediría firmas que el
navegador le habría negado. Por eso la extensión **se retira en los marcos de
otro origen**: leer el origen del marco de arriba lanza justo cuando es ajeno, y
ante la duda se devuelve la llamada al navegador, que aplica la política de
verdad en vez de imitarla.

Medido en Firefox real, contando consultas al agente desde dentro del iframe:

| Caso | script presente | consulta al agente |
|---|---|---|
| sin `all_frames`, iframe propio | **no** | 0 — la llave no se ofrecía |
| con `all_frames`, iframe propio | sí | **1** |
| con `all_frames`, iframe **ajeno** | sí | **0** |

La tercera fila es la que evita que el arreglo se convierta en un agujero, y
`tests/las_llaves_llegan_a_los_marcos.rs` comprueba que las dos mitades siguen
puestas: quitar cualquiera de las dos pone la suite roja.

### La petición que el sitio hace al cargar no se toca

Con `mediation: "conditional"` un sitio **no está pidiendo entrar**: prepara el
autocompletado, y lo hace nada más cargar la página. Atender esas peticiones era
lo que hacía que Gmail entrara **solo**, con la primera cuenta, sin que nadie
hubiera pulsado nada.

Ofrecerlas como es debido exige integrarse con el autocompletado del navegador,
que una extensión no puede hacer; así que se devuelven enteras en vez de
atenderlas a medias.

Medido en Firefox 153 con [`extension/banco/`](extension/banco/), contando
cuántas veces la extensión consulta al agente:

| Versión | condicional (al cargar) | explícita (al pulsar) |
|---|---|---|
| sin el filtro | **1 consulta** — firmaba sin que nadie pidiera nada | 1 |
| con el filtro | **0** | 1 |

### Una petición lenta no puede dejar al resto en cola

Desde que una firma espera el visto bueno del usuario, esa petición se queda
hasta minuto y medio en el aire. El agente atendía las conexiones **de una en
una**, así que eso congelaba todo: el complemento decía «Consultando…» para
siempre mientras la aplicación respondía perfectamente si se le hablaba por su
socket. No estaba rota — estaba en cola.

Va un hilo por conexión, con tope de 32 a la vez. Y no bastaba con eso: el primer
intento compartía el agente tras un candado que **se llevaba consigo la espera**,
con lo que los hilos no servían de nada. Lo que hacía falta era que la
exclusividad durara lo que dura tocar el estado, no lo que dura la petición.

Lo comprueban `tests/una_firma_lenta_no_congela_el_resto.rs`, que habla por el
socket de verdad con dos clientes y un plazo —sin plazo, una regresión aquí no se
ve como un rojo sino como una prueba que no termina— y una simulación de **120
peticiones desde 12 hilos** con la firma bloqueada todo el rato.

### El enlace se cierra por inactividad, y la inactividad es la tuya

El enlace con el navegador se cierra solo a las **12 horas sin señales de que
haya alguien delante**. La bóveda no se toca: sigue abierta en la ventana. Lo que
caduca es que el navegador pueda pedir una firma de passkey. Fueron 15 minutos
hasta 0.3.0: con el agente reducido a solo passkeys —que además exigen aprobación
por uso en la ventana— el plazo dejó de ser la barrera contra la exfiltración
(ya no hay contraseñas que servir) y 15 min solo cortaban el login legítimo en
silencio durante la navegación normal.

La parte que costó una tarde es **qué cuenta como estar delante**. La primera
versión miraba solo las peticiones del navegador, y con eso el plazo medía otra
cosa que la que decía: una mañana entera trabajando en la ventana —con la bóveda
abierta y 598 entradas en pantalla— era «inactividad» para el agente. Firefox y
Brave contestaban lo mismo: *«La bóveda está cerrada. Ábrela desde la
aplicación.»* Un consejo imposible de seguir, porque ya estaba abierta.

Y no se recuperaba. La comprobación del plazo cortaba **antes** de refrescar el
reloj, así que ninguna petición del navegador podía revivirlo: una vez vencido,
la única salida era reiniciar la aplicación, y nada lo decía. Se veía como una
extensión rota.

Ahora el reloj es **uno solo y vive en la aplicación**, compartido por la ventana
y el agente, porque las dos mitades son la misma persona usando el programa. Se
sella al teclear la frase, al mirar la lista, al editar, al generar, al decidir
una firma — y al usar el complemento. Se puede volver: si el plazo venció, basta
con volver a la ventana.

Lo que **no** cuenta es el sondeo. La interfaz pregunta cada segundo si hay una
firma esperando (`GET /api/firma`), y si eso contara el plazo no vencería nunca:
quedaría una defensa que solo lo parece —el
mismo patrón que el testigo de sesión que ya nadie miraba—. Por eso
`gui::es_de_una_persona` **enumera lo que sí significa presencia** y manda todo
lo demás a *no se puede saber*. Escrito al revés —«todo cuenta salvo el
sondeo»— el día que se añadiera un sondeo nuevo el plazo dejaría de vencer sin
que nada se pusiera rojo.

Y cuando no se atiende, se dice **por qué**: la respuesta lleva `razon`
—`sin_boveda` o `inactividad`—, que es lo único que distingue «teclea la frase»
de «vuelve a la ventana». No revela nada del contenido: cuántas entradas hay
sigue siendo `null` mientras esté cerrado.

Lo vigilan cinco pruebas en `src/navegador/mod.rs`, y las dos que importan son
las que tiran de lados opuestos: `trabajar_en_la_ventana_mantiene_vivo_el_enlace`
(el fallo) y `el_sondeo_de_la_ventana_no_cuenta_como_presencia` (la
sobrecorrección). Quitar el sellado desde la ventana tumba dos; hacer que el
sondeo cuente tumba la otra.

### Nadie firma sin que tú lo autorices

Antes, la aplicación firmaba **en cuanto se lo pedían**. Con la bóveda abierta,
cualquier página que visitaras podía llamar a `navigator.credentials.get()` y
llevarse una aserción válida en silencio: la passkey se comportaba como una
cookie, y entrar en un sitio bastaba para quedar autenticado ante él. La aserción
además afirmaba en sus banderas que el usuario había estado presente y había sido
verificado, cuando nadie había tocado nada.

Ahora cada firma pasa por la ventana: se ve **el origen que puso el navegador**
—no el `rpId` que dice la página—, y hay que autorizarla. Las banderas de
presencia y verificación pasan a ser ciertas: hubo un clic, y la bóveda se abrió
con la frase de paso.

De paso se arregla lo que se veía en Gmail. La aplicación recogía la **primera**
passkey del sitio y firmaba con ella, así que con dos cuentas de Google se
entraba siempre con la misma sin poder elegir. Ahora se ofrecen todas.

La petición caduca a los 90 segundos, y la decisión lleva el identificador de la
petición: sin él, una respuesta que llegara tarde autorizaría la **siguiente**
firma — una que nadie llegó a mirar.

Lo comprueba `tests/la_firma_pide_permiso.rs`, que cruza los dos lados de verdad
—un hilo pide la firma, otro hace de ventana y decide—. Devolviendo el
comportamiento anterior, 4 de sus 5 pruebas se caen; la quinta sobrevive porque
es la que comprueba que un sitio **sin** passkey no llega a molestar al usuario,
y esa no depende del permiso.

#### Y la ventana se anuncia sola

Pedir permiso en la aplicación tiene un precio: **el usuario no la está
mirando**. Está en el sitio donde quiere entrar, y si la ventana quedó detrás
del navegador la espera se ve igual que un fallo — la página dice «verificando»
y nada indica que hay algo que pulsar a dos ventanas de distancia.

Así que al llegar una firma la ventana pide paso: `set_focus` para el caso
fácil, y `request_user_attention` para cuando el escritorio se niega a robarle
el foco al programa que estás usando —que hace bien—, y entonces parpadea en la
barra de tareas. Lo que la prueba fija es que **el aviso sale**, no que el
gestor de ventanas obedezca: eso no depende de este programa y medirlo sería
fingir. Y sale **solo cuando hay algo que autorizar**: un sitio del que no
tenemos ninguna llave no avisa, porque un aviso que resulta vacío dos veces es
un aviso que a la tercera nadie mira.

En el diálogo, la acción afirmativa es pulsar la cuenta. Antes eso no lo decía
nada —el único elemento con aspecto de botón decía «No autorizar»—, así que
ahora se pide de forma explícita y la fila lleva borde propio: lo que hay que
pulsar tiene que parecer pulsable.

### Los dos mundos de la extensión no se hablan con eventos

Firefox aísla el content script de la página con visión X-ray: **un objeto creado
en el content script no es legible desde la página**. Con un `CustomEvent`, la
página recibía el evento y su `detail` le llegaba inaccesible; la promesa no
resolvía, vencía el plazo, y la llamada caía al camino del navegador.

El síntoma no se parecía a la causa: Firefox pedía una **llave de seguridad
física** teniendo la passkey correcta guardada, la extensión inyectada y la
aplicación firmando perfectamente si se le hablaba por su socket. Hubo que
descartar antes la CSP del sitio, el permiso de host, la versión instalada y el
formato del identificador.

Se arregla con `window.postMessage`, que clona estructuralmente y funciona igual
en los dos navegadores sin una línea por plataforma — en vez de envolver cada
objeto con el `cloneInto` que receta Mozilla.

Que la página vea esos mensajes no le sirve de nada: falsificar una respuesta es
fabricarse una credencial a sí misma, y falsificar una petición no le da alcance
porque **el origen lo pone el script de fondo** desde `sender.url` y no viaja en
el mensaje.

Medido en Firefox 153, mismo agente y misma página, cada versión con el protocolo
que entiende:

| Versión | ¿se inyecta? | ¿contesta el puente? |
|---|---|---|
| `CustomEvent` | sí | **no** — «sin respuesta en 6 s» |
| `postMessage` | sí | **sí** |

El banco que lo mide está en [`extension/banco/`](extension/banco/) y ejercita la
cadena entera en un Firefox real. `tests/el_puente_no_cruza_mundos_con_eventos.rs`
impide que el patrón vuelva a entrar.

### Hay que conceder un permiso a mano, y si no se hace no se ve el fallo

En Manifest V3, Firefox trata los permisos de host como **opcionales**: aunque el
manifiesto los declare para los *content scripts*, hasta que el usuario los
concede esos scripts **no se inyectan**. Y lo demás —el popup, rellenar
contraseñas, el puente nativo— sigue funcionando, así que no hay ningún error a
la vista: el sitio pide la llave y se queda esperando para siempre.

Se concede en `about:addons` → Chuspa → Permisos → «Acceder a tus datos para
todos los sitios web». Desde la 0.2.1 el popup detecta que falta y ofrece
activarlo con un botón, en vez de callar. No se pide al instalar.

> **Desde 0.3.0 la extensión maneja SOLO llaves de acceso (passkeys).** El popup
> dejó de rellenar y guardar contraseñas —se retiró ese código y, con él, los
> permisos `activeTab` y `scripting`—: la extensión queda reducida a su papel
> resistente a phishing. Las contraseñas pasan a manejarse con el gestor nativo
> del navegador, y se traen a la bóveda con el importador («Sincronizar desde los
> navegadores»): Chromium (Brave/Chrome/Chromium/Edge) por `os_crypt` + llavero, y
> Firefox por NSS, en Rust puro.
> Y el **agente** también: se retiraron del protocolo los mensajes
> `Buscar`/`Credencial`/`Generar`/`Proponer` del viejo autofill, así que por el
> socket ya no sale ninguna contraseña —lo único que entrega un secreto es
> `Autenticar`, con aprobación por uso en la ventana—. Eso es lo que hace seguro
> que el enlace con el navegador aguante **12 h** de inactividad en vez de 15 min:
> una extensión comprometida ya no tiene a quién pedirle contraseñas.

### El identificador de la credencial viene en dos formas

Bitwarden guarda el `credentialId` como **UUID con guiones**; el navegador lo
manda como los 16 bytes crudos. Comparar una forma con la otra no casa nunca, y
el resultado es idéntico al anterior: la bóveda tiene la llave, el sitio la pide,
nadie responde. Se normaliza en `Passkey::de_entrada`, el único punto por el que
pasan todas — así las bóvedas ya creadas quedan arregladas sin reimportar.

La simulación sobre las 19 passkeys reales da **19 usables**; con la
normalización quitada da **0**, que es lo que la vuelve una prueba y no un
adorno.

## La ventana

Sigue el tema del escritorio. Estaba fijada en claro, así que con GNOME en
oscuro la aplicación era el único cuadro luminoso de la pantalla; ahora Material
recalcula toda su paleta según el sistema y en el CSS no queda ningún color
escrito a pelo — un `#666` se ve bien en claro y desaparece en oscuro, y ese
fallo no se nota hasta que alguien la abre de noche.

La lista pinta cada entrada con una inicial de color propio, derivada del nombre
y **estable**: una entrada tiene siempre el mismo color, así que se aprende
dónde está sin leerla.

La inicial no sale del nombre crudo sino de la parte que identifica al sitio:
`account.foxit.com` es Foxit, no «account». Sin eso, las 174 entradas que
empiezan por `www.` compartían letra —casi un tercio de la bóveda con el mismo
círculo—. Medido sobre las 595 reales, la letra más repetida baja **del 29 % al
11 %**. Las reglas viven en `interfaz/src/app/nombre.ts` con su banco al lado,
que corre dentro de `cargo test`.

### La CSP dejó la hoja de estilos «para imprimir»

Los iconos salían como su ligadura —«lock» donde va el candado, «sh» donde va el
escudo— y la causa no estaba ni en la fuente ni en el CSS. Angular optimiza con
**CSS crítico**: incrusta lo de arriba del todo en un `<style>` y carga el resto
con `<link media="print" onload="this.media='all'">`. Ese `onload` es un
manejador **en línea**, y la CSP de esta ventana no lleva `'unsafe-inline'` para
scripts, así que **no corre nunca**: la hoja se quedaba en `media="print"`,
aplicándose solo al imprimir.

Lo que lo hizo difícil es que no parece una página sin estilos. La parte crítica
va incrustada, así que la aplicación se ve bien; solo falta lo que el inlineador
no consideró crítico. Y las reglas seguían **en el CSSOM** —una hoja `print` se
parsea igual—, de modo que inspeccionarlas decía que todo estaba correcto
mientras `getComputedStyle` devolvía la fuente heredada.

Se arregla en la causa, `inlineCritical: false`, y no abriendo la CSP: esa
optimización existe para ahorrar un viaje de red, y aquí la hoja viaja **dentro
del binario**. Lo vigila
`gui::pruebas::la_hoja_de_estilos_no_se_carga_solo_para_imprimir`, que falla si
el `index.html` embebido vuelve a traer un `media="print"` o un `onload=`.

## Dos cosas del empaquetado que no dan error cuando fallan

**La interfaz tiene que llegar al ejecutable.** `rust-embed` mete
`interfaz/dist` dentro del binario y cargo no lo sabe: sin el
`rerun-if-changed` de `build.rs`, cargo ve el Rust intacto, no recompila, y el
ejecutable conserva la interfaz anterior. Pasó: un `ng build` falló dejando
`dist` a medias, el `cargo build` siguiente embebió eso, y el `ng build` bueno de
después ya no disparó nada. Se empaquetó un RPM sin fuentes ni iconos con todas
las pruebas en verde, porque miraban `dist` y no el ejecutable. Lo vigila
`tests/la_interfaz_llega_al_binario.rs`.

**El paquete tiene que llevar la extensión entera.** Los archivos estaban
enumerados uno a uno en `Cargo.toml` y la lista se quedó en los tres originales:
`fondo.js`, `passkeys.js` y `puente-passkeys.js` no viajaban, así que quien
instalara la extensión desde `/usr/share/chuspa/extension` tenía las llaves de
acceso muertas y ni un aviso. Ahora va por patrón, y
`tests/el_rpm_lleva_la_extension_entera.rs` comprueba que cubre todo lo que el
manifiesto declara necesitar.

## Cuando una llave no funciona: la bitácora

Cada pieza se puede comprobar por separado —la extensión está instalada, el
permiso concedido, la aplicación firma si se le habla por su socket— y aun así
el conjunto puede fallar. Lo que faltaba era saber **si la petición llega**, que
es lo que separa «el fallo está en el navegador» de «el fallo está aquí». Sin ese
dato solo quedan hipótesis, y se gastan de una en una.

```bash
pkill chuspa-gui
CHUSPA_BITACORA=/tmp/chuspa.log chuspa-gui &
# … abrir la bóveda e intentar entrar en el sitio …
cat /tmp/chuspa.log
```

Cada línea es una petición que llegó: `entra autenticar rp_id=… origen=…`,
`firma candidatas=2`, `firma autorizada` o `firma SIN AUTORIZAR`.

Desde el 2026-08-09 la bitácora cubre **las dos fronteras del programa**, no
solo la del navegador: las líneas que empiezan por `ventana` son lo que la
ventana pide y lo que se le contesta —`ventana POST /api/abrir cuerpo=59` y
`ventana POST /api/abrir -> 401 application/json`—. Dicen qué se pidió y cuánto
cuerpo traía; **nunca qué traía dentro**.

- **Si no aparece ninguna línea al intentar entrar**, la petición no llega: el
  fallo está entre el sitio y la extensión.
- **Si aparece `entra autenticar` y nada más**, la aplicación está esperando tu
  visto bueno. La ventana se anuncia sola al llegar la petición; si tu escritorio
  no la deja pasar al frente, la verás parpadeando en la barra de tareas.

No se enciende sola, y es deliberado: un gestor de contraseñas que apunte por su
cuenta a dónde entra su dueño sería otro problema, aunque no anote ni un secreto.
Y no los anota — `tests/la_bitacora_no_filtra.rs` falla al **escribir** una
anotación que mencione una clave, un reto o una frase, no al ejecutarla, así que
también cubre las líneas que se añadan mañana.

## Revisión de la bóveda

```bash
CHUSPA_FRASE='...' cargo run --release --example informe_salud -- boveda.chuspa
```

Todo **offline**. Los gestores comerciales consultan filtraciones a un servicio;
aquí se compara la bóveda consigo misma y se mide lo que se puede medir sin
ayuda. Se pierde la detección de filtraciones concretas y se gana no confiar en
nadie.

Ningún hallazgo es una categoría abierta — cada uno es una afirmación
comprobable: «está en 4 entradas más», «aunque fuera aleatoria tendría 47 bits»,
«es una secuencia de teclado». Y **nunca se dice que una contraseña es fuerte**:
la medida de entropía es una cota *superior*, así que sirve para descartar, no
para tranquilizar. `contraseñacontraseña` tiene 20 caracteres y no vale nada.

Sobre un export real de 595 entradas: 352 con algún problema, 285 con contraseña
repetida, 190 cortas, 154 recicladas del historial de otra entrada y 28 sitios
que aún usan `http`.

## Generar contraseñas

El detalle que casi todos hacen mal es `byte % alfabeto.len()`: con 62
caracteres, los ocho primeros salen un 25 % más. Aquí hay **muestreo por
rechazo**, y la prueba lo verifica con chi-cuadrado **validado contra un
generador sesgado a propósito** — un medidor que nunca ha visto un positivo es un
generador de ceros.

Las frases salen de la lista BIP-39 que ya viaja en el binario: 2 048 palabras
son 11 bits exactos por palabra, así que la entropía es una multiplicación y no
una estimación.

## Segundo factor

`src/totp.rs` implementa el RFC 6238 y se comprueba contra **los 18 vectores del
apéndice B del estándar**, no contra sí mismo. Antes de esto el enlace entregaba
el secreto `otpauth://` en el campo que decía «código ya calculado», y la
extensión lo habría escrito entero en la casilla de seis dígitos.

## La interfaz

```bash
chuspa-gui            # o desde el menú de GNOME
```

El HTML lo teje **el propio binario** con `maud` —macros de Rust, compiladas por
`rustc`— y htmx hace los intercambios parciales. Un solo ejecutable, sin
conexión, sin navegador y sin ningún puerto abierto. La frase de paso se teclea
aquí y no viaja por ninguna variable de entorno: las variables se heredan a todos
los procesos hijos.

**Desde el 2026-08-09 no hay Node en el build.** Antes era un binario **más** un
árbol de JavaScript que había que construir antes; ahora «un solo ejecutable» es
literal. El recuento de dependencias de frontal es **una** —htmx, MIT,
vendorizada dentro del binario— más código propio. El estado vive en el
servidor, que es donde ya vivía: la bóveda está en este proceso, y no hay un
segundo modelo de los datos en el navegador que pueda desincronizarse del
primero.

### Sin puerto, sin navegador

La primera versión servía la interfaz por HTTP en `127.0.0.1` y la abría con
`xdg-open`. Eso obligaba a tres capas de defensa —escuchar solo en loopback,
comprobar la cabecera `Host` contra *DNS rebinding*, y un testigo de sesión— y
aun así dejaba fuera lo peor: **las extensiones del navegador**. Una extensión
con permiso sobre todos los sitios puede leer el DOM de `http://127.0.0.1:*`, o
sea las contraseñas en pantalla.

Y eso contradecía el resto del proyecto: el enlace con Firefox existe justamente
para que la bóveda **no** pase por el navegador.

Ahora la interfaz vive en una ventana propia y se sirve por un **esquema
propio** (`chuspa://`) que solo resuelve el motor de esa ventana. Las tres capas
no se reforzaron: **desaparecieron**, porque desapareció lo que las hacía falta.

| | Antes | Ahora |
|---|:--:|:--:|
| Puertos abiertos | 1 | **0** — verificado con `ss -tlnp` |
| Las extensiones del navegador ven la bóveda | Sí | **No** |
| Testigo, `Host`, `Origin` | 3 capas | ninguna hace falta |
| Un proceso local sacaba el testigo pidiendo `/` | Sí | no hay testigo que sacar |

Se añade una cabecera `Content-Security-Policy` estricta y las herramientas de
desarrollo van desactivadas: en una ventana que muestra contraseñas,
«inspeccionar elemento» es una forma cómoda de dejarlas a la vista.

**Lo que sigue sin cubrirse**, y no lo cubre ninguna interfaz: un proceso local
con tu usuario. Puede leer el archivo de la bóveda, hacer `ptrace` al programa o
leer el portapapeles. Es una limitación del escritorio sin aislamiento, y se dice
en vez de fingir que se resuelve.

### El puente del cuerpo, y por qué la «ñ» rompía la ventana

Quitar el puerto tuvo un precio que se cobró tarde. **WebKitGTK no entrega el
cuerpo de un `POST` cuando la petición va a un esquema propio**: llega con cero
bytes. La ventana lo resuelve pasando el cuerpo a la cabecera `X-Chuspa-Cuerpo`
—nada de esto sale del proceso, no hay red por medio—.

Lo que no estaba visto: **`setRequestHeader` lanza `TypeError` con cualquier byte
≥ 0x80**, y `JSON.stringify` no escapa lo que no es ASCII. O sea que hasta el
2026-08-09, en un gestor de contraseñas pensado para usarse en castellano:

- una frase de paso con **ñ** o una tilde no abría la bóveda,
- una entrada con acentos no se guardaba,
- una ruta como `~/Imágenes/copia.chuspa` no servía para la copia,

y **el error no hablaba nunca de la causa** — la petición moría dentro de la
ventana, o llegaba al otro lado percent-encoded y contestaba «petición mal
formada». Corregido el 2026-08-09 escapando a `\uXXXX`, que es JSON válido y
ASCII puro: el lado Rust lo decodifica sin cambiar nada.

Se midió dibujando la ventana de verdad (`examples/ventana_de_prueba.rs`), con
su control al lado: el mismo `POST` a la misma ruta, con puente y sin él,
contestando 401 y 400. Lo vigila
`tests/el_puente_del_cuerpo_escapa_lo_que_no_es_ascii.rs`, que corre los bancos
de las dos implementaciones del puente y comprueba el escapado **en el paquete
compilado**, no en el fuente.

### Un solo proceso

El enlace con Firefox vive **dentro de la aplicación**. Al principio eran dos
programas —la ventana y un agente aparte— y no podían funcionar a la vez: el
cerrojo del archivo impide abrir la misma bóveda dos veces, así que uno de los
dos siempre se quedaba fuera y la extensión decía «no se pudo hablar con la
aplicación». Era cierto: la aplicación con la que hablaba no era la que el
usuario tenía delante.

Ahora la ventana atiende el socket. Si la bóveda está cerrada, la extensión
recibe «cerrada» — y no puede abrirla, eso solo pasa tecleando la frase en la
ventana.

## La extensión pasa el filtro de Mozilla

```
errors 0 · notices 0
```

Comprobado con `addons-linter`, el validador oficial de AMO. Manifest V3, sin
código dinámico —desde 0.3.0 ni siquiera `scripting`: la extensión solo usa
`nativeMessaging`—, sin `innerHTML`, sin red, sin almacenamiento, y con
`data_collection_permissions` declarado como `none`. El único aviso que queda es que Firefox para Android no
admite la versión mínima, lo cual es correcto: *native messaging* no existe en
Android.

## Instalar

**Debian y Ubuntu (`.deb`):**

```bash
cargo build --release && cargo deb
sudo apt install ./target/debian/chuspa_*_amd64.deb   # resuelve las libs de GTK4
```

**openSUSE Tumbleweed y Fedora (`.rpm`):**

```bash
cargo build --release && cargo generate-rpm
sudo dnf install ./target/generate-rpm/chuspa-*.x86_64.rpm   # resuelve las libs de GTK4
```

`dnf install ./…` y NO `rpm -Uvh`: el `.rpm` declara sus dependencias de GTK4
(`libgtk-4.so.1`, `libglib-2.0`, `libcairo`…, auto-detectadas del ELF), y `dnf`
las resuelve e instala; `rpm -Uvh` falla en una máquina sin el runtime de GTK4
listando todas las libs. Verificado en Fedora 44 el 2026-10-12 (chuspa 0.5.0).

Ya no hay paso de `npm`: desde la migración a GTK (y antes a `maud`+htmx) la
interfaz la compila `rustc` y va DENTRO del binario. Los dos paquetes son gemelos
declarativos —`[package.metadata.deb]` y `[package.metadata.generate-rpm]` en
`Cargo.toml`— y ambos instalan lo mismo en una sola orden: la aplicación
`chuspa-gtk`, el puente `chuspa-puente`, sus manifiestos de *native messaging* y
la extensión. `apt install ./…` sobre el `.deb` resuelve solo las bibliotecas de
GTK4 (`Depends: $auto`).

El número de versión no se escribe aquí a propósito: envejece, y una orden que
nombra un paquete que ya no existe se copia igual y falla. Sale de `Cargo.toml`.

### En Windows

El frontal de escritorio en Windows es **`chuspa-egui`** (migración a egui,
2026-10-04): un solo `.exe`, sin runtime de GTK que empaquetar. Se construye con
`cargo build --release --no-default-features --features egui-ui` (`egui-ui` es la
única feature que compila en Windows). **`chuspa-gtk` es el frontal de Linux y
el `default`** (feature `gtk-ui`): en la máquina Linux un `cargo build` pelado da
el producto Linux, y el `.exe` de Windows se pide explícito con la línea de
arriba. El reparto es permanente —un frontal por plataforma—, no una fase de
transición (decisión de Juan, 2026-10-11).

El puente para el navegador se registra con un script, porque en Windows el
navegador no lee un directorio de manifiestos sino una **clave del registro**:

```powershell
empaque\instalar-puente.ps1 -Puente target\release\chuspa-puente.exe
```

Escribe el manifiesto en `%LOCALAPPDATA%\chuspa\` y apunta a él las claves de
`HKCU` de Firefox (`Software\Mozilla\…`), Chrome (`Software\Google\Chrome\…`) y
Brave (`Software\BraveSoftware\Brave-Browser\…`) — cada navegador Chromium lee su
propia rama. Todo por-usuario, sin administrador. `desinstalar-puente.ps1` lo
revierte.

El enlace agente↔puente usa un socket de dominio Unix en Linux
(`std::os::unix::net`, archivo `0600` en un directorio `0700`) y un **named pipe**
en Windows (`\\.\pipe\chuspa.<hash de la ruta>`), este por el crate propio
`chuspa-ipc-win`. El `unsafe` del FFI Win32 vive AISLADO en ese crate, así que el
núcleo conserva `unsafe_code = "forbid"`. El aislamiento del pipe es la paridad
con el `0600`/`0700` de Linux y es de TRES piezas (concilio 2026-10-10): la DACL
de cada instancia concede solo al usuario dueño + SYSTEM + Administradores (nadie
más lee el contenido); `FILE_FLAG_FIRST_PIPE_INSTANCE` hace que el agente DETECTE
si otro proceso ocupó el nombre antes (el nombre es público y adivinable, no da
exclusividad por sí solo); y el cliente verifica que el SID dueño del proceso
servidor es el suyo antes de hablarle (anti-suplantación), abriendo además con
`SECURITY_IDENTIFICATION` para que el servidor no pueda impersonarlo. El
transporte está medido en Windows (`ipc-win` 7 pruebas + `tests/enlace_navegador.rs`);
el flujo completo de passkeys en un navegador real en Windows se valida a mano (no
hay forma de automatizar el gesto de WebAuthn).

### Qué versión hay instalada de verdad

```bash
chuspa-gtk --version      # chuspa-gtk 0.5.0 (<commit>)   — frontal Linux
chuspa-egui --version     # chuspa-egui 0.5.0 (<commit>)  — frontal Windows
chuspa-puente --version   # va en el mismo paquete que la app (.deb y .rpm)
```

El commit va porque **el número de versión no basta**. El 2026-08-03 el paquete
instalado se llamaba `0.2.9` y le faltaban los tres últimos commits —guardar
desde el navegador, el arreglo de Brave y el que impedía que editar una entrada
le destruyera el TOTP—: se había construido antes que ellos y nadie subió el
número. Misma versión, distinto contenido, y ninguna forma de notarlo desde la
máquina donde estaba instalado; las pruebas seguían verdes porque miran el árbol
de trabajo, no lo instalado.

El sello lo pone `build.rs` en cada compilación, y dice la verdad completa: un
árbol con cambios sin commitear produce `422383b-sucio`, y compilar fuera de un
repositorio produce `sin-git` — que es «no se puede saber», no un hash
inventado. Lo vigila `tests/el_binario_dice_de_que_commit_sale.rs`, que arranca
el ejecutable de verdad y compara el sello contra `git rev-parse HEAD`.

**En el RPM** el manifiesto del puente se instala en **dos rutas**
(`/usr/lib/mozilla` y `/usr/lib64/mozilla`) porque Firefox lo busca junto a donde
está instalado: la documentación de Mozilla dice la primera, pero en openSUSE y
Fedora el navegador vive en `/usr/lib64/firefox` y mira la segunda. Con una sola,
la extensión dice «no se pudo hablar con la aplicación» aunque todo lo demás
funcione. **En el `.deb` va en una sola** (`/usr/lib/mozilla`): Debian no tiene
`/usr/lib64`, y su Firefox mira ahí.

Si tu distribución usa otra ruta, la de usuario funciona siempre:

```bash
mkdir -p ~/.mozilla/native-messaging-hosts
sudo cp /usr/lib/mozilla/native-messaging-hosts/com.xiliux.chuspa.json \
  ~/.mozilla/native-messaging-hosts/
```

Para Brave, Chrome y Chromium el paquete instala el manifiesto en `/etc/brave`,
`/etc/opt/chrome` y `/etc/chromium`, por lo mismo: ninguno mira las rutas de los
otros. Ahí la autorización va por `allowed_origins` con el identificador fijo de
la extensión, y una prueba comprueba que ese identificador no se ha separado de
la clave pública que lo produce — si se separan, el navegador dice «Access to the
specified native messaging host is forbidden» y no hay nada en el código que lo
explique.

Instala los dos binarios, los manifiestos del puente en las rutas del sistema
—con `allowed_extensions` (Firefox) y `allowed_origins` (Chrome) restringidos a
la extensión de Chuspa y a ninguna otra— y la extensión en
`/usr/share/chuspa/extension`. El binario tiene que ser de **release**: en debug
la bóveda tardaría 12 s en abrirse.

## Decisiones de diseño

**Native messaging, no un puerto en localhost.** Firefox arranca el proceso por
stdio; no hay puerto abierto, no hay CORS que configurar, y solo la extensión con
el identificador declarado puede hablar con el binario. Un servidor HTTP local
sería superficie de ataque a cambio de nada.

**Cifrado por entrada, no un blob monolítico.** La frase de paso deriva la clave
maestra una sola vez (Argon2id); cada entrada se abre con su propia subclave vía
HKDF. Desbloquear la bóveda no pone todas las contraseñas en claro en memoria.

**Lo post-cuántico está en la recuperación, no en el candado.** Una bóveda local
abierta con frase de paso es cifrado simétrico, que ya resiste al adversario
cuántico por sí solo. ML-KEM aporta al cifrar la bóveda también hacia una clave
pública de respaldo. Se dice aquí para que no acabe contado como otra cosa.

**Respaldo en papel.** La clave maestra se respalda con el módulo `papel` de
Quipu: BIP-39 más Reed-Solomon, en QR o en texto tecleable.

## Licencia

AGPL-3.0-or-later. Copyright (C) 2026 Juan Carlos Isaza. Ver `NOTICE`.
