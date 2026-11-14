// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! La bóveda cifrada: un archivo, cifrado **entrada por entrada**.
//!
//! # Por qué no un solo bloque cifrado
//!
//! Lo fácil sería cifrar toda la bóveda como un bloque. El problema es lo que
//! pasa al abrirla: las 595 contraseñas quedarían en claro en memoria durante
//! toda la sesión, cuando el usuario solo quería una. Un volcado de memoria, un
//! archivo de intercambio o un proceso con permisos se lo lleva todo. Es lo que
//! hacen casi todos los gestores.
//!
//! Aquí cada entrada tiene su **propia clave**, derivada de la maestra por HKDF
//! con el identificador de la entrada como etiqueta de dominio. Abrir la bóveda
//! descifra solo el índice; abrir una entrada descifra solo esa. (Única
//! excepción: migrar un índice de una versión ANTERIOR descifra una vez sus
//! entradas para derivar el usuario de la lista; una bóveda ya guardada con esta
//! versión no lo hace.) Lo que no se pide nunca llega a estar en claro.
//!
//! # Cómo se ata todo junto
//!
//! El cifrado por entrada crea un problema nuevo: si cada bloque es
//! independiente, alguien con acceso al archivo podría reordenarlos, duplicar
//! uno, quitar otro o devolver una entrada a una versión anterior —con la
//! contraseña que ya rotaste—, y cada bloque seguiría descifrando
//! perfectamente porque su tag AEAD es válido. Es el fallo clásico de cifrar por
//! partes: cada parte es íntegra y el conjunto no.
//!
//! La pieza que lo cierra es una sola: **el índice guarda el hash de cada bloque
//! cifrado**, y el índice va cifrado con el contador de versión de la bóveda
//! dentro de su AAD. De ahí sale todo lo demás:
//!
//! - sustituir o revertir un bloque → su hash no cuadra con el del índice;
//! - reordenarlos → los hashes no cuadran en su posición;
//! - pegar un índice viejo sobre un archivo nuevo → el contador del AAD no
//!   coincide y el índice no descifra;
//! - trasplantar una entrada de otra bóveda → su AAD lleva el salt de la bóveda
//!   original y su identificador, así que no descifra aquí.
//!
//! Y como el AAD de las entradas NO lleva el contador, guardar un cambio solo
//! recifra el índice y las entradas tocadas. Lo demás se copia como bytes
//! opacos, sin necesidad de tenerlo descifrado.
//!
//! # Qué esconde el archivo
//!
//! Un archivo de bóveda no solo tiene que ocultar los secretos: su **forma**
//! también habla. Un formato con un bloque visible por entrada dice cuántas
//! credenciales tienes, y el tamaño de cada bloque dice cuál es la nota larga.
//!
//! Aquí el cuerpo es una masa opaca: los desplazamientos, las longitudes y los
//! nonces de cada entrada viven **dentro del índice cifrado**, no en claro. Y
//! tanto el índice como la masa llevan relleno Padmé, que cuantiza la longitud
//! con un sobrecoste acotado (~12%). De fuera se ve un archivo de un tamaño
//! redondeado y nada más.
//!
//! # El archivo llave
//!
//! Una frase de paso es lo que una persona puede recordar, y eso pone un techo a
//! su entropía. La [`Llave`] opcional es un secreto de alta entropía que se
//! guarda **aparte** —un USB, otra carpeta, otro dispositivo— y entra en la
//! derivación junto a la frase.
//!
//! Lo que cambia es el escenario realista de robo: la copia de seguridad que
//! acabó en la nube, el archivo en un disco extraviado, el adjunto de un correo.
//! Quien se lleve solo la bóveda no puede probar frases contra ella, porque le
//! falta un secreto de 256 bits que no está ahí. No protege contra quien copia
//! el equipo entero con la llave dentro; eso hay que decirlo, y por eso la
//! recomendación es que la llave viva en otro soporte.
//!
//! Es la idea del *key file* de KeePassXC y de la *Secret Key* de 1Password. No
//! se inventa nada: se implementa lo que funciona, y se combina con lo anterior.
//!
//! # Lo que esto NO protege
//!
//! Conviene decirlo sin adornos, porque un gestor de contraseñas invita a creer
//! que protege más de lo que puede:
//!
//! - **La memoria del proceso.** Una entrada abierta está en claro en RAM. No se
//!   puede fijar en memoria física (`mlock`) sin `unsafe`, y este crate lo
//!   prohíbe, así que puede acabar en el archivo de intercambio. Si el equipo
//!   tiene swap, que esté cifrado. Cifrar la maestra en RAM con otra clave que
//!   vive en el mismo proceso sería teatro: quien puede leer una puede leer la
//!   otra.
//! - **El número de entradas, del todo.** El relleno oculta el tamaño exacto,
//!   pero un archivo de 500 KB sigue diciendo que no guardas tres contraseñas.
//! - **`repreguntar`.** Es una barrera de la interfaz, no criptográfica: la
//!   clave maestra ya está en memoria mientras la bóveda esté abierta.
//! - **Un atacante con acceso al equipo desbloqueado.** Nada de esto ayuda ahí.

use crate::boveda::{Campo, Clase, ClaveAnterior, Entrada, Uri};
use quipu::{antihacker, cipher, kdf, prelayers};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// `CHUSPA` más un byte nulo: seis letras y un terminador, para que un archivo
/// truncado a menos de la cabecera no pueda confundirse con uno válido.
const MAGIA: &[u8; 7] = b"CHUSPA\0";
const VERSION: u8 = 3;
const CABECERA_LEN: usize = 61;
const NONCE_LEN: usize = cipher::NONCE_LEN;
const SALT_LEN: usize = kdf::SALT_LEN;
const HASH_LEN: usize = 32;

/// La bóveda exige un archivo llave además de la frase de paso.
///
/// Va en claro a propósito. Saber que existe una llave no ayuda a nadie —son 256
/// bits que no están en el archivo— y, sin el aviso, quien se dejara la llave en
/// casa recibiría «contraseña incorrecta» y probaría frases durante una hora.
/// La regla se prueba contra el usuario legítimo, no contra el atacante.
const FLAG_LLAVE: u8 = 1 << 0;

/// Etiquetas de dominio del HKDF. Distinta etiqueta, distinta subclave: la clave
/// del índice no sirve para ninguna entrada y la de una entrada no sirve para
/// otra, aunque todas salgan de la misma maestra.
const INFO_INDICE: &[u8] = b"chuspa/v3/indice";
const INFO_ENTRADA: &[u8] = b"chuspa/v3/entrada/";
/// Etiqueta de la clave que ENVUELVE a la maestra. La deriva la frase de paso.
const INFO_ENVOLTURA: &[u8] = b"chuspa/v3/envoltura";

/// Nonce + 32 bytes de clave + 16 de tag.
const ENVOLTURA_LEN: usize = NONCE_LEN + kdf::KEY_LEN + 16;

/// Tamaño recomendado de un archivo llave nuevo.
pub const LLAVE_LEN: usize = 32;

/// Coste Argon2id por defecto para una bóveda: el máximo que Quipu admite
/// (256 MiB) y cuatro iteraciones, cuatro veces el perfil interactivo.
///
/// **Medido, no estimado** (release, 4 núcleos, 2026-08-01):
///
/// | MiB | iteraciones | tiempo |
/// |----:|------------:|-------:|
/// |  64 |           3 |  150 ms |
/// | 128 |           4 |  441 ms |
/// | 256 |           4 |  844 ms |
///
/// Menos de un segundo para abrir la bóveda, y cuatro veces más caro para quien
/// pruebe contraseñas contra el archivo robado. La regla se probó contra el uso
/// legítimo: un coste que obligara a esperar diez segundos no endurecería nada,
/// llevaría a dejar la bóveda abierta todo el día.
///
/// **En debug tarda ~14× más** (12 s la misma derivación). No es un problema del
/// parámetro sino del modo de compilación, y conviene saberlo antes de bajarlo
/// por una medición hecha con `cargo run` sin `--release` — que es exactamente
/// el error que estuvo a punto de cambiar este valor.
///
/// `parallelism` se queda en 1 porque subirlo **no acelera nada**: medido, 64 MiB
/// con p=1 y con p=4 tardan lo mismo (150 ms). La implementación de Argon2 de
/// RustCrypto no reparte el trabajo en hilos; `p` solo cambia la función que se
/// calcula. Poner 4 daría sensación de aprovechar la máquina sin aprovecharla.
pub fn coste_por_defecto() -> kdf::KdfParams {
    kdf::KdfParams {
        mem_kib: kdf::KdfParams::MAX_MEM_KIB,
        iterations: 4,
        parallelism: 1,
    }
}

/// Genera un archivo llave nuevo: 32 bytes del generador del sistema.
pub fn generar_llave() -> Result<Zeroizing<Vec<u8>>, BovedaError> {
    let mut llave = Zeroizing::new(vec![0u8; LLAVE_LEN]);
    quipu::aleatorio::llenar(&mut llave).map_err(|_| BovedaError::SinEntropia)?;
    Ok(llave)
}

/// Escribe un archivo llave con permisos `0600`.
///
/// Existe como función de la librería, y no como un `fs::write` en cada sitio
/// que la necesite, porque escribir 32 bytes es trivial y ponerles los permisos
/// correctos se olvida: la primera versión del ejemplo de importación dejó la
/// llave en `0644`, legible por cualquier usuario del sistema. Un secreto de 256
/// bits protegido por los permisos por defecto no es un secreto.
pub fn escribir_llave(ruta: impl AsRef<Path>, llave: &[u8]) -> Result<(), BovedaError> {
    use std::io::Write;
    let mut f = std::fs::File::create(ruta.as_ref())?;
    solo_el_dueno(&f)?;
    f.write_all(llave)?;
    f.sync_all()?;
    Ok(())
}

/// Con qué se abre una bóveda: la frase de paso y, si la hay, el archivo llave.
///
/// Van juntos en un tipo porque son una sola credencial: abrir con la frase
/// correcta y sin la llave no es «medio abierto», es no abrir.
pub struct Acceso<'a> {
    pub frase: &'a str,
    pub llave: Option<&'a [u8]>,
}

impl<'a> Acceso<'a> {
    /// Solo frase de paso.
    pub fn frase(frase: &'a str) -> Self {
        Self { frase, llave: None }
    }

    /// Frase de paso más archivo llave.
    pub fn con_llave(frase: &'a str, llave: &'a [u8]) -> Self {
        Self { frase, llave: Some(llave) }
    }

    pub(crate) fn pepper(&self) -> &[u8] {
        self.llave.unwrap_or(&[])
    }

    pub(crate) fn secreto(&self) -> &str {
        self.frase
    }

    pub(crate) fn usa_llave(&self) -> bool {
        self.llave.is_some()
    }
}

/// Valoración **heurística** de una frase de paso.
///
/// No es una medida de entropía: calcularla de verdad exigiría saber cómo se
/// eligió la frase, y ningún programa lo sabe. Sirve para avisar, y por eso solo
/// [`Fortaleza::Vacia`] impide crear una bóveda.
///
/// Rechazar frases «débiles» sería el error de cerrar por costumbre: una frase
/// corta con archivo llave puede ser perfectamente razonable, y quien se
/// encuentra un rechazo suele responder añadiendo un `1` al final. Se rechaza lo
/// imposible —una frase vacía no es un secreto— y se avisa de lo demás.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fortaleza {
    Vacia,
    MuyDebil,
    Debil,
    Aceptable,
    Buena,
}

impl Fortaleza {
    pub fn aviso(self) -> Option<&'static str> {
        match self {
            Fortaleza::Vacia => Some("una frase vacía no protege nada"),
            Fortaleza::MuyDebil => Some(
                "frase muy corta: contra un archivo robado se prueba en minutos. \
                 Usa varias palabras, o añade un archivo llave.",
            ),
            Fortaleza::Debil => Some(
                "frase corta. Cuatro o cinco palabras sin relación aguantan mucho \
                 más que una palabra con símbolos.",
            ),
            Fortaleza::Aceptable => None,
            Fortaleza::Buena => None,
        }
    }
}

/// Valora una frase de paso. Ver [`Fortaleza`] sobre por qué es heurística.
pub fn evaluar_frase(frase: &str) -> Fortaleza {
    if frase.is_empty() {
        return Fortaleza::Vacia;
    }
    let caracteres = frase.chars().count();
    // Las palabras pesan más que los caracteres: cuatro palabras corrientes
    // resisten mucho más que ocho caracteres con símbolos, y la costumbre de
    // premiar los símbolos es justo la que produce «P@ssw0rd!».
    let palabras = frase.split_whitespace().filter(|p| p.len() >= 2).count();
    match (caracteres, palabras) {
        (0..=7, _) => Fortaleza::MuyDebil,
        (8..=11, 0..=1) => Fortaleza::Debil,
        (_, 4..) => Fortaleza::Buena,
        (24.., _) => Fortaleza::Buena,
        _ => Fortaleza::Aceptable,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BovedaError {
    #[error("no se pudo leer o escribir la bóveda: {0}")]
    Io(#[from] std::io::Error),

    #[error("el archivo no es una bóveda de Chuspa")]
    NoEsBoveda,

    #[error("la bóveda es de la versión {encontrada}; esta build entiende hasta la {VERSION}")]
    VersionDesconocida { encontrada: u8 },

    #[error("la bóveda está truncada o incompleta")]
    Truncada,

    #[error(
        "los parámetros de derivación de la bóveda están fuera de los límites \
         seguros; el archivo está manipulado"
    )]
    ParametrosInsensatos,

    #[error("contraseña incorrecta, o la bóveda fue alterada")]
    NoAbre,

    #[error(
        "esta bóveda exige un ARCHIVO LLAVE además de la frase de paso, y no se \
         dio ninguno. Sin él la frase correcta tampoco abre."
    )]
    FaltaLlave,

    #[error(
        "esta bóveda NO usa archivo llave y se dio uno. Abrir con una llave de más \
         no funcionaría, y fallar aquí evita que parezca contraseña incorrecta."
    )]
    LlaveDeMas,

    #[error("una frase de paso vacía no protege nada")]
    FraseVacia,

    #[error(
        "la entrada {0} no coincide con la huella que el índice tiene de ella: \
         el archivo fue alterado (una entrada sustituida, reordenada o devuelta \
         a una versión anterior)"
    )]
    HuellaNoCuadra(usize),

    #[error(
        "esta bóveda es la versión {encontrada} y se esperaba al menos la \
         {minima}: alguien puede haber restaurado una copia ANTERIOR, que \
         contendría contraseñas ya rotadas"
    )]
    Retrocedida { encontrada: u64, minima: u64 },

    #[error("no existe la entrada {0}")]
    NoExiste(usize),

    #[error("la bóveda quedó ilegible al serializarla: {0}")]
    Formato(#[from] serde_json::Error),

    #[error("no hay entropía del sistema para generar material aleatorio")]
    SinEntropia,

    #[error(
        "esta bóveda se abrió con la clave maestra de un respaldo y no tiene \
         acceso conocido. Fija una frase de paso con `cambiar_acceso` antes de \
         guardar, o la bóveda quedaría con un acceso que su dueño no conoce."
    )]
    SinAcceso,

    #[error(
        "otra instancia de Chuspa tiene abierta esta bóveda (proceso {pid}). Dos \
         procesos escribiendo a la vez harían que uno perdiera sus cambios sin \
         avisar."
    )]
    Ocupada { pid: u32 },
}

/// Lo que se ve de una entrada sin abrirla: lo justo para listar, buscar y
/// decidir si la extensión ofrece autocompletar.
///
/// Va dentro del índice, que está cifrado — el nombre de un sitio y su URL
/// también son secretos: revelan dónde tienes cuenta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resumen {
    /// Identificador interno, estable durante toda la vida de la entrada. Es la
    /// etiqueta de dominio de su subclave, así que cambiarlo la deja ilegible.
    pub id: [u8; 16],
    pub nombre: String,
    pub clase: Clase,
    pub carpeta: Option<String>,
    /// Usuario de la cuenta (`acceso.usuario`), duplicado aquí para DISTINGUIR en
    /// la lista dos cuentas del mismo sitio sin abrir la entrada. Tres estados, y
    /// la distinción importa (D32): `None` = resumen de un índice de una versión
    /// ANTERIOR, aún SIN DERIVAR (lo deriva `rellenar_usuarios_del_indice` al
    /// abrir); `Some(s)` = DERIVADO, con usuario `s` —`Some("")` si la entrada no
    /// tiene usuario—. `sellar` escribe siempre `Some(..)`, así que una entrada ya
    /// guardada con esta versión NUNCA es `None` y no se re-descifra al abrir. Su
    /// fuente de verdad es el campo de la entrada; `sellar` lo re-deriva en cada
    /// guardado, así que no se desincroniza. `#[serde(default)]` da `None` solo
    /// para el índice viejo que no trae el campo.
    #[serde(default)]
    pub usuario: Option<String>,
    pub favorita: bool,
    pub archivada: Option<String>,
    pub repreguntar: bool,
    pub uris: Vec<Uri>,
    pub creada: Option<String>,
    pub revisada: Option<String>,
    /// SHA-256 del bloque cifrado de esta entrada. Es la pieza que ata el
    /// conjunto: sin ella cada bloque sería íntegro por separado y el conjunto
    /// manipulable.
    pub huella: [u8; HASH_LEN],
    /// Nonce del bloque. Vive aquí, cifrado, y no en claro junto al bloque:
    /// en claro serviría para contar las entradas desde fuera.
    nonce: [u8; NONCE_LEN],
    /// Dónde empieza y cuánto ocupa el bloque dentro de la masa opaca.
    desde: u64,
    largo: u64,
}

impl Resumen {
    /// Primer byte de la masa que esta entrada ya NO ocupa.
    ///
    /// Se expone para diagnóstico y para poder compactar el archivo más
    /// adelante. No revela nada a quien no pueda descifrar el índice: para
    /// llegar a este valor hay que haber abierto la bóveda.
    pub fn fin(&self) -> usize {
        usize::try_from(self.desde.saturating_add(self.largo)).unwrap_or(usize::MAX)
    }

    /// El subtítulo de la entrada en la lista: lo que distingue dos cuentas del
    /// mismo sitio sin abrirla. El USUARIO manda; si no lo hay, la carpeta; y si
    /// tampoco, la clase. UNA definición para los dos frontales (egui y gtk): la
    /// lección del concilio de la migración a GTK es que la UI reUSA el núcleo,
    /// no lo reimplementa —reimplementar un trozo de frontal ya tiró en silencio
    /// un `.trim()` y reabrió una familia de bugs— (D9).
    pub fn subtitulo(&self) -> String {
        self.usuario
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| self.carpeta.clone())
            .unwrap_or_else(|| self.clase.etiqueta().to_owned())
    }
}

impl Zeroize for Resumen {
    fn zeroize(&mut self) {
        // Los metadatos también son secretos: el nombre de un sitio dice dónde
        // tienes cuenta. Se borran al cerrar la bóveda como cualquier otro dato.
        self.nombre.zeroize();
        if let Some(c) = self.carpeta.as_mut() {
            c.zeroize();
        }
        if let Some(u) = self.usuario.as_mut() {
            u.zeroize();
        }
        for uri in &mut self.uris {
            uri.uri.zeroize();
        }
        self.id.zeroize();
    }
}

/// Saca el `acceso.usuario` de una entrada (sea `Texto` o `Secreto`), vacío =
/// `None`. Es el dato que distingue dos cuentas del mismo sitio en la lista.
fn usuario_de_entrada(e: &Entrada) -> Option<String> {
    e.campo("acceso.usuario").and_then(|c| match &c.valor {
        crate::boveda::Valor::Texto(t) if !t.is_empty() => Some(t.clone()),
        crate::boveda::Valor::Secreto(s) if !s.is_empty() => Some(s.to_string()),
        _ => None,
    })
}

/// La parte de la entrada que solo existe descifrada cuando alguien la pide.
#[derive(Debug, Serialize, Deserialize)]
struct Registro {
    id_origen: Option<String>,
    notas: Option<Zeroizing<String>>,
    campos: Vec<Campo>,
    historial: Vec<ClaveAnterior>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Indice {
    resumenes: Vec<Resumen>,
}

/// Una bóveda abierta.
///
/// Mantiene en memoria la clave maestra y los bloques cifrados **sin descifrar**.
/// Solo [`Boveda::abrir_entrada`] descifra, y solo la entrada pedida —salvo la
/// migración de un índice anterior, que al abrir descifra una vez las entradas
/// sin `usuario` derivado (`rellenar_usuarios_del_indice`).
pub struct Boveda {
    ruta: PathBuf,
    /// Clave maestra ALEATORIA, independiente de la frase de paso. De ella
    /// cuelgan todas las subclaves.
    maestra: Zeroizing<[u8; kdf::KEY_LEN]>,
    /// Clave que envuelve a la maestra, derivada de la frase (y de la llave).
    /// Es `None` cuando la bóveda se abrió con la maestra de un respaldo en
    /// papel: en ese caso no hay acceso conocido y hay que fijar uno con
    /// [`Boveda::cambiar_acceso`] antes de poder guardar.
    envoltura: Option<Zeroizing<[u8; kdf::KEY_LEN]>>,
    /// Identidad de la bóveda, estable de por vida. Ata las entradas a ESTA
    /// bóveda sin depender del acceso, que puede cambiar.
    id_boveda: [u8; 16],
    salt: [u8; SALT_LEN],
    params: kdf::KdfParams,
    contador: u64,
    con_llave: bool,
    resumenes: Vec<Resumen>,
    /// Bloques cifrados, alineados uno a uno con `resumenes`.
    bloques: Vec<Vec<u8>>,
    /// Se suelta al cerrar la bóveda.
    _cerrojo: Cerrojo,
}

impl Boveda {
    /// Crea una bóveda vacía en memoria. No toca el disco hasta [`Boveda::guardar`].
    pub fn crear(
        ruta: impl Into<PathBuf>,
        acceso: &Acceso<'_>,
        params: kdf::KdfParams,
    ) -> Result<Self, BovedaError> {
        if !params.is_sane() {
            return Err(BovedaError::ParametrosInsensatos);
        }
        // Lo único que se rechaza es lo imposible. Una frase débil solo se avisa,
        // vía `evaluar_frase`, para que quien llama lo enseñe.
        if acceso.frase.is_empty() {
            return Err(BovedaError::FraseVacia);
        }
        let ruta = ruta.into();
        let cerrojo = Cerrojo::tomar(&ruta)?;

        let mut salt = [0u8; SALT_LEN];
        quipu::aleatorio::llenar(&mut salt).map_err(|_| BovedaError::SinEntropia)?;

        // La maestra es ALEATORIA, no derivada de la frase. La frase solo deriva
        // la clave que la envuelve. Eso es lo que permite rotar el acceso sin
        // tocar una sola entrada, y lo que hace que un respaldo en papel de la
        // maestra siga sirviendo después de cambiar la frase.
        let mut maestra = Zeroizing::new([0u8; kdf::KEY_LEN]);
        quipu::aleatorio::llenar(&mut maestra[..]).map_err(|_| BovedaError::SinEntropia)?;
        let mut id_boveda = [0u8; 16];
        quipu::aleatorio::llenar(&mut id_boveda).map_err(|_| BovedaError::SinEntropia)?;

        let envoltura = Zeroizing::new(kdf::derive_master_key(
            acceso.frase,
            &salt,
            acceso.pepper(),
            &params,
        ));
        Ok(Self {
            ruta,
            maestra,
            envoltura: Some(envoltura),
            id_boveda,
            salt,
            params,
            contador: 0,
            con_llave: acceso.llave.is_some(),
            resumenes: Vec::new(),
            bloques: Vec::new(),
            _cerrojo: cerrojo,
        })
    }

    /// Abre una bóveda existente. Descifra **solo el índice** (y, si es de una
    /// versión anterior, una vez sus entradas para derivar el usuario de la lista).
    pub fn abrir(ruta: impl AsRef<Path>, acceso: &Acceso<'_>) -> Result<Self, BovedaError> {
        Self::abrir_verificando(ruta, acceso, 0)
    }

    /// Igual que [`Boveda::abrir`], pero rechaza la bóveda si su contador de
    /// versión es menor que `contador_minimo`.
    ///
    /// Es la única defensa posible contra que alguien reponga una copia de
    /// seguridad antigua: el archivo por sí solo no puede saber que existió una
    /// versión posterior. Quien llama debe guardar el último contador visto
    /// **fuera** de la bóveda —en la configuración de la aplicación— y pasarlo
    /// aquí. Con `0` no hay comprobación, y eso es exactamente lo que significa:
    /// ninguna, no «alguna por defecto».
    pub fn abrir_verificando(
        ruta: impl AsRef<Path>,
        acceso: &Acceso<'_>,
        contador_minimo: u64,
    ) -> Result<Self, BovedaError> {
        let acceso = Acceso { frase: acceso.frase, llave: acceso.llave };
        Self::abrir_interno(ruta.as_ref(), acceso, contador_minimo, None)
    }

    fn abrir_interno(
        ruta: &Path,
        acceso: Acceso<'_>,
        contador_minimo: u64,
        maestra_directa: Option<&[u8; kdf::KEY_LEN]>,
    ) -> Result<Self, BovedaError> {
        let ruta = ruta.to_path_buf();
        let bytes = std::fs::read(&ruta)?;
        if bytes.len() < CABECERA_LEN {
            return Err(BovedaError::NoEsBoveda);
        }
        let cabecera = &bytes[..CABECERA_LEN];
        if &cabecera[..7] != MAGIA {
            return Err(BovedaError::NoEsBoveda);
        }
        let version = cabecera[7];
        if version != VERSION {
            return Err(BovedaError::VersionDesconocida { encontrada: version });
        }

        // Se comprueba la llave ANTES de derivar: así quien se dejó el USB en
        // casa recibe un mensaje que le dice qué hacer, en vez de esperar un
        // segundo por un «contraseña incorrecta» que le hará dudar de la frase.
        let con_llave = cabecera[8] & FLAG_LLAVE != 0;
        if maestra_directa.is_none() {
            match (con_llave, acceso.llave.is_some()) {
                (true, false) => return Err(BovedaError::FaltaLlave),
                (false, true) => return Err(BovedaError::LlaveDeMas),
                _ => {}
            }
        }

        let params = kdf::KdfParams {
            mem_kib: u32_le(&cabecera[9..13]),
            iterations: u32_le(&cabecera[13..17]),
            parallelism: u32_le(&cabecera[17..21]),
        };
        // Los parámetros vienen del archivo, que puede estar manipulado, y el KDF
        // corre ANTES de que ningún tag pueda desmentirlos. Validar aquí es lo
        // que impide que una cabecera falsa nos haga reservar memoria absurda.
        if !params.is_sane() {
            return Err(BovedaError::ParametrosInsensatos);
        }

        let contador = u64_le(&cabecera[21..29]);
        if contador < contador_minimo {
            return Err(BovedaError::Retrocedida {
                encontrada: contador,
                minima: contador_minimo,
            });
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&cabecera[29..45]);
        let mut id_boveda = [0u8; 16];
        id_boveda.copy_from_slice(&cabecera[45..61]);

        // El cerrojo se toma antes de derivar: derivar cuesta un segundo y no
        // tiene sentido pagarlo para descubrir después que la bóveda está en uso.
        let cerrojo = Cerrojo::tomar(&ruta)?;

        if bytes.len() < CABECERA_LEN + ENVOLTURA_LEN {
            return Err(BovedaError::Truncada);
        }

        // Dos caminos hasta la misma maestra: desenvolverla con la frase, o
        // recibirla directamente de un respaldo en papel.
        let (maestra, envoltura) = match maestra_directa {
            Some(m) => (Zeroizing::new(*m), None),
            None => {
                let envoltura = Zeroizing::new(kdf::derive_master_key(
                    acceso.frase,
                    &salt,
                    acceso.pepper(),
                    &params,
                ));
                let mut nonce_env = [0u8; NONCE_LEN];
                nonce_env.copy_from_slice(&bytes[CABECERA_LEN..CABECERA_LEN + NONCE_LEN]);
                let mut clave_env = kdf::derive_subkey(&envoltura, INFO_ENVOLTURA);
                let desenvuelta = cipher::decrypt(
                    &clave_env,
                    &nonce_env,
                    &bytes[CABECERA_LEN + NONCE_LEN..CABECERA_LEN + ENVOLTURA_LEN],
                    &aad_envoltura(cabecera),
                );
                antihacker::wipe(&mut clave_env);
                let mut desenvuelta = desenvuelta.map_err(|_| BovedaError::NoAbre)?;
                if desenvuelta.len() != kdf::KEY_LEN {
                    return Err(BovedaError::Truncada);
                }
                let mut maestra = Zeroizing::new([0u8; kdf::KEY_LEN]);
                maestra.copy_from_slice(&desenvuelta);
                desenvuelta.zeroize();
                (maestra, Some(envoltura))
            }
        };

        // Cabecera | envoltura | nonce del índice | longitud del índice | índice | masa
        let inicio_indice = CABECERA_LEN + ENVOLTURA_LEN + NONCE_LEN + 4;
        if bytes.len() < inicio_indice {
            return Err(BovedaError::Truncada);
        }
        let base = CABECERA_LEN + ENVOLTURA_LEN;
        let mut nonce_indice = [0u8; NONCE_LEN];
        nonce_indice.copy_from_slice(&bytes[base..base + NONCE_LEN]);
        let len_indice = u32_le(&bytes[base + NONCE_LEN..inicio_indice]) as usize;
        let fin_indice = inicio_indice
            .checked_add(len_indice)
            .ok_or(BovedaError::Truncada)?;
        if fin_indice > bytes.len() {
            return Err(BovedaError::Truncada);
        }

        let mut clave_indice = kdf::derive_subkey(&maestra, INFO_INDICE);
        let indice_claro = cipher::decrypt(
            &clave_indice,
            &nonce_indice,
            &bytes[inicio_indice..fin_indice],
            &aad_indice(cabecera),
        );
        antihacker::wipe(&mut clave_indice);
        let mut relleno = indice_claro.map_err(|_| BovedaError::NoAbre)?;
        let mut indice_claro =
            prelayers::unpad(&relleno).map_err(|_| BovedaError::Truncada)?;
        relleno.zeroize();

        let indice: Indice = serde_json::from_slice(&indice_claro)?;
        indice_claro.zeroize();

        // La masa opaca: bloques concatenados y rellenados con ceros. No hay nada
        // que "desempaquetar" — los desplazamientos vienen del índice cifrado, y
        // el relleno sobrante simplemente no se referencia.
        let masa = &bytes[fin_indice..];

        let mut bloques = Vec::with_capacity(indice.resumenes.len());
        for (i, resumen) in indice.resumenes.iter().enumerate() {
            let desde = usize::try_from(resumen.desde).map_err(|_| BovedaError::Truncada)?;
            let largo = usize::try_from(resumen.largo).map_err(|_| BovedaError::Truncada)?;
            let hasta = desde.checked_add(largo).ok_or(BovedaError::Truncada)?;
            if hasta > masa.len() {
                return Err(BovedaError::Truncada);
            }
            let bloque = &masa[desde..hasta];
            // La huella se comprueba AQUÍ, al abrir, no al leer la entrada: así
            // una manipulación se detecta aunque el usuario no llegue a abrir esa
            // entrada nunca.
            if !iguales_en_tiempo_constante(Sha256::digest(bloque).as_slice(), &resumen.huella) {
                return Err(BovedaError::HuellaNoCuadra(i));
            }
            bloques.push(bloque.to_vec());
        }

        let mut boveda = Self {
            ruta,
            maestra,
            envoltura,
            id_boveda,
            salt,
            params,
            contador,
            con_llave,
            resumenes: indice.resumenes,
            bloques,
            _cerrojo: cerrojo,
        };
        // Migración de un índice de una versión ANTERIOR (sin `usuario`): se
        // deriva en memoria para que la lista distinga cuentas del mismo sitio ya
        // en la primera apertura. En una bóveda nueva o ya re-guardada TODOS los
        // resúmenes vienen con `usuario = Some(..)`, así que esto no descifra nada.
        boveda.rellenar_usuarios_del_indice();
        Ok(boveda)
    }

    /// Deriva en memoria el `usuario` de los resúmenes de un índice ANTERIOR, que
    /// son los únicos con `usuario == None` (`None` = «aún sin derivar»; una
    /// entrada SIN usuario ya derivada es `Some("")`, no `None` — ver `sellar`).
    /// Descifra solo esas entradas, y cada una marca su resumen como DERIVADA
    /// aunque no tenga usuario, para NO volver a descifrarla en la próxima
    /// apertura. Es relleno de solo memoria; el primer `guardar` de cualquier cosa
    /// persiste la migración de toda la bóveda (`guardar` serializa el índice
    /// entero), y a partir de ahí el coste cae a cero. Una bóveda sin usuarios que
    /// nunca se guarde paga el descifrado de ESAS entradas en cada apertura, igual
    /// que el informe de salud descifra todo bajo demanda.
    fn rellenar_usuarios_del_indice(&mut self) {
        let faltan: Vec<usize> = (0..self.resumenes.len())
            .filter(|&i| self.resumenes[i].usuario.is_none())
            .collect();
        for i in faltan {
            // Si descifra, marca DERIVADA: `Some(usuario)` o `Some("")` si no hay.
            // Si falla (no debería: la huella se verificó al abrir), se deja `None`
            // y se reintenta en la próxima apertura — fail-safe, no fail-open.
            if let Ok(e) = self.abrir_entrada(i) {
                self.resumenes[i].usuario = Some(usuario_de_entrada(&e).unwrap_or_default());
            }
        }
    }

    /// Versión de la bóveda. Sube en uno con cada guardado; guárdalo fuera para
    /// poder pasárselo luego a [`Boveda::abrir_verificando`].
    pub fn contador(&self) -> u64 {
        self.contador
    }

    /// Identificador de esta bóveda. Aleatorio al crearla y estable después:
    /// sobrevive a rotar la frase y a rotar la maestra, así que sirve para
    /// saber si una copia de seguridad y una bóveda son la misma cosa.
    ///
    /// No es un secreto —va en claro en la cabecera— y no revela nada del
    /// contenido: es un número al azar que solo significa «esta bóveda».
    pub fn identidad(&self) -> [u8; 16] {
        self.id_boveda
    }

    /// `true` si esta bóveda exige archivo llave.
    pub fn usa_llave(&self) -> bool {
        self.con_llave
    }

    pub fn len(&self) -> usize {
        self.resumenes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resumenes.is_empty()
    }

    /// Lo que se puede ver sin descifrar ninguna entrada.
    pub fn listar(&self) -> &[Resumen] {
        &self.resumenes
    }

    /// Descifra **una** entrada. El resto sigue cifrado en memoria.
    pub fn abrir_entrada(&self, i: usize) -> Result<Entrada, BovedaError> {
        let resumen = self.resumenes.get(i).ok_or(BovedaError::NoExiste(i))?;

        let mut clave = self.clave_de(&resumen.id);
        let claro = cipher::decrypt(
            &clave,
            &resumen.nonce,
            &self.bloques[i],
            &self.aad_entrada(&resumen.id),
        );
        antihacker::wipe(&mut clave);
        let mut relleno = claro.map_err(|_| BovedaError::NoAbre)?;
        let mut claro = prelayers::unpad(&relleno).map_err(|_| BovedaError::Truncada)?;
        relleno.zeroize();

        let registro: Registro = serde_json::from_slice(&claro)?;
        claro.zeroize();

        Ok(Entrada {
            id_origen: registro.id_origen,
            nombre: resumen.nombre.clone(),
            clase: resumen.clase,
            carpeta: resumen.carpeta.clone(),
            favorita: resumen.favorita,
            archivada: resumen.archivada.clone(),
            repreguntar: resumen.repreguntar,
            notas: registro.notas,
            campos: registro.campos,
            uris: resumen.uris.clone(),
            historial: registro.historial,
            creada: resumen.creada.clone(),
            revisada: resumen.revisada.clone(),
        })
    }

    /// Añade una entrada. Se le asigna un identificador aleatorio nuevo.
    pub fn anadir(&mut self, entrada: Entrada) -> Result<usize, BovedaError> {
        let mut id = [0u8; 16];
        quipu::aleatorio::llenar(&mut id).map_err(|_| BovedaError::SinEntropia)?;
        let (resumen, bloque) = self.sellar(id, entrada)?;
        self.resumenes.push(resumen);
        self.bloques.push(bloque);
        Ok(self.resumenes.len() - 1)
    }

    /// Reemplaza una entrada conservando su identificador.
    ///
    /// El identificador se conserva a propósito: es la etiqueta de dominio de la
    /// subclave, y cambiarlo dejaría ilegible cualquier copia de seguridad del
    /// bloque anterior. Además el nonce se genera nuevo en cada sellado, así que
    /// no hay reutilización de par (clave, nonce) aunque el contenido no cambie.
    pub fn reemplazar(&mut self, i: usize, entrada: Entrada) -> Result<(), BovedaError> {
        let id = self.resumenes.get(i).ok_or(BovedaError::NoExiste(i))?.id;
        let (resumen, bloque) = self.sellar(id, entrada)?;
        self.resumenes[i].zeroize();
        self.resumenes[i] = resumen;
        self.bloques[i] = bloque;
        Ok(())
    }

    pub fn borrar(&mut self, i: usize) -> Result<(), BovedaError> {
        if i >= self.resumenes.len() {
            return Err(BovedaError::NoExiste(i));
        }
        self.resumenes.remove(i).zeroize();
        self.bloques.remove(i).zeroize();
        Ok(())
    }

    /// Cambia la frase de paso y/o el archivo llave.
    ///
    /// Recifra **toda** la bóveda, y no hay atajo: la clave maestra cambia, así
    /// que cambian todas las subclaves. Es la operación que hay que ejecutar
    /// después de sospechar que la frase se vio comprometida, y por eso existe:
    /// un gestor sin rotación obliga a recrear la bóveda a mano.
    ///
    /// Durante la operación todas las entradas pasan por memoria en claro. Es
    /// inevitable —hay que recifrarlas— y conviene saberlo.
    pub fn cambiar_acceso(&mut self, nuevo: &Acceso<'_>) -> Result<(), BovedaError> {
        if nuevo.frase.is_empty() {
            return Err(BovedaError::FraseVacia);
        }
        // Solo se re-deriva la clave que ENVUELVE a la maestra. La maestra no
        // cambia, así que ninguna entrada se toca: rotar la frase de una bóveda
        // de 595 entradas cuesta lo mismo que rotar la de una vacía.
        //
        // La primera versión de esto descifraba y recifraba las 595 entradas, lo
        // que ponía todos los secretos en memoria a la vez — exactamente lo que
        // el cifrado por entrada existe para evitar. La envoltura lo resuelve de
        // raíz en vez de añadir una precaución encima.
        let mut salt = [0u8; SALT_LEN];
        quipu::aleatorio::llenar(&mut salt).map_err(|_| BovedaError::SinEntropia)?;
        self.salt = salt;
        self.envoltura = Some(Zeroizing::new(kdf::derive_master_key(
            nuevo.frase,
            &salt,
            nuevo.pepper(),
            &self.params,
        )));
        self.con_llave = nuevo.llave.is_some();
        Ok(())
    }

    /// Comprueba si una clave maestra candidata abre esta bóveda, **sin abrirla**.
    ///
    /// Es lo que convierte un respaldo en algo en lo que se puede confiar. Una
    /// copia de seguridad que nunca se ha probado no es una copia de seguridad:
    /// es una suposición, y se descubre falsa justo el día que hace falta. Con
    /// esto se puede coger la hoja del cajón una vez al año, teclearla y saber
    /// que sigue sirviendo.
    ///
    /// No toma el cerrojo: solo lee, y tiene que poder ejecutarse mientras la
    /// bóveda está abierta en otra ventana. Y devuelve un `bool` en vez de un
    /// error porque «esta hoja no es de esta bóveda» es una respuesta válida a
    /// una pregunta legítima, no un fallo.
    pub fn comprobar_maestra(
        ruta: impl AsRef<Path>,
        maestra: &[u8; kdf::KEY_LEN],
    ) -> Result<bool, BovedaError> {
        let bytes = std::fs::read(ruta.as_ref())?;
        if bytes.len() < CABECERA_LEN + ENVOLTURA_LEN + NONCE_LEN + 4 {
            return Err(BovedaError::NoEsBoveda);
        }
        let cabecera = &bytes[..CABECERA_LEN];
        if &cabecera[..7] != MAGIA {
            return Err(BovedaError::NoEsBoveda);
        }
        if cabecera[7] != VERSION {
            return Err(BovedaError::VersionDesconocida { encontrada: cabecera[7] });
        }

        // Se intenta descifrar SOLO el índice: si la maestra es la buena, el tag
        // AEAD lo confirma; si no, no. No hace falta tocar ninguna entrada.
        let base = CABECERA_LEN + ENVOLTURA_LEN;
        let inicio = base + NONCE_LEN + 4;
        let len_indice = u32_le(&bytes[base + NONCE_LEN..inicio]) as usize;
        let fin = inicio.checked_add(len_indice).ok_or(BovedaError::Truncada)?;
        if fin > bytes.len() {
            return Err(BovedaError::Truncada);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[base..base + NONCE_LEN]);

        let maestra = Zeroizing::new(*maestra);
        let mut clave = kdf::derive_subkey(&maestra, INFO_INDICE);
        let resultado = cipher::decrypt(&clave, &nonce, &bytes[inicio..fin], &aad_indice(cabecera));
        antihacker::wipe(&mut clave);
        Ok(resultado.is_ok())
    }

    /// Genera una clave maestra NUEVA e invalida todos los respaldos anteriores.
    ///
    /// # Cuándo se usa esto y no `cambiar_acceso`
    ///
    /// [`Boveda::cambiar_acceso`] cambia la frase de paso y deja la maestra
    /// intacta — por eso es instantáneo y por eso el papel sigue valiendo. Pero
    /// eso significa que **una hoja comprometida sigue abriendo la bóveda para
    /// siempre**: cambiar la frase mil veces no la invalida.
    ///
    /// Esta operación es la respuesta a eso: si el papel se perdió de vista, si
    /// un custodio dejó de ser de confianza, o si un sobre acabó donde no debía.
    /// Después de ejecutarla, todos los respaldos hechos hasta ahora son papel
    /// mojado y hay que generar unos nuevos.
    ///
    /// **Es la operación cara**, y no hay forma de que no lo sea: cambiar la
    /// maestra obliga a recifrar cada entrada, así que todas pasan por memoria en
    /// claro. Es aceptable porque ocurre una vez y por un motivo grave, no en
    /// cada guardado — que es justo la diferencia con lo que hacía la primera
    /// versión de `cambiar_acceso`.
    pub fn rotar_maestra(&mut self) -> Result<(), BovedaError> {
        let entradas: Vec<Entrada> = (0..self.len())
            .map(|i| self.abrir_entrada(i))
            .collect::<Result<_, _>>()?;
        let ids: Vec<[u8; 16]> = self.resumenes.iter().map(|r| r.id).collect();

        quipu::aleatorio::llenar(&mut self.maestra[..]).map_err(|_| BovedaError::SinEntropia)?;

        for r in &mut self.resumenes {
            r.zeroize();
        }
        for b in &mut self.bloques {
            b.zeroize();
        }
        self.resumenes.clear();
        self.bloques.clear();

        // Los identificadores se conservan: son de la entrada, no de la clave.
        for (id, entrada) in ids.into_iter().zip(entradas) {
            let (resumen, bloque) = self.sellar(id, entrada)?;
            self.resumenes.push(resumen);
            self.bloques.push(bloque);
        }
        Ok(())
    }

    /// Exporta la clave maestra para respaldarla en papel.
    ///
    /// Estos 32 bytes **son** la bóveda: quien los tenga la abre sin frase de
    /// paso y sin archivo llave. Se exportan igualmente porque la alternativa
    /// —no poder respaldar— convierte olvidar la frase en perderlo todo.
    ///
    /// Como la maestra no depende del acceso, un respaldo hecho hoy sigue
    /// sirviendo después de cambiar la frase mil veces.
    pub fn exportar_maestra(&self) -> Zeroizing<[u8; kdf::KEY_LEN]> {
        self.maestra.clone()
    }

    /// Abre una bóveda con la clave maestra de un respaldo, sin frase de paso.
    ///
    /// Es el camino de recuperación: la bóveda queda **sin acceso conocido**, así
    /// que [`Boveda::guardar`] falla hasta que se fije uno con
    /// [`Boveda::cambiar_acceso`]. Fallar es deliberado — guardar en silencio con
    /// un acceso improvisado dejaría una bóveda que su dueño no sabe abrir.
    pub fn abrir_con_maestra(
        ruta: impl AsRef<Path>,
        maestra: &[u8; kdf::KEY_LEN],
    ) -> Result<Self, BovedaError> {
        Self::abrir_interno(ruta.as_ref(), Acceso::frase(""), 0, Some(maestra))
    }

    /// Escribe la bóveda al disco y sube el contador de versión.
    ///
    /// La escritura es atómica: se escribe un archivo temporal en el mismo
    /// directorio, se sincroniza, y se renombra encima. Un corte de luz a mitad
    /// deja la bóveda anterior intacta en vez de un archivo a medias — que en un
    /// gestor de contraseñas no es una molestia, es la pérdida de todo.
    pub fn guardar(&mut self) -> Result<(), BovedaError> {
        self.contador = self.contador.saturating_add(1);

        // La masa opaca se arma antes que el índice, porque el índice guarda
        // dónde cae cada bloque dentro de ella.
        let mut masa = Vec::new();
        for (resumen, bloque) in self.resumenes.iter_mut().zip(&self.bloques) {
            resumen.desde = masa.len() as u64;
            resumen.largo = bloque.len() as u64;
            masa.extend_from_slice(bloque);
        }
        // Relleno con ceros hasta la longitud Padmé, SIN prefijo de longitud.
        //
        // No se usa `prelayers::pad` aquí, y la diferencia es justo lo que hace
        // que el relleno sirva: `pad` escribe la longitud real en los ocho
        // primeros bytes, porque está pensado para aplicarse al plaintext ANTES
        // de cifrar, donde ese prefijo queda dentro del ciphertext. La masa ya
        // está cifrada, así que el prefijo quedaría EN CLARO y anunciaría el
        // tamaño exacto que el relleno pretendía esconder. La longitud real no
        // hace falta en ninguna parte: los desplazamientos viven en el índice.
        let objetivo = redondear_padme(masa.len());
        masa.resize(objetivo, 0);
        let masa_rellena = std::mem::take(&mut masa);

        let cabecera = self.cabecera();
        let indice = Indice { resumenes: self.resumenes.clone() };
        let mut claro = serde_json::to_vec(&indice)?;
        // Relleno también aquí: sin él, el tamaño del índice delata cuántas
        // entradas hay aunque su contenido esté cifrado.
        let mut relleno = prelayers::pad(&claro);
        claro.zeroize();

        let mut nonce_indice = [0u8; NONCE_LEN];
        quipu::aleatorio::llenar(&mut nonce_indice).map_err(|_| BovedaError::SinEntropia)?;
        let mut clave_indice = kdf::derive_subkey(&self.maestra, INFO_INDICE);
        let indice_cifrado = cipher::encrypt(
            &clave_indice,
            &nonce_indice,
            &relleno,
            &aad_indice(&cabecera),
        );
        antihacker::wipe(&mut clave_indice);
        relleno.zeroize();

        // Envolver la maestra con la clave del acceso actual.
        let envoltura = self.envoltura.as_ref().ok_or(BovedaError::SinAcceso)?;
        let mut nonce_env = [0u8; NONCE_LEN];
        quipu::aleatorio::llenar(&mut nonce_env).map_err(|_| BovedaError::SinEntropia)?;
        let mut clave_env = kdf::derive_subkey(envoltura, INFO_ENVOLTURA);
        let envuelta = cipher::encrypt(
            &clave_env,
            &nonce_env,
            &self.maestra[..],
            &aad_envoltura(&cabecera),
        );
        antihacker::wipe(&mut clave_env);

        let mut salida = Vec::with_capacity(
            CABECERA_LEN + ENVOLTURA_LEN + NONCE_LEN + 4 + indice_cifrado.len() + masa_rellena.len(),
        );
        salida.extend_from_slice(&cabecera);
        salida.extend_from_slice(&nonce_env);
        salida.extend_from_slice(&envuelta);
        salida.extend_from_slice(&nonce_indice);
        salida.extend_from_slice(&(indice_cifrado.len() as u32).to_le_bytes());
        salida.extend_from_slice(&indice_cifrado);
        salida.extend_from_slice(&masa_rellena);

        escribir_atomico(&self.ruta, &salida)?;
        salida.zeroize();
        Ok(())
    }

    /// Cifra una entrada y produce su resumen. La entrada se consume: sus
    /// secretos se borran al soltarla.
    fn sellar(&self, id: [u8; 16], entrada: Entrada) -> Result<(Resumen, Vec<u8>), BovedaError> {
        // Se lee ANTES de mover `campos` al registro. El índice lo guarda para
        // poder distinguir la cuenta en la lista sin descifrar el bloque. Siempre
        // `Some`: `Some("")` cuando la entrada no tiene usuario (una nota, un login
        // sin usuario), para que el resumen quede marcado DERIVADO y el relleno de
        // apertura NO lo trate como un índice viejo y lo redescifre. `None` queda
        // reservado EXCLUSIVAMENTE a un índice de una versión anterior.
        let usuario = Some(usuario_de_entrada(&entrada).unwrap_or_default());
        let registro = Registro {
            id_origen: entrada.id_origen,
            notas: entrada.notas,
            campos: entrada.campos,
            historial: entrada.historial,
        };
        let mut claro = serde_json::to_vec(&registro)?;
        // Relleno por entrada: sin él, el tamaño del bloque distingue la nota
        // larga de la contraseña corta aunque ninguna se pueda leer.
        let mut relleno = prelayers::pad(&claro);
        claro.zeroize();

        let mut nonce = [0u8; NONCE_LEN];
        quipu::aleatorio::llenar(&mut nonce).map_err(|_| BovedaError::SinEntropia)?;

        let mut clave = self.clave_de(&id);
        let datos = cipher::encrypt(&clave, &nonce, &relleno, &self.aad_entrada(&id));
        antihacker::wipe(&mut clave);
        relleno.zeroize();

        let huella: [u8; HASH_LEN] = Sha256::digest(&datos).into();

        Ok((
            Resumen {
                id,
                nombre: entrada.nombre,
                clase: entrada.clase,
                carpeta: entrada.carpeta,
                usuario,
                favorita: entrada.favorita,
                archivada: entrada.archivada,
                repreguntar: entrada.repreguntar,
                uris: entrada.uris,
                creada: entrada.creada,
                revisada: entrada.revisada,
                huella,
                nonce,
                // Los rellena `guardar`, que es quien decide dónde cae cada uno.
                desde: 0,
                largo: 0,
            },
            datos,
        ))
    }

    fn clave_de(&self, id: &[u8; 16]) -> [u8; kdf::KEY_LEN] {
        let mut info = Vec::with_capacity(INFO_ENTRADA.len() + id.len());
        info.extend_from_slice(INFO_ENTRADA);
        info.extend_from_slice(id);
        kdf::derive_subkey(&self.maestra, &info)
    }

    fn cabecera(&self) -> [u8; CABECERA_LEN] {
        let mut c = [0u8; CABECERA_LEN];
        c[..7].copy_from_slice(MAGIA);
        c[7] = VERSION;
        c[8] = if self.con_llave { FLAG_LLAVE } else { 0 };
        c[9..13].copy_from_slice(&self.params.mem_kib.to_le_bytes());
        c[13..17].copy_from_slice(&self.params.iterations.to_le_bytes());
        c[17..21].copy_from_slice(&self.params.parallelism.to_le_bytes());
        c[21..29].copy_from_slice(&self.contador.to_le_bytes());
        c[29..45].copy_from_slice(&self.salt);
        c[45..61].copy_from_slice(&self.id_boveda);
        c
    }

    /// AAD de una entrada: identidad de la bóveda (versión del formato,
    /// parámetros y salt) más el identificador de la entrada.
    ///
    /// **No lleva el contador**, y es deliberado: si lo llevara, cada guardado
    /// obligaría a recifrar las 595 entradas, lo que exigiría tenerlas todas
    /// descifradas a la vez y echaría abajo justamente lo que este módulo
    /// consigue. La frescura del conjunto la garantiza el índice a través de las
    /// huellas.
    fn aad_entrada(&self, id: &[u8; 16]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(MAGIA);
        aad.push(VERSION);
        // La IDENTIDAD de la bóveda, no su acceso. Antes iban aquí el salt y los
        // parámetros del KDF, y eso ataba las entradas a la frase de paso: rotar
        // la frase cambiaba el salt y dejaba las 595 entradas ilegibles, así que
        // rotar obligaba a descifrarlas y recifrarlas TODAS —con todos los
        // secretos en memoria a la vez, justo lo que este módulo evita—.
        aad.extend_from_slice(&self.id_boveda);
        aad.extend_from_slice(b"entrada");
        aad.extend_from_slice(id);
        aad
    }
}

/// `Debug` escrito a mano, nunca derivado.
///
/// Derivarlo pondría la clave maestra al alcance de cualquier `{:?}` —un
/// `dbg!` olvidado, un `panic!` con contexto, una traza de error— y eso es una
/// filtración total de la bóveda a través de algo que nadie considera código
/// sensible. Aquí solo sale lo que no compromete nada.
impl std::fmt::Debug for Boveda {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Boveda")
            .field("ruta", &self.ruta)
            .field("contador", &self.contador)
            .field("entradas", &self.resumenes.len())
            .field("con_llave", &self.con_llave)
            .field("maestra", &"<oculta>")
            .finish()
    }
}

impl Drop for Boveda {
    fn drop(&mut self) {
        // `maestra` se borra sola por `Zeroizing`. Los metadatos del índice no:
        // son String y Vec corrientes, y el nombre de un sitio es tan revelador
        // como la contraseña que guarda.
        for resumen in &mut self.resumenes {
            resumen.zeroize();
        }
        for bloque in &mut self.bloques {
            bloque.zeroize();
        }
    }
}

/// AAD del índice: la cabecera **entera**, contador y bandera de llave
/// incluidos. Es lo que impide pegar un índice de una versión anterior sobre un
/// archivo actual, o quitar la bandera de llave para que parezca que no hace
/// falta.
fn aad_envoltura(cabecera: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(cabecera.len() + 9);
    aad.extend_from_slice(cabecera);
    aad.extend_from_slice(b"envoltura");
    aad
}

fn aad_indice(cabecera: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(cabecera.len() + 6);
    aad.extend_from_slice(cabecera);
    aad.extend_from_slice(b"indice");
    aad
}

/// Longitud objetivo del relleno Padmé para `l` bytes.
///
/// Replica el cálculo de `quipu_nucleo::prelayers`, donde es privado. Se
/// duplican ocho líneas a propósito: la función pública de allí añade un prefijo
/// de longitud que aquí quedaría en claro sobre datos ya cifrados, delatando
/// exactamente lo que el relleno esconde. Cuantiza con un sobrecoste acotado
/// (~12%): un archivo de 400 KB y uno de 430 KB acaban del mismo tamaño.
fn redondear_padme(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    let e = (usize::BITS - 1 - l.leading_zeros()) as usize; // floor(log2(l))
    let s = (usize::BITS - e.leading_zeros()) as usize; // bit_length(e)
    let mask = (1usize << e.saturating_sub(s)) - 1;
    (l + mask) & !mask
}

/// Compara sin cortocircuitar en el primer byte distinto.
///
/// Las huellas del índice no son secretas, así que no hay un ataque de tiempo
/// conocido contra esta comparación en concreto. Se hace igual porque cuesta
/// cuatro líneas y ahorra tener que volver a razonarlo cada vez que el código
/// cambie de sitio: una comparación de material criptográfico que sale antes de
/// tiempo es una discusión que no merece la pena tener dos veces.
fn iguales_en_tiempo_constante(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diferencia = 0u8;
    for (x, y) in a.iter().zip(b) {
        diferencia |= x ^ y;
    }
    diferencia == 0
}

/// Cerrojo entre procesos: impide que dos instancias escriban la misma bóveda.
///
/// Sin él, dos procesos con la bóveda abierta guardan uno detrás de otro y el
/// segundo pisa los cambios del primero **sin que nada falle**. Es la forma de
/// pérdida de datos más difícil de notar: no hay error, solo una contraseña que
/// vuelve a ser la vieja.
///
/// El cerrojo es un archivo con el identificador del proceso dentro. Si al
/// tomarlo ya existe, se mira si ese proceso sigue vivo: un cerrojo huérfano —de
/// un cierre sucio, un corte de luz— se reclama en vez de bloquear la bóveda
/// para siempre, que sería cambiar una pérdida de datos por otra.
struct Cerrojo {
    ruta: PathBuf,
    /// `false` si no se pudo crear (por ejemplo, en un directorio de solo
    /// lectura). No se falla por eso: la bóveda sigue siendo legible.
    tomado: bool,
}

impl Cerrojo {
    fn tomar(boveda: &Path) -> Result<Self, BovedaError> {
        use std::io::Write;
        let ruta = ruta_de_cerrojo(boveda);

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ruta)
        {
            Ok(mut f) => {
                let _ = write!(f, "{}", std::process::id());
                Ok(Self { ruta, tomado: true })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = std::fs::read_to_string(&ruta)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                match pid {
                    Some(pid) if proceso_vivo(pid) => Err(BovedaError::Ocupada { pid }),
                    _ => {
                        // Huérfano: el proceso que lo dejó ya no existe.
                        std::fs::remove_file(&ruta)?;
                        Self::tomar(boveda)
                    }
                }
            }
            // Un directorio de solo lectura no debe impedir ABRIR la bóveda.
            Err(_) => Ok(Self { ruta, tomado: false }),
        }
    }
}

impl Drop for Cerrojo {
    fn drop(&mut self) {
        if self.tomado {
            let _ = std::fs::remove_file(&self.ruta);
        }
    }
}

fn ruta_de_cerrojo(boveda: &Path) -> PathBuf {
    let mut nombre = boveda.file_name().unwrap_or_default().to_os_string();
    nombre.push(".lock");
    boveda.with_file_name(nombre)
}

/// `true` si el proceso sigue existiendo.
///
/// En Linux se mira `/proc`; en Windows se pregunta a `tasklist`. En cualquier
/// otro sistema se responde `true` —conservador—: más vale pedir que se cierre
/// la otra instancia que arriesgarse a que dos escriban a la vez.
///
/// Por qué importa el camino de Windows: sin él, la respuesta por defecto era
/// `true` SIEMPRE, y entonces un cerrojo huérfano —de un corte de luz— dejaba la
/// bóveda **inaccesible para siempre** en Windows, que es cambiar una pérdida de
/// datos por otra (lo caza `un_cerrojo_huerfano_no_deja_la_boveda_inaccesible`).
fn proceso_vivo(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Sin `/proc` y sin `unsafe` (el repo es `unsafe_code = "forbid"`, así que
        // `OpenProcess`/`GetExitCodeProcess` quedan descartados): se consulta
        // `tasklist`, que viene con Windows. Con el filtro de PID exacto y salida
        // CSV sin cabecera, aparece UNA fila solo si el proceso existe; si no,
        // `tasklist` imprime un «INFO: No tasks...» que no lleva el PID entre
        // comillas. La comprobación es por eso robusta al idioma del sistema.
        //
        // RUTA ABSOLUTA a System32: `Command::new("tasklist")` se resolvería ANTES
        // en el directorio del ejecutable que en System32 (orden de búsqueda de
        // Windows), así que un `tasklist.exe` plantado junto al binario ganaría.
        // `CREATE_NO_WINDOW` evita el parpadeo de una consola negra al desbloquear
        // con un cerrojo presente (esta app no tiene consola).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let tasklist = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
        )
        .join("System32")
        .join("tasklist.exe");
        match std::process::Command::new(&tasklist)
            .args(["/NH", "/FO", "CSV", "/FI", &format!("PID eq {pid}")])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            // SOLO una corrida que TERMINA BIEN cuenta como respuesta. Un
            // `tasklist` que arranca y falla (repositorio WMI caído, un EDR que lo
            // mata, una política que lo bloquea) da stdout vacío con `status != 0`;
            // leerlo como «no está» reclamaría el cerrojo de un dueño VIVO —dos
            // procesos escribiendo la misma bóveda, justo la pérdida de datos que el
            // cerrojo existe para impedir—. Ante cualquier duda, VIVO (conservador).
            Ok(salida) if salida.status.success() => {
                String::from_utf8_lossy(&salida.stdout).contains(&format!("\"{pid}\""))
            }
            _ => true,
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        true
    }
}

/// Escribe de forma que un fallo a mitad no destruya la bóveda anterior.
fn escribir_atomico(ruta: &Path, datos: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let temporal = ruta.with_extension("chuspa-tmp");
    {
        let mut f = std::fs::File::create(&temporal)?;
        solo_el_dueno(&f)?;
        f.write_all(datos)?;
        // Sin este `sync_all`, el renombrado puede llegar al disco antes que el
        // contenido y dejar un archivo del tamaño correcto lleno de ceros.
        f.sync_all()?;
    }
    std::fs::rename(&temporal, ruta)?;

    // Sincronizar el DIRECTORIO es lo que hace duradero el renombrado. En
    // sistemas donde abrir un directorio no está permitido, se ignora: el
    // renombrado ya es atómico y esto solo refuerza la durabilidad.
    if let Some(dir) = ruta.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn solo_el_dueno(f: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // 0600 ANTES de escribir nada: crear con los permisos por defecto y
    // corregirlos después deja una ventana en la que el archivo es legible.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn solo_el_dueno(_f: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::boveda::Valor;

    /// Coste mínimo admisible. Las pruebas de este módulo comprueban el ATADO
    /// criptográfico, no la dureza del KDF; usar el coste real haría que cada
    /// prueba tardara segundos sin medir nada distinto. La dureza se ejercita en
    /// la prueba de integración que usa `coste_por_defecto`.
    fn coste_de_prueba() -> kdf::KdfParams {
        kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
    }

    /// Cada prueba necesita SU ruta: el cerrojo entre procesos es real y dos
    /// pruebas en paralelo sobre el mismo archivo se bloquean entre sí. Que
    /// ocurriera al escribir estas pruebas es la primera confirmación de que el
    /// cerrojo hace su trabajo.
    fn boveda(etiqueta: &str) -> Boveda {
        let dir = std::env::temp_dir().join(format!("chuspa-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Boveda::crear(
            dir.join(format!("{etiqueta}.chuspa")),
            &Acceso::frase("contraseña"),
            coste_de_prueba(),
        )
        .unwrap()
    }

    fn entrada() -> Entrada {
        Entrada {
            id_origen: None,
            nombre: "Banco".into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: vec![Campo::estandar("acceso.clave", Valor::secreto("s3cr3t"))],
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        }
    }

    fn entrada_con_usuario(usuario: &str) -> Entrada {
        let mut e = entrada();
        e.campos.push(Campo::estandar("acceso.usuario", Valor::texto(usuario)));
        e
    }

    /// El usuario viaja en el ÍNDICE: tras guardar y reabrir, la lista lo tiene
    /// sin abrir la entrada. Es lo que distingue dos cuentas del mismo sitio.
    #[test]
    fn el_indice_guarda_el_usuario_para_distinguir_la_lista() {
        let dir = std::env::temp_dir().join(format!("chuspa-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("indice_usuario.chuspa");
        {
            let mut b =
                Boveda::crear(ruta.clone(), &Acceso::frase("contraseña"), coste_de_prueba()).unwrap();
            b.anadir(entrada_con_usuario("juan@gmail.com")).unwrap();
            // Aísla `sellar`: el usuario está en el índice EN MEMORIA ya, sin
            // reabrir ni rellenar. (Al reabrir, el relleno lo repondría aunque
            // `sellar` no lo guardara, enmascarando ese fallo.)
            assert_eq!(b.listar()[0].usuario.as_deref(), Some("juan@gmail.com"), "sellar debe poblarlo");
            b.guardar().unwrap();
        } // suelta el cerrojo antes de reabrir
        let b = Boveda::abrir(&ruta, &Acceso::frase("contraseña")).unwrap();
        assert_eq!(b.listar()[0].usuario.as_deref(), Some("juan@gmail.com"), "y debe sobrevivir al guardar+reabrir");
    }

    /// El subtítulo de la lista es la cascada usuario -> carpeta -> clase, UNA
    /// definición para los dos frontales. El caso rojo de cada escalón es el de
    /// arriba: un mutante que ignore el usuario devolvería la clase en la primera
    /// aserción; uno que ignore la carpeta, la clase en la segunda.
    #[test]
    fn el_subtitulo_es_usuario_luego_carpeta_luego_clase() {
        let dir = std::env::temp_dir().join(format!("chuspa-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("subtitulo.chuspa");
        let mut b =
            Boveda::crear(ruta, &Acceso::frase("contraseña"), coste_de_prueba()).unwrap();
        let mut con_usuario = entrada_con_usuario("juan@gmail.com");
        con_usuario.nombre = "ConUsuario".into();
        b.anadir(con_usuario).unwrap();
        let mut con_carpeta = entrada();
        con_carpeta.nombre = "ConCarpeta".into();
        con_carpeta.carpeta = Some("Trabajo".into());
        b.anadir(con_carpeta).unwrap();
        let mut pelada = entrada();
        pelada.nombre = "Pelada".into();
        b.anadir(pelada).unwrap();

        let r = b.listar();
        let busca = |n: &str| r.iter().find(|x| x.nombre == n).unwrap();
        assert_eq!(busca("ConUsuario").subtitulo(), "juan@gmail.com", "el usuario manda");
        assert_eq!(busca("ConCarpeta").subtitulo(), "Trabajo", "sin usuario, la carpeta");
        let p = busca("Pelada");
        assert_eq!(p.subtitulo(), p.clase.etiqueta(), "sin ninguno, la clase");
    }

    /// El relleno repone el usuario de un índice que no lo trae (migración de una
    /// versión anterior), descifrando la entrada por la vía real del `open`. El
    /// caso rojo es el índice SIN usuario: sin el relleno, la lista no distingue.
    #[test]
    fn rellenar_repone_el_usuario_de_un_indice_sin_el() {
        let dir = std::env::temp_dir().join(format!("chuspa-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("relleno_usuario.chuspa");
        let mut b =
            Boveda::crear(ruta, &Acceso::frase("contraseña"), coste_de_prueba()).unwrap();
        b.anadir(entrada_con_usuario("ana@correo.com")).unwrap();
        // Simula el índice viejo: el resumen SIN usuario.
        b.resumenes[0].usuario = None;
        assert_eq!(b.listar()[0].usuario, None, "de partida, el índice no lo trae");
        b.rellenar_usuarios_del_indice();
        assert_eq!(b.listar()[0].usuario.as_deref(), Some("ana@correo.com"));
    }

    /// Una entrada SIN usuario (una nota, un login sin `acceso.usuario`) queda
    /// marcada DERIVADA —`Some("")`, no `None`— tanto al sellar como al derivar un
    /// índice viejo, para que el relleno de apertura NO la trate como pendiente y
    /// la redescifre en CADA apertura. Es el defecto que halló el concilio: `None`
    /// con dos significados (D32). Dos casos rojos: si `sellar` escribe `None`,
    /// cae la 1.ª aserción; si el relleno solo marca cuando HAY usuario, cae la 2.ª.
    #[test]
    fn una_entrada_sin_usuario_queda_derivada_y_no_se_redescifra() {
        let dir = std::env::temp_dir().join(format!("chuspa-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("sin_usuario.chuspa");
        let mut b = Boveda::crear(ruta, &Acceso::frase("contraseña"), coste_de_prueba()).unwrap();
        b.anadir(entrada()).unwrap(); // `entrada()` solo trae `acceso.clave`, sin usuario
        // (sellar) En memoria ya está DERIVADA: `Some("")`, no `None`.
        assert_eq!(
            b.listar()[0].usuario.as_deref(),
            Some(""),
            "sellar marca derivada aunque no haya usuario"
        );
        // Simula un índice VIEJO de esa misma entrada (resumen sin derivar).
        b.resumenes[0].usuario = None;
        b.rellenar_usuarios_del_indice();
        // (rellenar) La marca DERIVADA aunque no tenga usuario: `Some("")`, no `None`.
        assert_eq!(
            b.listar()[0].usuario.as_deref(),
            Some(""),
            "el relleno deriva una entrada sin usuario a Some(\"\"), no la deja None"
        );
    }

    /// Cada entrada tiene su propia clave: la de una no abre la de otra. Es lo
    /// que hace que abrir una entrada no exponga las demás.
    #[test]
    fn la_clave_de_una_entrada_no_abre_otra() {
        let b = boveda("la_clave_de_una_entrada_no_abre_otra");
        let (id_a, id_b) = ([1u8; 16], [2u8; 16]);
        let (resumen, datos) = b.sellar(id_a, entrada()).unwrap();

        let clave_ajena = b.clave_de(&id_b);
        assert!(
            cipher::decrypt(&clave_ajena, &resumen.nonce, &datos, &b.aad_entrada(&id_a)).is_err(),
            "la subclave de otra entrada no puede abrir esta"
        );

        let clave_propia = b.clave_de(&id_a);
        assert!(
            cipher::decrypt(&clave_propia, &resumen.nonce, &datos, &b.aad_entrada(&id_a)).is_ok(),
            "la suya sí"
        );
    }

    /// Aunque alguien tuviera la clave correcta, el AAD ata el bloque a SU
    /// identificador: no se puede hacer pasar la entrada A por la B.
    #[test]
    fn el_aad_ata_el_bloque_a_su_identificador() {
        let b = boveda("el_aad_ata_el_bloque_a_su_identificador");
        let (id_a, id_b) = ([3u8; 16], [4u8; 16]);
        let (resumen, datos) = b.sellar(id_a, entrada()).unwrap();
        let clave = b.clave_de(&id_a);

        assert!(
            cipher::decrypt(&clave, &resumen.nonce, &datos, &b.aad_entrada(&id_b)).is_err(),
            "con el AAD de otra entrada no debe abrir ni con la clave correcta"
        );
    }

    /// La otra cara de la decisión: el contador NO entra en el AAD de las
    /// entradas, para que guardar no obligue a recifrarlas todas. Si alguien lo
    /// añadiera, esta prueba se pone roja y le hace leer por qué.
    #[test]
    fn el_contador_no_entra_en_el_aad_de_las_entradas() {
        let mut b = boveda("el_contador_no_entra_en_el_aad_de_las_entradas");
        let id = [5u8; 16];
        let (resumen, datos) = b.sellar(id, entrada()).unwrap();

        b.contador = 42; // como si se hubiera guardado 42 veces
        let clave = b.clave_de(&id);
        assert!(
            cipher::decrypt(&clave, &resumen.nonce, &datos, &b.aad_entrada(&id)).is_ok(),
            "un bloque sellado antes debe seguir abriéndose tras guardar"
        );
    }

    /// El AAD de una entrada depende de la IDENTIDAD de la bóveda, no de su
    /// acceso: cambiar la frase, el salt o la bandera de llave no toca ninguna
    /// entrada. Eso es lo que permite rotar el acceso sin recifrar 595 bloques.
    ///
    /// La bandera de llave sigue protegida, pero una capa más arriba: va en el
    /// AAD de la envoltura y del índice, y quitarla del archivo impide abrirlo.
    /// Lo comprueba `quitar_la_bandera_de_llave_no_abre_la_boveda` en las
    /// pruebas de integración, que es donde esa capa se puede ejercitar de
    /// verdad.
    #[test]
    fn el_aad_de_una_entrada_no_depende_del_acceso() {
        let mut b = boveda("el_aad_de_una_entrada_no_depende_del_acceso");
        let id = [8u8; 16];
        let (resumen, datos) = b.sellar(id, entrada()).unwrap();
        let clave = b.clave_de(&id);

        b.con_llave = !b.con_llave;
        b.salt = [0xAB; SALT_LEN];
        b.contador = 99;
        assert!(
            cipher::decrypt(&clave, &resumen.nonce, &datos, &b.aad_entrada(&id)).is_ok(),
            "rotar el acceso no puede dejar ilegibles las entradas"
        );

        // Lo que sí las ata: la identidad de la bóveda.
        b.id_boveda = [0xFF; 16];
        assert!(
            cipher::decrypt(&clave, &resumen.nonce, &datos, &b.aad_entrada(&id)).is_err(),
            "una entrada no puede leerse bajo la identidad de otra bóveda"
        );
    }

    /// Dos sellados del mismo contenido dan nonces distintos. Repetir el par
    /// (clave, nonce) en XChaCha20-Poly1305 rompe la confidencialidad.
    #[test]
    fn cada_sellado_usa_un_nonce_nuevo() {
        let b = boveda("cada_sellado_usa_un_nonce_nuevo");
        let id = [6u8; 16];
        let (uno, datos_uno) = b.sellar(id, entrada()).unwrap();
        let (otro, datos_otro) = b.sellar(id, entrada()).unwrap();
        assert_ne!(uno.nonce, otro.nonce);
        assert_ne!(datos_uno, datos_otro);
    }

    /// La huella del índice es del bloque CIFRADO: cambiar un byte la invalida.
    #[test]
    fn la_huella_cubre_el_bloque_cifrado() {
        let b = boveda("la_huella_cubre_el_bloque_cifrado");
        let (resumen, mut datos) = b.sellar([7u8; 16], entrada()).unwrap();
        assert!(iguales_en_tiempo_constante(
            Sha256::digest(&datos).as_slice(),
            &resumen.huella
        ));
        datos[0] ^= 1;
        assert!(!iguales_en_tiempo_constante(
            Sha256::digest(&datos).as_slice(),
            &resumen.huella
        ));
    }

    /// Padmé no promete que dos tamaños cualesquiera coincidan —eso sería un
    /// relleno a bloque fijo, mucho más caro—: promete **cuantizar**, que muchas
    /// longitudes distintas caigan en pocos valores observables. Eso es lo que se
    /// mide aquí, y no una igualdad concreta que la primera versión de esta
    /// prueba daba por supuesta y era falsa.
    #[test]
    fn el_relleno_cuantiza_los_tamanos() {
        let b = boveda("el_relleno_cuantiza_los_tamanos");
        let mut tamanos = std::collections::BTreeSet::new();
        for n in 0..120 {
            let mut e = entrada();
            e.campos = vec![Campo::estandar("a", Valor::texto("b".repeat(n)))];
            let (_, datos) = b.sellar([9u8; 16], e).unwrap();
            tamanos.insert(datos.len());
        }
        assert!(
            tamanos.len() < 30,
            "120 longitudes distintas produjeron {} tamaños observables; \
             el relleno no está cuantizando",
            tamanos.len()
        );
    }

    /// La cuantización tiene que costar poco: un relleno que doblara el archivo
    /// se acabaría desactivando, y un relleno desactivado no protege nada.
    #[test]
    fn el_relleno_no_cuesta_mas_del_doce_por_ciento() {
        for l in [1usize, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let redondeado = redondear_padme(l);
            assert!(redondeado >= l);
            let exceso = (redondeado - l) as f64 / l as f64;
            assert!(
                exceso <= 0.12,
                "para {l} bytes el relleno añade el {:.1} por ciento",
                exceso * 100.0
            );
        }
    }

    #[test]
    fn la_comparacion_constante_distingue() {
        assert!(iguales_en_tiempo_constante(b"abc", b"abc"));
        assert!(!iguales_en_tiempo_constante(b"abc", b"abd"));
        assert!(!iguales_en_tiempo_constante(b"abc", b"ab"));
        // El primer byte distinto no debe decidir el resultado por sí solo.
        assert!(!iguales_en_tiempo_constante(b"Xbc", b"abc"));
    }

    #[test]
    fn la_frase_vacia_se_rechaza_y_las_demas_solo_se_avisan() {
        assert_eq!(evaluar_frase(""), Fortaleza::Vacia);
        assert_eq!(evaluar_frase("corta"), Fortaleza::MuyDebil);
        assert_eq!(evaluar_frase("caballo batería grapa correcta"), Fortaleza::Buena);
        // Una frase inusual pero legítima no se bloquea.
        assert!(evaluar_frase("Tr0ub4dor").aviso().is_none() || evaluar_frase("Tr0ub4dor") < Fortaleza::Buena);
    }
}
