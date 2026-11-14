// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Copia de seguridad **cifrada y comprimida** de la bóveda entera.
//!
//! # Por qué no basta con copiar el archivo
//!
//! El `.chuspa` ya está cifrado, así que copiarlo a un USB es un respaldo
//! legítimo. Lo que no es, es pequeño — y no lo va a ser: **el texto cifrado no
//! se comprime**. Medido sobre una bóveda de 8 entradas, `gzip -9` sobre el
//! archivo la deja en 6 543 bytes partiendo de 6 513: *crece* 30. Es lo
//! esperable —un buen cifrado produce algo indistinguible de ruido— pero
//! conviene decirlo, porque «comprimir la copia» suena a que se puede hacer
//! sobre el archivo y ahí no hay nada que ganar.
//!
//! Comprimir solo significa algo **antes** de cifrar. Por eso esta copia se
//! construye del CONTENIDO y no del archivo: se abren las entradas, se
//! serializan, se comprimen y se cifra el resultado. El mismo contenido en
//! claro pasa de 820 a 340 bytes, un 59 % menos.
//!
//! # El precio, dicho antes de cobrarlo
//!
//! La bóveda presume de que abrirla **no** pone las 595 contraseñas en claro en
//! memoria: se descifra el índice, y cada entrada solo cuando se pide. Una copia
//! de seguridad completa suspende eso por definición — para copiarlo todo hay
//! que tenerlo todo, y encima el compresor hace sus propias copias intermedias
//! que este código no puede borrar.
//!
//! No hay forma de evitarlo, así que se acota: es una operación **explícita**,
//! nunca automática ni de fondo, y los búferes propios se borran en cuanto
//! dejan de hacer falta. Quien haga una copia debe saber que ese es el minuto
//! de mayor exposición de su bóveda.
//!
//! # Qué abre la copia
//!
//! La copia lleva **su propia envoltura de la clave maestra**, igual que la
//! bóveda: con la frase de paso se restaura en otra máquina sin tener el
//! `.chuspa` original delante. Y como lo que envuelve es la maestra —la misma
//! que respalda la hoja de papel—, **la hoja también abre la copia**. Un
//! respaldo que dependiera de recordar la frase sería un respaldo que caduca el
//! día que se olvida justo lo que hay que respaldar.
//!
//! # Restaurar no pisa nada por defecto
//!
//! [`comprobar`] es lo que se hace por defecto y no toca ningún archivo: dice
//! de cuándo es la copia y cuántas entradas trae. [`restaurar`] hay que pedirlo
//! aparte y **se niega a escribir sobre una bóveda que ya existe**. Es la misma
//! regla que en la recuperación por papel, y por el mismo motivo: una copia que
//! nunca se ha probado no es una copia, es una suposición — y probarla no puede
//! ser lo mismo que sobrescribir lo que se tiene.

use crate::boveda::Entrada;
use crate::cifrado::{Acceso, Boveda, BovedaError};
use quipu::{antihacker, cipher, kdf, prelayers};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

/// Marca de archivo. Distinta de la de la bóveda a propósito: una copia y una
/// bóveda no se pueden confundir ni por accidente ni al mirar el archivo.
const MAGIA: &[u8; 7] = b"CHUSPAC";
const VERSION: u8 = 1;
const FLAG_LLAVE: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = cipher::NONCE_LEN;
/// Lo que el AEAD añade al sellar. La envoltura son la clave más su tag.
const TAG_LEN: usize = 16;
const ENVOLTURA_LEN: usize = kdf::KEY_LEN + TAG_LEN;

/// Etiqueta de dominio de la clave que cifra el contenido.
///
/// Deriva de la maestra por HKDF, así que **no es** ninguna de las claves de
/// entrada ni la del índice: comprometer la copia no da nada de la bóveda que
/// no diera ya la maestra, y usar una clave común habría atado su seguridad a
/// la de todo lo demás.
const INFO_CONTENIDO: &[u8] = b"chuspa:copia:contenido:v1";

/// Techo de lo que se acepta descomprimir.
///
/// Sin él, una copia manipulada con unos pocos kilobytes puede pedir gigabytes
/// al descomprimir y tumbar el proceso. El límite es generoso —256 MiB, cuando
/// una bóveda de 595 entradas ronda el medio mega en claro— porque su trabajo
/// es cortar lo absurdo, no lo grande.
const LIMITE_DESCOMPRESION: usize = 256 * 1024 * 1024;

/// Nivel de compresión. El 9 tarda un poco más y aquí eso da igual: una copia
/// se hace de vez en cuando y lo que importa es que ocupe poco en el sitio
/// donde va a vivir años.
const NIVEL: u8 = 9;

#[derive(Debug, thiserror::Error)]
pub enum CopiaError {
    #[error("esto no es una copia de seguridad de Chuspa (le falta la marca del formato)")]
    NoEsCopia,

    #[error("la copia es de la versión {encontrada}; esta build entiende hasta la {VERSION}")]
    VersionFutura { encontrada: u8 },

    #[error("la copia está truncada: se esperaban al menos {minimo} bytes y hay {hay}")]
    Truncada { minimo: usize, hay: usize },

    #[error(
        "la copia no se pudo abrir con este acceso. O la frase de paso no es la que \
         tenía la bóveda cuando se hizo, o el archivo fue alterado."
    )]
    NoAbre,

    #[error(
        "esta copia se hizo CON archivo llave y no se dio ninguno. Sin él no se abre, \
         ni con la frase correcta."
    )]
    FaltaLlave,

    #[error("esta copia NO se hizo con archivo llave y se dio uno")]
    LlaveDeMas,

    #[error("la copia dice descomprimirse a más de {LIMITE_DESCOMPRESION} bytes: no se acepta")]
    DemasiadoGrande,

    #[error("la copia se descifró pero su contenido no se entiende: {0}")]
    Contenido(#[from] serde_json::Error),

    #[error(
        "«{0}» ya existe. Restaurar escribiría encima de una bóveda que puede ser la \
         buena; si de verdad quieres reemplazarla, muévela o bórrala tú primero."
    )]
    DestinoOcupado(String),

    #[error(transparent)]
    Boveda(#[from] BovedaError),

    #[error("no se pudo leer o escribir la copia: {0}")]
    Io(#[from] std::io::Error),

    #[error("no hay entropía del sistema para generar material aleatorio")]
    SinEntropia,
}

/// Lo que va dentro, ya descifrado y descomprimido.
///
/// `deny_unknown_fields` por el mismo motivo que en el importador: si una
/// versión futura añade un campo, restaurar con una build vieja se **detiene**
/// diciendo cuál, en vez de descartarlo en silencio y devolver una bóveda a la
/// que le falta algo que su dueño cree tener.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contenido {
    /// De qué bóveda salió. Sirve para saber si una copia y una bóveda son
    /// parientes antes de restaurar encima.
    id_boveda: [u8; 16],
    /// El contador de versión que tenía la bóveda al copiarla. Restaurar deja
    /// la bóveda nueva en este número, para que `abrir_verificando` siga
    /// detectando una reposición anterior.
    contador: u64,
    /// Segundos desde el epoch. Es el dato que convierte «tengo una copia» en
    /// «tengo una copia de anteayer».
    creada: u64,
    entradas: Vec<Entrada>,
}

/// Lo que se puede decir de una copia sin restaurarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ficha {
    pub entradas: usize,
    pub creada: u64,
    pub contador: u64,
    pub id_boveda: [u8; 16],
    /// Tamaño del archivo y del contenido en claro, para poder decir cuánto
    /// ahorró comprimir sin tener que medirlo por fuera.
    pub bytes_archivo: usize,
    pub bytes_en_claro: usize,
}

impl Ficha {
    /// Porcentaje que la compresión se ahorró. Sirve para el informe, no para
    /// decidir nada.
    pub fn ahorro(&self) -> f64 {
        if self.bytes_en_claro == 0 {
            return 0.0;
        }
        let ratio = self.bytes_archivo as f64 / self.bytes_en_claro as f64;
        (1.0 - ratio) * 100.0
    }
}

/// Construye la copia a partir de una bóveda ABIERTA.
///
/// El `acceso` es el que abrirá la copia, y no tiene por qué ser el de la
/// bóveda: se puede hacer una copia con una frase distinta —para dársela a otro
/// custodio, por ejemplo— sin tocar la bóveda de origen.
pub fn crear(boveda: &Boveda, acceso: &Acceso<'_>) -> Result<Vec<u8>, CopiaError> {
    if acceso.secreto().is_empty() {
        return Err(BovedaError::FraseVacia.into());
    }

    // Todas las entradas en claro a la vez. Es el momento caro y es inevitable:
    // ver la nota del módulo.
    let mut entradas = Vec::with_capacity(boveda.len());
    for i in 0..boveda.len() {
        entradas.push(boveda.abrir_entrada(i)?);
    }

    let contenido = Contenido {
        id_boveda: boveda.identidad(),
        contador: boveda.contador(),
        creada: ahora(),
        entradas,
    };
    let mut claro = serde_json::to_vec(&contenido)?;
    let en_claro = claro.len();

    let mut comprimido = miniz_oxide::deflate::compress_to_vec(&claro, NIVEL);
    claro.zeroize();

    // Relleno DESPUÉS de comprimir, y ese orden es el punto: comprimir vuelve a
    // introducir la fuga de longitud que la bóveda evita rellenando cada
    // entrada. El tamaño de un archivo comprimido dice cuánto y qué tipo de
    // contenido hay dentro. Padmé lo redondea a un conjunto pequeño de tamaños
    // posibles, así que el archivo deja de ser una medida del contenido.
    let mut relleno = prelayers::pad(&comprimido);
    comprimido.zeroize();

    let mut salt = [0u8; SALT_LEN];
    quipu::aleatorio::llenar(&mut salt).map_err(|_| CopiaError::SinEntropia)?;
    let mut nonce_env = [0u8; NONCE_LEN];
    quipu::aleatorio::llenar(&mut nonce_env).map_err(|_| CopiaError::SinEntropia)?;
    let mut nonce = [0u8; NONCE_LEN];
    quipu::aleatorio::llenar(&mut nonce).map_err(|_| CopiaError::SinEntropia)?;

    let params = crate::cifrado::coste_por_defecto();
    let cabecera = cabecera(
        &params,
        acceso.usa_llave(),
        &salt,
        &contenido.id_boveda,
        contenido.contador,
        contenido.creada,
        &nonce_env,
        &nonce,
    );

    // La maestra va envuelta por la frase, igual que en la bóveda: eso es lo que
    // permite restaurar en otra máquina sin el archivo original, y lo que hace
    // que la hoja de papel —que ES la maestra— también abra esta copia.
    let maestra = boveda.exportar_maestra();
    let mut envoltura = kdf::derive_master_key(acceso.secreto(), &salt, acceso.pepper(), &params);
    let envuelta = cipher::encrypt(&envoltura, &nonce_env, &maestra[..], &cabecera);
    antihacker::wipe(&mut envoltura);

    let mut clave = kdf::derive_subkey(&maestra, INFO_CONTENIDO);
    let datos = cipher::encrypt(&clave, &nonce, &relleno, &cabecera);
    antihacker::wipe(&mut clave);
    relleno.zeroize();

    let mut salida = Vec::with_capacity(cabecera.len() + envuelta.len() + datos.len());
    salida.extend_from_slice(&cabecera);
    salida.extend_from_slice(&envuelta);
    salida.extend_from_slice(&datos);
    debug_assert!(en_claro > 0);
    Ok(salida)
}

/// Escribe la copia con permisos 0600.
///
/// Existe para que los permisos no dependan de que quien llama se acuerde. Una
/// copia tiene dentro exactamente lo mismo que la bóveda, y dejarla legible
/// para todo el sistema regalaría el trabajo de cifrarla — el ejemplo de línea
/// de órdenes lo hacía bien y la ventana lo habría olvidado, que es justo la
/// clase de descuido que se arregla poniéndolo en un solo sitio.
pub fn escribir(bytes: &[u8], ruta: impl AsRef<Path>) -> Result<(), CopiaError> {
    let ruta = ruta.as_ref();
    std::fs::write(ruta, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ruta, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Abre la copia y dice qué hay dentro. **No toca ningún archivo.**
pub fn comprobar(bytes: &[u8], acceso: &Acceso<'_>) -> Result<Ficha, CopiaError> {
    let (contenido, en_claro) = descifrar(bytes, acceso)?;
    Ok(Ficha {
        entradas: contenido.entradas.len(),
        creada: contenido.creada,
        contador: contenido.contador,
        id_boveda: contenido.id_boveda,
        bytes_archivo: bytes.len(),
        bytes_en_claro: en_claro,
    })
}

/// Restaura la copia en una bóveda NUEVA.
///
/// Se niega si el destino existe: quien quiera reemplazar la suya que la mueva
/// antes, a mano y sabiendo lo que hace.
pub fn restaurar(
    bytes: &[u8],
    acceso: &Acceso<'_>,
    destino: impl AsRef<Path>,
    nuevo: &Acceso<'_>,
) -> Result<Ficha, CopiaError> {
    let destino = destino.as_ref();
    if destino.exists() {
        return Err(CopiaError::DestinoOcupado(destino.display().to_string()));
    }
    let (contenido, en_claro) = descifrar(bytes, acceso)?;

    let params = crate::cifrado::coste_por_defecto();
    let mut boveda = Boveda::crear(destino, nuevo, params)?;
    for entrada in contenido.entradas.iter().cloned() {
        boveda.anadir(entrada)?;
    }
    boveda.guardar()?;

    Ok(Ficha {
        entradas: contenido.entradas.len(),
        creada: contenido.creada,
        contador: contenido.contador,
        id_boveda: contenido.id_boveda,
        bytes_archivo: bytes.len(),
        bytes_en_claro: en_claro,
    })
}

/// Abre la copia con la **clave maestra**, sin frase de paso.
///
/// Son los mismos 32 bytes que imprime la hoja de respaldo y que reconstruye el
/// reparto k-de-n. Existe porque la promesa del papel sería falsa sin esto: si
/// la copia solo se abriera con la frase, un olvido dejaría fuera justo el
/// respaldo que se guardó para ese día.
pub fn comprobar_con_maestra(
    bytes: &[u8],
    maestra: &[u8; kdf::KEY_LEN],
) -> Result<Ficha, CopiaError> {
    let (contenido, en_claro) = abrir_contenido(bytes, maestra)?;
    Ok(ficha(&contenido, bytes.len(), en_claro))
}

/// Restaura con la clave maestra. Las mismas reglas que [`restaurar`]: no pisa
/// un destino que ya exista.
pub fn restaurar_con_maestra(
    bytes: &[u8],
    maestra: &[u8; kdf::KEY_LEN],
    destino: impl AsRef<Path>,
    nuevo: &Acceso<'_>,
) -> Result<Ficha, CopiaError> {
    let destino = destino.as_ref();
    if destino.exists() {
        return Err(CopiaError::DestinoOcupado(destino.display().to_string()));
    }
    let (contenido, en_claro) = abrir_contenido(bytes, maestra)?;
    escribir_boveda(&contenido, destino, nuevo)?;
    Ok(ficha(&contenido, bytes.len(), en_claro))
}

fn ficha(contenido: &Contenido, bytes_archivo: usize, bytes_en_claro: usize) -> Ficha {
    Ficha {
        entradas: contenido.entradas.len(),
        creada: contenido.creada,
        contador: contenido.contador,
        id_boveda: contenido.id_boveda,
        bytes_archivo,
        bytes_en_claro,
    }
}

fn escribir_boveda(
    contenido: &Contenido,
    destino: &Path,
    nuevo: &Acceso<'_>,
) -> Result<(), CopiaError> {
    let params = crate::cifrado::coste_por_defecto();
    let mut boveda = Boveda::crear(destino, nuevo, params)?;
    for entrada in contenido.entradas.iter().cloned() {
        boveda.anadir(entrada)?;
    }
    boveda.guardar()?;
    Ok(())
}

/// El camino común de `comprobar` y `restaurar`.
fn descifrar(bytes: &[u8], acceso: &Acceso<'_>) -> Result<(Contenido, usize), CopiaError> {
    let minimo = CABECERA_LEN + ENVOLTURA_LEN;
    if bytes.len() < minimo {
        return Err(CopiaError::Truncada { minimo, hay: bytes.len() });
    }
    if &bytes[..7] != MAGIA {
        return Err(CopiaError::NoEsCopia);
    }
    let version = bytes[7];
    if version != VERSION {
        return Err(CopiaError::VersionFutura { encontrada: version });
    }

    let con_llave = bytes[8] & FLAG_LLAVE != 0;
    // Se dice ANTES de derivar. Un «no abre» cuando lo que falta es el USB manda
    // a probar frases durante una hora.
    if con_llave && !acceso.usa_llave() {
        return Err(CopiaError::FaltaLlave);
    }
    if !con_llave && acceso.usa_llave() {
        return Err(CopiaError::LlaveDeMas);
    }

    let params = kdf::KdfParams {
        mem_kib: u32::from_le_bytes(bytes[9..13].try_into().unwrap()),
        iterations: u32::from_le_bytes(bytes[13..17].try_into().unwrap()),
        parallelism: u32::from_le_bytes(bytes[17..21].try_into().unwrap()),
    };
    // Se validan ANTES de derivar: unos parámetros falseados pueden pedir
    // terabytes de memoria, y eso es una forma barata de tumbar el proceso de
    // quien solo quería mirar su copia.
    if !params.is_sane() {
        return Err(BovedaError::ParametrosInsensatos.into());
    }
    let salt: [u8; SALT_LEN] = bytes[21..37].try_into().unwrap();
    let nonce_env: [u8; NONCE_LEN] = bytes[69..69 + NONCE_LEN].try_into().unwrap();
    let cabecera = &bytes[..CABECERA_LEN];

    let mut envoltura = kdf::derive_master_key(acceso.secreto(), &salt, acceso.pepper(), &params);
    let fin_env = CABECERA_LEN + ENVOLTURA_LEN;
    let maestra = cipher::decrypt(&envoltura, &nonce_env, &bytes[CABECERA_LEN..fin_env], cabecera);
    antihacker::wipe(&mut envoltura);
    let mut maestra: [u8; kdf::KEY_LEN] = maestra
        .map_err(|_| CopiaError::NoAbre)?
        .as_slice()
        .try_into()
        .map_err(|_| CopiaError::NoAbre)?;

    let salida = abrir_contenido(bytes, &maestra);
    antihacker::wipe(&mut maestra);
    salida
}

/// Descifra el contenido teniendo ya la maestra, venga de donde venga: de la
/// envoltura que abre la frase, o de la hoja de papel.
fn abrir_contenido(
    bytes: &[u8],
    maestra: &[u8; kdf::KEY_LEN],
) -> Result<(Contenido, usize), CopiaError> {
    let minimo = CABECERA_LEN + ENVOLTURA_LEN;
    if bytes.len() < minimo {
        return Err(CopiaError::Truncada { minimo, hay: bytes.len() });
    }
    if &bytes[..7] != MAGIA {
        return Err(CopiaError::NoEsCopia);
    }
    if bytes[7] != VERSION {
        return Err(CopiaError::VersionFutura { encontrada: bytes[7] });
    }
    let nonce: [u8; NONCE_LEN] = bytes[69 + NONCE_LEN..CABECERA_LEN].try_into().unwrap();
    let cabecera = &bytes[..CABECERA_LEN];
    let fin_env = CABECERA_LEN + ENVOLTURA_LEN;

    let mut clave = kdf::derive_subkey(maestra, INFO_CONTENIDO);
    let relleno = cipher::decrypt(&clave, &nonce, &bytes[fin_env..], cabecera);
    antihacker::wipe(&mut clave);
    let mut relleno = relleno.map_err(|_| CopiaError::NoAbre)?;

    let mut comprimido = prelayers::unpad(&relleno).map_err(|_| CopiaError::NoAbre)?;
    relleno.zeroize();

    let mut claro = miniz_oxide::inflate::decompress_to_vec_with_limit(
        &comprimido,
        LIMITE_DESCOMPRESION,
    )
    .map_err(|_| CopiaError::DemasiadoGrande)?;
    comprimido.zeroize();

    let en_claro = claro.len();
    let contenido: Contenido = serde_json::from_slice(&claro)?;
    claro.zeroize();
    Ok((contenido, en_claro))
}

/// Cabecera en claro: lo justo para poder derivar y nada que revele contenido.
///
/// No lleva el número de entradas ni el tamaño en claro — eso iría a decir qué
/// tan grande es la bóveda a quien encuentre el archivo, que es justo lo que el
/// relleno acaba de esconder.
const CABECERA_LEN: usize = 69 + NONCE_LEN * 2;

#[allow(clippy::too_many_arguments)]
fn cabecera(
    params: &kdf::KdfParams,
    con_llave: bool,
    salt: &[u8; SALT_LEN],
    id_boveda: &[u8; 16],
    contador: u64,
    creada: u64,
    nonce_env: &[u8; NONCE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut c = vec![0u8; CABECERA_LEN];
    c[..7].copy_from_slice(MAGIA);
    c[7] = VERSION;
    c[8] = if con_llave { FLAG_LLAVE } else { 0 };
    c[9..13].copy_from_slice(&params.mem_kib.to_le_bytes());
    c[13..17].copy_from_slice(&params.iterations.to_le_bytes());
    c[17..21].copy_from_slice(&params.parallelism.to_le_bytes());
    c[21..37].copy_from_slice(salt);
    c[37..53].copy_from_slice(id_boveda);
    c[53..61].copy_from_slice(&contador.to_le_bytes());
    c[61..69].copy_from_slice(&creada.to_le_bytes());
    c[69..69 + NONCE_LEN].copy_from_slice(nonce_env);
    c[69 + NONCE_LEN..].copy_from_slice(nonce);
    c
}

/// Cuántos segundos han pasado desde un instante de los que guarda la copia.
///
/// Vive aquí y no en quien pregunta porque la copia es quien define en qué
/// unidad guarda su fecha; que cada llamante lo dedujera del campo sería
/// invitar a que uno se equivoque en silencio.
pub fn segundos_desde(cuando: u64) -> u64 {
    ahora().saturating_sub(cuando)
}

/// La cabecera entera va como AAD, así que cambiar un solo byte de ella
/// —la fecha, el contador, el id de origen— rompe el descifrado en vez de
/// producir una copia que miente sobre su procedencia.
fn ahora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
