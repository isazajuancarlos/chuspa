// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Descifrado del `os_crypt` de Chromium en Linux (Chrome, Brave, Edge,
//! Chromium). Es la primera fase del importador de contraseñas de navegadores:
//! una función PURA que toma los bytes cifrados de la columna `password_value`
//! y devuelve el texto claro. No abre archivos, no habla con el llavero y no
//! toca la bóveda — eso son fases aparte.
//!
//! # El formato, medido contra Chromium
//!
//! Cada `password_value` de la tabla `logins` es:
//!
//! ```text
//!   "v10" | "v11"  ++  AES-128-CBC( PKCS7(clave) )
//! ```
//!
//! - **IV = 16 bytes 0x20** (espacios). Es fijo en la implementación de Linux;
//!   no viaja con el dato.
//! - **Clave** = `PBKDF2-HMAC-SHA1(secreto, "saltysalt", iteraciones = 1,
//!   longitud = 16)`.
//! - **El secreto** depende del prefijo:
//!   - `v10`: la cadena literal `"peanuts"` — es lo que usa Chromium cuando no
//!     hay llavero (o el «basic» text store).
//!   - `v11`: el secreto «Chrome/Brave Safe Storage» que guarda el Secret
//!     Service (llavero de GNOME/KWallet). Obtenerlo es la fase 3; aquí solo se
//!     recibe ya resuelto.
//!
//! # Por qué a mano y no con `cbc`/`pbkdf2`
//!
//! El modo CBC y el relleno PKCS7 son triviales sobre el cifrador de bloque, y
//! con `iteraciones = 1` PBKDF2 se reduce a un solo bloque HMAC. Añadir las
//! crates `cbc` y `pbkdf2` habría metido dos dependencias nuevas en un producto
//! que guarda contraseñas —y que no las tenía vendorizadas offline— para código
//! que cabe en esta página. Se usa `aes` (la misma que quipu) para el cifrador,
//! y `hmac`/`sha1` que el árbol ya trae.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

/// El `salt` fijo de Chromium.
const SALT: &[u8] = b"saltysalt";
/// El IV fijo de la implementación de Linux: 16 espacios.
const IV: [u8; 16] = [0x20; 16];
/// El secreto que usa `v10` cuando no hay llavero.
pub const SECRETO_V10: &[u8] = b"peanuts";

/// Por qué no se pudo descifrar un valor. Se falla RUIDOSAMENTE (directiva 20):
/// un valor que no se puede leer se reporta, nunca se sustituye por vacío.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorOsCrypt {
    /// No empieza por `v10` ni `v11`. Puede ser un valor sin cifrar (Chromium
    /// muy viejo) o un formato que aún no manejamos: el importador debe decirlo,
    /// no adivinar.
    PrefijoDesconocido,
    /// El texto cifrado está vacío o su longitud no es múltiplo de 16. Un bloque
    /// CBC de AES mide 16 bytes exactos.
    LongitudInvalida,
    /// El relleno PKCS7 no cuadra. Casi siempre significa clave equivocada
    /// (secreto del llavero incorrecto), no un dato corrupto.
    RellenoInvalido,
}

/// Deriva la clave AES de 16 bytes a partir del secreto.
///
/// `PBKDF2-HMAC-SHA1(secreto, "saltysalt", 1, 16)`. Con una sola iteración, el
/// bloque `i = 1` de PBKDF2 es `U1 = HMAC-SHA1(secreto, salt ++ INT32BE(1))`, y
/// la clave son sus primeros 16 bytes (SHA-1 da 20). No hay más bloques porque
/// 16 ≤ 20.
pub fn derivar_clave(secreto: &[u8]) -> Zeroizing<[u8; 16]> {
    // HMAC admite una clave de cualquier longitud, así que esto no falla nunca;
    // aun así no se hace `unwrap` a ciegas.
    let mut mac = <Hmac<Sha1>>::new_from_slice(secreto)
        .expect("HMAC-SHA1 acepta una clave de cualquier longitud");
    mac.update(SALT);
    mac.update(&1u32.to_be_bytes());
    let u1 = mac.finalize().into_bytes(); // 20 bytes
    // La clave se envuelve en `Zeroizing`: se borra de memoria al soltarse, en vez
    // de quedar en el montón hasta que otra cosa lo pise. Es material sensible en
    // un gestor de contraseñas.
    let mut clave = Zeroizing::new([0u8; 16]);
    clave.copy_from_slice(&u1[..16]);
    clave
}

/// Descifra un `password_value` completo (con su prefijo) dada la clave ya
/// derivada. Función pura.
pub fn descifrar(blob: &[u8], clave: &[u8; 16]) -> Result<Vec<u8>, ErrorOsCrypt> {
    let cifrado = match blob.get(..3) {
        Some(b"v10") | Some(b"v11") => &blob[3..],
        _ => return Err(ErrorOsCrypt::PrefijoDesconocido),
    };
    if cifrado.is_empty() || cifrado.len() % 16 != 0 {
        return Err(ErrorOsCrypt::LongitudInvalida);
    }

    let cifrador = Aes128::new(&Array::from(*clave));
    let mut anterior = IV;
    let mut claro = Vec::with_capacity(cifrado.len());
    // `as_chunks::<16>()` en vez de `chunks_exact(16)`: ya se comprobó que la
    // longitud es múltiplo de 16, así que el resto (`.1`) está vacío.
    for &bloque_cifrado in cifrado.as_chunks::<16>().0 {
        let mut bloque = Array::from(bloque_cifrado);
        cifrador.decrypt_block(&mut bloque);
        let descifrado: [u8; 16] = bloque.into();
        // CBC: el bloque descifrado se XORea con el CIFRADO anterior (o el IV).
        let mut p = [0u8; 16];
        for j in 0..16 {
            p[j] = descifrado[j] ^ anterior[j];
        }
        claro.extend_from_slice(&p);
        anterior = bloque_cifrado;
    }

    quitar_relleno_pkcs7(&mut claro)?;
    Ok(claro)
}

/// Descifra recibiendo el secreto en claro (no la clave ya derivada). Es la vía
/// que usará el importador: `v10` con `"peanuts"`, `v11` con lo del llavero.
pub fn descifrar_con_secreto(blob: &[u8], secreto: &[u8]) -> Result<Vec<u8>, ErrorOsCrypt> {
    descifrar(blob, &derivar_clave(secreto))
}

/// Quita el relleno PKCS7 en el sitio. El último byte dice cuántos hay (1..=16),
/// y TODOS ellos tienen que valer ese número — si no, el relleno es inválido, que
/// es la señal habitual de clave equivocada.
fn quitar_relleno_pkcs7(datos: &mut Vec<u8>) -> Result<(), ErrorOsCrypt> {
    let n = *datos.last().ok_or(ErrorOsCrypt::RellenoInvalido)? as usize;
    if n == 0 || n > 16 || n > datos.len() {
        return Err(ErrorOsCrypt::RellenoInvalido);
    }
    if datos[datos.len() - n..].iter().any(|&b| b as usize != n) {
        return Err(ErrorOsCrypt::RellenoInvalido);
    }
    datos.truncate(datos.len() - n);
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Decodifica hex en las pruebas. Los VECTORES son independientes de este
    /// código: la clave la calculó `python3 hashlib.pbkdf2_hmac` y el texto
    /// cifrado lo produjo `openssl enc -aes-128-cbc` (directiva 33: la aguja no
    /// se fabrica con la misma ruta que se mide).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- vectores KAT independientes (v10, secreto "peanuts") ---
    const CLAVE_V10_HEX: &str = "fd621fe5a2b402539dfa147ca9272778";
    const BLOB_V10_HEX: &str =
        "763130cf6a57d0c0770678bd33d414ce8d1a3e910e7744949dd895841fb37a34a24652";
    const CLARO: &str = "hunter2-contraseña";

    // --- vector KAT independiente v11 (secreto distinto de "peanuts", como el
    // que daría el llavero) — mismo camino de código, distinto prefijo/secreto ---
    const SECRETO_V11: &[u8] = b"v11-safe-storage-secret-de-prueba";
    const BLOB_V11_HEX: &str =
        "7631312b730f1e034b6240bdf0745dd33543a5c42e05adef0fba3c62ee732986bae3bb";
    const CLARO_V11: &str = "clave-v11-áéí";

    #[test]
    fn la_clave_v10_coincide_con_el_oraculo_independiente() {
        // Si el salt, las iteraciones o el orden de bytes de INT(1) estuvieran
        // mal, esta clave NO saldría igual a la de hashlib.
        assert_eq!(&derivar_clave(SECRETO_V10)[..], hex(CLAVE_V10_HEX).as_slice());
    }

    #[test]
    fn descifra_el_kat_v10() {
        let blob = hex(BLOB_V10_HEX);
        let clave: [u8; 16] = hex(CLAVE_V10_HEX).try_into().unwrap();
        let claro = descifrar(&blob, &clave).unwrap();
        assert_eq!(claro, CLARO.as_bytes());
    }

    #[test]
    fn la_via_con_secreto_reproduce_el_kat() {
        // El camino real: recibe "peanuts", deriva y descifra en un paso.
        let blob = hex(BLOB_V10_HEX);
        let claro = descifrar_con_secreto(&blob, SECRETO_V10).unwrap();
        assert_eq!(claro, CLARO.as_bytes());
    }

    #[test]
    fn descifra_el_kat_v11_con_su_secreto() {
        // v11 usa el prefijo "v11" y un secreto del llavero, no "peanuts".
        let blob = hex(BLOB_V11_HEX);
        let claro = descifrar_con_secreto(&blob, SECRETO_V11).unwrap();
        assert_eq!(claro, CLARO_V11.as_bytes());
    }

    // --- casos rojos, cada uno por su vía real (directiva 33) ---

    // Los dos siguientes prueban `quitar_relleno_pkcs7` DIRECTAMENTE (el concilio
    // 2026-09-15 midió por mutación que el banco vía `descifrar` no los cubría: un
    // mutante `n > 16` → `n > 255` y otro que solo mira el último byte SOBREVIVÍAN
    // porque ningún vector fijo ejercitaba esas ramas por la vía no accidental).

    #[test]
    fn relleno_con_un_byte_interior_distinto_es_invalido() {
        // Último byte dice n=3, pero uno de los tres bytes de cola no vale 3.
        // Mata al mutante que solo comprobaría el ÚLTIMO byte.
        let mut datos = vec![0x41, 0x41, 0x41, 0x05, 0x03, 0x03];
        assert_eq!(quitar_relleno_pkcs7(&mut datos), Err(ErrorOsCrypt::RellenoInvalido));
    }

    #[test]
    fn relleno_mayor_de_16_es_invalido() {
        // n = 17, todos los bytes de cola valen 17: el chequeo `n > 16` es lo
        // único que lo rechaza. Mata al mutante `n > 16` → `n > 255`.
        let mut datos = vec![17u8; 17];
        assert_eq!(quitar_relleno_pkcs7(&mut datos), Err(ErrorOsCrypt::RellenoInvalido));
        // y n = 0 (todos ceros): el otro extremo del rango.
        let mut ceros = vec![0u8; 16];
        assert_eq!(quitar_relleno_pkcs7(&mut ceros), Err(ErrorOsCrypt::RellenoInvalido));
    }

    #[test]
    fn con_clave_equivocada_no_devuelve_el_texto() {
        // La defensa que importa: sin la clave correcta no se lee. Con la clave
        // mal, o el PKCS7 no cuadra (lo normal) o sale basura — nunca el claro.
        let blob = hex(BLOB_V10_HEX);
        let mala = [0u8; 16];
        assert_ne!(descifrar(&blob, &mala), Ok(CLARO.as_bytes().to_vec()));
    }

    #[test]
    fn rechaza_prefijo_desconocido() {
        // Sin prefijo, y con un prefijo parecido pero falso.
        assert_eq!(descifrar(b"hola", &[0u8; 16]), Err(ErrorOsCrypt::PrefijoDesconocido));
        let mut casi = hex(BLOB_V10_HEX);
        casi[2] = b'9'; // "v19"
        assert_eq!(descifrar(&casi, &[0u8; 16]), Err(ErrorOsCrypt::PrefijoDesconocido));
    }

    #[test]
    fn rechaza_longitud_no_multiplo_de_16() {
        let clave: [u8; 16] = hex(CLAVE_V10_HEX).try_into().unwrap();
        let mut corto = hex(BLOB_V10_HEX);
        corto.pop(); // el cifrado deja de ser múltiplo de 16
        assert_eq!(descifrar(&corto, &clave), Err(ErrorOsCrypt::LongitudInvalida));
        // v10 sin nada detrás
        assert_eq!(descifrar(b"v10", &clave), Err(ErrorOsCrypt::LongitudInvalida));
    }

    #[test]
    fn rechaza_relleno_corrupto() {
        // Un bloque cifrado alterado casi siempre rompe el PKCS7 del final.
        let clave: [u8; 16] = hex(CLAVE_V10_HEX).try_into().unwrap();
        let mut roto = hex(BLOB_V10_HEX);
        let ultimo = roto.len() - 1;
        roto[ultimo] ^= 0xFF;
        assert_eq!(descifrar(&roto, &clave), Err(ErrorOsCrypt::RellenoInvalido));
    }

    // --- round-trip propio para las longitudes límite del PKCS7 ---
    // Esto NO ancla las constantes (eso lo hace el KAT); ejercita el encadenado
    // CBC y el relleno en 0, 1, 15, 16 y 17 bytes, donde el padding cambia de
    // forma (un bloque entero de relleno cuando el texto ya es múltiplo de 16).

    fn cifrar_para_prueba(claro: &[u8], clave: &[u8; 16]) -> Vec<u8> {
        use aes::cipher::BlockCipherEncrypt;
        let n = 16 - (claro.len() % 16);
        let mut datos = claro.to_vec();
        datos.extend(std::iter::repeat_n(n as u8, n)); // PKCS7
        let cifrador = Aes128::new(&Array::from(*clave));
        let mut anterior = IV;
        let mut salida = b"v10".to_vec();
        for trozo in datos.as_chunks::<16>().0 {
            let mut b = [0u8; 16];
            for j in 0..16 {
                b[j] = trozo[j] ^ anterior[j];
            }
            let mut bloque = Array::from(b);
            cifrador.encrypt_block(&mut bloque);
            let c: [u8; 16] = bloque.into();
            salida.extend_from_slice(&c);
            anterior = c;
        }
        salida
    }

    #[test]
    fn round_trip_en_las_longitudes_limite() {
        let clave: [u8; 16] = hex(CLAVE_V10_HEX).try_into().unwrap();
        for largo in [0usize, 1, 15, 16, 17, 31, 32] {
            let claro: Vec<u8> = (0..largo).map(|i| (i * 7 + 3) as u8).collect();
            let blob = cifrar_para_prueba(&claro, &clave);
            assert_eq!(descifrar(&blob, &clave).unwrap(), claro, "largo {largo}");
        }
    }
}
