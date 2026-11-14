// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Descifrado del almacén de contraseñas de Firefox (NSS). Fase 6 del importador.
//!
//! Firefox guarda la clave maestra en `key4.db` (un SQLite con las tablas
//! `metaData` y `nssPrivate`) y las credenciales en `logins.json` (ASN.1 en
//! base64). La cadena, toda en Rust puro:
//!
//! 1. `metaData` da el `globalSalt` (item1) y un `password-check` (item2).
//! 2. La clave que protege el almacén se deriva así (peculiaridades de NSS):
//!    `k = SHA1(globalSalt || contraseña-primaria)`, y luego
//!    `PBKDF2-HMAC-SHA256(k, entrySalt, iteraciones)` de la ASN.1. La
//!    contraseña primaria vacía es `b""`.
//! 3. Se descifra con **AES-256-CBC**, y el IV es la peculiaridad más famosa:
//!    los 14 bytes almacenados se usan CON su envoltura ASN.1 `04 0E` delante,
//!    formando 16 bytes. Descifrar el `password-check` tiene que dar
//!    `"password-check"`: es el oráculo que valida la derivación.
//! 4. `nssPrivate.a11` se descifra igual y da la **clave maestra**.
//! 5. Cada entrada de `logins.json` es `SEQUENCE { keyId, AlgId{cifrador, IV},
//!    texto-cifrado }`. Se descifra con la clave maestra por **AES-256-CBC**
//!    (perfiles modernos) o **3DES-EDE-CBC** ([`super::des3`], perfiles viejos),
//!    según el OID del cifrador.
//!
//! El algoritmo se validó contra un perfil real (588 logins, 0 fallos) y contra
//! el oráculo `password-check`, sin exponer ninguna contraseña.

use super::des3;
use aes::Aes256;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Una credencial de Firefox ya descifrada. NO deriva `Debug`: `Zeroizing`
/// reenvía su `Debug` al contenido —no lo redacta—, así que un `{:?}`/`dbg!`
/// filtraría la contraseña. El `Debug` manual redacta los campos secretos, de
/// modo que cualquier futuro `{:?}` sobre este tipo sea inofensivo por
/// construcción (hallazgo del concilio, fase 6).
#[derive(Clone)]
pub struct Credencial {
    pub url: String,
    pub usuario: Zeroizing<String>,
    pub clave: Zeroizing<String>,
}

impl std::fmt::Debug for Credencial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credencial")
            .field("url", &self.url)
            .field("usuario", &"[redactado]")
            .field("clave", &"[redactado]")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorNss {
    /// `key4.db` no se pudo leer como SQLite.
    Key4(super::sqlite::ErrorSqlite),
    /// Falta la fila `password` en `metaData` o la clave en `nssPrivate`.
    SinClaveMaestra,
    /// `logins.json` no es un JSON con la forma esperada.
    LoginsIlegibles,
    /// La ASN.1 no tiene la forma esperada.
    Asn1,
    /// La contraseña primaria es incorrecta (el `password-check` no cuadra).
    ContrasenaPrimaria,
    /// Un cifrador que no manejamos (ni AES-256-CBC ni 3DES).
    CifradorDesconocido,
}

// ───────────────────────────── OIDs (cuerpo DER) ─────────────────────────────
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];
const OID_DES_EDE3_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];

// ───────────────────────────── ASN.1 DER mínimo ─────────────────────────────
/// Un nodo TLV: etiqueta, contenido y dónde sigue el siguiente.
struct Tlv<'a> {
    tag: u8,
    valor: &'a [u8],
    resto: &'a [u8],
}

/// Lee UN TLV desde el principio de `b`. Solo longitudes cortas (<128) y largas
/// de 1–2 bytes, que es todo lo que aparece en estos archivos.
fn tlv(b: &[u8]) -> Option<Tlv<'_>> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, ini) = if l0 & 0x80 == 0 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 2 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let valor = b.get(ini..ini + len)?;
    Some(Tlv { tag, valor, resto: &b[ini + len..] })
}

/// El contenido de un SEQUENCE (tag 0x30), o `None` si no lo es.
fn secuencia(b: &[u8]) -> Option<&[u8]> {
    let t = tlv(b)?;
    (t.tag == 0x30).then_some(t.valor)
}

// ───────────────────────────── primitivas cripto ─────────────────────────────
/// PBKDF2-HMAC-SHA256 a mano (la crate `pbkdf2` no está vendorizada; `hmac` y
/// `sha2` sí). Bloques de 32 bytes, tantos como haga falta para `dk_len`.
fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iteraciones: u32, dk_len: usize) -> Zeroizing<Vec<u8>> {
    let mut dk = Zeroizing::new(Vec::with_capacity(dk_len));
    let mut bloque = 1u32;
    while dk.len() < dk_len {
        // U1 = HMAC(pw, salt || INT(bloque))
        let mut mac = <Hmac<Sha256>>::new_from_slice(pw).expect("HMAC acepta cualquier clave");
        mac.update(salt);
        mac.update(&bloque.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iteraciones {
            let mut mac = <Hmac<Sha256>>::new_from_slice(pw).expect("HMAC acepta cualquier clave");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        dk.extend_from_slice(&t);
        t.iter_mut().for_each(|x| *x = 0);
        bloque += 1;
    }
    dk.truncate(dk_len);
    dk
}

fn sha1(datos: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut h = Sha1::new();
    h.update(datos);
    h.finalize().into()
}

/// AES-256-CBC descifrar, SIN quitar relleno (el llamante decide). `clave` 32,
/// `iv` 16.
fn aes256_cbc(datos: &[u8], clave: &[u8], iv: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if clave.len() != 32 || iv.len() != 16 || datos.is_empty() || !datos.len().is_multiple_of(16) {
        return None;
    }
    let cifrador = Aes256::new(&Array::from(<[u8; 32]>::try_from(clave).ok()?));
    let mut anterior: [u8; 16] = iv.try_into().ok()?;
    let mut claro = Zeroizing::new(Vec::with_capacity(datos.len()));
    for trozo in datos.as_chunks::<16>().0 {
        let mut bloque = Array::from(*trozo);
        cifrador.decrypt_block(&mut bloque);
        let d: [u8; 16] = bloque.into();
        let mut p = [0u8; 16];
        for j in 0..16 {
            p[j] = d[j] ^ anterior[j];
        }
        claro.extend_from_slice(&p);
        anterior = *trozo;
    }
    Some(claro)
}

/// Quita el relleno PKCS#7 (tamaño de bloque `bloque`), o `None` si es inválido.
fn sin_pkcs7(mut datos: Zeroizing<Vec<u8>>, bloque: usize) -> Option<Zeroizing<Vec<u8>>> {
    let pad = *datos.last()? as usize;
    if pad == 0 || pad > bloque || pad > datos.len() {
        return None;
    }
    if datos[datos.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    let n = datos.len() - pad;
    datos.truncate(n);
    Some(datos)
}

// ───────────────────────── descifrado PBES2 (key4.db) ─────────────────────────
/// Descifra un blob PBES2 de `key4.db` (`password-check` o la clave maestra) con
/// la contraseña primaria (vacía = `b""`). Devuelve el claro CON relleno.
fn descifrar_pbes2(blob: &[u8], global_salt: &[u8], primaria: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    // SEQUENCE { AlgId, ciphertext }
    let seq = secuencia(blob)?;
    let alg = tlv(seq)?;
    let ct = tlv(alg.resto)?;
    // AlgId = SEQUENCE { OID(PBES2), params }
    let alg_c = (alg.tag == 0x30).then_some(alg.valor)?;
    let _oid = tlv(alg_c)?; // OID PBES2 (no se comprueba; la forma manda)
    let params = secuencia(_oid.resto)?; // SEQUENCE { KDF, encScheme }
    let kdf = tlv(params)?;
    let enc = tlv(kdf.resto)?;
    // KDF = SEQUENCE { OID(PBKDF2), SEQUENCE { salt, iter, keyLen, prf } }
    let kdf_c = (kdf.tag == 0x30).then_some(kdf.valor)?;
    let _kdfoid = tlv(kdf_c)?;
    let kdfp = secuencia(_kdfoid.resto)?;
    let salt = tlv(kdfp)?; // OCTET STRING
    let iter = tlv(salt.resto)?; // INTEGER
    let klen = tlv(iter.resto)?; // INTEGER
    let entry_salt = (salt.tag == 0x04).then_some(salt.valor)?;
    let iteraciones = entero(iter.valor)? as u32;
    let key_len = entero(klen.valor)? as usize;
    // Cotas contra un `key4.db` hostil: `key_len` va a `Vec::with_capacity`, y un
    // valor gigante desborda la capacidad (pánico); un `iteraciones` enorme cuelga
    // el PBKDF2. Un `key4.db` legítimo usa `key_len` de 32 y pocas iteraciones. Es
    // la misma disciplina con que se endureció el lector SQLite (D20/fase 2).
    if key_len > 1024 || iteraciones > 10_000_000 {
        return None;
    }
    // encScheme = SEQUENCE { OID(aes256-CBC), IV(OCTET) }
    let enc_c = (enc.tag == 0x30).then_some(enc.valor)?;
    let _encoid = tlv(enc_c)?;
    let iv_tlv = tlv(_encoid.resto)?;
    // La peculiaridad NSS: el IV de AES son los 14 bytes CON su envoltura ASN.1
    // `04 0E` delante = 16 bytes. Se reconstruye del propio TLV.
    let iv: Vec<u8> = if iv_tlv.valor.len() == 14 {
        let mut v = vec![0x04, 0x0e];
        v.extend_from_slice(iv_tlv.valor);
        v
    } else {
        iv_tlv.valor.to_vec()
    };
    // k = SHA1(globalSalt || primaria); key = PBKDF2-SHA256(k, entrySalt, iter)
    let mut k = Vec::with_capacity(global_salt.len() + primaria.len());
    k.extend_from_slice(global_salt);
    k.extend_from_slice(primaria);
    let k = Zeroizing::new(k);
    let k1 = Zeroizing::new(sha1(&k).to_vec());
    let key = pbkdf2_sha256(&k1, entry_salt, iteraciones, key_len);
    let ciphertext = (ct.tag == 0x04).then_some(ct.valor)?;
    aes256_cbc(ciphertext, &key, &iv)
}

fn entero(b: &[u8]) -> Option<i64> {
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    let mut n = 0i64;
    for &x in b {
        n = (n << 8) | x as i64;
    }
    Some(n)
}

// ───────────────────────── descifrado de una credencial ─────────────────────────
/// Descifra una entrada de `logins.json` (`encryptedUsername`/`encryptedPassword`
/// ya en base64→bytes) con la clave maestra. Dispatcha AES-256-CBC o 3DES según
/// el OID del cifrador.
fn descifrar_credencial(blob: &[u8], maestra: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    // SEQUENCE { keyId(OCTET), AlgId{ OID, IV(OCTET) }, ciphertext(OCTET) }
    let seq = secuencia(blob)?;
    let keyid = tlv(seq)?;
    let alg = tlv(keyid.resto)?;
    let ct = tlv(alg.resto)?;
    let alg_c = (alg.tag == 0x30).then_some(alg.valor)?;
    let oid = tlv(alg_c)?;
    let iv = tlv(oid.resto)?;
    let ciphertext = (ct.tag == 0x04).then_some(ct.valor)?;
    let iv_b = (iv.tag == 0x04).then_some(iv.valor)?;
    if oid.valor == OID_AES256_CBC {
        sin_pkcs7(aes256_cbc(ciphertext, maestra, iv_b)?, 16)
    } else if oid.valor == OID_DES_EDE3_CBC {
        des3::descifrar_cbc(ciphertext, maestra, iv_b) // ya quita PKCS7
    } else {
        None
    }
}

// ───────────────────────────── entrada pública ─────────────────────────────
/// Descifra todas las credenciales de un perfil Firefox. `key4_db` es el archivo
/// entero; `logins_json` su texto; `primaria` la contraseña primaria (vacía =
/// `b""`). No imprime ni registra ningún secreto.
pub fn descifrar_perfil(
    key4_db: &[u8],
    logins_json: &str,
    primaria: &[u8],
) -> Result<(Vec<Credencial>, usize), ErrorNss> {
    // 1) metaData: globalSalt (item1) + password-check (item2).
    let (cols_m, filas_m) = super::sqlite::leer_tabla_bytes(key4_db, "metaData").map_err(ErrorNss::Key4)?;
    let ci = |cols: &[String], n: &str| cols.iter().position(|c| c == n);
    let (i_id, i1, i2) = (
        ci(&cols_m, "id").ok_or(ErrorNss::SinClaveMaestra)?,
        ci(&cols_m, "item1").ok_or(ErrorNss::SinClaveMaestra)?,
        ci(&cols_m, "item2").ok_or(ErrorNss::SinClaveMaestra)?,
    );
    let mut global_salt = None;
    let mut pwcheck = None;
    for f in &filas_m {
        if f.get(i_id).and_then(|c| c.as_deref()) == Some(b"password") {
            global_salt = f.get(i1).and_then(|c| c.clone());
            pwcheck = f.get(i2).and_then(|c| c.clone());
        }
    }
    let global_salt = global_salt.ok_or(ErrorNss::SinClaveMaestra)?;
    let pwcheck = pwcheck.ok_or(ErrorNss::SinClaveMaestra)?;

    // 2) Validar la contraseña primaria con el oráculo password-check.
    let check = descifrar_pbes2(&pwcheck, &global_salt, primaria).ok_or(ErrorNss::Asn1)?;
    if !check.starts_with(b"password-check") {
        return Err(ErrorNss::ContrasenaPrimaria);
    }

    // 3) nssPrivate.a11 → clave maestra (con la misma derivación PBES2). Se elige
    //    la fila por su CKA_ID (`a102 == f8000…0001`), no la primera con `a11`:
    //    un perfil con OTRAS claves privadas (S/MIME, certos de cliente) podría
    //    ordenar otra antes y daríamos con la clave equivocada.
    const CKA_ID_MAESTRA: &[u8] = &[
        0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let (cols_n, filas_n) = super::sqlite::leer_tabla_bytes(key4_db, "nssPrivate").map_err(ErrorNss::Key4)?;
    let i_a11 = ci(&cols_n, "a11").ok_or(ErrorNss::SinClaveMaestra)?;
    let i_a102 = ci(&cols_n, "a102");
    let fila_maestra = |f: &&Vec<Option<Vec<u8>>>| {
        // Si hay columna a102, exige el CKA_ID; si no, cae a la primera con a11.
        match i_a102 {
            Some(j) => f.get(j).and_then(|c| c.as_deref()) == Some(CKA_ID_MAESTRA),
            None => true,
        }
    };
    let a11 = filas_n
        .iter()
        .filter(fila_maestra)
        .find_map(|f| f.get(i_a11).and_then(|c| c.clone()))
        .ok_or(ErrorNss::SinClaveMaestra)?;
    let maestra_con_pad = descifrar_pbes2(&a11, &global_salt, primaria).ok_or(ErrorNss::Asn1)?;
    let maestra = sin_pkcs7(maestra_con_pad, 16)
        .or_else(|| sin_pkcs7_bloque8(&a11, &global_salt, primaria))
        .ok_or(ErrorNss::SinClaveMaestra)?;

    // 4) logins.json → descifrar cada credencial.
    let json: serde_json::Value =
        serde_json::from_str(logins_json).map_err(|_| ErrorNss::LoginsIlegibles)?;
    let logins = json.get("logins").and_then(|l| l.as_array()).ok_or(ErrorNss::LoginsIlegibles)?;
    let mut salida = Vec::new();
    for l in logins {
        let url = l
            .get("hostname")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        let usuario = descifrar_campo(l, "encryptedUsername", &maestra);
        let clave = descifrar_campo(l, "encryptedPassword", &maestra);
        if let (Some(u), Some(c)) = (usuario, clave) {
            salida.push(Credencial {
                url,
                usuario: Zeroizing::new(u),
                clave: Zeroizing::new(c),
            });
        }
        // Una entrada que no descifra se omite (el llamante la contará como
        // sin_descifrar); no se inventa nada (D20).
    }
    Ok((salida, logins.len()))
}

/// La clave maestra tiene relleno de bloque de 8 (3DES) en perfiles viejos y de
/// 16 (AES) en modernos; se prueba el de 8 si el de 16 no cuadró.
fn sin_pkcs7_bloque8(a11: &[u8], gs: &[u8], primaria: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    sin_pkcs7(descifrar_pbes2(a11, gs, primaria)?, 8)
}

fn descifrar_campo(login: &serde_json::Value, campo: &str, maestra: &[u8]) -> Option<String> {
    use base64ct::{Base64, Encoding};
    let b64 = login.get(campo)?.as_str()?;
    let blob = Base64::decode_vec(b64).ok()?;
    let claro = descifrar_credencial(&blob, maestra)?;
    String::from_utf8(claro.to_vec()).ok()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn pbkdf2_sha256_contra_vector_conocido() {
        // RFC-estilo: pw="password", salt="salt", iter=1 → primer bloque conocido
        // (comprobado con hashlib): 0x120fb6cffcf8b32c43e7225256c4f837a86548c9.
        let dk = pbkdf2_sha256(b"password", b"salt", 1, 20);
        assert_eq!(hex(&dk), "120fb6cffcf8b32c43e7225256c4f837a86548c9");
        // iter=2 ejerce el acumulador XOR de U2 (el bucle de iteraciones), que
        // el caso iter=1 no toca (concilio fase 6, fable obs 2). Vía hashlib.
        let dk2 = pbkdf2_sha256(b"password", b"salt", 2, 20);
        assert_eq!(hex(&dk2), "ae4d0c95af6b46d32d0adff928f06dd02a303f8e");
    }

    /// KAT del descifrado PBES2 de `key4.db` con un vector REAL de Firefox (un
    /// perfil desechable generado por el propio Firefox), horneado para que corra
    /// en CI sin necesitar un perfil. Ancla la cadena entera —`SHA1(globalSalt)`,
    /// PBKDF2-HMAC-SHA256, la peculiaridad del IV `04 0E`+14 y AES-256-CBC— contra
    /// el oráculo `password-check` que el propio Firefox mete. Cierra el hueco que
    /// el concilio (fase 6) señaló: sin esto, la ruta solo la validaba un e2e
    /// `#[ignore]`. Muta el `04 0E`, la SHA1 o el AES y esta prueba enrojece (D33).
    #[test]
    fn pbes2_key4db_contra_vector_real_de_firefox() {
        let global_salt = hex_a_bytes("DB8F422A3AB01A79099213DD6871E27CF7EF3566");
        // item2 de metaData (id='password'): la ASN.1 del password-check.
        let pwcheck = hex_a_bytes(
            "308181306D06092A864886F70D01050D3060304106092A864886F70D01050C30340420\
             6025C0E0A9D1107E4C14359AB6C978E15B3F0C0735385009F942F0130BE2C00D020101\
             020120300A06082A864886F70D0209301B060960864801650304012A040EEA3CD215A5\
             AC5F11A03CF27A6E820410A7C8ED872DD7EDFCDED4BEFB9878A6B0",
        );
        // Con la contraseña primaria vacía, el claro empieza por «password-check».
        let claro = descifrar_pbes2(&pwcheck, &global_salt, b"").expect("debe descifrar");
        assert!(
            claro.starts_with(b"password-check"),
            "la derivación PBES2 de key4.db no da el oráculo password-check"
        );
        // Control: una contraseña primaria equivocada NO da el oráculo.
        let malo = descifrar_pbes2(&pwcheck, &global_salt, b"primaria-equivocada");
        assert!(
            malo.map(|c| c.starts_with(b"password-check")) != Some(true),
            "una primaria equivocada no puede pasar el oráculo"
        );
    }

    /// KAT MULTIBLOQUE de `aes256_cbc` cruzado con OPENSSL. Cierra el hueco que
    /// el concilio (fase 6, opus) probó: el `password-check` es de UN bloque, así
    /// que valida la derivación pero NO el encadenamiento CBC; romper `anterior =
    /// *trozo` dejaba el CI en verde. Este vector de DOS bloques lo caza (D33).
    #[test]
    fn aes256_cbc_multibloque_contra_openssl() {
        let key = hex_a_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = hex_a_bytes("000102030405060708090a0b0c0d0e0f");
        let ct = hex_a_bytes("1ff2c3477a831f2b5cbcf1e210ee3e2c44917b7ae9583c817e3770510d26c279");
        let pt = b"bloque-uno-de16!bloque-dos-de16!"; // 32 bytes, 2 bloques
        let claro = aes256_cbc(&ct, &key, &iv).expect("debe descifrar");
        assert_eq!(&claro[..], pt, "AES-256-CBC multibloque no coincide con openssl");
        // Control: un IV equivocado corrompe SOLO el primer bloque (propiedad CBC),
        // así que el resultado difiere del claro.
        let iv2 = hex_a_bytes("0102030405060708090a0b0c0d0e0f00");
        assert!(aes256_cbc(&ct, &key, &iv2).map(|c| c.to_vec()) != Some(pt.to_vec()));
    }

    fn hex_a_bytes(h: &str) -> Vec<u8> {
        let limpio: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        (0..limpio.len() / 2)
            .map(|i| u8::from_str_radix(&limpio[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Cierra el hueco #1 del concilio (opus + fable): NINGUNA prueba offline
    /// ejercía `descifrar_perfil` ENTERO (leer metaData/nssPrivate, oráculo
    /// password-check, selección por CKA_ID, clave maestra, parseo de
    /// logins.json, dispatch AES). Este fixture lo hace con un `key4.db` y un
    /// `logins.json` SINTÉTICOS construidos por python+openssl (oráculo
    /// independiente del lector Rust) con una credencial CONOCIDA. La fila señuelo
    /// en `nssPrivate` prueba que el filtro por CKA_ID escoge la maestra correcta.
    #[test]
    fn descifrar_perfil_completo_contra_fixture_sintetico() {
        const KEY4: &[u8] = include_bytes!("key4_fixture.db");
        const LOGINS: &str = include_str!("logins_fixture.json");
        let (creds, total) = descifrar_perfil(KEY4, LOGINS, b"").expect("debe descifrar el fixture");
        assert_eq!(total, 1);
        assert_eq!(creds.len(), 1, "la credencial conocida se descifra");
        assert_eq!(creds[0].url, "https://ejemplo.com");
        assert_eq!(&*creds[0].usuario, "usuario-conocido");
        assert_eq!(&*creds[0].clave, "clave-conocida-42");
    }

    /// Control del anterior (D33): una contraseña primaria equivocada NO descifra
    /// el fixture (el oráculo password-check lo corta).
    #[test]
    fn el_fixture_rechaza_una_primaria_equivocada() {
        const KEY4: &[u8] = include_bytes!("key4_fixture.db");
        const LOGINS: &str = include_str!("logins_fixture.json");
        assert!(matches!(
            descifrar_perfil(KEY4, LOGINS, b"equivocada"),
            Err(ErrorNss::ContrasenaPrimaria)
        ));
    }

    /// Un perfil CON contraseña primaria: descifra con la primaria CORRECTA, y
    /// falla ruidoso con la vacía o una equivocada. Ejerce la ruta de la primaria
    /// no vacía (el perfil real de prueba no la tiene, así que va por fixture).
    #[test]
    fn un_perfil_con_primaria_necesita_la_primaria_correcta() {
        const KEY4: &[u8] = include_bytes!("key4_fixture_primaria.db");
        const LOGINS: &str = include_str!("logins_fixture_primaria.json");
        // Correcta → descifra.
        let (creds, _) = descifrar_perfil(KEY4, LOGINS, b"clave-primaria-secreta")
            .expect("con la primaria correcta descifra");
        assert_eq!(creds.len(), 1);
        assert_eq!(&*creds[0].usuario, "user-primaria");
        assert_eq!(&*creds[0].clave, "pass-primaria");
        // Vacía y equivocada → ContrasenaPrimaria (falla ruidoso, no basura).
        assert!(matches!(descifrar_perfil(KEY4, LOGINS, b""), Err(ErrorNss::ContrasenaPrimaria)));
        assert!(matches!(descifrar_perfil(KEY4, LOGINS, b"otra"), Err(ErrorNss::ContrasenaPrimaria)));
    }

    /// Guardián del hallazgo del concilio (fase 6): el `Debug` de `Credencial`
    /// redacta usuario y clave.
    #[test]
    fn el_debug_de_credencial_no_filtra_secretos() {
        let c = Credencial {
            url: "https://sitio.com".into(),
            usuario: Zeroizing::new("ana".into()),
            clave: Zeroizing::new("CONTRASENA-real".into()),
        };
        let d = format!("{c:?}");
        assert!(!d.contains("CONTRASENA-real"), "filtró la clave: {d}");
        assert!(!d.contains("ana"), "filtró el usuario: {d}");
        assert!(d.contains("sitio.com") && d.contains("redactado"));
    }

    #[test]
    fn tlv_lee_secuencia_y_octet() {
        // SEQUENCE { OCTET STRING(3){AA BB CC} }
        let der = [0x30, 0x05, 0x04, 0x03, 0xAA, 0xBB, 0xCC];
        let seq = secuencia(&der).unwrap();
        let o = tlv(seq).unwrap();
        assert_eq!(o.tag, 0x04);
        assert_eq!(o.valor, &[0xAA, 0xBB, 0xCC]);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // e2e contra un perfil Firefox REAL (necesita ~/.config/mozilla/... o
    // ~/.mozilla/...). No imprime ninguna contraseña; solo cuenta. Se corre a
    // mano donde hay perfil (directiva 28):
    //   cargo test --release descifrar_firefox_real -- --ignored --nocapture
    #[test]
    #[ignore = "necesita un perfil Firefox real con contraseñas"]
    fn descifrar_firefox_real() {
        let mut base = std::path::PathBuf::from(std::env::var("HOME").unwrap());
        base.push(".config/mozilla/firefox");
        if !base.is_dir() {
            base = std::path::PathBuf::from(std::env::var("HOME").unwrap());
            base.push(".mozilla/firefox");
        }
        let Ok(entradas) = std::fs::read_dir(&base) else {
            println!("no hay carpeta de perfiles Firefox; se omite");
            return;
        };
        for e in entradas.flatten() {
            let p = e.path();
            let (k4, lj) = (p.join("key4.db"), p.join("logins.json"));
            if !(k4.is_file() && lj.is_file()) {
                continue;
            }
            let db = std::fs::read(&k4).unwrap();
            let json = std::fs::read_to_string(&lj).unwrap();
            match descifrar_perfil(&db, &json, b"") {
                Ok((creds, total)) => {
                    let vacias = creds.iter().filter(|c| c.clave.is_empty()).count();
                    println!(
                        "perfil {:?}: {}/{} credenciales descifradas ({} con clave vacía); NINGUNA se imprime",
                        p.file_name().unwrap(),
                        creds.len(),
                        total,
                        vacias
                    );
                    assert!(!creds.is_empty(), "el perfil tenía logins");
                }
                Err(e) => println!("perfil {:?}: {:?}", p.file_name().unwrap(), e),
            }
        }
    }
}
