// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! DES y 3DES-EDE en CBC, en Rust puro y a mano. Parte de la fase 6 del
//! importador: Firefox VIEJO cifra las entradas de `logins.json` con
//! `des-ede3-cbc` (los perfiles modernos usan AES-256-CBC, que ya tenemos). No
//! hay crate `des` vendorizada offline, así que se implementa aquí —como se hizo
//! con AES en [`super::oscrypt`]— y se ancla con los vectores KAT del NIST, que
//! es la única forma honesta de dar por bueno un cifrador escrito a mano (D33).
//!
//! DES está roto para proteger datos nuevos; aquí solo se USA para DESCIFRAR lo
//! que Firefox ya escribió. No se ofrece para cifrar nada.

use zeroize::Zeroizing;

// ─────────────────────────── tablas estándar de DES ───────────────────────────
// (FIPS 46-3). Los índices son 1-based como en el estándar; se restan al usar.

/// Permutación inicial.
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Permutación final (inversa de IP).
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansión E: 32 → 48 bits.
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// Permutación P tras las S-boxes.
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

/// PC-1: 64 → 56 bits (quita los de paridad).
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

/// PC-2: 56 → 48 bits (genera la subclave de cada ronda).
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Rotaciones a la izquierda por ronda.
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// Las 8 S-boxes (cada una 4×16 aplanada a 64).
const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
        12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8,
        7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Toma el bit en la posición 1-based `pos` (desde el MSB) de un valor de `ancho`
/// bits.
fn bit(valor: u64, pos: u8, ancho: u8) -> u64 {
    (valor >> (ancho - pos)) & 1
}

/// Aplica una tabla de permutación: por cada índice, saca ese bit de la entrada.
fn permutar(entrada: u64, tabla: &[u8], ancho_entrada: u8) -> u64 {
    let mut salida = 0u64;
    for &p in tabla {
        salida = (salida << 1) | bit(entrada, p, ancho_entrada);
    }
    salida
}

/// Las 16 subclaves de 48 bits a partir de una clave de 8 bytes.
fn subclaves(clave8: &[u8]) -> [u64; 16] {
    let clave = u64::from_be_bytes(clave8.try_into().expect("clave DES de 8 bytes"));
    let permutada = permutar(clave, &PC1, 64); // 56 bits
    let mut c = (permutada >> 28) & 0x0FFF_FFFF;
    let mut d = permutada & 0x0FFF_FFFF;
    let mut ks = [0u64; 16];
    for (i, ks_i) in ks.iter_mut().enumerate() {
        let s = SHIFTS[i];
        c = ((c << s) | (c >> (28 - s))) & 0x0FFF_FFFF;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFF_FFFF;
        let cd = (c << 28) | d;
        *ks_i = permutar(cd, &PC2, 56); // 48 bits
    }
    ks
}

/// La función f de Feistel: 32 bits de medio bloque + subclave → 32 bits.
fn feistel(r: u64, subclave: u64) -> u64 {
    let expandido = permutar(r, &E, 32) ^ subclave; // 48 bits
    let mut salida = 0u64;
    for (i, caja) in S.iter().enumerate() {
        let seis = (expandido >> (42 - 6 * i as u64)) & 0x3F;
        let fila = ((seis >> 5) << 1) | (seis & 1);
        let col = (seis >> 1) & 0x0F;
        salida = (salida << 4) | caja[(fila * 16 + col) as usize] as u64;
    }
    permutar(salida, &P, 32)
}

/// Un bloque DES (cifra o descifra según el orden de las subclaves).
fn des_bloque(bloque: u64, ks: &[u64; 16], descifrar: bool) -> u64 {
    let permutado = permutar(bloque, &IP, 64);
    let mut l = (permutado >> 32) & 0xFFFF_FFFF;
    let mut r = permutado & 0xFFFF_FFFF;
    for i in 0..16 {
        let k = if descifrar { ks[15 - i] } else { ks[i] };
        let nuevo = l ^ feistel(r, k);
        l = r;
        r = nuevo;
    }
    let rl = (r << 32) | l; // se intercambian al final
    permutar(rl, &FP, 64)
}

/// 3DES-EDE con una clave de 24 bytes (K1|K2|K3): C = E_k1(D_k2(E_k3(P)))… no.
/// La convención EDE de descifrado invierte: P = D_k1(E_k2(D_k3(C))).
struct Tdes {
    k1: [u64; 16],
    k2: [u64; 16],
    k3: [u64; 16],
}

impl Tdes {
    fn nueva(clave24: &[u8]) -> Option<Self> {
        if clave24.len() != 24 {
            return None;
        }
        Some(Tdes {
            k1: subclaves(&clave24[0..8]),
            k2: subclaves(&clave24[8..16]),
            k3: subclaves(&clave24[16..24]),
        })
    }
    /// Descifra un bloque: EDE al revés → D_k1(E_k2(D_k3(C))).
    fn descifrar_bloque(&self, c: u64) -> u64 {
        let a = des_bloque(c, &self.k3, true);
        let b = des_bloque(a, &self.k2, false);
        des_bloque(b, &self.k1, true)
    }
}

/// Descifra `datos` con 3DES-EDE en CBC y quita el relleno PKCS#7. `clave` son 24
/// bytes; `iv` son 8. Es lo que hace falta para `des-ede3-cbc` de Firefox viejo.
pub fn descifrar_cbc(datos: &[u8], clave: &[u8], iv: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let tdes = Tdes::nueva(clave)?;
    if iv.len() != 8 || datos.is_empty() || !datos.len().is_multiple_of(8) {
        return None;
    }
    let mut anterior = u64::from_be_bytes(iv.try_into().ok()?);
    let mut salida = Zeroizing::new(Vec::with_capacity(datos.len()));
    for trozo in datos.as_chunks::<8>().0 {
        let c = u64::from_be_bytes(*trozo);
        let claro = tdes.descifrar_bloque(c) ^ anterior;
        salida.extend_from_slice(&claro.to_be_bytes());
        anterior = c;
    }
    // PKCS#7 unpad.
    let pad = *salida.last()? as usize;
    if pad == 0 || pad > 8 || pad > salida.len() {
        return None;
    }
    if salida[salida.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    let nueva_len = salida.len() - pad;
    salida.truncate(nueva_len);
    Some(salida)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// KAT de DES simple (FIPS 81 / vector clásico de Feistel): clave
    /// 133457799BBCDFF1, claro 0123456789ABCDEF → cifrado 85E813540F0AB405.
    /// Se comprueba por la vía de DESCIFRAR (que es lo que usamos): descifrar el
    /// cifrado con esa clave TIENE que devolver el claro.
    #[test]
    fn des_simple_kat_del_nist() {
        let ks = subclaves(&hex(b"133457799BBCDFF1"));
        let cifrado = u64::from_be_bytes(hex(b"85E813540F0AB405"));
        let claro = des_bloque(cifrado, &ks, true);
        assert_eq!(claro.to_be_bytes(), hex(b"0123456789ABCDEF"), "DES no descifra el KAT");
        // Y el control: cifrar el claro reproduce el cifrado (el mutante que
        // rompa una tabla falla por los dos lados).
        let re = des_bloque(u64::from_be_bytes(hex(b"0123456789ABCDEF")), &ks, false);
        assert_eq!(re.to_be_bytes(), hex(b"85E813540F0AB405"));
    }

    /// KAT de 3DES-EDE (NIST SP 800-67, tres claves iguales = DES simple): con
    /// K1=K2=K3, 3DES-EDE descifrar equivale a DES descifrar. Aguja + control.
    #[test]
    fn tdes_ede_tres_claves_iguales_es_des() {
        let k = hex(b"133457799BBCDFF1");
        let mut k24 = [0u8; 24];
        k24[0..8].copy_from_slice(&k);
        k24[8..16].copy_from_slice(&k);
        k24[16..24].copy_from_slice(&k);
        let tdes = Tdes::nueva(&k24).unwrap();
        let cifrado = u64::from_be_bytes(hex(b"85E813540F0AB405"));
        assert_eq!(
            tdes.descifrar_bloque(cifrado).to_be_bytes(),
            hex(b"0123456789ABCDEF"),
            "3DES-EDE con claves iguales debe igualar a DES"
        );
    }

    /// KAT de 3DES-EDE con tres claves DISTINTAS contra OPENSSL (oráculo
    /// independiente): `openssl enc -des-ede3-cbc` con IV=0 del bloque
    /// 6BC1BEE22E409F96 y esa clave da 714772F339841D34; descifrarlo con IV=0
    /// tiene que devolver el bloque.
    #[test]
    fn tdes_cbc_kat_tres_claves_distintas() {
        let clave = hex_vec(b"0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
        let ct = hex(b"714772F339841D34"); // de openssl
        let tdes = Tdes::nueva(&clave).unwrap();
        let bloque = u64::from_be_bytes(ct);
        let claro = tdes.descifrar_bloque(bloque); // IV = 0
        assert_eq!(claro.to_be_bytes(), hex(b"6BC1BEE22E409F96"), "3DES no coincide con openssl");
    }

    /// El desenrollo CBC + PKCS7 de la API pública, cruzado con OPENSSL: el
    /// cifrado de «hola-firefox» con esa clave/iv por openssl es
    /// FB98480ED8E8E5C97629E99C95F70298, y `descifrar_cbc` tiene que recuperar el
    /// texto. Doble control: (a) coincide con el cifrado de openssl, (b) un IV
    /// equivocado NO acierta.
    #[test]
    fn descifrar_cbc_contra_openssl_y_su_control() {
        let clave = hex_vec(b"0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
        let iv = hex(b"0011223344556677");
        let claro = b"hola-firefox";
        let cifrado_openssl = hex_vec(b"FB98480ED8E8E5C97629E99C95F70298");
        // (a) descifrar lo que produjo openssl devuelve el claro.
        let recuperado = descifrar_cbc(&cifrado_openssl, &clave, &iv).unwrap();
        assert_eq!(&recuperado[..], claro, "no descifra el texto de openssl");
        // (b) nuestro cifrado propio coincide byte a byte con el de openssl.
        assert_eq!(cifrar_cbc_pkcs7(claro, &clave, &iv), cifrado_openssl, "el CBC no cuadra con openssl");
        // (c) control: un IV equivocado NO puede devolver el claro.
        let iv2 = hex(b"0011223344556678");
        let malo = descifrar_cbc(&cifrado_openssl, &clave, &iv2);
        assert!(malo.map(|z| z.to_vec()) != Some(claro.to_vec()), "un IV equivocado no puede acertar");
    }

    // ── ayudas de prueba (solo cifran para armar los KAT; producción solo descifra) ──
    fn hex(h: &[u8]) -> [u8; 8] {
        let v = hex_vec(h);
        let mut a = [0u8; 8];
        a.copy_from_slice(&v[..8.min(v.len())]);
        if v.len() == 8 { a } else { panic!("hex de 8 bytes") }
    }
    fn hex_vec(h: &[u8]) -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(std::str::from_utf8(&h[2 * i..2 * i + 2]).unwrap(), 16).unwrap())
            .collect()
    }
    fn cifrar_bloque_ede(b: u64, clave: &[u8]) -> u64 {
        let k1 = subclaves(&clave[0..8]);
        let k2 = subclaves(&clave[8..16]);
        let k3 = subclaves(&clave[16..24]);
        // EDE cifrar: E_k1(D_k2(E_k3(P)))… la inversa exacta de descifrar_bloque.
        let a = des_bloque(b, &k1, false);
        let b2 = des_bloque(a, &k2, true);
        des_bloque(b2, &k3, false)
    }
    fn cifrar_cbc_pkcs7(claro: &[u8], clave: &[u8], iv: &[u8]) -> Vec<u8> {
        let pad = 8 - (claro.len() % 8);
        let mut datos = claro.to_vec();
        datos.extend(std::iter::repeat_n(pad as u8, pad));
        let mut anterior = u64::from_be_bytes(iv.try_into().unwrap());
        let mut out = Vec::new();
        for trozo in datos.as_chunks::<8>().0 {
            let p = u64::from_be_bytes(*trozo) ^ anterior;
            let c = cifrar_bloque_ede(p, clave);
            out.extend_from_slice(&c.to_be_bytes());
            anterior = c;
        }
        out
    }
}
