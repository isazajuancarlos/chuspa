// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Códigos de un solo uso por tiempo (TOTP, RFC 6238).
//!
//! # Qué arregla esto
//!
//! La bóveda guarda el secreto TOTP tal como lo dio el servicio: casi siempre un
//! `otpauth://totp/...?secret=...`. Antes de este módulo, el enlace con el
//! navegador entregaba **ese texto** en el campo que decía «código ya
//! calculado». La extensión habría escrito la URI entera en la casilla de seis
//! dígitos.
//!
//! No era un fallo peligroso —no filtraba nada— pero sí uno de los que erosionan
//! la confianza en un gestor: el usuario ve un galimatías donde esperaba un
//! número, y a la tercera vez deja de usar la función.
//!
//! # Por qué se admite SHA-1
//!
//! SHA-1 está roto para firmas y **no lo está para HMAC**: los ataques de
//! colisión no se trasladan a HMAC-SHA1, y el RFC 6238 lo fija como algoritmo
//! por omisión. La inmensa mayoría de los servicios que dan un código de seis
//! dígitos usan SHA-1, así que rechazarlo no haría a nadie más seguro: haría que
//! el gestor no sirviera. Se admiten también SHA-256 y SHA-512, que algunos
//! servicios ya usan.
//!
//! # Lo que este módulo NO hace
//!
//! No sustituye a una llave física. Un código TOTP se puede pedir por teléfono y
//! teclear en una página falsa; una passkey no. Que Chuspa lo genere es una
//! comodidad, no una promesa de que el sitio es el correcto — para eso está la
//! comprobación de dominio de [`crate::navegador::coincidencia`], que decide si
//! la credencial se ofrece siquiera.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

/// Función de hash del HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algoritmo {
    /// El defecto del RFC 6238 y de casi todos los servicios.
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("el secreto no está en base32 válida: carácter «{caracter}» en la posición {posicion}")]
    Base32 { caracter: char, posicion: usize },

    #[error("el secreto está vacío")]
    SecretoVacio,

    #[error("«{0}» no es un algoritmo TOTP conocido (se admiten SHA1, SHA256 y SHA512)")]
    AlgoritmoDesconocido(String),

    #[error(
        "un código de {0} dígitos no es un TOTP válido: el RFC 6238 admite de 6 a 8, \
         y fuera de ese rango el código pierde o inventa entropía"
    )]
    DigitosFuera(u32),

    #[error("el periodo no puede ser cero: dividiría el tiempo entre nada")]
    PeriodoCero,

    #[error("no se pudo leer el reloj del sistema")]
    SinReloj,
}

/// Un generador de códigos, ya interpretado.
#[derive(Debug, Clone)]
pub struct Totp {
    secreto: Zeroizing<Vec<u8>>,
    pub algoritmo: Algoritmo,
    pub digitos: u32,
    pub periodo: u64,
    /// Lo que el servicio puso como nombre de cuenta, si venía en la URI.
    pub cuenta: Option<String>,
    /// Quién emite el código (`Google`, `GitHub`…), si venía.
    pub emisor: Option<String>,
}

impl Totp {
    /// Interpreta lo que hay guardado en la entrada.
    ///
    /// Admite las dos formas que se encuentran en la práctica: la URI completa
    /// `otpauth://totp/...` y el secreto base32 a pelo, que es lo que pega mucha
    /// gente desde la pantalla del servicio. Los espacios se ignoran porque los
    /// servicios los ponen para que el secreto se pueda leer en voz alta.
    pub fn interpretar(guardado: &str) -> Result<Self, TotpError> {
        let guardado = guardado.trim();
        if let Some(resto) = guardado
            .strip_prefix("otpauth://totp/")
            .or_else(|| guardado.strip_prefix("otpauth://TOTP/"))
        {
            Self::desde_uri(resto)
        } else {
            Ok(Self {
                secreto: descifrar_base32(guardado)?,
                algoritmo: Algoritmo::default(),
                digitos: 6,
                periodo: 30,
                cuenta: None,
                emisor: None,
            })
        }
    }

    fn desde_uri(resto: &str) -> Result<Self, TotpError> {
        let (etiqueta, consulta) = resto.split_once('?').unwrap_or((resto, ""));
        let etiqueta = decodificar_porcentaje(etiqueta);
        let (emisor_etiqueta, cuenta) = match etiqueta.split_once(':') {
            Some((e, c)) => (Some(e.trim().to_string()), Some(c.trim().to_string())),
            None if etiqueta.is_empty() => (None, None),
            None => (None, Some(etiqueta.clone())),
        };

        let (mut secreto, mut algoritmo, mut digitos, mut periodo, mut emisor) =
            (None, Algoritmo::default(), 6u32, 30u64, emisor_etiqueta);

        for par in consulta.split('&').filter(|p| !p.is_empty()) {
            let (clave, valor) = par.split_once('=').unwrap_or((par, ""));
            let valor = decodificar_porcentaje(valor);
            match clave.to_ascii_lowercase().as_str() {
                "secret" => secreto = Some(descifrar_base32(&valor)?),
                "algorithm" => {
                    algoritmo = match valor.to_ascii_uppercase().as_str() {
                        "SHA1" => Algoritmo::Sha1,
                        "SHA256" => Algoritmo::Sha256,
                        "SHA512" => Algoritmo::Sha512,
                        otro => return Err(TotpError::AlgoritmoDesconocido(otro.to_string())),
                    }
                }
                // Un parámetro con valor ilegible se ignora y se usa el defecto
                // del RFC: es lo que hace el resto del mundo, y fallar aquí
                // dejaría sin código a quien tiene una URI con una errata.
                "digits" => digitos = valor.parse().unwrap_or(6),
                "period" => periodo = valor.parse().unwrap_or(30),
                "issuer" => emisor = Some(valor),
                _ => {}
            }
        }

        let secreto = secreto.ok_or(TotpError::SecretoVacio)?;
        if !(6..=8).contains(&digitos) {
            return Err(TotpError::DigitosFuera(digitos));
        }
        if periodo == 0 {
            return Err(TotpError::PeriodoCero);
        }
        Ok(Self { secreto, algoritmo, digitos, periodo, cuenta, emisor })
    }

    /// El código para el instante dado, en segundos desde la época Unix.
    pub fn codigo_en(&self, segundos: u64) -> String {
        let contador = segundos / self.periodo;
        let mensaje = contador.to_be_bytes();

        let digest: Vec<u8> = match self.algoritmo {
            Algoritmo::Sha1 => {
                let mut m = Hmac::<sha1::Sha1>::new_from_slice(&self.secreto).expect("HMAC admite cualquier longitud de clave");
                m.update(&mensaje);
                m.finalize().into_bytes().to_vec()
            }
            Algoritmo::Sha256 => {
                let mut m = Hmac::<sha2::Sha256>::new_from_slice(&self.secreto).expect("HMAC admite cualquier longitud de clave");
                m.update(&mensaje);
                m.finalize().into_bytes().to_vec()
            }
            Algoritmo::Sha512 => {
                let mut m = Hmac::<sha2::Sha512>::new_from_slice(&self.secreto).expect("HMAC admite cualquier longitud de clave");
                m.update(&mensaje);
                m.finalize().into_bytes().to_vec()
            }
        };

        // Truncamiento dinámico del RFC 4226: el nibble bajo del último byte
        // dice por dónde cortar.
        let desplazamiento = (digest[digest.len() - 1] & 0x0f) as usize;
        let binario = u32::from_be_bytes([
            digest[desplazamiento] & 0x7f,
            digest[desplazamiento + 1],
            digest[desplazamiento + 2],
            digest[desplazamiento + 3],
        ]);
        let modulo = 10u32.pow(self.digitos);
        format!("{:0ancho$}", binario % modulo, ancho = self.digitos as usize)
    }

    /// El código de ahora mismo.
    pub fn codigo(&self) -> Result<String, TotpError> {
        let ahora = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TotpError::SinReloj)?
            .as_secs();
        Ok(self.codigo_en(ahora))
    }

    /// Segundos que le quedan de vida al código actual.
    ///
    /// La interfaz lo necesita: entregar un código que caduca en un segundo es
    /// entregar un código que va a fallar, y el usuario culpará al gestor.
    pub fn segundos_restantes(&self) -> Result<u64, TotpError> {
        let ahora = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TotpError::SinReloj)?
            .as_secs();
        Ok(self.periodo - (ahora % self.periodo))
    }
}

/// Base32 del RFC 4648, que es el que usa TOTP.
///
/// No se reutiliza el base32 de `quipu_nucleo::papel`: ese tiene su propio
/// alfabeto y sus propias correcciones de tecleo, pensadas para que una persona
/// copie de un papel. Aquí hay que leer exactamente lo que dice el estándar, y
/// mezclarlos daría códigos que no coinciden con los del teléfono.
fn descifrar_base32(texto: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    const ALFABETO: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut bits = 0u32;
    let mut acumulados = 0u32;
    let mut salida = Zeroizing::new(Vec::new());

    for (posicion, c) in texto.chars().enumerate() {
        // Los servicios reparten el secreto en grupos para poder leerlo; el
        // relleno `=` es opcional en TOTP y sobra al decodificar.
        if c.is_whitespace() || c == '-' || c == '=' {
            continue;
        }
        let mayuscula = c.to_ascii_uppercase();
        let valor = ALFABETO
            .iter()
            .position(|&a| a == mayuscula as u8)
            .ok_or(TotpError::Base32 { caracter: c, posicion })? as u32;

        bits = (bits << 5) | valor;
        acumulados += 5;
        if acumulados >= 8 {
            acumulados -= 8;
            salida.push((bits >> acumulados) as u8);
        }
    }
    if salida.is_empty() {
        return Err(TotpError::SecretoVacio);
    }
    Ok(salida)
}

/// Decodifica `%XX` en las etiquetas de la URI. Solo eso: no es un decodificador
/// de URL general, y no lo necesita.
fn decodificar_porcentaje(texto: &str) -> String {
    let bytes = texto.as_bytes();
    let mut salida = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let alto = (bytes[i + 1] as char).to_digit(16);
            let bajo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (alto, bajo) {
                salida.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        salida.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&salida).into_owned()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Los vectores del **apéndice B del RFC 6238**, tal cual están publicados.
    ///
    /// Esto es lo que hace que este módulo sea creíble: no se comprueba contra
    /// mi propia implementación —eso solo diría que es consistente consigo
    /// misma— sino contra los números que publica el estándar. Si el código de
    /// Chuspa no coincide con estos, tampoco coincidirá con el del teléfono.
    #[test]
    fn los_vectores_del_rfc_6238_cuadran() {
        // La semilla del RFC es ASCII "12345678901234567890" repetida hasta
        // llenar la longitud del hash. En base32:
        let sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        let sha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

        let casos: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];

        for &(t, esperado1, esperado256, esperado512) in casos {
            for (semilla, algoritmo, esperado) in [
                (sha1, Algoritmo::Sha1, esperado1),
                (sha256, Algoritmo::Sha256, esperado256),
                (sha512, Algoritmo::Sha512, esperado512),
            ] {
                let totp = Totp {
                    secreto: descifrar_base32(semilla).unwrap(),
                    algoritmo,
                    digitos: 8,
                    periodo: 30,
                    cuenta: None,
                    emisor: None,
                };
                assert_eq!(
                    totp.codigo_en(t),
                    esperado,
                    "RFC 6238, t={t}, {algoritmo:?}"
                );
            }
        }
    }

    #[test]
    fn se_interpreta_una_uri_completa() {
        let uri = "otpauth://totp/GitHub:juan?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub&digits=6&period=30";
        let t = Totp::interpretar(uri).unwrap();
        assert_eq!(t.emisor.as_deref(), Some("GitHub"));
        assert_eq!(t.cuenta.as_deref(), Some("juan"));
        assert_eq!(t.digitos, 6);
        assert_eq!(t.periodo, 30);
        assert_eq!(t.algoritmo, Algoritmo::Sha1);
        assert_eq!(t.codigo_en(59).len(), 6);
    }

    #[test]
    fn se_interpreta_un_secreto_a_pelo() {
        // Es lo que pega mucha gente desde la pantalla del servicio, con los
        // espacios que el servicio pone para poder leerlo.
        // La semilla del RFC son 20 bytes; con la mitad sale otro código, y esa
        // fue la primera versión equivocada de esta prueba.
        let t = Totp::interpretar("GEZDGNBV GY3TQOJQ GEZDGNBV GY3TQOJQ").unwrap();
        assert_eq!(t.digitos, 6);
        assert_eq!(t.codigo_en(59), "287082", "los 6 últimos del vector del RFC");
    }

    #[test]
    fn las_etiquetas_con_porcentaje_se_leen() {
        let uri = "otpauth://totp/Mi%20Banco:juan%40ejemplo.com?secret=GEZDGNBVGY3TQOJQ";
        let t = Totp::interpretar(uri).unwrap();
        assert_eq!(t.emisor.as_deref(), Some("Mi Banco"));
        assert_eq!(t.cuenta.as_deref(), Some("juan@ejemplo.com"));
    }

    #[test]
    fn un_periodo_distinto_cambia_el_codigo() {
        let a = Totp::interpretar("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=30").unwrap();
        let b = Totp::interpretar("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=60").unwrap();
        assert_ne!(a.codigo_en(59), b.codigo_en(59));
    }

    #[test]
    fn el_codigo_cambia_al_cambiar_de_ventana_y_no_dentro() {
        let t = Totp::interpretar("GEZDGNBVGY3TQOJQ").unwrap();
        // Dentro de la misma ventana de 30 s, el mismo código.
        assert_eq!(t.codigo_en(30), t.codigo_en(59));
        // En la siguiente, otro.
        assert_ne!(t.codigo_en(59), t.codigo_en(60));
    }

    #[test]
    fn lo_que_no_se_entiende_se_rechaza() {
        assert!(matches!(Totp::interpretar(""), Err(TotpError::SecretoVacio)));
        assert!(matches!(
            Totp::interpretar("no-es-base32-!!!"),
            Err(TotpError::Base32 { .. })
        ));
        assert!(matches!(
            Totp::interpretar("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5"),
            Err(TotpError::AlgoritmoDesconocido(_))
        ));
        // Un número de dígitos fuera del rango del RFC: 4 dígitos se adivinan y
        // 10 no caben en el truncamiento.
        assert!(matches!(
            Totp::interpretar("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=4"),
            Err(TotpError::DigitosFuera(4))
        ));
        assert!(matches!(
            Totp::interpretar("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0"),
            Err(TotpError::PeriodoCero)
        ));
    }

    #[test]
    fn el_codigo_siempre_tiene_los_digitos_pedidos() {
        // Un código con ceros por delante se muestra con ellos: «042931» no es
        // «42931», y el servicio rechazaría el segundo.
        let t = Totp::interpretar("GEZDGNBVGY3TQOJQ").unwrap();
        for segundo in (0..30_000).step_by(37) {
            let c = t.codigo_en(segundo);
            assert_eq!(c.len(), 6, "en t={segundo} salió «{c}»");
            assert!(c.chars().all(|d| d.is_ascii_digit()));
        }
    }

    #[test]
    fn el_secreto_no_aparece_en_la_depuracion() {
        // `Totp` deriva Debug y lleva el secreto dentro. Se comprueba que el
        // Zeroizing no lo imprime en claro.
        let t = Totp::interpretar("GEZDGNBVGY3TQOJQ").unwrap();
        let texto = format!("{t:?}");
        assert!(
            !texto.contains("GEZDGNBVGY3TQOJQ"),
            "el secreto en base32 no debe salir en Debug"
        );
    }
}
