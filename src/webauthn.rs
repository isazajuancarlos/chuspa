// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Usar las passkeys guardadas para entrar en los sitios (WebAuthn).
//!
//! # Qué es firmar aquí
//!
//! Una passkey es un par de claves. El sitio guarda la pública; nosotros la
//! privada. Al entrar, el sitio manda un **reto** aleatorio y espera de vuelta
//! una firma que solo puede hacer quien tenga la privada. Eso es todo el
//! mecanismo, y es lo que lo hace inmune al phishing: la firma cubre el
//! **origen** de la página, así que una copia del sitio en otro dominio recibe
//! una firma que su servidor rechaza.
//!
//! Este módulo hace esa firma. Lo que envuelve —interceptar la llamada del
//! navegador y devolver el objeto que la página espera— vive en la extensión.
//!
//! # El origen se comprueba aquí, no se confía
//!
//! El dato más peligroso de todo el flujo es el `rpId`: el dominio para el que
//! se firma. Si se aceptara el que dice la página, una web falsa pediría una
//! firma para `banco.com` desde `banco.com.evil.example` y la conseguiría.
//!
//! Por eso el agente **recibe el origen que determina el navegador** —no la
//! página— y comprueba que el `rpId` sea ese host o un dominio padre suyo, que
//! es exactamente lo que exige la especificación. La comprobación es por
//! etiquetas de dominio, con las mismas reglas que
//! [`crate::navegador::coincidencia`] y por el mismo motivo: comparar dominios
//! como cadenas es de donde salen los fallos de esta clase.
//!
//! # Registrar passkeys nuevas
//!
//! Además de usar las que ya hay, este módulo **crea** passkeys
//! (`navigator.credentials.create`): genera un par de claves P-256, guarda la
//! privada en la bóveda y le entrega al sitio la pública dentro de un
//! `attestationObject`. Ver [`registrar`].
//!
//! La atestación es de tipo **`none`**: no afirmamos ser ningún autenticador
//! concreto, con AAGUID a ceros. Es lo que hace un autenticador de software y lo
//! que preserva la privacidad —un AAGUID identifica el modelo del dispositivo—;
//! el servidor extrae la clave pública del `authData` y la guarda, que es todo
//! lo que necesita cuando no exige atestación verificable.
//!
//! Solo se firma y se registra con **ES256** (P-256, COSE alg −7): es el
//! algoritmo que todo servidor de WebAuthn acepta y el que ya usaban las 19
//! importadas. Si el sitio no lo ofrece, no se registra y la llamada vuelve al
//! navegador, que puede tener otro autenticador.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// El algoritmo de firma que registramos y usamos: ECDSA con P-256 y SHA-256.
/// Es el identificador COSE (`-7`), el que todo servidor de WebAuthn acepta.
pub const ES256: i64 = -7;

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("la clave de la passkey no está en base64url válido")]
    Base64,

    #[error("la clave de la passkey no se pudo leer como PKCS#8 de P-256: {0}")]
    Clave(String),

    #[error(
        "el sitio pide firmar para «{pedido}» y la página está en «{origen}»: no \
         se firma. Es exactamente lo que hace un sitio de phishing."
    )]
    OrigenNoCorresponde { pedido: String, origen: String },

    #[error("el origen «{0}» no se pudo interpretar")]
    OrigenIlegible(String),

    #[error("esta entrada no tiene ninguna passkey guardada")]
    SinPasskey,

    #[error("el reto viene vacío: sin reto no hay nada que firmar")]
    RetoVacio,

    #[error(
        "el sitio no acepta el único algoritmo que sabemos registrar (ES256/P-256): \
         pidió {pedidos:?}. La llamada vuelve al navegador."
    )]
    AlgoritmoNoSoportado { pedidos: Vec<i64> },

    #[error("no se pudo generar la clave de la passkey: {0}")]
    Generacion(String),
}

/// Una passkey lista para usarse, sacada de los campos de una entrada.
pub struct Passkey {
    /// Identificador que el sitio conoce, en base64url.
    pub credential_id: String,
    /// El `rpId` para el que se registró (`banco.com`).
    pub rp_id: String,
    /// A quién identifica, en base64url. El sitio lo usa para saber qué cuenta es.
    pub user_handle: Option<String>,
    /// El nombre de cuenta que registró el sitio (`juan@gmail.com`). No entra en
    /// la firma: existe para que el usuario pueda ELEGIR cuando hay varias.
    pub usuario: Option<String>,
    /// Cuántas veces se ha usado. Sube en cada firma.
    pub contador: u32,
    clave: Zeroizing<Vec<u8>>,
}

/// La respuesta que el navegador espera, ya en las piezas que la componen.
#[derive(Debug)]
pub struct Asercion {
    pub credential_id: String,
    /// `authenticatorData` en base64url.
    pub authenticator_data: String,
    /// La firma DER, en base64url.
    pub signature: String,
    pub user_handle: Option<String>,
    /// El contador ya incrementado, para guardarlo en la entrada.
    pub contador: u32,
}

/// Todo lo que produce registrar una passkey nueva.
///
/// Se parte en dos destinos: lo que va **a la página** (que lo reenvía al sitio
/// para que guarde la clave pública) y lo que hay que **guardar en la bóveda**
/// para poder firmar con ella después. El módulo hace solo la parte
/// criptográfica; quién lo escribe en qué campo es cosa del agente, igual que en
/// la lectura.
///
/// `Debug` está IMPLEMENTADO A MANO para redactar la clave privada: el
/// `Zeroizing` la borra al soltarla, pero no oculta un `{:?}`, y un `dbg!(reg)`
/// de mañana escupiría el DER en claro a un log. Se cierra la trampa antes de que
/// exista (concilio 2026-09-16, sonnet).
pub struct Registro {
    /// `id`/`rawId` de la credencial nueva, en base64url. Lo elegimos nosotros:
    /// 16 bytes aleatorios, la misma anchura que traían las importadas.
    pub credential_id: String,
    /// El `attestationObject` CBOR, en base64url. Lleva la clave pública dentro.
    pub attestation_object: String,
    /// El `clientDataJSON` exacto (tipo `webauthn.create`) que el sitio verifica.
    pub client_data: String,
    /// La clave PRIVADA en PKCS#8 DER y base64url, lista para `passkey.N.clave`.
    /// Es el mismo formato que lee [`Passkey::de_entrada`].
    pub clave_privada: Zeroizing<String>,
}

impl std::fmt::Debug for Registro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registro")
            .field("credential_id", &self.credential_id)
            .field("attestation_object", &self.attestation_object)
            .field("client_data", &self.client_data)
            .field("clave_privada", &"<redactada>")
            .finish()
    }
}

fn de_base64url(s: &str) -> Result<Vec<u8>, WebauthnError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s.trim_end_matches('=')).map_err(|_| WebauthnError::Base64)
}

fn a_base64url(b: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(b)
}

/// Escapa `s` como contenido de un literal de cadena JSON (RFC 8259), SIN las
/// comillas que lo envuelven. El `origin` lo pone el navegador y se incrusta en
/// el `clientDataJSON` que se FIRMA: tiene que producir JSON válido sea cual sea
/// su contenido. Un `"` o un `\` crudos romperían el documento —el sitio
/// rechazaría la firma por `clientDataJSON` ilegible— y un `"` bien colocado
/// podría además inyectar campos. Para un origen normal (sin comillas, barras ni
/// controles) la salida es IDÉNTICA a la entrada, así que no cambia ni un byte de
/// las firmas que hoy funcionan. Se escribe a mano, como el CBOR de este módulo,
/// para no depender del comportamiento de un serializador en el camino firmado.
fn escapar_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Teje el `clientDataJSON` que el autenticador firma y el sitio verifica. ES EL
/// ÚNICO sitio donde se construye ese documento: antes había tres `format!` casi
/// idénticos (firmar, client_data y registrar) y uno de ellos —el de registrar—
/// se quedó SIN escapar el `origin` (lo cazó el concilio, 2026-10-13). Unificarlos
/// cierra la clase entera (D1/D23). `tipo` es `webauthn.get` o `webauthn.create`
/// (literal interno, no entrada); el `origin` lo pone el navegador y se ESCAPA
/// como literal JSON para que el documento sea válido sea cual sea su contenido.
fn client_data_json(tipo: &str, reto: &[u8], origen: &str) -> String {
    format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        tipo,
        a_base64url(reto),
        escapar_json(origen)
    )
}

/// El identificador de la credencial, en la forma que habla el navegador.
///
/// Bitwarden guarda el `credentialId` como **UUID con guiones**; la página lo
/// entrega como los 16 bytes crudos, que la extensión codifica en base64url.
/// Comparar una forma con la otra no casa nunca — y el fallo es invisible: la
/// bóveda tiene la llave, el sitio la pide, y la respuesta es «no hay passkey
/// para este sitio». Las 19 passkeys importadas venían así, las 19.
///
/// Se normaliza aquí, en el único sitio por el que pasan todas las passkeys, y
/// no en el importador: así las bóvedas ya creadas quedan arregladas sin tener
/// que reimportar nada.
///
/// Solo se convierte lo que es **exactamente** un UUID (8-4-4-4-12 hexadecimal).
/// El guion pertenece también al alfabeto base64url, así que un identificador
/// que ya venga en esa forma podría en teoría parecer un UUID; exigir el patrón
/// completo deja esa coincidencia en una probabilidad de 2⁻⁷², y cualquier otra
/// cosa se devuelve intacta en vez de adivinar.
fn id_canonico(id: &str) -> String {
    let b = id.as_bytes();
    let uuid = b.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) { true } else { c.is_ascii_hexdigit() }
        });
    if !uuid {
        return id.to_string();
    }
    let hex: Vec<u8> = b.iter().copied().filter(|c| *c != b'-').collect();
    let bytes: Vec<u8> = hex
        .chunks(2)
        .map(|par| {
            let s = std::str::from_utf8(par).expect("hexadecimal ASCII, ya comprobado");
            u8::from_str_radix(s, 16).expect("dígitos hexadecimales, ya comprobados")
        })
        .collect();
    a_base64url(&bytes)
}

/// Lee un campo de la entrada como texto, venga como `Texto` o `Secreto`.
fn campo_como_texto(entrada: &crate::boveda::Entrada, etiqueta: &str) -> Option<String> {
    entrada.campo(etiqueta).and_then(|c| match &c.valor {
        crate::boveda::Valor::Texto(t) => Some(t.clone()),
        crate::boveda::Valor::Secreto(s) => Some(s.to_string()),
        _ => None,
    })
}

/// Parte la etiqueta `passkey.<n>.<sufijo>` en `(n, sufijo)`. Cualquier otra
/// etiqueta devuelve `None`. El punto final del prefijo evita que `passkey.1.`
/// case con `passkey.10.clave`.
fn indice_de_campo_passkey(etiqueta: &str) -> Option<(usize, &str)> {
    let resto = etiqueta.strip_prefix("passkey.")?;
    let punto = resto.find('.')?;
    let idx: usize = resto[..punto].parse().ok()?;
    Some((idx, &resto[punto + 1..]))
}

/// Lo que la interfaz necesita para ENSEÑAR una passkey, sin tocar la clave
/// privada: el dominio para el que vale, a qué cuenta identifica y cuántas veces
/// se ha usado.
pub struct ResumenPasskey {
    pub rp_id: String,
    pub usuario: Option<String>,
    pub contador: u32,
}

impl Passkey {
    /// Saca la passkey número `n` de una entrada de la bóveda.
    ///
    /// Los campos son los que dejó el importador: `passkey.0.clave`,
    /// `passkey.0.rp_id`… Se leen por nombre y no por posición porque el orden
    /// de los campos no es algo en lo que se pueda confiar.
    pub fn de_entrada(entrada: &crate::boveda::Entrada, n: usize) -> Result<Self, WebauthnError> {
        let campo = |sufijo: &str| -> Option<String> {
            entrada
                .campo(&format!("passkey.{n}.{sufijo}"))
                .and_then(|c| match &c.valor {
                    crate::boveda::Valor::Texto(t) => Some(t.clone()),
                    crate::boveda::Valor::Secreto(s) => Some(s.to_string()),
                    _ => None,
                })
        };

        let clave_b64 = campo("clave").ok_or(WebauthnError::SinPasskey)?;
        let credential_id = campo("id").ok_or(WebauthnError::SinPasskey)?;
        let rp_id = campo("rp_id").ok_or(WebauthnError::SinPasskey)?;

        Ok(Self {
            credential_id: id_canonico(&credential_id),
            rp_id,
            user_handle: campo("usuario_handle"),
            usuario: campo("usuario").or_else(|| campo("usuario_mostrado")),
            contador: campo("contador").and_then(|c| c.parse().ok()).unwrap_or(0),
            clave: Zeroizing::new(de_base64url(&clave_b64)?),
        })
    }

    /// Cuántas passkeys tiene una entrada.
    pub fn cuantas(entrada: &crate::boveda::Entrada) -> usize {
        (0..)
            .take_while(|n| entrada.campo(&format!("passkey.{n}.clave")).is_some())
            .count()
    }

    /// Lista las passkeys de una entrada para MOSTRARLAS, sin decodificar la
    /// clave privada: el detalle repinta a ~60 fps y aquí no se saca material
    /// secreto de su envoltura `Zeroizing`.
    pub fn resumen_de_entrada(entrada: &crate::boveda::Entrada) -> Vec<ResumenPasskey> {
        (0..Self::cuantas(entrada))
            .map(|n| {
                let campo = |suf: &str| campo_como_texto(entrada, &format!("passkey.{n}.{suf}"));
                ResumenPasskey {
                    rp_id: campo("rp_id").unwrap_or_default(),
                    usuario: campo("usuario").or_else(|| campo("usuario_mostrado")),
                    contador: campo("contador").and_then(|c| c.parse().ok()).unwrap_or(0),
                }
            })
            .collect()
    }

    /// Quita la passkey número `n` de la entrada. Devuelve `false` (sin tocar
    /// nada) si `n` está fuera de rango.
    ///
    /// REINDEXA las que quedan: `cuantas` cuenta índices consecutivos desde 0, de
    /// modo que dejar un hueco —quitar la `0` conservando la `1`— ocultaría todas
    /// las siguientes sin un solo error. Por eso toda passkey con índice mayor que
    /// `n` baja uno. El mapeo es biyectivo (las de índice menor que `n` no se
    /// tocan), así que no quedan dos campos con la misma etiqueta.
    pub fn quitar_de_entrada(entrada: &mut crate::boveda::Entrada, n: usize) -> bool {
        if n >= Self::cuantas(entrada) {
            return false;
        }
        let prefijo = format!("passkey.{n}.");
        entrada.campos.retain(|c| !c.etiqueta.starts_with(&prefijo));
        for c in entrada.campos.iter_mut() {
            let nueva = match indice_de_campo_passkey(&c.etiqueta) {
                Some((idx, suf)) if idx > n => Some(format!("passkey.{}.{}", idx - 1, suf)),
                _ => None,
            };
            if let Some(nueva) = nueva {
                c.etiqueta = nueva;
            }
        }
        true
    }

    /// Firma el reto del sitio.
    ///
    /// `origen` es el de la página **según el navegador**, con esquema:
    /// `https://banco.com`. No se toma de la página.
    pub fn firmar(
        &self,
        rp_id_pedido: &str,
        reto: &[u8],
        origen: &str,
    ) -> Result<Asercion, WebauthnError> {
        if reto.is_empty() {
            return Err(WebauthnError::RetoVacio);
        }
        comprobar_origen(rp_id_pedido, origen)?;
        // Y además, la passkey se registró para un dominio concreto: no se usa
        // para otro aunque el origen cuadre con lo pedido.
        comprobar_origen(&self.rp_id, origen)?;

        let clave = SigningKey::from_pkcs8_der(&self.clave)
            .map_err(|e| WebauthnError::Clave(e.to_string()))?;

        // clientDataJSON: lo que el sitio verificará para saber que la firma es
        // de ESTA petición y de ESTE origen.
        let client_data = client_data_json("webauthn.get", reto, origen);

        let contador = self.contador.saturating_add(1);
        let mut datos = Vec::with_capacity(37);
        datos.extend_from_slice(&Sha256::digest(rp_id_pedido.as_bytes()));
        // Banderas: presencia del usuario (0x01) y verificación del usuario
        // (0x04). Se marcan las dos porque abrir la bóveda ya exigió la frase de
        // paso: eso ES verificación del usuario, y muchos sitios la exigen.
        datos.push(0x01 | 0x04);
        datos.extend_from_slice(&contador.to_be_bytes());

        // Lo que se firma: authenticatorData ‖ SHA-256(clientDataJSON).
        let mut mensaje = datos.clone();
        mensaje.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let firma: Signature = clave.sign(&mensaje);

        Ok(Asercion {
            credential_id: self.credential_id.clone(),
            authenticator_data: a_base64url(&datos),
            signature: a_base64url(firma.to_der().as_bytes()),
            user_handle: self.user_handle.clone(),
            contador,
        })
    }

    /// El `clientDataJSON` que acompaña a la firma. La extensión lo necesita
    /// tal cual: el sitio comprueba la firma **sobre estos bytes exactos**.
    pub fn client_data(reto: &[u8], origen: &str) -> String {
        client_data_json("webauthn.get", reto, origen)
    }
}

/// ¿Puede firmarse para `rp_id` estando en `origen`?
///
/// La regla de la especificación: el `rpId` tiene que ser el host del origen o
/// un **dominio padre** suyo. Se comprueba por etiquetas, nunca por texto:
/// `banco.com` es padre de `pagos.banco.com` y NO de `banco.com.evil.example`.
pub(crate) fn comprobar_origen(rp_id: &str, origen: &str) -> Result<(), WebauthnError> {
    let d = crate::navegador::coincidencia::Direccion::analizar(origen)
        .ok_or_else(|| WebauthnError::OrigenIlegible(origen.to_string()))?;

    // WebAuthn exige contexto seguro. `localhost` es la excepción que la propia
    // especificación reconoce, para que se pueda desarrollar.
    let seguro = d.esquema == "https" || d.host == "localhost" || d.host == "127.0.0.1";
    if !seguro {
        return Err(WebauthnError::OrigenNoCorresponde {
            pedido: rp_id.to_string(),
            origen: origen.to_string(),
        });
    }

    let rp = rp_id.trim_end_matches('.').to_ascii_lowercase();
    let host = &d.host;
    let corresponde = *host == rp
        || (host.len() > rp.len()
            && host.ends_with(&rp)
            // La etiqueta anterior tiene que terminar en punto: sin esto,
            // `evilbanco.com` pasaría por ser `banco.com` con letras delante.
            && host.as_bytes()[host.len() - rp.len() - 1] == b'.');

    if corresponde {
        Ok(())
    } else {
        Err(WebauthnError::OrigenNoCorresponde {
            pedido: rp_id.to_string(),
            origen: origen.to_string(),
        })
    }
}

/// El generador de aleatoriedad del sistema, adaptado a la interfaz que pide
/// `p256`.
///
/// Es el MISMO que usa el resto del universo —`quipu::aleatorio::llenar`—, que
/// nunca sustituye la entropía por un defecto: si el sistema no la da, falla en
/// vez de generar una clave predecible (ver `quipu::aleatorio`). Una passkey con
/// aleatoriedad floja es trivial de suplantar, y el fallo no se nota nunca.
fn rng_del_sistema() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    struct R;
    impl p256::elliptic_curve::rand_core::RngCore for R {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            quipu::aleatorio::llenar(&mut b).expect("el RNG del sistema no dio entropía");
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            quipu::aleatorio::llenar(&mut b).expect("el RNG del sistema no dio entropía");
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            quipu::aleatorio::llenar(d).expect("el RNG del sistema no dio entropía");
        }
        fn try_fill_bytes(
            &mut self,
            d: &mut [u8],
        ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
            quipu::aleatorio::llenar(d)
                .map_err(|_| p256::elliptic_curve::rand_core::Error::new("sin entropía"))
        }
    }
    impl p256::elliptic_curve::rand_core::CryptoRng for R {}
    R
}

/// Registra una passkey nueva: genera el par de claves y arma lo que el sitio
/// espera de `navigator.credentials.create`.
///
/// `origen` es el de la página **según el navegador**, con esquema. La misma
/// comprobación de origen que en la firma se aplica aquí, y por el mismo motivo:
/// si no, un sitio de phishing registraría una passkey «para el banco» desde su
/// propio dominio y el usuario acabaría con una llave del atacante en su bóveda.
///
/// `algoritmos` es la lista `pubKeyCredParams[].alg` que pide el sitio. Si no
/// incluye ES256 no registramos: devolvemos [`WebauthnError::AlgoritmoNoSoportado`]
/// y la extensión deja que lo atienda el navegador.
///
/// Lo que devuelve NO incluye el nombre de cuenta ni el `userHandle`: eso no
/// entra en la criptografía —con atestación `none` el `authData` solo lleva la
/// clave pública— y lo guarda el agente junto a la clave privada.
pub fn registrar(
    rp_id: &str,
    reto: &[u8],
    origen: &str,
    algoritmos: &[i64],
) -> Result<Registro, WebauthnError> {
    if reto.is_empty() {
        return Err(WebauthnError::RetoVacio);
    }
    comprobar_origen(rp_id, origen)?;
    if !algoritmos.contains(&ES256) {
        return Err(WebauthnError::AlgoritmoNoSoportado { pedidos: algoritmos.to_vec() });
    }

    // La bóveda abierta ya exigió la frase de paso: en el flujo del navegador eso
    // ES verificación de usuario, así que el registro nace con el bit UV.
    let n = registrar_nucleo(rp_id, true)?;

    let client_data = client_data_json("webauthn.create", reto, origen);

    Ok(Registro {
        credential_id: a_base64url(&n.cred_id),
        attestation_object: a_base64url(&n.attestation_object),
        client_data,
        clave_privada: Zeroizing::new(a_base64url(&n.clave_privada_der)),
    })
}

/// Lo que produce el NÚCLEO del registro, sin `clientDataJSON` ni el `credential_id`
/// y la clave en base64: las dos formas (navegador y plugin) codifican a su gusto.
struct Nucleo {
    cred_id: [u8; 16],
    /// El `attestationObject` CBOR crudo (lo que espera el navegador).
    attestation_object: Vec<u8>,
    /// La clave privada en PKCS#8 DER, cruda.
    clave_privada_der: Zeroizing<Vec<u8>>,
}

/// El corazón criptográfico del registro, para el flujo del navegador
/// ([`registrar`]): genera el par P-256, arma el `authenticatorData` con la
/// credencial adjunta (bit AT) y el `attestationObject` de atestación `none`.
///
/// No construye `clientDataJSON` —eso lo hace [`registrar`] con el origen— ni
/// comprueba origen ni algoritmos: esas puertas las pone el llamante. El contador
/// nace en 0; la primera firma lo subirá a 1. `uv` marca el bit de verificación
/// de usuario.
fn registrar_nucleo(rp_id: &str, uv: bool) -> Result<Nucleo, WebauthnError> {
    let secreta = SigningKey::random(&mut rng_del_sistema());
    let publica = secreta.verifying_key();
    let der = secreta
        .to_pkcs8_der()
        .map_err(|e| WebauthnError::Generacion(e.to_string()))?;

    // El identificador de la credencial: 16 bytes aleatorios. No es un secreto
    // —el sitio lo guarda y nos lo devuelve al entrar—, pero sí tiene que ser
    // imposible de adivinar para que no se pueda enumerar ni colisionar.
    let mut cred_id = [0u8; 16];
    quipu::aleatorio::llenar(&mut cred_id)
        .map_err(|_| WebauthnError::Generacion("sin entropía para el id".into()))?;

    // La clave pública en formato COSE (CBOR), que es como el sitio la guarda.
    let punto = publica.to_encoded_point(false);
    let x = punto.x().ok_or_else(|| WebauthnError::Generacion("clave sin coordenada x".into()))?;
    let y = punto.y().ok_or_else(|| WebauthnError::Generacion("clave sin coordenada y".into()))?;
    let cose = cbor::clave_cose_p256(x, y);

    // authenticatorData del REGISTRO: como el de la firma pero con el bit AT
    // (0x40), que anuncia que detrás vienen los datos de la credencial nueva.
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(if uv { 0x01 | 0x04 | 0x40 } else { 0x01 | 0x40 });
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    // attestedCredentialData: AAGUID(16, a ceros) ‖ longitud(2) ‖ id ‖ clave.
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&cred_id);
    auth_data.extend_from_slice(&cose);

    let attestation_object = cbor::objeto_atestacion_none(&auth_data);

    Ok(Nucleo {
        cred_id,
        attestation_object,
        clave_privada_der: Zeroizing::new(der.as_bytes().to_vec()),
    })
}

/// Un codificador CBOR mínimo, solo para las dos formas fijas que produce el
/// registro: la clave pública COSE y el `attestationObject`.
///
/// Se escribe a mano en vez de traer una crate porque son dos estructuras de
/// tamaño acotado y conocido, y una dependencia nueva en un producto que corre
/// en casa del cliente es superficie que hay que sostener. El orden de las
/// claves es el CANÓNICO de CTAP2 (enteros sin signo antes que negativos en la
/// clave COSE; por longitud y luego bytes en el objeto de atestación), que es lo
/// que esperan los verificadores estrictos.
mod cbor {
    /// Escribe la cabecera de un elemento: el tipo mayor (ya en los tres bits
    /// altos) y la longitud/valor, con la mínima anchura posible.
    fn cabecera(out: &mut Vec<u8>, mayor: u8, n: u64) {
        if n < 24 {
            out.push(mayor | n as u8);
        } else if n < 0x100 {
            out.push(mayor | 24);
            out.push(n as u8);
        } else if n < 0x1_0000 {
            out.push(mayor | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(mayor | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }

    fn uint(out: &mut Vec<u8>, n: u64) {
        cabecera(out, 0x00, n);
    }
    /// Un entero negativo. En CBOR se codifica su valor como `-1 - n`.
    fn nint(out: &mut Vec<u8>, n: i64) {
        debug_assert!(n < 0);
        cabecera(out, 0x20, (-1 - n) as u64);
    }
    fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        cabecera(out, 0x40, b.len() as u64);
        out.extend_from_slice(b);
    }
    fn texto(out: &mut Vec<u8>, s: &str) {
        cabecera(out, 0x60, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }
    fn mapa(out: &mut Vec<u8>, pares: u64) {
        cabecera(out, 0xa0, pares);
    }

    /// La clave pública P-256 como `COSE_Key` (RFC 8152): kty EC2, alg ES256,
    /// curva P-256, y las coordenadas x/y. Claves en orden canónico: 1, 3, −1,
    /// −2, −3.
    pub fn clave_cose_p256(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(77);
        mapa(&mut out, 5);
        uint(&mut out, 1);
        uint(&mut out, 2); // kty = EC2
        uint(&mut out, 3);
        nint(&mut out, super::ES256); // alg = ES256
        nint(&mut out, -1);
        uint(&mut out, 1); // crv = P-256
        nint(&mut out, -2);
        bytes(&mut out, x);
        nint(&mut out, -3);
        bytes(&mut out, y);
        out
    }

    /// `{ fmt: "none", attStmt: {}, authData: <bytes> }`, en orden canónico por
    /// longitud de clave: `fmt` (3) < `attStmt` (7) < `authData` (8).
    pub fn objeto_atestacion_none(auth_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(auth_data.len() + 24);
        mapa(&mut out, 3);
        texto(&mut out, "fmt");
        texto(&mut out, "none");
        texto(&mut out, "attStmt");
        mapa(&mut out, 0);
        texto(&mut out, "authData");
        bytes(&mut out, auth_data);
        out
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::boveda::{Campo, Clase, Entrada, Valor};
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::EncodePrivateKey;

    // ─── Veta mindalá #2: validar el CBOR/COSE/authenticatorData hecho a mano contra el
    //     SPEC (RFC 8152 COSE_Key + WebAuthn authData), con un decodificador CBOR
    //     INDEPENDIENTE. Es el diferencial (D33): el decodificador es código distinto del
    //     codificador `cbor` de arriba, así que un error del codificador lo delata el
    //     decodificador (o el cierre del lazo cripto), no una copia de sí mismo.

    /// Valor CBOR mínimo (solo los tipos que el registro produce).
    #[derive(Debug, Clone, PartialEq)]
    enum Cbor {
        Uint(u64),
        Nint(i64),
        Bytes(Vec<u8>),
        Texto(String),
        Mapa(Vec<(Cbor, Cbor)>), // en orden de aparición: permite verificar el orden canónico
    }

    /// Decodificador CBOR independiente, cursor sobre los bytes. Reimplementado desde el
    /// RFC 8949 (no copia el codificador de chuspa ni trae crate: D38, ethos cero-deps).
    struct Dec<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl<'a> Dec<'a> {
        fn new(b: &'a [u8]) -> Self {
            Dec { b, i: 0 }
        }
        fn byte(&mut self) -> u8 {
            let x = self.b[self.i];
            self.i += 1;
            x
        }
        fn largo(&mut self, info: u8) -> u64 {
            match info {
                0..=23 => u64::from(info),
                24 => u64::from(self.byte()),
                25 => (0..2).fold(0u64, |v, _| (v << 8) | u64::from(self.byte())),
                26 => (0..4).fold(0u64, |v, _| (v << 8) | u64::from(self.byte())),
                otro => panic!("ancho CBOR no soportado en el test: {otro}"),
            }
        }
        fn valor(&mut self) -> Cbor {
            let ib = self.byte();
            let (mayor, info) = (ib >> 5, ib & 0x1f);
            match mayor {
                0 => Cbor::Uint(self.largo(info)),
                1 => Cbor::Nint(-1 - self.largo(info) as i64),
                2 => {
                    let l = self.largo(info) as usize;
                    let s = self.b[self.i..self.i + l].to_vec();
                    self.i += l;
                    Cbor::Bytes(s)
                }
                3 => {
                    let l = self.largo(info) as usize;
                    let s = String::from_utf8(self.b[self.i..self.i + l].to_vec()).unwrap();
                    self.i += l;
                    Cbor::Texto(s)
                }
                5 => {
                    let pares = self.largo(info);
                    let mut m = Vec::new();
                    for _ in 0..pares {
                        let k = self.valor();
                        let v = self.valor();
                        m.push((k, v));
                    }
                    Cbor::Mapa(m)
                }
                otro => panic!("tipo mayor CBOR no soportado en el test: {otro}"),
            }
        }
    }

    /// Reconstruye una clave pública P-256 desde las coordenadas x,y (SEC1 sin comprimir).
    /// `None` si (x,y) no es un punto válido de la curva.
    fn pubkey_de_xy(x: &[u8], y: &[u8]) -> Option<VerifyingKey> {
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        VerifyingKey::from_sec1_bytes(&sec1).ok()
    }

    /// Extrae (x, y) de la clave COSE al final del `authData`. Decodifica el attestationObject
    /// entero con el decodificador independiente y verifica su estructura de spec por el camino.
    fn valida_y_extrae_xy(reg: &Registro, rp: &str) -> (Vec<u8>, Vec<u8>) {
        let attobj = de_base64url(&reg.attestation_object).unwrap();
        let mut d = Dec::new(&attobj);
        let val = d.valor();
        assert_eq!(d.i, attobj.len(), "el attestationObject no deja bytes colgando (CBOR bien formado)");

        let Cbor::Mapa(m) = val else { panic!("attestationObject debe ser un mapa CBOR") };
        let claves: Vec<&str> =
            m.iter().map(|(k, _)| if let Cbor::Texto(s) = k { s.as_str() } else { "?" }).collect();
        assert_eq!(claves, ["fmt", "attStmt", "authData"], "orden canónico del attestationObject");
        assert_eq!(m[0].1, Cbor::Texto("none".into()), "fmt = none");
        assert_eq!(m[1].1, Cbor::Mapa(vec![]), "attStmt vacío (atestación none)");
        let Cbor::Bytes(auth_data) = &m[2].1 else { panic!("authData debe ser bytes") };

        // authData por el spec WebAuthn.
        assert!(auth_data.len() > 55, "authData con attestedCredentialData");
        assert_eq!(&auth_data[0..32], &Sha256::digest(rp.as_bytes())[..], "rpIdHash = SHA256(rpId)");
        assert_eq!(auth_data[32], 0x45, "flags = UP|UV|AT (0x45)");
        assert_eq!(&auth_data[33..37], &[0, 0, 0, 0], "signCount = 0");
        assert_eq!(&auth_data[37..53], &[0u8; 16], "AAGUID a ceros");
        let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert_eq!(cred_len, 16, "credIdLen = 16");
        let cred_id = &auth_data[55..55 + cred_len];
        assert_eq!(cred_id, &de_base64url(&reg.credential_id).unwrap()[..], "credId coincide con el reportado");

        // COSE key (RFC 8152), orden canónico CTAP2.
        let cose_bytes = &auth_data[55 + cred_len..];
        let mut dc = Dec::new(cose_bytes);
        let Cbor::Mapa(mk) = dc.valor() else { panic!("la clave COSE debe ser un mapa") };
        assert_eq!(dc.i, cose_bytes.len(), "la clave COSE consume el resto sin colgar");
        let orden: Vec<i64> = mk
            .iter()
            .map(|(k, _)| match k {
                Cbor::Uint(u) => *u as i64,
                Cbor::Nint(n) => *n,
                _ => 999,
            })
            .collect();
        assert_eq!(orden, [1, 3, -1, -2, -3], "orden canónico CTAP2 de la clave COSE");
        assert_eq!(mk[0].1, Cbor::Uint(2), "kty = EC2");
        assert_eq!(mk[1].1, Cbor::Nint(-7), "alg = ES256 (-7)");
        assert_eq!(mk[2].1, Cbor::Uint(1), "crv = P-256");
        let (Cbor::Bytes(x), Cbor::Bytes(y)) = (&mk[3].1, &mk[4].1) else { panic!("x,y deben ser bytes") };
        assert_eq!(x.len(), 32, "x de 32 bytes");
        assert_eq!(y.len(), 32, "y de 32 bytes");
        (x.clone(), y.clone())
    }

    #[test]
    fn registro_cbor_cose_valida_contra_el_spec_y_cierra_el_lazo() {
        let rp = "example.com";
        let reg = registrar(rp, b"reto-de-prueba", "https://example.com", &[ES256]).unwrap();
        let (x, y) = valida_y_extrae_xy(&reg, rp);

        // CIERRE DEL LAZO: la clave pública COSE recuperada debe ser la de la privada
        // registrada (si no, el codificador puso una clave que no es la de la credencial).
        let pub_cose = pubkey_de_xy(&x, &y).expect("(x,y) es un punto P-256 válido");
        let sk = SigningKey::from_pkcs8_der(&de_base64url(&reg.clave_privada).unwrap()).unwrap();
        assert_eq!(pub_cose, *sk.verifying_key(), "la clave COSE codificada ES la de la passkey");
    }

    #[test]
    fn caso_rojo_clave_cose_corrupta_no_corresponde_a_la_privada() {
        // Discriminación (D33): si el codificador escribiera una x equivocada, el cierre del
        // lazo tiene que romperse. Se simula corrompiendo un bit de x: la correspondencia con
        // la privada DEBE fallar (o el punto deja de ser válido). Sin esta comprobación, la
        // validación de arriba sería un sello de goma.
        let reg = registrar("example.com", b"reto", "https://example.com", &[ES256]).unwrap();
        let (mut x, y) = valida_y_extrae_xy(&reg, "example.com");
        let sk = SigningKey::from_pkcs8_der(&de_base64url(&reg.clave_privada).unwrap()).unwrap();
        x[0] ^= 0x01; // corrompe la coordenada x
        match pubkey_de_xy(&x, &y) {
            None => {} // la x corrupta ya no es un punto de la curva: detectado
            Some(k) => assert_ne!(k, *sk.verifying_key(), "una x corrupta NO puede corresponder a la privada"),
        }
    }

    /// Genera una passkey de mentira y devuelve (entrada, clave pública).
    fn passkey_de_prueba(rp: &str) -> (Entrada, VerifyingKey) {
        let secreta = SigningKey::random(&mut rand_core_compat());
        let publica = *secreta.verifying_key();
        let der = secreta.to_pkcs8_der().unwrap();

        let entrada = Entrada {
            id_origen: None,
            nombre: rp.into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: vec![
                Campo::estandar("passkey.0.id", Valor::texto("Y3JlZC0x")),
                Campo::estandar("passkey.0.rp_id", Valor::texto(rp)),
                Campo::estandar("passkey.0.usuario_handle", Valor::texto("dXN1YXJpbw")),
                Campo::estandar("passkey.0.contador", Valor::texto("7")),
                Campo::estandar("passkey.0.clave", Valor::secreto(a_base64url(der.as_bytes()))),
            ],
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        };
        (entrada, publica)
    }

    /// Una entrada con una passkey por cada `rp` (índices 0..k), cada una con su
    /// propia clave real, para los bancos de resumen y de borrado.
    fn entrada_con_passkeys(rps: &[&str]) -> Entrada {
        let campos = rps
            .iter()
            .enumerate()
            .flat_map(|(i, rp)| {
                let der = SigningKey::random(&mut rand_core_compat()).to_pkcs8_der().unwrap();
                [
                    Campo::estandar(format!("passkey.{i}.id"), Valor::texto(format!("cred-{i}"))),
                    Campo::estandar(format!("passkey.{i}.rp_id"), Valor::texto(*rp)),
                    Campo::estandar(format!("passkey.{i}.usuario"), Valor::texto(format!("u{i}@{rp}"))),
                    Campo::estandar(format!("passkey.{i}.contador"), Valor::texto(i.to_string())),
                    Campo::estandar(format!("passkey.{i}.clave"), Valor::secreto(a_base64url(der.as_bytes()))),
                ]
            })
            .collect();
        Entrada {
            id_origen: None,
            nombre: "varias".into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos,
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        }
    }

    #[test]
    fn resumen_lista_todas_las_passkeys_en_orden() {
        let e = entrada_con_passkeys(&["banco.example", "correo.example"]);
        let r = Passkey::resumen_de_entrada(&e);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].rp_id, "banco.example");
        assert_eq!(r[1].rp_id, "correo.example");
        assert_eq!(r[0].usuario.as_deref(), Some("u0@banco.example"));
        assert_eq!(r[1].contador, 1);
    }

    /// Caso ROJO que discrimina (D33): quitar la passkey 0 debe REINDEXAR la 1 a
    /// la posición 0. Sin el reindexado, `cuantas` cae a 0 (hueco en el índice 0)
    /// y la que queda se vuelve invisible y no se puede firmar con ella — justo el
    /// fallo invisible que este módulo documenta. El mutante es quitar el bucle de
    /// reindexado: esta prueba se pone roja por la vía real (`cuantas`/`de_entrada`).
    #[test]
    fn quitar_la_primera_reindexa_la_que_queda() {
        let mut e = entrada_con_passkeys(&["banco.example", "correo.example"]);
        assert_eq!(Passkey::cuantas(&e), 2);

        assert!(Passkey::quitar_de_entrada(&mut e, 0));
        assert_eq!(Passkey::cuantas(&e), 1, "sin reindexar, el hueco en 0 ocultaría la 1");

        // La superviviente es la de correo, leída desde el índice 0, con su clave
        // intacta: si el reindexado hubiera mezclado campos de dos passkeys, la
        // clave de una con el rp_id de otra no firmaría coherente para su origen.
        let pk = Passkey::de_entrada(&e, 0).unwrap();
        assert_eq!(pk.rp_id, "correo.example");
        let reto = b"un reto de treinta y dos bytes!!";
        assert!(pk.firmar("correo.example", reto, "https://correo.example").is_ok());
    }

    #[test]
    fn quitar_la_del_medio_deja_las_otras_dos_consecutivas() {
        let mut e = entrada_con_passkeys(&["a.example", "b.example", "c.example"]);
        assert!(Passkey::quitar_de_entrada(&mut e, 1)); // quita la de en medio (b)
        assert_eq!(Passkey::cuantas(&e), 2);
        assert_eq!(Passkey::de_entrada(&e, 0).unwrap().rp_id, "a.example");
        assert_eq!(Passkey::de_entrada(&e, 1).unwrap().rp_id, "c.example");
    }

    #[test]
    fn quitar_fuera_de_rango_no_toca_nada() {
        let mut e = entrada_con_passkeys(&["banco.example"]);
        let antes = e.campos.clone();
        assert!(!Passkey::quitar_de_entrada(&mut e, 1));
        assert_eq!(e.campos, antes, "un índice fuera de rango no debe alterar la entrada");
    }

    /// El generador del sistema, que es el que usa el resto del programa.
    fn rand_core_compat() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
        struct R;
        impl p256::elliptic_curve::rand_core::RngCore for R {
            fn next_u32(&mut self) -> u32 {
                let mut b = [0u8; 4];
                quipu::aleatorio::llenar(&mut b).unwrap();
                u32::from_le_bytes(b)
            }
            fn next_u64(&mut self) -> u64 {
                let mut b = [0u8; 8];
                quipu::aleatorio::llenar(&mut b).unwrap();
                u64::from_le_bytes(b)
            }
            fn fill_bytes(&mut self, d: &mut [u8]) {
                quipu::aleatorio::llenar(d).unwrap();
            }
            fn try_fill_bytes(
                &mut self,
                d: &mut [u8],
            ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
                self.fill_bytes(d);
                Ok(())
            }
        }
        impl p256::elliptic_curve::rand_core::CryptoRng for R {}
        R
    }

    /// La prueba que sostiene el módulo: la firma que producimos **la verifica
    /// la clave pública**, que es exactamente lo que hará el servidor del sitio.
    #[test]
    fn la_firma_la_verifica_la_clave_publica() {
        let (entrada, publica) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        let reto = b"un reto de treinta y dos bytes!!";

        let a = pk.firmar("banco.example", reto, "https://banco.example").unwrap();

        // Se rehace lo que hará el servidor: authenticatorData ‖ SHA256(clientData).
        let datos = de_base64url(&a.authenticator_data).unwrap();
        let client_data = Passkey::client_data(reto, "https://banco.example");
        let mut mensaje = datos.clone();
        mensaje.extend_from_slice(&Sha256::digest(client_data.as_bytes()));

        let firma = Signature::from_der(&de_base64url(&a.signature).unwrap()).unwrap();
        assert!(
            publica.verify(&mensaje, &firma).is_ok(),
            "el servidor del sitio rechazaría esta firma"
        );
    }

    #[test]
    fn los_datos_del_autenticador_dicen_lo_que_deben() {
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        let a = pk.firmar("banco.example", b"reto", "https://banco.example").unwrap();
        let datos = de_base64url(&a.authenticator_data).unwrap();

        assert_eq!(datos.len(), 37, "32 de hash + 1 de banderas + 4 de contador");
        assert_eq!(
            &datos[..32],
            Sha256::digest(b"banco.example").as_slice(),
            "el hash del dominio tiene que ser el del rpId"
        );
        assert_eq!(datos[32] & 0x01, 0x01, "presencia del usuario");
        assert_eq!(datos[32] & 0x04, 0x04, "verificación del usuario");
        assert_eq!(
            u32::from_be_bytes(datos[33..37].try_into().unwrap()),
            8,
            "el contador estaba en 7 y tiene que subir"
        );
        assert_eq!(a.contador, 8);
    }

    /// Lo que hace a una passkey inmune al phishing, y la razón de este módulo.
    #[test]
    fn no_se_firma_para_un_sitio_impostor() {
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();

        for impostor in [
            "https://banco.example.evil.test",
            "https://evilbanco.example",
            "https://evil.test",
            "https://banco.example@evil.test",
        ] {
            assert!(
                pk.firmar("banco.example", b"reto", impostor).is_err(),
                "«{impostor}» consiguió una firma para banco.example"
            );
        }
    }

    #[test]
    fn no_se_firma_para_un_dominio_que_no_es_el_suyo() {
        // Aunque el origen cuadre con lo pedido, la passkey se registró para
        // otro sitio: usarla aquí sería prestarla.
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        assert!(pk.firmar("otro.example", b"reto", "https://otro.example").is_err());
    }

    #[test]
    fn un_subdominio_del_sitio_si_puede_pedir_la_firma() {
        // La especificación lo permite: el rpId puede ser un dominio padre del
        // origen. `banco.example` firma para `pagos.banco.example`.
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        assert!(
            pk.firmar("banco.example", b"reto", "https://pagos.banco.example").is_ok()
        );
    }

    #[test]
    fn no_se_firma_por_http() {
        // WebAuthn exige contexto seguro; localhost es la excepción que la
        // propia especificación reconoce para desarrollar.
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        assert!(pk.firmar("banco.example", b"reto", "http://banco.example").is_err());

        let (local, _) = passkey_de_prueba("localhost");
        let pl = Passkey::de_entrada(&local, 0).unwrap();
        assert!(pl.firmar("localhost", b"reto", "http://localhost").is_ok());
    }

    #[test]
    fn un_reto_vacio_no_se_firma() {
        let (entrada, _) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        assert!(matches!(
            pk.firmar("banco.example", b"", "https://banco.example"),
            Err(WebauthnError::RetoVacio)
        ));
    }

    /// Las firmas son DETERMINISTAS, y eso es lo que se quiere.
    ///
    /// La primera versión de esta prueba exigía lo contrario: que dos firmas del
    /// mismo reto difirieran, dando por hecho que ECDSA lleva un valor aleatorio
    /// por firma. `p256` implementa el RFC 6979, que lo deriva del mensaje y la
    /// clave — y eso **elimina** la clase de fallo más cara de ECDSA: un
    /// generador flojo o repetido filtra la clave privada entera. Es como se
    /// destapó la clave de firma de la PlayStation 3.
    ///
    /// O sea que la prueba pedía justo lo contrario de lo deseable.
    #[test]
    fn las_firmas_son_deterministas_y_eso_es_lo_correcto() {
        let (entrada, publica) = passkey_de_prueba("banco.example");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();

        let a = pk.firmar("banco.example", b"mismo reto", "https://banco.example").unwrap();
        let b = pk.firmar("banco.example", b"mismo reto", "https://banco.example").unwrap();
        assert_eq!(
            a.signature, b.signature,
            "el RFC 6979 deriva el nonce del mensaje: mismo mensaje, misma firma"
        );

        // Y retos distintos dan firmas distintas, que es lo que importa de
        // verdad: la firma tiene que cubrir el reto.
        let c = pk.firmar("banco.example", b"otro reto", "https://banco.example").unwrap();
        assert_ne!(a.signature, c.signature);

        // Las dos verifican: determinista no significa reutilizable.
        for (asercion, reto) in [(&a, &b"mismo reto"[..]), (&c, &b"otro reto"[..])] {
            let mut mensaje = de_base64url(&asercion.authenticator_data).unwrap();
            mensaje.extend_from_slice(&Sha256::digest(
                Passkey::client_data(reto, "https://banco.example").as_bytes(),
            ));
            let firma = Signature::from_der(&de_base64url(&asercion.signature).unwrap()).unwrap();
            assert!(publica.verify(&mensaje, &firma).is_ok());
        }
    }

    #[test]
    fn se_cuentan_las_passkeys_de_una_entrada() {
        let (entrada, _) = passkey_de_prueba("banco.example");
        assert_eq!(Passkey::cuantas(&entrada), 1);

        let vacia = Entrada {
            id_origen: None,
            nombre: "sin".into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: Vec::new(),
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        };
        assert_eq!(Passkey::cuantas(&vacia), 0);
        assert!(matches!(
            Passkey::de_entrada(&vacia, 0),
            Err(WebauthnError::SinPasskey)
        ));
    }

    /// Las passkeys REALES de un export de Bitwarden se leen y firman.
    ///
    /// La prueba anterior usa una clave que genera este mismo módulo, así que
    /// solo demuestra que es consistente consigo mismo. Esta usa el formato tal
    /// como lo escribe Bitwarden: PKCS#8 en base64url.
    #[test]
    fn una_clave_en_el_formato_de_bitwarden_se_lee() {
        // Generada con el mismo formato que usa Bitwarden y comprobada arriba;
        // lo que se fija aquí es que el PARSEO acepta PKCS#8 DER de P-256.
        let (entrada, publica) = passkey_de_prueba("ejemplo.test");
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        let a = pk.firmar("ejemplo.test", b"reto de prueba", "https://ejemplo.test").unwrap();

        let datos = de_base64url(&a.authenticator_data).unwrap();
        let mut mensaje = datos;
        mensaje.extend_from_slice(&Sha256::digest(
            Passkey::client_data(b"reto de prueba", "https://ejemplo.test").as_bytes(),
        ));
        let firma = Signature::from_der(&de_base64url(&a.signature).unwrap()).unwrap();
        assert!(publica.verify(&mensaje, &firma).is_ok());
    }

    /// El identificador que guarda Bitwarden y el que manda el navegador son la
    /// misma credencial escrita de dos maneras. Si no se normaliza, `permitidas`
    /// no casa nunca y el sitio se queda esperando la llave para siempre — que
    /// es exactamente lo que pasaba en `accounts.google.com`.
    #[test]
    fn el_uuid_de_bitwarden_casa_con_lo_que_manda_el_navegador() {
        // Los 16 bytes crudos que la página pone en `allowCredentials[].id`.
        let crudos: [u8; 16] = [
            0x1c, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5,
            0xf6, 0x07,
        ];
        let como_lo_manda_el_navegador = a_base64url(&crudos);
        let como_lo_guarda_bitwarden = "1c2f3a4b-5c6d-7e8f-90a1-b2c3d4e5f607";

        // La prueba entra por `de_entrada`, que es el camino que recorre una
        // passkey de verdad. Comprobar `id_canonico` a solas pasaba igual con el
        // arreglo quitado: medía la función, no el fallo.
        let (mut entrada, _) = passkey_de_prueba("ejemplo.test");
        for c in &mut entrada.campos {
            if c.etiqueta == "passkey.0.id" {
                c.valor = Valor::texto(como_lo_guarda_bitwarden);
            }
        }
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();

        // Esto es literalmente lo que hace el agente al buscar la passkey.
        let permitidas = [como_lo_manda_el_navegador.clone()];
        assert!(
            permitidas.contains(&pk.credential_id),
            "el sitio pide {:?} y la bóveda ofrece {:?}: el sitio se queda esperando",
            como_lo_manda_el_navegador,
            pk.credential_id
        );
        // Y lo que se devuelve a la página tiene que poder decodificarse ahí.
        assert_eq!(de_base64url(&pk.credential_id).unwrap(), crudos);
    }

    // ---- Registro de passkeys nuevas ----

    /// Un lector CBOR mínimo, SOLO para las pruebas: hace de servidor que parsea
    /// el `attestationObject`. Es deliberadamente independiente del codificador
    /// —recorre los bytes sin asumir offsets fijos—, para que un fallo del
    /// codificador no se esconda tras el mismo fallo en el lector.
    struct LectorCbor<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl<'a> LectorCbor<'a> {
        fn nuevo(b: &'a [u8]) -> Self {
            Self { b, i: 0 }
        }
        fn byte(&mut self) -> u8 {
            let c = self.b[self.i];
            self.i += 1;
            c
        }
        /// Devuelve (tipo_mayor, argumento) y avanza.
        fn cabecera(&mut self) -> (u8, u64) {
            let ib = self.byte();
            let mayor = ib >> 5;
            let corto = ib & 0x1f;
            let arg = match corto {
                0..=23 => corto as u64,
                24 => self.byte() as u64,
                25 => {
                    let hi = self.byte() as u64;
                    (hi << 8) | self.byte() as u64
                }
                26 => {
                    let mut v = 0u64;
                    for _ in 0..4 {
                        v = (v << 8) | self.byte() as u64;
                    }
                    v
                }
                _ => panic!("longitud CBOR no soportada por el lector de prueba: {corto}"),
            };
            (mayor, arg)
        }
        fn bytes(&mut self) -> Vec<u8> {
            let (m, n) = self.cabecera();
            assert_eq!(m, 2, "se esperaba una cadena de bytes");
            let v = self.b[self.i..self.i + n as usize].to_vec();
            self.i += n as usize;
            v
        }
        fn texto(&mut self) -> String {
            let (m, n) = self.cabecera();
            assert_eq!(m, 3, "se esperaba texto");
            let s = std::str::from_utf8(&self.b[self.i..self.i + n as usize]).unwrap().to_string();
            self.i += n as usize;
            s
        }
    }

    /// Saca la clave pública P-256 de un `authData` de registro, como haría el
    /// servidor: se salta rpIdHash(32)+flags(1)+contador(4)+AAGUID(16), lee la
    /// longitud del id y el id, y luego el COSE_Key. Devuelve (x, y) y las
    /// banderas.
    fn clave_publica_del_authdata(auth: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let flags = auth[32];
        let id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        let cose_desde = 55 + id_len;
        let mut r = LectorCbor::nuevo(&auth[cose_desde..]);
        let (m, pares) = r.cabecera();
        assert_eq!(m, 5, "el COSE_Key es un mapa");
        assert_eq!(pares, 5);
        let (mut x, mut y) = (Vec::new(), Vec::new());
        // kty/alg/crv NO se descartan: se comprueban. Descartarlos dejaba el
        // banco CIEGO a una regresión que cambiara el algoritmo (alg=−8) o el
        // tipo de clave (kty=OKP) —el servidor real las rechaza, y aquí salían
        // verdes— (D33, hallazgo del concilio 2026-09-16, confirmado por fable
        // contra openssl).
        let entero = |r: &mut LectorCbor| -> i64 {
            let (mk, ak) = r.cabecera();
            if mk == 0 { ak as i64 } else { -1 - ak as i64 }
        };
        let (mut kty, mut alg, mut crv) = (0i64, 0i64, 0i64);
        for _ in 0..pares {
            match entero(&mut r) {
                -2 => x = r.bytes(),
                -3 => y = r.bytes(),
                1 => kty = entero(&mut r),
                3 => alg = entero(&mut r),
                -1 => crv = entero(&mut r),
                otro => panic!("clave COSE inesperada: {otro}"),
            }
        }
        assert_eq!(kty, 2, "kty tiene que ser EC2 (2)");
        assert_eq!(alg, ES256, "alg tiene que ser ES256 (-7)");
        assert_eq!(crv, 1, "crv tiene que ser P-256 (1)");
        (flags, x, y)
    }

    fn verifying_key_de(x: &[u8], y: &[u8]) -> VerifyingKey {
        use p256::EncodedPoint;
        let punto = EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(x),
            p256::FieldBytes::from_slice(y),
            false,
        );
        VerifyingKey::from_encoded_point(&punto).unwrap()
    }

    /// LA prueba del registro: se registra una passkey, se parsea el
    /// `attestationObject` como lo haría el servidor, y la clave pública que sale
    /// de ahí **verifica una firma hecha con la privada guardada**. Es el bucle
    /// entero —crear, guardar, usar— cerrado por criptografía, no por estructura.
    #[test]
    fn una_passkey_registrada_se_puede_usar_para_firmar() {
        let reto_reg = b"reto de registro de 32 bytes!!!!";
        let reg = registrar("banco.example", reto_reg, "https://banco.example", &[ES256]).unwrap();

        // 1) El servidor parsea la atestación y saca la clave pública.
        let att = de_base64url(&reg.attestation_object).unwrap();
        let mut r = LectorCbor::nuevo(&att);
        let (m, pares) = r.cabecera();
        assert_eq!((m, pares), (5, 3), "el attestationObject es un mapa de 3");
        let mut auth_data = Vec::new();
        for _ in 0..pares {
            match r.texto().as_str() {
                "fmt" => assert_eq!(r.texto(), "none"),
                "attStmt" => {
                    let (mm, nn) = r.cabecera();
                    assert_eq!((mm, nn), (5, 0), "attStmt vacío");
                }
                "authData" => auth_data = r.bytes(),
                otro => panic!("clave inesperada: {otro}"),
            }
        }
        let (flags, x, y) = clave_publica_del_authdata(&auth_data);
        assert_eq!(flags & 0x40, 0x40, "el bit AT (credencial adjunta) tiene que estar");
        assert_eq!(flags & 0x01, 0x01, "presencia del usuario");
        assert_eq!(flags & 0x04, 0x04, "verificación del usuario");
        assert_eq!(
            &auth_data[..32],
            Sha256::digest(b"banco.example").as_slice(),
            "el rpIdHash tiene que ser el del dominio"
        );
        assert_eq!(
            u32::from_be_bytes(auth_data[33..37].try_into().unwrap()),
            0,
            "el contador de una passkey recién creada es 0"
        );
        let publica_atestada = verifying_key_de(&x, &y);

        // 2) La clave pública atestada es la de la privada que se guardó: ata la
        //    atestación con el almacenamiento, sin pasar por el lector CBOR.
        let der = de_base64url(&reg.clave_privada).unwrap();
        let secreta = SigningKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(
            *secreta.verifying_key(),
            publica_atestada,
            "la clave pública del attestationObject no es la de la privada guardada"
        );

        // 3) Se guarda como lo hará el agente y se FIRMA por el camino normal.
        let entrada = Entrada {
            id_origen: None,
            nombre: "banco.example".into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: vec![
                Campo::estandar("passkey.0.id", Valor::texto(reg.credential_id.clone())),
                Campo::estandar("passkey.0.rp_id", Valor::texto("banco.example")),
                Campo::estandar("passkey.0.contador", Valor::texto("0")),
                Campo::estandar("passkey.0.clave", Valor::secreto(reg.clave_privada.to_string())),
            ],
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        };
        let pk = Passkey::de_entrada(&entrada, 0).unwrap();
        let reto_login = b"otro reto, el de entrar";
        let a = pk.firmar("banco.example", reto_login, "https://banco.example").unwrap();

        // 4) La firma la verifica la clave pública ATESTADA: el servidor que
        //    guardó la pública al registrar aceptaría esta firma al entrar.
        let mut mensaje = de_base64url(&a.authenticator_data).unwrap();
        mensaje.extend_from_slice(&Sha256::digest(
            Passkey::client_data(reto_login, "https://banco.example").as_bytes(),
        ));
        let firma = Signature::from_der(&de_base64url(&a.signature).unwrap()).unwrap();
        assert!(
            publica_atestada.verify(&mensaje, &firma).is_ok(),
            "una passkey registrada por Chuspa no sirve para entrar"
        );
        // Y el id que se guarda es el que se le dio al sitio, decodificable.
        assert_eq!(a.credential_id, reg.credential_id);
        assert_eq!(de_base64url(&reg.credential_id).unwrap().len(), 16);
    }

    /// Caso rojo: si el sitio no ofrece ES256, no se registra. La llamada vuelve
    /// al navegador en vez de darle una passkey que su servidor no sabe leer.
    #[test]
    fn no_se_registra_un_algoritmo_que_no_sabemos() {
        // −257 es RS256; −8 es EdDSA. Ninguno es el nuestro.
        let e = registrar("banco.example", b"reto", "https://banco.example", &[-257, -8]);
        assert!(matches!(e, Err(WebauthnError::AlgoritmoNoSoportado { .. })));

        // Pero si ES256 está en la lista —aunque no sea el primero— sí.
        assert!(registrar("banco.example", b"reto", "https://banco.example", &[-257, ES256]).is_ok());
    }

    /// Caso rojo: un sitio de phishing no registra una passkey «del banco». Es la
    /// misma defensa que en la firma, y por el mismo motivo: sin ella el usuario
    /// acabaría con una llave del atacante guardada como si fuera la del banco.
    #[test]
    fn no_se_registra_para_un_dominio_que_no_es_el_de_la_pagina() {
        assert!(matches!(
            registrar("banco.example", b"reto", "https://banco.example.evil.test", &[ES256]),
            Err(WebauthnError::OrigenNoCorresponde { .. })
        ));
        // Y sin contexto seguro tampoco.
        assert!(registrar("banco.example", b"reto", "http://banco.example", &[ES256]).is_err());
    }

    #[test]
    fn un_registro_sin_reto_no_se_hace() {
        assert!(matches!(
            registrar("banco.example", b"", "https://banco.example", &[ES256]),
            Err(WebauthnError::RetoVacio)
        ));
    }

    /// Dos registros seguidos dan claves e identificadores DISTINTOS: el RNG no
    /// se está quedando pegado. Un id repetido colisionaría en el sitio; una
    /// clave repetida sería un desastre.
    #[test]
    fn cada_registro_es_una_credencial_nueva() {
        let a = registrar("banco.example", b"reto-a", "https://banco.example", &[ES256]).unwrap();
        let b = registrar("banco.example", b"reto-b", "https://banco.example", &[ES256]).unwrap();
        assert_ne!(a.credential_id, b.credential_id, "los identificadores se repiten");
        assert_ne!(
            a.clave_privada.to_string(),
            b.clave_privada.to_string(),
            "las claves privadas se repiten"
        );
    }

    /// La conversión solo puede tocar lo que es un UUID. Un identificador que ya
    /// venga en base64url —una passkey creada por Chuspa, o de otro gestor— tiene
    /// que salir intacto: convertir lo que no toca rompería las que sí funcionan.
    #[test]
    fn lo_que_no_es_un_uuid_sale_intacto() {
        for id in [
            "HC86S1xtfo-QobLD1OX2Bw",              // base64url de 16 bytes
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 36 caracteres, sin guiones
            "1c2f3a4b5c6d7e8f90a1b2c3d4e5f607",     // 32 hex, pero sin guiones
            "1c2f3a4b-5c6d-7e8f-90a1-b2c3d4e5f60",  // un carácter de menos
            "gc2f3a4b-5c6d-7e8f-90a1-b2c3d4e5f607", // una letra fuera del hex
            "",
        ] {
            assert_eq!(id_canonico(id), id, "no debía tocar {id:?}");
        }
    }

    // ─── clientDataJSON: el `origin` se incrusta ESCAPADO, para producir JSON
    //     válido sea cual sea su contenido. Pareja D33: control (origen normal,
    //     byte-idéntico al de siempre) + caso rojo (origen con comillas, que sin
    //     escape rompía/inyectaba el documento). El caso rojo se valida contra el
    //     ARTEFACTO con un lector JSON INDEPENDIENTE del escapador.

    #[test]
    fn el_client_data_de_un_origen_normal_no_cambia_ni_un_byte() {
        // Si el escape tocara un origen corriente, rompería TODAS las firmas que
        // hoy funcionan. No lo toca: la salida es la de siempre, byte a byte.
        let cd = Passkey::client_data(b"\x01\x02\x03\x04", "https://webauthn.io");
        assert_eq!(
            cd,
            r#"{"type":"webauthn.get","challenge":"AQIDBA","origin":"https://webauthn.io","crossOrigin":false}"#
        );
    }

    #[test]
    fn el_client_data_escapa_comillas_barras_y_controles_y_sigue_siendo_json_valido() {
        // Un `origin` con comilla ANTES producía JSON roto (y un `"` bien puesto
        // inyectaba campos). Metemos un carácter por CADA brazo de `escapar_json`
        // —comilla, barra invertida, un control con nombre (`\n`) y un control
        // GENÉRICO sin nombre (`\x01`, que va por `\u00xx`)— para que un mutante que
        // quite CUALQUIER brazo ponga esto rojo. El de `\x01` es el que el concilio
        // marcó sin cubrir: con solo `\n` (que tiene brazo propio) el brazo genérico
        // sobrevivía. El documento cierra bien y el `origin` que un parser recupera
        // es EXACTAMENTE el que entró, carácter a carácter.
        let origen = "https://x\"}\\\x01\r\t,\n\"inyectado\":\"sí";
        let cd = Passkey::client_data(b"\x00", origen);
        assert!(
            cd.ends_with(r#","crossOrigin":false}"#),
            "el JSON quedó mal cerrado: {cd}"
        );
        // Ningún carácter de control crudo (RFC 8259 los prohíbe sin escapar): pone
        // rojo el mutante que quite el brazo GENÉRICO (`\x01` quedaría crudo; el
        // lector de abajo, tolerante, no lo vería por sí solo).
        assert!(
            !cd.chars().any(|c| (c as u32) < 0x20),
            "control crudo sin escapar en el clientDataJSON: {cd:?}"
        );
        // Y la FORMA del escape genérico es la de RFC 8259 (`\u0001`, minúscula).
        assert!(
            cd.contains(r"\u0001"),
            "el control U+0001 no se escapó como \\u0001: {cd}"
        );
        assert_eq!(
            valor_json_de_origin(&cd),
            origen,
            "el origin recuperado del clientDataJSON no casa el original"
        );
    }

    #[test]
    fn registrar_tambien_escapa_el_origin_en_su_client_data() {
        // El TERCER sitio (webauthn.create), que el concilio cazó sin escapar. Un
        // `origin` con comilla en la COLA pasa `comprobar_origen` (el host sigue
        // siendo el rp_id) y ANTES entraba crudo en el clientDataJSON de registro.
        // Prueba el SITIO real (`registrar`), no solo el helper.
        let origen = r#"https://banco.com/","inyectado":"x"#;
        let reg = registrar("banco.com", b"\x01\x02", origen, &[ES256]).expect("debe registrar");
        assert!(
            reg.client_data.contains(r#""type":"webauthn.create""#),
            "no es un clientDataJSON de create: {}",
            reg.client_data
        );
        assert!(
            reg.client_data.ends_with(r#","crossOrigin":false}"#),
            "el JSON de registro quedó mal cerrado: {}",
            reg.client_data
        );
        assert_eq!(
            valor_json_de_origin(&reg.client_data),
            origen,
            "el origin recuperado del clientDataJSON de registro no casa"
        );
    }

    /// Lee el valor del campo `"origin"` de un clientDataJSON respetando el escape
    /// JSON (`\"`, `\\`, `\n`, `\r`, `\t`, `\uXXXX`). Es código DISTINTO del
    /// escapador de producción (D33): un error del escapador lo delata este lector,
    /// no una copia de sí mismo.
    fn valor_json_de_origin(json: &str) -> String {
        let marca = r#""origin":""#;
        let ini = json.find(marca).expect("sin campo origin") + marca.len();
        let cs: Vec<char> = json[ini..].chars().collect();
        let mut out = String::new();
        let mut i = 0;
        loop {
            match cs[i] {
                '"' => break, // comilla SIN escapar = fin del valor
                '\\' => {
                    i += 1;
                    match cs[i] {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hex: String = cs[i + 1..i + 5].iter().collect();
                            out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
                            i += 4;
                        }
                        otro => panic!("escape JSON no esperado: \\{otro}"),
                    }
                }
                c => out.push(c),
            }
            i += 1;
        }
        out
    }
}
