// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Lo que se dicen la extensión y la aplicación.
//!
//! # Quién decide qué
//!
//! Hay tres procesos y solo uno tiene poder:
//!
//! - **La aplicación** (el agente) tiene la bóveda abierta y la frase de paso.
//!   Es quien decide si una credencial corresponde a una página.
//! - **El puente** lo lanza Firefox y no decide nada: traduce el formato de
//!   *native messaging* al socket del agente y devuelve la respuesta. No ve la
//!   frase de paso, no abre la bóveda, no compara dominios.
//! - **La extensión** solo pide firmas de passkey. Nunca recibe la bóveda ni
//!   ninguna contraseña.
//!
//! Que el puente no decida es deliberado. Es el proceso que un navegador
//! comprometido puede alcanzar más fácilmente, y cuanto menos sepa, menos hay
//! que perder si cae. La frase de paso **no pasa nunca por el navegador**, que
//! es la diferencia con los gestores que la piden en un formulario de la
//! extensión.
//!
//! # Solo passkeys (desde 0.3.0)
//!
//! El agente **no entrega contraseñas al navegador**: se retiraron los mensajes
//! `Buscar`/`Credencial`/`Generar`/`Proponer` del viejo autofill. Lo único que
//! devuelve un secreto es [`Peticion::Autenticar`], y esa firma exige aprobación
//! por uso en la ventana (`gui::decidir_firma`) — no basta con que la bóveda
//! esté abierta. Las contraseñas se manejan con el gestor nativo del navegador,
//! sincronizado desde la aplicación (importador). Retirar esos cuatro mensajes
//! es lo que permite alargar el plazo de inactividad sin abrir una vía de
//! exfiltración silenciosa: una extensión comprometida ya no tiene a quién
//! pedirle contraseñas.

use serde::{Deserialize, Serialize};

/// Lo que la extensión pide.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case", deny_unknown_fields)]
pub enum Peticion {
    /// ¿Hay bóveda abierta? No revela nada de su contenido.
    ///
    /// Se declara con llaves —`Estado {}`, no `Estado`— y no es cosmética: en
    /// serde, una variante *unit* de un enum etiquetado **ignora los campos que
    /// no conoce** aunque el enum lleve `deny_unknown_fields`. Con llaves, la
    /// regla se aplica también aquí, y `{"tipo":"estado","frase":"..."}` se
    /// rechaza en vez de admitirse y descartar el campo en silencio.
    Estado {},
    /// Cierra la bóveda. La extensión puede pedirlo; abrirla, no.
    Bloquear {},
    /// Firma un reto de WebAuthn con una passkey guardada.
    ///
    /// El `origen` lo pone el **navegador**, no la página: es la pieza de la que
    /// depende que esto no sirva para el phishing. La extensión lo saca de
    /// `sender.url`, que la página no puede tocar.
    Autenticar {
        /// El dominio para el que el sitio pide la firma.
        rp_id: String,
        /// El reto del sitio, en base64url.
        reto: String,
        /// Origen de la página según el navegador: `https://banco.com`.
        origen: String,
        /// Identificadores que el sitio acepta, en base64url. Vacío = cualquiera
        /// registrada para ese dominio.
        permitidas: Vec<String>,
    },
    /// Registra una passkey nueva (`navigator.credentials.create`).
    ///
    /// Como en `Autenticar`, el `origen` lo pone el **navegador**, no la página:
    /// es lo que impide que un sitio de phishing registre una passkey «del banco»
    /// desde su propio dominio. Lo que se devuelve a la página —el
    /// `attestationObject`— NO es un secreto: lleva la clave PÚBLICA, y la privada
    /// no sale nunca de la bóveda. Registrar, como firmar, exige aprobación por
    /// uso en la ventana.
    Registrar {
        /// El dominio de la parte de confianza (`rp.id`).
        rp_id: String,
        /// Su nombre legible (`rp.name`), para nombrar la entrada en la bóveda.
        #[serde(default)]
        rp_nombre: Option<String>,
        /// Identificador de la cuenta (`user.id`), en base64url. Es el
        /// `userHandle` que el sitio pedirá de vuelta al entrar.
        usuario_handle: String,
        /// Nombre de cuenta (`user.name`), para que el usuario reconozca la
        /// entrada. No entra en la criptografía.
        #[serde(default)]
        usuario: Option<String>,
        /// Nombre para mostrar (`user.displayName`).
        #[serde(default)]
        usuario_mostrado: Option<String>,
        /// El reto del sitio, en base64url.
        reto: String,
        /// Origen de la página según el navegador: `https://banco.com`.
        origen: String,
        /// Los algoritmos que el sitio acepta (`pubKeyCredParams[].alg`, COSE).
        /// Si no está ES256 (−7), no se registra.
        algoritmos: Vec<i64>,
        /// Credenciales que el sitio ya tiene (`excludeCredentials[].id`), en
        /// base64url. Si una es nuestra, no se duplica.
        #[serde(default)]
        excluidas: Vec<String>,
    },
}

/// Por qué la aplicación no está atendiendo al navegador.
///
/// No dice nada del contenido: ni cuántas entradas hay, ni cuáles. Lo único que
/// distingue es **qué tiene que hacer el usuario**, que es justo lo que la
/// respuesta anterior no sabía decir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Razon {
    /// No hay ninguna bóveda abierta. Hay que teclear la frase en la ventana.
    SinBoveda,
    /// La bóveda está abierta, pero hace demasiado que no se sabe de nadie.
    /// Basta con volver a la ventana: el enlace se restablece solo.
    Inactividad,
}

/// Lo que la aplicación responde.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case")]
pub enum Respuesta {
    Estado {
        abierta: bool,
        /// Por qué no se atiende. `None` cuando sí se atiende.
        ///
        /// Existe porque sin él las dos causas se contestaban igual, y una de
        /// las dos respuestas era falsa: con la bóveda abierta en pantalla, el
        /// complemento decía «la bóveda está cerrada, ábrela desde la
        /// aplicación» — un consejo que no se puede seguir, porque ya está
        /// abierta.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        razon: Option<Razon>,
    },
    Hecho,
    /// La firma de WebAuthn, en las piezas que el navegador espera.
    Asercion {
        credential_id: String,
        authenticator_data: String,
        signature: String,
        client_data: String,
        user_handle: Option<String>,
    },
    /// La credencial recién registrada, en las piezas que el navegador espera de
    /// `navigator.credentials.create`. El `attestation_object` NO es secreto:
    /// lleva la clave pública, no la privada.
    Credencial {
        credential_id: String,
        attestation_object: String,
        client_data: String,
    },
    /// Algo salió mal. El texto es para enseñárselo a una persona.
    Error { mensaje: String },
}

/// Errores del transporte de *native messaging*.
#[derive(Debug, thiserror::Error)]
pub enum TransporteError {
    #[error("error de entrada/salida: {0}")]
    Io(#[from] std::io::Error),

    #[error("mensaje mal formado: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "el mensaje dice medir {tamano} bytes y el máximo admitido es {maximo}. \
         Un mensaje así solo puede venir de algo que no es la extensión."
    )]
    DemasiadoGrande { tamano: u32, maximo: u32 },

    /// La otra punta cerró. No es un error: es cómo termina el puente cuando
    /// Firefox se cierra.
    #[error("la conexión se cerró")]
    Cerrado,
}

/// Tamaño máximo de un mensaje entrante.
///
/// Firefox limita a 1 MiB lo que la extensión puede enviar, así que cualquier
/// cosa mayor no viene de la extensión. Se comprueba **antes** de reservar la
/// memoria: sin este límite, cuatro bytes de longitud bastarían para pedir que
/// se reserven 4 GiB.
pub const MAXIMO_MENSAJE: u32 = 1024 * 1024;

/// Lee un mensaje en el formato de *native messaging*: cuatro bytes de longitud
/// en orden nativo, y detrás el JSON en UTF-8.
pub fn leer_mensaje<R: std::io::Read>(origen: &mut R) -> Result<Peticion, TransporteError> {
    let mut cabecera = [0u8; 4];
    match origen.read_exact(&mut cabecera) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransporteError::Cerrado);
        }
        Err(e) => return Err(e.into()),
    }
    // Orden NATIVO, no big-endian: lo dice la especificación de native
    // messaging, y equivocarse aquí da longitudes absurdas en vez de un error
    // claro.
    let tamano = u32::from_ne_bytes(cabecera);
    if tamano > MAXIMO_MENSAJE {
        return Err(TransporteError::DemasiadoGrande {
            tamano,
            maximo: MAXIMO_MENSAJE,
        });
    }
    let mut cuerpo = vec![0u8; tamano as usize];
    origen.read_exact(&mut cuerpo)?;
    Ok(serde_json::from_slice(&cuerpo)?)
}

/// Escribe una respuesta en el mismo formato.
pub fn escribir_respuesta<W: std::io::Write>(
    destino: &mut W,
    respuesta: &Respuesta,
) -> Result<(), TransporteError> {
    let cuerpo = serde_json::to_vec(respuesta)?;
    destino.write_all(&(cuerpo.len() as u32).to_ne_bytes())?;
    destino.write_all(&cuerpo)?;
    destino.flush()?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn empaquetar(json: &str) -> Vec<u8> {
        let mut v = (json.len() as u32).to_ne_bytes().to_vec();
        v.extend_from_slice(json.as_bytes());
        v
    }

    #[test]
    fn una_peticion_da_la_vuelta() {
        let bytes = empaquetar(
            r#"{"tipo":"autenticar","rp_id":"banco.com","reto":"AA","origen":"https://banco.com","permitidas":[]}"#,
        );
        match leer_mensaje(&mut bytes.as_slice()).unwrap() {
            Peticion::Autenticar { rp_id, .. } => assert_eq!(rp_id, "banco.com"),
            otro => panic!("se leyó otra cosa: {otro:?}"),
        }
    }

    #[test]
    fn un_mensaje_enorme_se_rechaza_sin_reservar_memoria() {
        // Cuatro bytes bastarían para pedir 4 GiB. Se comprueba el tamaño ANTES
        // de reservar nada.
        let mut bytes = u32::MAX.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        match leer_mensaje(&mut bytes.as_slice()) {
            Err(TransporteError::DemasiadoGrande { maximo, .. }) => {
                assert_eq!(maximo, MAXIMO_MENSAJE);
            }
            otro => panic!("un mensaje de 4 GiB debe rechazarse: {otro:?}"),
        }
    }

    #[test]
    fn un_campo_desconocido_detiene_la_peticion() {
        // Igual que en el importador: lo que no se entiende no se ignora. Un
        // campo de más puede ser un intento de que el agente haga algo distinto
        // de lo que cree.
        let bytes = empaquetar(r#"{"tipo":"autenticar","rp_id":"x","reto":"AA","origen":"https://x","permitidas":[],"extra":1}"#);
        assert!(matches!(
            leer_mensaje(&mut bytes.as_slice()),
            Err(TransporteError::Json(_))
        ));
    }

    #[test]
    fn no_existe_una_peticion_para_abrir_la_boveda() {
        // La frase de paso no pasa por el navegador, y eso se garantiza porque
        // el protocolo no tiene forma de transportarla. Si algún día alguien
        // añade `Desbloquear { frase }`, esta prueba se pone roja.
        let intentos = [
            r#"{"tipo":"desbloquear","frase":"x"}"#,
            r#"{"tipo":"abrir","frase":"x"}"#,
            r#"{"tipo":"estado","frase":"x"}"#,
        ];
        for json in intentos {
            let bytes = empaquetar(json);
            assert!(
                leer_mensaje(&mut bytes.as_slice()).is_err(),
                "el protocolo no puede admitir «{json}»"
            );
        }
    }

    #[test]
    fn el_protocolo_no_tiene_ninguna_peticion_que_pida_una_contrasena() {
        // Desde 0.3.0 el agente no entrega contraseñas al navegador. La garantía
        // es estructural: ninguna variante de `Peticion` puede pedir una, y
        // ninguna de `Respuesta` puede llevarla. Estos mensajes del viejo autofill
        // ya no deserializan; si alguien reintroduce uno, esta prueba se pone roja.
        for json in [
            r#"{"tipo":"buscar","url":"https://banco.com/"}"#,
            r#"{"tipo":"credencial","ficha":"abc"}"#,
            r#"{"tipo":"generar","url":"https://banco.com/"}"#,
            r#"{"tipo":"proponer","url":"https://banco.com/","clave":"x"}"#,
        ] {
            let bytes = empaquetar(json);
            assert!(
                leer_mensaje(&mut bytes.as_slice()).is_err(),
                "el protocolo ya no puede transportar «{json}»"
            );
        }
    }

    #[test]
    fn una_respuesta_da_la_vuelta() {
        let mut salida = Vec::new();
        escribir_respuesta(
            &mut salida,
            &Respuesta::Estado { abierta: true, razon: None },
        )
        .unwrap();
        let largo = u32::from_ne_bytes(salida[..4].try_into().unwrap()) as usize;
        assert_eq!(largo, salida.len() - 4);
        let v: serde_json::Value = serde_json::from_slice(&salida[4..]).unwrap();
        assert_eq!(v["tipo"], "estado");
        assert_eq!(v["abierta"], true);
        // Desde 0.3.0 el estado NO lleva el conteo de entradas (no tenía
        // consumidor y era un dato de más hacia el navegador).
        assert!(v.get("entradas").is_none(), "el estado no puede filtrar el conteo");
    }

    #[test]
    fn una_peticion_de_registro_da_la_vuelta() {
        let bytes = empaquetar(
            r#"{"tipo":"registrar","rp_id":"banco.com","usuario_handle":"dQ","reto":"AA","origen":"https://banco.com","algoritmos":[-7]}"#,
        );
        match leer_mensaje(&mut bytes.as_slice()).unwrap() {
            Peticion::Registrar { rp_id, algoritmos, usuario, excluidas, .. } => {
                assert_eq!(rp_id, "banco.com");
                assert_eq!(algoritmos, vec![-7]);
                // Los campos opcionales ausentes caen a `None`/vacío, no fallan.
                assert!(usuario.is_none());
                assert!(excluidas.is_empty());
            }
            otro => panic!("se leyó otra cosa: {otro:?}"),
        }
    }

    #[test]
    fn un_registro_con_campo_desconocido_se_detiene() {
        // Igual que el resto del protocolo: `deny_unknown_fields` no deja pasar
        // un campo de más que pudiera desviar lo que el agente hace.
        let bytes = empaquetar(
            r#"{"tipo":"registrar","rp_id":"x","usuario_handle":"dQ","reto":"AA","origen":"https://x","algoritmos":[-7],"colado":1}"#,
        );
        assert!(matches!(
            leer_mensaje(&mut bytes.as_slice()),
            Err(TransporteError::Json(_))
        ));
    }

    #[test]
    fn una_credencial_da_la_vuelta() {
        let mut salida = Vec::new();
        escribir_respuesta(
            &mut salida,
            &Respuesta::Credencial {
                credential_id: "aWQ".into(),
                attestation_object: "bw==".into(),
                client_data: "{\"type\":\"webauthn.create\"}".into(),
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&salida[4..]).unwrap();
        assert_eq!(v["tipo"], "credencial");
        assert_eq!(v["credential_id"], "aWQ");
        // La respuesta de registro NO lleva la clave privada por ninguna parte.
        assert!(v.get("clave").is_none() && v.get("clave_privada").is_none());
    }

    #[test]
    fn el_cierre_limpio_no_es_un_error_de_verdad() {
        let vacio: &[u8] = &[];
        assert!(matches!(
            leer_mensaje(&mut &vacio[..]),
            Err(TransporteError::Cerrado)
        ));
    }
}
