// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! El puente que el navegador lanza. **No decide nada.**
//!
//! Traduce entre el formato de *native messaging* (por la entrada y la salida
//! estándar) y el socket del agente. No abre la bóveda, no ve la frase de paso y
//! no compara dominios: eso lo hace el agente, que es un proceso aparte con su
//! propia vida.
//!
//! Ese reparto es el punto: este proceso es el que un navegador comprometido
//! alcanza primero, y cuanto menos sepa, menos hay que perder si cae. Lo peor
//! que puede hacer un puente controlado por un atacante es reenviar peticiones
//! que el agente va a juzgar igual.
//!
//! El navegador lo arranca porque un manifiesto de native-messaging lo declara
//! —en Linux un JSON en `~/.mozilla/native-messaging-hosts/`, en Windows una clave
//! del registro que apunta a ese JSON—, y ese manifiesto restringe qué extensión
//! puede hablar con él (`allowed_extensions`/`allowed_origins`).
//!
//! El canal con el agente: en Linux un socket de dominio Unix
//! (`std::os::unix::net`), en Windows un named pipe por `chuspa_ipc_win` (misma
//! forma de API). Ver `chuspa::navegador` para el porqué del cambio (2026-10-10).

use chuspa::navegador::protocolo::{self, Respuesta, TransporteError};
use std::io::{BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use chuspa_ipc_win::UnixStream;

fn main() {
    // El puente lo arranca el navegador con argumentos suyos —el manifiesto y
    // el identificador de la extensión—, así que esto solo dispara cuando lo
    // llama una persona a mano para ver qué versión hay instalada.
    chuspa::version::atender_peticion_de_version("chuspa-puente");

    let entrada = std::io::stdin();
    let mut salida = std::io::stdout();

    loop {
        let peticion = match protocolo::leer_mensaje(&mut entrada.lock()) {
            Ok(p) => p,
            // El navegador cerró: es como termina este proceso normalmente.
            Err(TransporteError::Cerrado) => break,
            Err(e) => {
                // El error se devuelve por el canal, no por la salida de error:
                // el puente no tiene terminal donde nadie lo vea.
                let _ = protocolo::escribir_respuesta(
                    &mut salida,
                    &Respuesta::Error { mensaje: e.to_string() },
                );
                continue;
            }
        };

        let respuesta = match consultar(&peticion) {
            Ok(r) => r,
            Err(e) => Respuesta::Error {
                mensaje: format!(
                    "no hay ninguna aplicación Chuspa escuchando ({e}). Abre la \
                     bóveda en la aplicación y vuelve a intentarlo."
                ),
            },
        };
        if protocolo::escribir_respuesta(&mut salida, &respuesta).is_err() {
            break;
        }
    }
}

/// Una conexión por petición: se abre, se pregunta, se cierra.
///
/// Mantener el socket abierto ahorraría muy poco y dejaría un canal vivo hacia
/// la bóveda durante toda la sesión del navegador.
fn consultar(peticion: &protocolo::Peticion) -> Result<Respuesta, TransporteError> {
    // La MISMA ruta que usa el agente (`navegador::ruta_del_socket`), multiplataforma
    // y sin duplicar: Linux `$XDG_RUNTIME_DIR/chuspa`, Windows `%LOCALAPPDATA%\chuspa`.
    let socket = chuspa::navegador::ruta_del_socket()?;
    let mut flujo = UnixStream::connect(&socket)?;
    flujo.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    let cuerpo = serde_json::to_vec(peticion)?;
    flujo.write_all(&(cuerpo.len() as u32).to_ne_bytes())?;
    flujo.write_all(&cuerpo)?;
    flujo.flush()?;

    let mut lector = BufReader::new(flujo);
    leer_respuesta(&mut lector)
}

fn leer_respuesta<R: std::io::Read>(origen: &mut R) -> Result<Respuesta, TransporteError> {
    let mut cabecera = [0u8; 4];
    origen.read_exact(&mut cabecera)?;
    let tamano = u32::from_ne_bytes(cabecera);
    if tamano > protocolo::MAXIMO_MENSAJE {
        return Err(TransporteError::DemasiadoGrande {
            tamano,
            maximo: protocolo::MAXIMO_MENSAJE,
        });
    }
    let mut cuerpo = vec![0u8; tamano as usize];
    origen.read_exact(&mut cuerpo)?;
    Ok(serde_json::from_slice(&cuerpo)?)
}
