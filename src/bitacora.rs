// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! La bitácora de diagnóstico: qué se pidió, nunca con qué.
//!
//! # Por qué existe
//!
//! Cuando una passkey no funciona, cada pieza se puede comprobar por separado
//! —la extensión está instalada, el permiso concedido, la aplicación firma si se
//! le habla por su socket— y aun así el conjunto falla. Lo que faltaba era saber
//! **si la petición llega**, que es lo que separa «el fallo está en el navegador»
//! de «el fallo está aquí». Sin ese dato solo quedan hipótesis, y se gastan de
//! una en una.
//!
//! # Por qué vive aquí y no dentro de `navegador`
//!
//! Nació ahí porque el navegador era la única frontera que cruzaba el programa.
//! Con la ventana en `maud` + htmx hay una segunda —el motor WebKitGTK pidiendo
//! fragmentos por `chuspa://`— y tiene exactamente el mismo problema: un
//! `hx-get` que no se dispara, un intercambio que cae en el sitio equivocado o
//! un cuerpo que el motor descarta devuelven todos la misma pantalla callada.
//! Una sola bitácora para las dos fronteras, y una sola regla sobre qué puede
//! escribirse.
//!
//! # La regla, que no se negocia
//!
//! **Nunca escribe contraseñas, claves, frases ni retos.** Solo qué se pidió,
//! para qué sitio, desde qué origen y cómo acabó. La vigila
//! `tests/la_bitacora_no_filtra.rs`, que falla al *escribir* la llamada —no al
//! ejecutarla—, así que cubre también las líneas que se añadan mañana.
//!
//! Y **no se enciende sola**: se pide con `CHUSPA_BITACORA=/ruta/al/archivo`. Un
//! gestor de contraseñas que apunte por su cuenta a dónde entra su dueño sería
//! otro problema, aunque no anote ni un secreto.

/// Escribe una línea, si y solo si hay bitácora pedida.
///
/// Es `pub` porque el arnés que dibuja la ventana (`examples/ventana_de_prueba.rs`)
/// anota por aquí lo que el DOM dice de sí mismo. Anotar por una segunda función
/// sería tener dos bitácoras con una sola regla escrita.
pub fn anotar(linea: &str) {
    let Some(ruta) = std::env::var_os("CHUSPA_BITACORA") else { return };
    use std::io::Write;
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(ruta) {
        let _ = writeln!(f, "{ahora} {linea}");
    }
}
