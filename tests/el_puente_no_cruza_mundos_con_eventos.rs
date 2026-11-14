// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que la extensión no vuelva a hablar entre sus dos mundos con `CustomEvent`.
//!
//! Firefox aísla el content script de la página con visión X-ray: **un objeto
//! creado en el content script no es legible desde la página**. Con un
//! `CustomEvent`, la página recibía el evento y su `detail` le llegaba
//! inaccesible, así que la promesa nunca resolvía, vencía el plazo, y la llamada
//! caía al camino del navegador.
//!
//! El síntoma no se parecía en nada a la causa: Firefox pedía una **llave de
//! seguridad física** con la passkey correcta guardada, la extensión inyectada y
//! la aplicación firmando perfectamente si se le hablaba por su socket. Costó
//! descartar la CSP del sitio, el permiso de host, la versión de la extensión y
//! el formato del identificador antes de mirar aquí.
//!
//! Lo medido de verdad está en `extension/banco/`, que ejercita la cadena entera
//! en un Firefox real y da `respondio: false` con el mecanismo viejo y
//! `respondio: true` con el nuevo. Esta prueba es la otra mitad: corre en cada
//! `cargo test` e impide que el patrón vuelva a entrar sin que nadie lo note.

use std::path::Path;

/// Los archivos que viven a caballo entre los dos mundos.
const A_CABALLO: [&str; 2] = ["passkeys.js", "puente-passkeys.js"];

#[test]
fn ningun_script_cruza_los_mundos_con_custom_event() {
    let ext = Path::new(env!("CARGO_MANIFEST_DIR")).join("extension");

    for archivo in A_CABALLO {
        let ruta = ext.join(archivo);
        let fuente = std::fs::read_to_string(&ruta)
            .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", ruta.display()));

        // Se buscan las dos mitades del patrón por separado. Nombrar solo
        // `CustomEvent` dejaría pasar un `dispatchEvent` con un evento
        // construido de otra forma, que falla igual.
        for veneno in ["CustomEvent", "dispatchEvent"] {
            // Las menciones en comentarios explican POR QUÉ no se usa, y tienen
            // que poder quedarse: si contaran, la única salida sería borrar la
            // explicación del fallo.
            let en_codigo = fuente
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains(veneno));

            assert!(
                !en_codigo,
                "{archivo} usa `{veneno}` para hablar entre los dos mundos.\n\
                 Firefox no deja leer a la página un objeto creado en el content \
                 script, así que la respuesta se pierde y la llamada cae al \
                 navegador sin un solo error.\n\
                 Se usa `window.postMessage`, que clona estructuralmente.\n\
                 Comprobarlo de verdad: extension/banco/README.md"
            );
        }

        // Y que el mecanismo bueno esté de verdad, no solo ausente el malo:
        // pasar por no tener ninguno de los dos sería un verde vacío.
        assert!(
            fuente.contains("postMessage"),
            "{archivo} no habla por `postMessage`: la prueba estaría pasando por \
             no encontrar nada, no por encontrar lo correcto"
        );
    }
}
