// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Imprime la hoja de respaldo de una bóveda.
//!
//! ```text
//! CHUSPA_FRASE='...' cargo run --release --example hoja_de_respaldo -- boveda.chuspa [llave]
//! ```
//!
//! La salida va a la **salida estándar** y contiene la clave que abre la bóveda
//! entera. Redirígela a la impresora o a un archivo que borres después; no la
//! dejes en el historial de la terminal.

use chuspa::cifrado::{Acceso, Boveda};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (ruta, ruta_llave) = match args.as_slice() {
        [r] => (r, None),
        [r, l] => (r, Some(l)),
        _ => {
            eprintln!("uso: CHUSPA_FRASE='...' hoja_de_respaldo <boveda.chuspa> [archivo.llave]");
            std::process::exit(2);
        }
    };

    let Ok(frase) = std::env::var("CHUSPA_FRASE") else {
        eprintln!("falta CHUSPA_FRASE (no se acepta como argumento: `ps` la vería)");
        std::process::exit(2);
    };

    let llave = ruta_llave.map(|l| match std::fs::read(l) {
        Ok(bytes) => zeroize::Zeroizing::new(bytes),
        Err(e) => {
            eprintln!("no se pudo leer el archivo llave «{l}»: {e}");
            std::process::exit(2);
        }
    });
    let acceso = match &llave {
        Some(l) => Acceso::con_llave(&frase, l),
        None => Acceso::frase(&frase),
    };

    let boveda = match Boveda::abrir(ruta, &acceso) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo abrir la bóveda: {e}");
            std::process::exit(1);
        }
    };

    let hoja = match chuspa::respaldo::hoja(&boveda.exportar_maestra()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("no se pudo preparar la hoja: {e}");
            std::process::exit(1);
        }
    };

    print!("{}", hoja.imprimible().as_str());
    eprintln!(
        "\n[{} entradas respaldadas | {} símbolos, se pueden perder {}]",
        boveda.len(),
        hoja.simbolos.len(),
        hoja.perdidas_toleradas
    );
}
