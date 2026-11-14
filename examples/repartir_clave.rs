// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Reparte la clave de una bóveda entre varios custodios (Shamir k-de-n).
//!
//! ```text
//! CHUSPA_FRASE='...' cargo run --release --example repartir_clave -- boveda.chuspa 3 5
//! ```
//!
//! Imprime `total` fragmentos. Con `umbral` cualquiera de ellos se recupera la
//! clave; con menos, **nada**. Cada uno va a un sitio o a una persona distinta.

use chuspa::cifrado::{Acceso, Boveda};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [ruta, umbral, total] = args.as_slice() else {
        eprintln!("uso: CHUSPA_FRASE='...' repartir_clave <boveda.chuspa> <umbral> <total>");
        std::process::exit(2);
    };
    let (umbral, total) = match (umbral.parse::<u8>(), total.parse::<u8>()) {
        (Ok(u), Ok(t)) => (u, t),
        _ => {
            eprintln!("el umbral y el total son números de 2 a 255");
            std::process::exit(2);
        }
    };

    let Ok(frase) = std::env::var("CHUSPA_FRASE") else {
        eprintln!("falta CHUSPA_FRASE (no se acepta como argumento: `ps` la vería)");
        std::process::exit(2);
    };

    if let Some(aviso) = chuspa::memoria::paginacion().aviso() {
        eprintln!("AVISO: {aviso}\n");
    }

    let boveda = match Boveda::abrir(ruta, &Acceso::frase(&frase)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo abrir la bóveda: {e}");
            std::process::exit(1);
        }
    };

    let fragmentos = match chuspa::respaldo::repartir(&boveda.exportar_maestra(), umbral, total) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("no se pudo repartir: {e}");
            std::process::exit(1);
        }
    };

    println!("REPARTO DE LA CLAVE DE UNA BÓVEDA CHUSPA");
    println!("========================================\n");
    println!(
        "Se han hecho {total} fragmentos. Hacen falta {umbral} para recuperar la\n\
         clave; con {} o menos no se obtiene NADA — ni media clave, ni una pista.\n",
        umbral - 1
    );
    println!(
        "Reparte cada fragmento en un sitio o una persona distinta, y RECORTA la\n\
         hoja: dos fragmentos juntos en un cajón valen por uno solo.\n"
    );

    for f in &fragmentos {
        println!("── FRAGMENTO {} de {total} ─────────────────────────", f.indice);
        println!(
            "   (hacen falta {} fragmentos cualesquiera; de este se pueden perder",
            f.umbral
        );
        println!("    hasta {} símbolos)\n", f.perdidas_toleradas);
        for (i, s) in f.simbolos.iter().enumerate() {
            println!("   [{:>2}] {}", i + 1, s.as_str());
        }
        println!();
    }
}
