// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Revisa la bóveda y dice qué hay que arreglar.
//!
//! ```text
//! CHUSPA_FRASE='...' cargo run --release --example informe_salud -- boveda.chuspa [--resumen]
//! ```
//!
//! Con `--resumen` solo imprime los totales: sirve para enseñar el resultado sin
//! revelar en qué sitios tienes cuenta, que es lo que dicen los nombres.

use chuspa::cifrado::{Acceso, Boveda};
use chuspa::salud::{self, Hallazgo};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (ruta, solo_resumen) = match args.as_slice() {
        [r] => (r.clone(), false),
        [r, f] if f == "--resumen" => (r.clone(), true),
        _ => {
            eprintln!("uso: CHUSPA_FRASE='...' informe_salud <boveda.chuspa> [--resumen]");
            std::process::exit(2);
        }
    };
    let Ok(frase) = std::env::var("CHUSPA_FRASE") else {
        eprintln!("falta CHUSPA_FRASE (no se acepta como argumento: `ps` la vería)");
        std::process::exit(2);
    };

    let boveda = match Boveda::abrir(&ruta, &Acceso::frase(&frase)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo abrir la bóveda: {e}");
            std::process::exit(1);
        }
    };

    // Revisar exige abrirlas todas. Se dice, porque es lo contrario de lo que
    // hace el resto del programa.
    eprintln!("Abriendo las {} entradas para revisarlas…", boveda.len());
    let entradas: Vec<_> = (0..boveda.len())
        .filter_map(|i| boveda.abrir_entrada(i).ok())
        .collect();

    let informe = salud::revisar(&entradas);

    println!("REVISIÓN DE LA BÓVEDA");
    println!("=====================\n");
    println!("Entradas revisadas ......... {}", informe.revisadas);
    println!("Sin contraseña que revisar . {}", informe.sin_contrasena);
    println!("Con algún problema ......... {}\n", informe.con_problemas());

    let repetidas = informe.cuantas(|h| matches!(h, Hallazgo::Repetida { .. }));
    let cortas = informe.cuantas(|h| matches!(h, Hallazgo::Corta { .. }));
    let patrones = informe.cuantas(|h| matches!(h, Hallazgo::Patron(_)));
    let claro = informe.cuantas(|h| matches!(h, Hallazgo::ViajaEnClaro { .. }));
    let recicladas = informe.cuantas(|h| matches!(h, Hallazgo::RecicladaDeOtroHistorial));
    let totp = informe.cuantas(|h| matches!(h, Hallazgo::TotpIlegible));

    println!("  contraseñas repetidas en varias entradas . {repetidas}");
    println!("  cortas incluso siendo aleatorias ......... {cortas}");
    println!("  con patrón conocido (qwerty, palabra+año)  {patrones}");
    println!("  recicladas del historial de otra ......... {recicladas}");
    println!("  sitios que aún usan http ................. {claro}");
    println!("  segundo factor ilegible .................. {totp}");

    if solo_resumen {
        return;
    }

    println!("\n── DETALLE, lo más grave primero ──────────────────────────\n");
    for ficha in &informe.fichas {
        let marca = match ficha.gravedad() {
            3 => "!!!",
            2 => " !!",
            _ => "  !",
        };
        println!("{marca} {}", ficha.nombre);
        for h in &ficha.hallazgos {
            println!("      · {}", h.explicacion());
        }
    }
    if informe.fichas.is_empty() {
        println!("Nada que arreglar.");
    }
}
