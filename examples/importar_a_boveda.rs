// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Importa un export de Bitwarden a una bóveda cifrada de Chuspa.
//!
//! ```text
//! CHUSPA_FRASE='...' cargo run --example importar_a_boveda -- export.json boveda.chuspa
//! ```
//!
//! La frase de paso se lee de la variable de entorno **a propósito, y nunca de
//! un argumento**: los argumentos de un proceso son legibles por cualquier otro
//! proceso del sistema (`ps aux`) y quedan en el historial del intérprete. La
//! variable de entorno tampoco es ideal —también se hereda— pero no se escribe
//! en el historial; la interfaz definitiva la pedirá por terminal sin eco.
//!
//! Este programa no imprime valores de la bóveda: solo conteos y tiempos.

use chuspa::cifrado::{coste_por_defecto, evaluar_frase, generar_llave, Acceso, Boveda};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [origen, destino] = args.as_slice() else {
        eprintln!("uso: CHUSPA_FRASE='...' importar_a_boveda <export> <boveda.chuspa>");
        std::process::exit(2);
    };

    let Ok(frase) = std::env::var("CHUSPA_FRASE") else {
        eprintln!("falta CHUSPA_FRASE. No se acepta la frase como argumento: sería");
        eprintln!("visible en «ps» para cualquier proceso del sistema.");
        std::process::exit(2);
    };
    if frase.is_empty() {
        eprintln!("CHUSPA_FRASE está vacía. Una bóveda sin frase de paso no es una bóveda.");
        std::process::exit(2);
    }

    let texto = match std::fs::read_to_string(origen) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer «{origen}»: {e}");
            std::process::exit(2);
        }
    };

    let importada = if texto.trim_start().starts_with('{') {
        chuspa::importar::bitwarden::importar(&texto).map_err(|e| e.to_string())
    } else {
        chuspa::importar::bitwarden_csv::importar(&texto).map_err(|e| e.to_string())
    };
    let importada = match importada {
        Ok(i) => i,
        Err(e) => {
            eprintln!("la importación se detuvo: {e}");
            std::process::exit(1);
        }
    };

    println!("entradas a guardar: {}", importada.entradas.len());
    for aviso in &importada.avisos {
        println!("  · {aviso}");
    }

    if let Some(aviso) = evaluar_frase(&frase).aviso() {
        println!("\nAVISO sobre la frase de paso: {aviso}");
    }

    // Archivo llave opcional: si se pide, se genera uno y se guarda aparte. Un
    // secreto de 256 bits que no está en la bóveda hace que quien se lleve solo
    // el archivo no pueda probar frases contra él.
    let llave = if std::env::var("CHUSPA_GENERAR_LLAVE").is_ok() {
        let llave = generar_llave().expect("entropía del sistema");
        let ruta_llave = format!("{destino}.llave");
        if let Err(e) = chuspa::cifrado::escribir_llave(&ruta_llave, &llave) {
            eprintln!("no se pudo escribir el archivo llave: {e}");
            std::process::exit(1);
        }
        println!("\nArchivo llave escrito en {ruta_llave}");
        println!("MUÉVELO a otro soporte (un USB, otro equipo). Junto a la bóveda no");
        println!("protege de nada: quien se lleve una se lleva la otra.");
        println!("Y sin él la bóveda NO se abre, ni con la frase correcta.");
        Some(llave)
    } else {
        None
    };
    let acceso = match &llave {
        Some(l) => Acceso::con_llave(&frase, l),
        None => Acceso::frase(&frase),
    };

    let reloj = std::time::Instant::now();
    let mut boveda = match Boveda::crear(destino, &acceso, coste_por_defecto()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo crear la bóveda: {e}");
            std::process::exit(1);
        }
    };
    let derivacion = reloj.elapsed();

    for entrada in importada.entradas {
        if let Err(e) = boveda.anadir(entrada) {
            eprintln!("no se pudo añadir una entrada: {e}");
            std::process::exit(1);
        }
    }
    if let Err(e) = boveda.guardar() {
        eprintln!("no se pudo guardar: {e}");
        std::process::exit(1);
    }

    let total = reloj.elapsed();
    let tam = std::fs::metadata(destino).map(|m| m.len()).unwrap_or(0);
    println!(
        "\nbóveda escrita: {} entradas, {tam} bytes, versión {}",
        boveda.len(),
        boveda.contador()
    );
    println!("derivar la clave maestra: {derivacion:?} | total: {total:?}");
    println!(
        "\nGuarda el contador ({}) fuera de la bóveda y pásaselo a abrir_verificando:",
        boveda.contador()
    );
    println!("es lo único que detecta que alguien repuso una copia anterior.");
}
