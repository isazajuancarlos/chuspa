// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Comprueba o recupera una bóveda desde un respaldo.
//!
//! ```text
//! # Comprobar que la hoja del cajón sigue sirviendo (NO toca la bóveda):
//! cargo run --release --example recuperar_boveda -- boveda.chuspa palabras
//! cargo run --release --example recuperar_boveda -- boveda.chuspa fragmentos frag1.txt frag2.txt frag3.txt
//! cargo run --release --example recuperar_boveda -- boveda.chuspa sobre sobre.txt privada.bin
//!
//! # Recuperar de verdad: fija una frase nueva y guarda.
//! CHUSPA_NUEVA_FRASE='...' cargo run --release --example recuperar_boveda -- boveda.chuspa palabras
//! ```
//!
//! **Comprobar es lo que hace por defecto.** Recuperar sobrescribe la bóveda con
//! un acceso nuevo, y eso no puede ser lo que pasa cuando alguien ejecuta el
//! comando para ver si su respaldo sigue bien. Hay que pedirlo aparte.
//!
//! Las palabras se teclean por la **entrada estándar**, no como argumento: un
//! argumento lo ve cualquier proceso con `ps` y se queda en el historial.

use chuspa::cifrado::{Acceso, Boveda};
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((ruta, resto)) = args.split_first() else {
        ayuda();
        std::process::exit(2);
    };
    let Some((metodo, extra)) = resto.split_first() else {
        ayuda();
        std::process::exit(2);
    };

    let maestra = match metodo.as_str() {
        "palabras" => desde_palabras(),
        "fragmentos" => desde_fragmentos(extra),
        "sobre" => desde_sobre(extra),
        otro => {
            eprintln!("método desconocido: «{otro}»\n");
            ayuda();
            std::process::exit(2);
        }
    };

    // Comprobar SIEMPRE, y antes de nada: si el respaldo no es de esta bóveda,
    // no hay que tocar nada ni pedir frases nuevas.
    match Boveda::comprobar_maestra(ruta, &maestra) {
        Ok(true) => println!("✓ El respaldo corresponde a esta bóveda."),
        Ok(false) => {
            eprintln!("✗ Este respaldo NO abre esta bóveda.");
            eprintln!("  O es de otra, o la clave se rotó después de hacerlo.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("no se pudo comprobar: {e}");
            std::process::exit(1);
        }
    }

    let Ok(nueva) = std::env::var("CHUSPA_NUEVA_FRASE") else {
        println!("\nNo se ha tocado la bóveda. Para recuperarla de verdad, vuelve a");
        println!("ejecutar con CHUSPA_NUEVA_FRASE definida: se abrirá con este");
        println!("respaldo y quedará con esa frase de paso.");
        return;
    };
    if nueva.is_empty() {
        eprintln!("CHUSPA_NUEVA_FRASE está vacía; una bóveda sin frase no es una bóveda");
        std::process::exit(2);
    }

    let mut boveda = match Boveda::abrir_con_maestra(ruta, &maestra) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo abrir con el respaldo: {e}");
            std::process::exit(1);
        }
    };
    println!("Bóveda abierta: {} entradas.", boveda.len());

    if let Some(aviso) = chuspa::cifrado::evaluar_frase(&nueva).aviso() {
        println!("AVISO sobre la frase nueva: {aviso}");
    }
    if let Err(e) = boveda.cambiar_acceso(&Acceso::frase(&nueva)) {
        eprintln!("no se pudo fijar el acceso nuevo: {e}");
        std::process::exit(1);
    }
    if let Err(e) = boveda.guardar() {
        eprintln!("no se pudo guardar: {e}");
        std::process::exit(1);
    }
    println!("Listo: la bóveda queda con la frase nueva (versión {}).", boveda.contador());
    println!();
    println!("El respaldo que acabas de usar SIGUE SIENDO VÁLIDO: cambiar la frase");
    println!("no invalida un respaldo. Si lo usaste porque se había perdido de");
    println!("vista, rota la clave maestra para dejarlo sin efecto.");
}

fn ayuda() {
    eprintln!("uso: recuperar_boveda <boveda.chuspa> <método> [archivos]");
    eprintln!();
    eprintln!("  palabras                       las 24 palabras, por la entrada estándar");
    eprintln!("  fragmentos <f1> <f2> ...       un archivo por fragmento del reparto");
    eprintln!("  sobre <sobre> <privada>        el sobre y la clave privada del destinatario");
    eprintln!();
    eprintln!("Por defecto solo COMPRUEBA. Define CHUSPA_NUEVA_FRASE para recuperar.");
}

fn desde_palabras() -> [u8; 32] {
    use std::io::Read;
    eprintln!("Teclea las 24 palabras separadas por espacios y pulsa Ctrl-D:");
    let mut texto = Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut texto).is_err() {
        eprintln!("no se pudo leer la entrada");
        std::process::exit(2);
    }
    match chuspa::respaldo::desde_palabras(&texto) {
        Ok(m) => *m,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn desde_fragmentos(rutas: &[String]) -> [u8; 32] {
    if rutas.is_empty() {
        eprintln!("hacen falta los archivos de al menos tantos fragmentos como el umbral");
        std::process::exit(2);
    }
    // Cada archivo es un fragmento: una línea por símbolo, y se ignora lo que no
    // parezca uno para poder pegar la hoja entera tal cual.
    let fragmentos: Vec<Vec<String>> = rutas
        .iter()
        .map(|r| match std::fs::read_to_string(r) {
            Ok(texto) => chuspa::respaldo::simbolos_de_texto(&texto),
            Err(e) => {
                eprintln!("no se pudo leer «{r}»: {e}");
                std::process::exit(2);
            }
        })
        .collect();

    match chuspa::respaldo::reunir(&fragmentos) {
        Ok(m) => *m,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("\n¿Son al menos tantos fragmentos como pide el umbral?");
            std::process::exit(1);
        }
    }
}

fn desde_sobre(rutas: &[String]) -> [u8; 32] {
    let [ruta_sobre, ruta_privada] = rutas else {
        eprintln!("uso: ... sobre <archivo-sobre> <archivo-clave-privada>");
        std::process::exit(2);
    };
    let sobre = match std::fs::read_to_string(ruta_sobre) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            eprintln!("no se pudo leer el sobre: {e}");
            std::process::exit(2);
        }
    };
    let privada = match std::fs::read(ruta_privada) {
        Ok(b) => Zeroizing::new(b),
        Err(e) => {
            eprintln!("no se pudo leer la clave privada: {e}");
            std::process::exit(2);
        }
    };
    let secreta = match chuspa::respaldo::privada_desde_bytes(&privada) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match chuspa::respaldo::abrir_sobre(sobre.trim(), &secreta) {
        Ok(m) => *m,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
