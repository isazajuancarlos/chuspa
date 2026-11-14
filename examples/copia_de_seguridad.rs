// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Crea, comprueba y restaura la copia de seguridad cifrada y comprimida.
//!
//! ```text
//! # Crear. La copia se abre con la MISMA frase, salvo que se dé otra.
//! CHUSPA_FRASE='...' cargo run --release --example copia_de_seguridad -- \
//!     crear boveda.chuspa copia.chuspacopia
//!
//! # Comprobar que la copia del cajón SIGUE sirviendo. No toca nada.
//! CHUSPA_FRASE='...' cargo run --release --example copia_de_seguridad -- \
//!     comprobar copia.chuspacopia
//!
//! # Restaurar en una bóveda NUEVA (se niega si el destino existe).
//! CHUSPA_FRASE='...' CHUSPA_NUEVA_FRASE='...' \
//!   cargo run --release --example copia_de_seguridad -- \
//!     restaurar copia.chuspacopia recuperada.chuspa
//! ```
//!
//! **Comprobar es lo barato y restaurar hay que pedirlo aparte**, igual que en
//! la recuperación por papel: una copia que nunca se ha probado no es una
//! copia, es una suposición — y probarla no puede ser lo mismo que crear cosas.
//!
//! La frase va por variable de entorno **a propósito**: los argumentos de un
//! proceso los lee cualquiera con `ps`. La interfaz gráfica la pide sin eco y
//! no la hereda a ningún hijo.
//!
//! Este programa no imprime valores de la bóveda: solo conteos, tamaños y
//! fechas.

use chuspa::cifrado::{Acceso, Boveda};
use chuspa::copia;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Ok(frase) = std::env::var("CHUSPA_FRASE") else {
        eprintln!("falta CHUSPA_FRASE. No se acepta como argumento: sería visible");
        eprintln!("en «ps» para cualquier proceso del sistema.");
        std::process::exit(2);
    };
    if frase.is_empty() {
        eprintln!("CHUSPA_FRASE está vacía.");
        std::process::exit(2);
    }
    let acceso = Acceso::frase(&frase);

    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["crear", boveda, destino] => crear(&acceso, boveda, destino),
        ["comprobar", copia] => comprobar(&acceso, copia),
        ["restaurar", copia, destino] => restaurar(&acceso, copia, destino),
        _ => {
            eprintln!("uso:");
            eprintln!("  copia_de_seguridad crear <boveda.chuspa> <copia>");
            eprintln!("  copia_de_seguridad comprobar <copia>");
            eprintln!("  copia_de_seguridad restaurar <copia> <destino.chuspa>");
            std::process::exit(2);
        }
    }
}

fn crear(acceso: &Acceso<'_>, boveda: &str, destino: &str) {
    let inicio = std::time::Instant::now();
    let b = match Boveda::abrir(boveda, acceso) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no se pudo abrir «{boveda}»: {e}");
            std::process::exit(1);
        }
    };
    let abierta = inicio.elapsed();

    let bytes = match copia::crear(&b, acceso) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("no se pudo crear la copia: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = std::fs::write(destino, &bytes) {
        eprintln!("no se pudo escribir «{destino}»: {e}");
        std::process::exit(1);
    }
    // Permisos 0600: una copia de seguridad tiene dentro lo mismo que la
    // bóveda, y dejarla legible para todo el sistema sería regalar el trabajo.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(destino, std::fs::Permissions::from_mode(0o600));
    }

    let ficha = copia::comprobar(&bytes, acceso).expect("recién creada, tiene que abrir");
    println!("copia escrita en {destino}");
    println!("  entradas:  {}", ficha.entradas);
    println!("  en claro:  {} bytes", ficha.bytes_en_claro);
    println!("  archivo:   {} bytes ({:.0} % menos)", ficha.bytes_archivo, ficha.ahorro());
    println!("  contador:  {}", ficha.contador);
    println!("  abrir la bóveda tardó {abierta:?}; el total, {:?}", inicio.elapsed());
    println!();
    println!("Guárdala donde no esté la bóveda. La abre esta frase de paso, y también");
    println!("la hoja de respaldo en papel: son la misma clave maestra.");
}

fn comprobar(acceso: &Acceso<'_>, ruta: &str) {
    let bytes = match std::fs::read(ruta) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("no se pudo leer «{ruta}»: {e}");
            std::process::exit(1);
        }
    };
    match copia::comprobar(&bytes, acceso) {
        Ok(f) => {
            println!("la copia se abre y su contenido cuadra.");
            println!("  entradas: {}", f.entradas);
            println!("  hecha:    hace {}", hace(f.creada));
            println!("  contador: {}", f.contador);
            println!("  archivo:  {} bytes ({:.0} % menos que en claro)", f.bytes_archivo, f.ahorro());
        }
        Err(e) => {
            eprintln!("ESTA COPIA NO SIRVE: {e}");
            std::process::exit(1);
        }
    }
}

fn restaurar(acceso: &Acceso<'_>, ruta: &str, destino: &str) {
    let Ok(nueva) = std::env::var("CHUSPA_NUEVA_FRASE") else {
        eprintln!("falta CHUSPA_NUEVA_FRASE: la frase con la que quedará la bóveda");
        eprintln!("restaurada. Se pide aparte para que restaurar nunca sea lo que pasa");
        eprintln!("por accidente cuando alguien solo quería comprobar la copia.");
        std::process::exit(2);
    };
    let bytes = match std::fs::read(ruta) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("no se pudo leer «{ruta}»: {e}");
            std::process::exit(1);
        }
    };
    match copia::restaurar(&bytes, acceso, destino, &Acceso::frase(&nueva)) {
        Ok(f) => {
            println!("bóveda restaurada en {destino}");
            println!("  entradas: {}", f.entradas);
            println!("  la copia era de hace {}", hace(f.creada));
            println!();
            println!("Ábrela con la frase nueva. La bóveda de origen no se ha tocado.");
        }
        Err(e) => {
            eprintln!("no se restauró: {e}");
            std::process::exit(1);
        }
    }
}

/// Cuánto hace, en palabras. Una fecha absoluta obligaría a formatear
/// calendario a mano; lo que se quiere saber aquí es si la copia es de esta
/// semana o del año pasado.
fn hace(creada: u64) -> String {
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = ahora.saturating_sub(creada);
    match s {
        0..=90 => "menos de dos minutos".to_string(),
        91..=5400 => format!("{} minutos", s / 60),
        5401..=172_800 => format!("{} horas", s / 3600),
        _ => format!("{} días", s / 86_400),
    }
}
