// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Qué versión —y qué commit— es el ejecutable que está corriendo.
//!
//! El 2026-08-03 el paquete instalado se llamaba 0.2.9 y le faltaban los tres
//! últimos commits: se había construido antes de ellos y nadie subió el número.
//! Misma versión, distinto contenido. Desde la máquina donde estaba instalado
//! no había ninguna forma de verlo, y las pruebas —que miran el árbol, no lo
//! instalado— salían todas verdes.
//!
//! El número de versión dice lo que el `Cargo.toml` prometía. El commit dice lo
//! que el binario ES. Por eso van los dos, y por eso `--version` existe en los
//! dos ejecutables: el puente también se instala, y también puede quedarse atrás.

/// La versión declarada en `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// El commit del que salió este binario, sellado por `build.rs`.
///
/// `sin-git` cuando se construyó fuera de un repositorio, y `<hash>-sucio`
/// cuando el árbol tenía cambios sin commitear: las dos son respuestas
/// honestas a «¿de dónde sale esto?», y ninguna se puede confundir con un hash.
pub const COMMIT: &str = env!("CHUSPA_COMMIT");

/// La línea que imprime `--version`, para un ejecutable con este nombre.
pub fn linea(programa: &str) -> String {
    format!("{programa} {VERSION} ({COMMIT})")
}

/// Atiende `--version` / `-V` y no vuelve: imprime y sale con 0.
///
/// Se llama lo primero de cada `main`, ANTES de tocar la bóveda o de abrir la
/// ventana. Preguntar qué versión hay instalada no puede exigir teclear la
/// frase de paso, ni dejar una ventana abierta en la pantalla.
pub fn atender_peticion_de_version(programa: &str) {
    let pide = std::env::args().skip(1).any(|a| a == "--version" || a == "-V");
    if pide {
        println!("{}", linea(programa));
        std::process::exit(0);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_linea_lleva_version_y_commit() {
        let l = linea("chuspa-gui");
        assert!(l.starts_with("chuspa-gui "), "falta el nombre: {l}");
        assert!(l.contains(VERSION), "falta la versión: {l}");
        assert!(l.contains(COMMIT), "falta el commit: {l}");
    }

    #[test]
    fn el_sello_del_commit_nunca_queda_vacio() {
        // Un sello vacío se leería como «no hay información» cuando en realidad
        // sería un fallo del `build.rs`. Si no se puede saber, lo dice.
        assert!(!COMMIT.is_empty());

        // Tres formas, y solo tres: el hash, el hash de un árbol sucio, y «no
        // se puede saber». Cualquier otra cosa es un `build.rs` que se rompió y
        // se está leyendo como si fuera un dato.
        let hex_de = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
        let bien = COMMIT == "sin-git"
            || hex_de(COMMIT)
            || COMMIT.strip_suffix("-sucio").is_some_and(hex_de);
        assert!(bien, "sello con forma inesperada: {COMMIT}");
    }
}
