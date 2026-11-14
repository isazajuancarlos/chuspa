// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Sella en el binario el commit del que sale.
//!
//! Eso es todo lo que hace hoy. Hasta el 2026-08-09 su otro trabajo era vigilar
//! `interfaz/dist` —la carpeta que `rust-embed` metía dentro del ejecutable sin
//! que cargo lo supiera—, y esa vigilancia se retiró con Angular: el detalle de
//! por qué existía y por qué ya no hace falta está en el cuerpo de `main`,
//! donde se lee al tocarlo.

fn main() {
    // Ya no hay nada que vigilar aquí.
    //
    // Hasta el 2026-08-09, `rust-embed` metía `interfaz/dist` dentro del
    // ejecutable y cargo no tenía forma de saberlo: sin un `rerun-if-changed`
    // sobre esa carpeta, un cambio en la interfaz no llegaba al binario y no
    // había error — los cambios simplemente no aparecían. Pasó de la peor
    // manera: un `ng build` a medias se embebió, el correcto de después ya no
    // disparó recompilación, y el RPM salió con la interfaz sin fuentes ni
    // iconos, con todas las pruebas en verde.
    //
    // Con `maud` + `include_str!` esa salvaguarda **desaparece porque
    // desaparece lo que la hacía falta** (directiva 1): las plantillas las
    // compila `rustc` y los estáticos los registra el propio compilador como
    // dependencias del crate. No hay dos artefactos que puedan separarse.
    println!("cargo:rerun-if-changed=build.rs");

    sellar_el_commit();
}

/// Deja dentro del binario el commit del que salió.
///
/// Nace de un caso real (2026-08-03): el RPM instalado se llamaba 0.2.9 y le
/// faltaban los tres últimos commits, porque se construyó ANTES de ellos y la
/// versión no se subió. Misma versión, distinto contenido, y ninguna forma de
/// notarlo desde la máquina donde estaba instalado. El número de versión dice
/// lo que el `Cargo.toml` prometía; el commit dice lo que el binario ES.
///
/// Cuando no hay repositorio —construir desde un tarball de fuentes— el sello
/// dice `sin-git`, no un valor inventado: es «no se puede saber», que es un
/// dato distinto de un hash.
fn sellar_el_commit() {
    // Sin esto el sello se queda con el commit de la primera compilación y
    // vuelve a mentir, que es justo el fallo que viene a cerrar.
    for archivo in ["../.git/HEAD", ".git/HEAD", ".git/index"] {
        if std::path::Path::new(archivo).exists() {
            println!("cargo:rerun-if-changed={archivo}");
        }
    }

    let sello = commit().unwrap_or_else(|| "sin-git".to_string());
    println!("cargo:rustc-env=CHUSPA_COMMIT={sello}");
}

fn commit() -> Option<String> {
    let salida = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !salida.status.success() {
        return None;
    }
    let hash = String::from_utf8(salida.stdout).ok()?.trim().to_string();
    if hash.is_empty() {
        return None;
    }

    // Un árbol con cambios sin commitear produce un binario que NO es ese
    // commit. Decir el hash a secas sería la misma mentira en pequeño.
    let sucio = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|s| s.status.success())
        .is_some_and(|s| !s.stdout.is_empty());

    Some(if sucio { format!("{hash}-sucio") } else { hash })
}
