// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Un ejecutable instalado tiene que poder decir de dónde sale.
//!
//! EL FALLO QUE VIGILA (2026-08-03, ocurrido de verdad): el RPM instalado se
//! llamaba `chuspa-0.2.9` y le faltaban los tres últimos commits —guardar desde
//! el navegador, el arreglo de Brave y el que impedía que editar una entrada le
//! destruyera el TOTP—. Se había construido antes de ellos y nadie subió el
//! número de versión. Misma versión, distinto contenido: desde la máquina donde
//! estaba instalado no había NADA que lo delatara, y las pruebas seguían verdes
//! porque miran el árbol de trabajo, no lo instalado.
//!
//! Se cruza la frontera del programa (directiva 28): se arranca el ejecutable
//! de verdad y se le habla como le habla una persona en la terminal. Mirar la
//! constante desde dentro del crate mediría el `env!`, no el producto.

use std::process::Command;

fn version_declarada() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// El frontal de escritorio que se construye bajo las features activas —el que de
// verdad se instala—: GTK con `gtk-ui`, y egui en cualquier otro caso (el
// DEFAULT, y el de Windows).
#[cfg(feature = "gtk-ui")]
const FRONTAL: &str = env!("CARGO_BIN_EXE_chuspa-gtk");
#[cfg(not(feature = "gtk-ui"))]
const FRONTAL: &str = env!("CARGO_BIN_EXE_chuspa-egui");

/// Lo que dice el ejecutable cuando se le pregunta, tal cual sale.
fn preguntarle(exe: &str, bandera: &str) -> String {
    let salida = Command::new(exe)
        .arg(bandera)
        .output()
        .unwrap_or_else(|e| panic!("no se pudo arrancar {exe}: {e}"));

    assert!(
        salida.status.success(),
        "{exe} {bandera} salió con {:?}; error: {}",
        salida.status.code(),
        String::from_utf8_lossy(&salida.stderr)
    );
    String::from_utf8(salida.stdout).expect("la salida no es UTF-8").trim().to_string()
}

// LAS PRUEBAS DEL FRONTAL VAN POR FEATURE, porque el binario de escritorio
// depende de ella: `chuspa-gtk` solo se construye con `gtk-ui` (Linux), y
// `chuspa-egui` con `egui-ui` (el que se instala en Windows y es el DEFAULT).
// Medir el que no se construyó daría «no se encuentra el archivo», que es
// exactamente como fallaba antes en Windows. El invariante —el binario que se
// envía dice su versión y su commit sin abrir ventana— se comprueba sobre el
// frontal que corresponde a cada plataforma.

#[cfg(feature = "gtk-ui")]
#[test]
fn la_aplicacion_gtk_dice_su_version_sin_abrir_ninguna_ventana() {
    // La aplicación de escritorio por defecto es GTK puro. Si abriera la ventana
    // o pidiera la frase, esta prueba se colgaría: que termine ya es parte de lo
    // que comprueba.
    let dicho = preguntarle(env!("CARGO_BIN_EXE_chuspa-gtk"), "--version");
    assert!(
        dicho.starts_with(&format!("chuspa-gtk {}", version_declarada())),
        "esperaba «chuspa-gtk {} (<commit>)», dijo «{dicho}»",
        version_declarada()
    );
}

#[cfg(feature = "gtk-ui")]
#[test]
fn la_forma_corta_gtk_dice_lo_mismo() {
    let largo = preguntarle(env!("CARGO_BIN_EXE_chuspa-gtk"), "--version");
    let corto = preguntarle(env!("CARGO_BIN_EXE_chuspa-gtk"), "-V");
    assert_eq!(largo, corto);
}

#[cfg(feature = "egui-ui")]
#[test]
fn la_aplicacion_egui_dice_su_version_sin_abrir_ninguna_ventana() {
    // El frontal egui es el que se instala en Windows. Igual que el de GTK, tiene
    // que responder `--version` ANTES de abrir la ventana —si dibujara o pidiera
    // la frase, la prueba se colgaría— (ver `main` en `chuspa-egui.rs`).
    let dicho = preguntarle(env!("CARGO_BIN_EXE_chuspa-egui"), "--version");
    assert!(
        dicho.starts_with(&format!("chuspa-egui {}", version_declarada())),
        "esperaba «chuspa-egui {} (<commit>)», dijo «{dicho}»",
        version_declarada()
    );
}

#[cfg(feature = "egui-ui")]
#[test]
fn la_forma_corta_egui_dice_lo_mismo() {
    let largo = preguntarle(env!("CARGO_BIN_EXE_chuspa-egui"), "--version");
    let corto = preguntarle(env!("CARGO_BIN_EXE_chuspa-egui"), "-V");
    assert_eq!(largo, corto);
}

#[test]
fn el_puente_tambien_dice_su_version() {
    // El puente se instala aparte y se registra a mano en cada navegador: es
    // justo el que puede quedarse atrás sin que nadie lo note.
    let dicho = preguntarle(env!("CARGO_BIN_EXE_chuspa-puente"), "--version");
    assert!(
        dicho.starts_with(&format!("chuspa-puente {}", version_declarada())),
        "esperaba «chuspa-puente {} (<commit>)», dijo «{dicho}»",
        version_declarada()
    );
}

#[test]
fn el_commit_sellado_es_el_commit_del_arbol() {
    // ESTA es la que discrimina. Sin el `rerun-if-changed` sobre `.git` en el
    // `build.rs`, el sello se queda con el commit de la primera compilación y
    // vuelve a mentir exactamente igual que la versión. Se mide sobre el frontal
    // de escritorio que se construye (el producto que se instala): GTK en Linux,
    // egui en Windows (ver `FRONTAL`).
    let dicho = preguntarle(FRONTAL, "--version");

    let cabeza = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("hace falta git para esta prueba; no se salta en silencio");
    assert!(cabeza.status.success(), "git rev-parse falló en el árbol de chuspa");
    let cabeza = String::from_utf8(cabeza.stdout).unwrap().trim().to_string();

    let sello = dicho
        .rsplit_once('(')
        .and_then(|(_, resto)| resto.strip_suffix(')'))
        .unwrap_or_else(|| panic!("no encuentro el commit entre paréntesis en «{dicho}»"))
        .to_string();

    // El árbol puede estar sucio mientras se trabaja —el sello lo dice—, pero
    // el hash tiene que ser el de HEAD.
    let hash = sello.strip_suffix("-sucio").unwrap_or(&sello);
    assert_eq!(
        hash, cabeza,
        "el binario dice salir de {hash} y HEAD es {cabeza}: el sello se quedó atrás"
    );
}
