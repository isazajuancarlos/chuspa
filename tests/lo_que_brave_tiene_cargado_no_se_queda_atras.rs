// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! La carpeta que Brave tiene cargada tiene que ser la del repositorio.
//!
//! EL FALLO QUE VIGILA (2026-08-03, ocurrido de verdad): `target/extension-chrome/`
//! llevaba desde el día anterior con el manifiesto en `0.2.5` mientras el
//! programa iba por `0.2.9`, y con un `popup.js` sin el arreglo del aviso en
//! pestañas que no son páginas web. Es la misma trampa que el paquete instalado
//! —artefacto armado fuera de git que se queda atrás sin un solo error—, pero
//! peor: en Firefox el `.xpi` se rearma con el número de versión dentro y hay
//! una prueba que lo mira; esta carpeta se «carga descomprimida» una vez y se
//! queda ahí para siempre, y el navegador no vuelve a preguntar.
//!
//! LO QUE NO ES UN FALLO: que la carpeta no exista. En un clon recién hecho no
//! hay nada armado y no hay nada cargado en ningún navegador — ausencia, no
//! desacuerdo. Lo que no se admite es que exista y desmienta al repositorio.

use std::path::{Path, PathBuf};

fn raiz() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Los archivos que `instalar-extension-chrome.sh` copia tal cual.
///
/// Se leen del directorio en vez de escribirlos aquí: una lista a mano se
/// queda corta el día que se añade un archivo, y justo entonces es cuando la
/// prueba tendría que hablar.
fn archivos_copiados() -> Vec<String> {
    std::fs::read_dir(raiz().join("extension"))
        .expect("no encuentro extension/")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !matches!(n.as_str(), "manifest.json" | "manifest.chrome.json" | "banco"))
        .collect()
}

fn armada() -> Option<PathBuf> {
    let d = raiz().join("target/extension-chrome");
    d.is_dir().then_some(d)
}

#[test]
fn lo_armado_para_brave_es_lo_que_dice_el_repositorio() {
    let Some(dir) = armada() else {
        // Nada armado: nada cargado. Se dice, no se calla.
        eprintln!("target/extension-chrome/ no existe: no hay nada armado que pueda estar atrasado");
        return;
    };

    let mut atrasados = Vec::new();
    for nombre in archivos_copiados() {
        let fuente = raiz().join("extension").join(&nombre);
        let copia = dir.join(&nombre);
        if fuente.is_dir() {
            continue; // los subdirectorios los copia `cp -r`; ninguno hoy
        }
        match std::fs::read(&copia) {
            Err(_) => atrasados.push(format!("{nombre} (no está en lo armado)")),
            Ok(c) if c != std::fs::read(&fuente).unwrap() => atrasados.push(nombre),
            Ok(_) => {}
        }
    }

    assert!(
        atrasados.is_empty(),
        "lo que Brave tiene cargado no es lo del repositorio: {atrasados:?}\n\
         Rearma con: bash empaque/instalar-extension-chrome.sh $PWD/target/release/chuspa-puente",
    );
}

#[test]
fn el_manifiesto_armado_es_el_de_chrome_y_lleva_esta_version() {
    let Some(dir) = armada() else {
        eprintln!("target/extension-chrome/ no existe: nada que comparar");
        return;
    };

    let leer = |p: &Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(p).unwrap_or_else(|e| panic!("{p:?}: {e}"))).unwrap()
    };

    // El armado sale de `manifest.chrome.json`, no del de Firefox: si alguien
    // copiara el equivocado, Chrome no arrancaría el fondo y no diría por qué.
    let del_repo = leer(&raiz().join("extension/manifest.chrome.json"));
    let armado = leer(&dir.join("manifest.json"));
    assert_eq!(del_repo, armado, "el manifiesto armado no es el de chrome del repositorio");

    // Y la versión es la del programa. Estuvo cuatro por detrás —0.2.5 contra
    // 0.2.9— y el único sitio donde se veía era la página de extensiones, que
    // nadie mira porque no hay motivo para sospechar.
    assert_eq!(
        armado["version"].as_str().unwrap(),
        env!("CARGO_PKG_VERSION"),
        "la extensión armada dice una versión y el programa otra"
    );
}
