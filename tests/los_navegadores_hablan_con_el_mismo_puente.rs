// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Todos los navegadores registrados tienen que hablar con el MISMO puente.
//!
//! EL FALLO QUE VIGILA (2026-08-15, ocurrido de verdad y vivo cinco días):
//! los manifiestos de Brave, Chrome y Chromium en `$HOME` apuntaban a
//! `…/target/release/chuspa-puente` —el árbol de construcción— y el de Firefox
//! a `/usr/bin/chuspa-puente` —el que instala el RPM—. En Chrome los de `$HOME`
//! TAPAN a los que el paquete deja en `/etc`, así que el manifiesto correcto
//! estaba puesto y no servía de nada.
//!
//! Los escribió `instalar-extension-chrome.sh` el 2026-08-10 con la ruta que se
//! le pasó a mano. Aquel día los dos binarios coincidían byte a byte, así que
//! no se veía nada; el del árbol es lo que dejó el último `cargo build`, y puede
//! ir por delante, por detrás o estar sucio. Es «misma versión, distinto
//! contenido» —lo mismo que persigue la ficha #411— una capa más abajo.
//!
//! POR QUÉ COMPARA BYTES Y NO RUTAS: registrar a propósito un puente sin
//! empaquetar es trabajo legítimo (probar un arreglo antes de hacer el RPM). Si
//! ese binario es idéntico al instalado, no hay dos programas y no hay nada que
//! denunciar. Lo que esta prueba mide es el fallo REAL —dos navegadores
//! ejecutando programas distintos contra la misma bóveda—, no su indicio.
//!
//! LO QUE NO ES UN FALLO: que no haya manifiestos, o que haya uno solo. En una
//! máquina sin navegadores no hay nada registrado — ausencia, no desacuerdo. Se
//! dice por qué se calla, que si no «sano» y «no miró» se ven igual.

use std::path::PathBuf;

/// Los sitios donde un navegador de esta máquina busca el manifiesto del puente.
///
/// Los de `$HOME` mandan sobre los de `/etc` en la familia de Chromium, y por
/// eso van los dos: el fallo de agosto consistió justamente en que el de `/etc`
/// era correcto y estaba tapado.
fn manifiestos() -> Vec<PathBuf> {
    let casa = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    [
        ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        ".config/google-chrome/NativeMessagingHosts",
        ".config/chromium/NativeMessagingHosts",
        ".mozilla/native-messaging-hosts",
    ]
    .iter()
    .map(|d| casa.join(d).join("com.xiliux.chuspa.json"))
    .chain(
        [
            "/etc/brave/native-messaging-hosts",
            "/etc/chromium/native-messaging-hosts",
            "/etc/opt/chrome/native-messaging-hosts",
            "/usr/lib/mozilla/native-messaging-hosts",
            "/usr/lib64/mozilla/native-messaging-hosts",
        ]
        .iter()
        .map(|d| PathBuf::from(d).join("com.xiliux.chuspa.json")),
    )
    .filter(|p| p.is_file())
    .collect()
}

/// La ruta que declara un manifiesto, y la huella de lo que hay en esa ruta.
fn puente_de(manifiesto: &PathBuf) -> Option<(String, Vec<u8>)> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(manifiesto).ok()?).ok()?;
    let ruta = v.get("path")?.as_str()?.to_string();
    // Un manifiesto que apunta a un programa que no existe es otro defecto, y
    // tiene su propia prueba abajo: aquí se devuelve la ausencia como huella
    // vacía para que las dos salgan a la luz por separado.
    let bytes = std::fs::read(&ruta).unwrap_or_default();
    Some((ruta, bytes))
}

#[test]
fn todos_los_navegadores_ejecutan_el_mismo_programa() {
    let encontrados = manifiestos();
    if encontrados.len() < 2 {
        eprintln!(
            "solo {} manifiesto(s) del puente en esta máquina: no hay dos que puedan discrepar",
            encontrados.len()
        );
        return;
    }

    let mut vistos: Vec<(PathBuf, String, Vec<u8>)> = Vec::new();
    for m in &encontrados {
        if let Some((ruta, bytes)) = puente_de(m) {
            vistos.push((m.clone(), ruta, bytes));
        }
    }

    let Some((_, _, primera_huella)) = vistos.first().cloned() else {
        panic!("hay manifiestos y ninguno se pudo leer: {encontrados:?}");
    };

    let discrepan: Vec<String> = vistos
        .iter()
        .filter(|(_, _, h)| *h != primera_huella)
        .map(|(m, r, _)| format!("{} -> {r}", m.display()))
        .collect();

    assert!(
        discrepan.is_empty(),
        "hay navegadores hablando con puentes DISTINTOS contra la misma bóveda.\n\
         El primero mira {}\n\
         y discrepan: {discrepan:#?}\n\
         Para dejarlos todos en el instalado:\n\
         \x20   bash empaque/instalar-extension-chrome.sh   (sin argumento)",
        vistos[0].1,
    );
}

#[test]
fn ningun_manifiesto_apunta_a_un_programa_que_no_existe() {
    let huerfanos: Vec<String> = manifiestos()
        .iter()
        .filter_map(|m| {
            let (ruta, bytes) = puente_de(m)?;
            bytes.is_empty().then(|| format!("{} -> {ruta}", m.display()))
        })
        .collect();

    assert!(
        huerfanos.is_empty(),
        "manifiestos que apuntan a un puente inexistente o ilegible: {huerfanos:#?}\n\
         El navegador dirá «no se pudo conectar» sin decir por qué.",
    );
}
