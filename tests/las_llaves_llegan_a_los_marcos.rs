// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que la extensión alcance los marcos anidados, y que sepa retirarse.
//!
//! `all_frames` es **false** por defecto: los content scripts solo corren en el
//! marco principal. Si el sitio pide la llave desde un iframe suyo —como hace
//! Google en su flujo—, ahí no hay nadie, y el navegador acaba pidiendo una
//! llave física con la passkey correcta guardada.
//!
//! Encenderlo sin más abre una puerta. Un iframe de un tercero solo puede usar
//! WebAuthn si la página que lo aloja se lo permite con `Permissions-Policy:
//! publickey-credentials-get`, y esa comprobación la hace el navegador:
//! interceptar ahí se la saltaría, y un anuncio incrustado pediría firmas que el
//! navegador le habría negado.
//!
//! Las dos mitades van juntas o no van. Lo medido de verdad está en
//! `extension/banco/`, sobre un Firefox real; aquí se vigila que nadie quite una
//! de las dos sin darse cuenta.

use std::path::Path;

#[test]
fn los_content_scripts_alcanzan_todos_los_marcos() {
    let ext = Path::new(env!("CARGO_MANIFEST_DIR")).join("extension");
    let crudo = std::fs::read_to_string(ext.join("manifest.json")).unwrap();
    let manifiesto: serde_json::Value = serde_json::from_str(&crudo).unwrap();

    let scripts = manifiesto["content_scripts"]
        .as_array()
        .expect("el manifiesto tiene que declarar content_scripts");
    assert!(!scripts.is_empty(), "sin content scripts no hay nada que medir");

    for cs in scripts {
        let ficheros = cs["js"].as_array().map(|a| format!("{a:?}")).unwrap_or_default();
        assert_eq!(
            cs["all_frames"],
            serde_json::Value::Bool(true),
            "{ficheros} no declara `all_frames: true`.\n\
             Por defecto es false y el script no entra en los iframes, que es \
             donde algunos sitios piden la llave."
        );
    }
}

#[test]
fn en_un_marco_ajeno_la_extension_se_retira() {
    let ext = Path::new(env!("CARGO_MANIFEST_DIR")).join("extension");
    let fuente = std::fs::read_to_string(ext.join("passkeys.js")).unwrap();

    // Se mira solo el código: la explicación del porqué vive en los comentarios
    // y tiene que poder quedarse.
    let codigo: String = fuente
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        codigo.contains("window.top") && codigo.contains("original(opciones)"),
        "`passkeys.js` no distingue el marco ajeno.\n\
         Con `all_frames` encendido y sin esta comprobación, un iframe de un \
         tercero pediría firmas que el navegador le habría negado por \
         Permissions-Policy. Ante la duda, se devuelve la llamada al navegador."
    );

    // Y que la petición condicional siga devolviéndose: es lo que hacía que un
    // sitio entrara solo, sin que nadie pulsara nada.
    assert!(
        codigo.contains("conditional"),
        "`passkeys.js` volvió a atender las peticiones condicionales, que es lo \
         que hacía que Gmail entrara solo con la primera cuenta"
    );
}
