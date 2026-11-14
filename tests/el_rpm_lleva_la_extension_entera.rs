// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que el paquete lleve la extensión COMPLETA.
//!
//! Los assets del RPM estuvieron enumerados fichero a fichero, y se quedaron en
//! los tres originales. Cuando la extensión creció a seis, los tres nuevos
//! —`fondo.js`, `passkeys.js`, `puente-passkeys.js`— dejaron de viajar en el
//! paquete: quien instalara la extensión desde `/usr/share/chuspa/extension`
//! tenía las llaves de acceso muertas, sin un solo error que lo dijera.
//!
//! Una lista escrita a mano de algo que crece es una lista que se queda vieja.
//! Aquí se comprueba que el empaquetado cubre todos los archivos que la
//! extensión declara necesitar, y no que estén los seis de hoy: fijar el número
//! reproduciría el mismo fallo con otra forma.

use std::collections::BTreeSet;
use std::path::Path;

/// Todos los archivos que el `manifest.json` de la extensión menciona.
///
/// Se leen del manifiesto y no del directorio porque el manifiesto es quien
/// dice qué hace falta para que la extensión funcione. Un `.js` suelto que
/// nadie referencia no es un fallo de empaquetado; uno referenciado que falta,
/// sí.
fn archivos_que_la_extension_necesita(raiz: &Path) -> BTreeSet<String> {
    let crudo = std::fs::read_to_string(raiz.join("extension/manifest.json"))
        .expect("el manifiesto de la extensión tiene que existir");
    let manifiesto: serde_json::Value =
        serde_json::from_str(&crudo).expect("el manifiesto tiene que ser JSON válido");

    let mut necesarios = BTreeSet::new();
    necesarios.insert("manifest.json".to_string());

    // Recorrido genérico: cualquier cadena del manifiesto que acabe en `.js`,
    // `.html` o `.css` y exista en el directorio es un archivo de la extensión.
    // Enumerar las claves concretas (`background.scripts`, `content_scripts[].js`,
    // `action.default_popup`…) sería otra lista que se queda vieja.
    fn recorrer(v: &serde_json::Value, raiz: &Path, salida: &mut BTreeSet<String>) {
        match v {
            serde_json::Value::String(s) => {
                let parece_archivo =
                    s.ends_with(".js") || s.ends_with(".html") || s.ends_with(".css");
                if parece_archivo && raiz.join("extension").join(s).is_file() {
                    salida.insert(s.clone());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| recorrer(x, raiz, salida)),
            serde_json::Value::Object(o) => o.values().for_each(|x| recorrer(x, raiz, salida)),
            _ => {}
        }
    }
    recorrer(&manifiesto, raiz, &mut necesarios);
    necesarios
}

#[test]
fn el_empaquetado_cubre_toda_la_extension() {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR"));
    let necesarios = archivos_que_la_extension_necesita(raiz);

    // Si el manifiesto no menciona nada, la prueba pasaría por vacía y no
    // mediría nada: es el verde que no distingue de «no se comprobó».
    assert!(
        necesarios.len() >= 3,
        "el manifiesto apenas menciona archivos ({necesarios:?}): la prueba no \
         estaría midiendo nada"
    );

    let cargo = std::fs::read_to_string(raiz.join("Cargo.toml")).unwrap();
    let assets = cargo
        .split_once("[package.metadata.generate-rpm]")
        .expect("el bloque de empaquetado tiene que existir")
        .1;

    for archivo in &necesarios {
        // Vale el patrón que barre el directorio entero o la línea del archivo
        // concreto: lo que se exige es que el paquete lo lleve, no cómo.
        let por_patron = assets.contains("source = \"extension/*\"");
        let por_nombre = assets.contains(&format!("extension/{archivo}"));
        assert!(
            por_patron || por_nombre,
            "«{archivo}» lo necesita la extensión y el RPM no lo empaqueta.\n\
             Con el patrón `extension/*` esto no vuelve a pasar."
        );
    }
}

/// Lo mismo para el paquete `.deb`, que es el gemelo del RPM en Debian/Ubuntu.
///
/// El RPM barre con `extension/*`; el `.deb` va por patrón de EXTENSIÓN de
/// archivo (`extension/*.js`, `*.json`, `*.html`) para dejar fuera el arnés de
/// pruebas de `extension/banco/`. El precio de esa precisión es que una
/// extensión NUEVA —un `.css`, un `.wasm`— no entraría sola: aquí es donde se
/// entera, ruidosamente, en vez de instalar la extensión con una pieza muerta.
#[test]
fn el_empaquetado_deb_cubre_toda_la_extension() {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR"));
    let necesarios = archivos_que_la_extension_necesita(raiz);

    assert!(
        necesarios.len() >= 3,
        "el manifiesto apenas menciona archivos ({necesarios:?}): la prueba no \
         estaría midiendo nada"
    );

    let cargo = std::fs::read_to_string(raiz.join("Cargo.toml")).unwrap();
    let assets = cargo
        .split_once("[package.metadata.deb]")
        .expect("el bloque de empaquetado .deb tiene que existir")
        .1;

    for archivo in &necesarios {
        let ext = Path::new(archivo)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        // Vale el patrón por extensión, el que barre todo, o el nombre a pelo:
        // lo que se exige es que el paquete lo lleve, no cómo. Se compara el
        // token ENTRE COMILLAS —`"extension/*.js"`, no `extension/*.js`— porque
        // sin ellas `extension/*.js` casa como subcadena con `extension/*.json`
        // y la prueba deja de discriminar (visto: quitar `*.js` no la ponía roja).
        let por_patron_ext =
            !ext.is_empty() && assets.contains(&format!("\"extension/*.{ext}\""));
        let por_patron_todo = assets.contains("\"extension/*\"");
        let por_nombre = assets.contains(&format!("\"extension/{archivo}\""));
        assert!(
            por_patron_ext || por_patron_todo || por_nombre,
            "«{archivo}» lo necesita la extensión y el .deb no lo empaqueta.\n\
             Añade el patrón `extension/*.{ext}` al bloque [package.metadata.deb]."
        );
    }
}
