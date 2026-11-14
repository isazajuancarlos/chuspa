// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que la bitácora de diagnóstico no se lleve por delante lo que protege.
//!
//! Existe para responder a una sola pregunta —«¿llega la petición?»— y esa
//! respuesta no necesita ni una contraseña, ni una clave, ni el reto que firma
//! el sitio. Un archivo de diagnóstico con secretos dentro es peor que no tener
//! diagnóstico: se queda en el disco, sin cifrar, y nadie se acuerda de él.
//!
//! Se comprueba sobre el código porque es donde se decide qué se escribe. Una
//! prueba de comportamiento diría que las líneas de HOY están limpias; esta dice
//! que las de mañana también, porque falla al escribir la llamada, no al
//! ejecutarla.
//!
//! # Qué cambió con la ventana de `maud` + htmx
//!
//! La bitácora nació dentro de `navegador` porque el navegador era la única
//! frontera que cruzaba el programa, y esta prueba miraba ESE archivo y solo
//! ese. Con la pantalla nueva hay una segunda frontera —el motor WebKitGTK
//! pidiendo fragmentos— que anota por el mismo sitio, y una prueba anclada a un
//! archivo se habría quedado verde vigilando la mitad. Ahora recorre **todo
//! `src/`**: la regla es «ninguna anotación, esté donde esté», que es lo que
//! siempre quiso decir.

use std::path::{Path, PathBuf};

/// Lo que jamás puede aparecer en una línea de bitácora.
const PROHIBIDO: [&str; 6] = ["clave", "reto", "frase", "secreto", "contrasena", "contraseña"];

/// Dónde vive la función que escribe. Es la única que toca el archivo.
const DEFINICION: &str = "src/bitacora.rs";

fn raiz() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Todos los `.rs` de `src/`, recursivamente.
fn fuentes(dir: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entradas) = std::fs::read_dir(dir) else { return };
    for e in entradas.flatten() {
        let ruta = e.path();
        if ruta.is_dir() {
            fuentes(&ruta, acc);
        } else if ruta.extension().is_some_and(|x| x == "rs") {
            acc.push(ruta);
        }
    }
}

/// El mismo texto con los comentarios de línea en blanco.
///
/// Se miran las llamadas, no las MENCIONES: este archivo y los módulos que
/// anotan nombran los venenos al explicarse, y un comentario no escribe nada.
/// Las líneas se conservan en blanco para que los números sigan cuadrando.
fn sin_comentarios(fuente: &str) -> String {
    fuente
        .lines()
        .map(|l| if l.trim_start().starts_with("//") { "" } else { l })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Toda llamada a `anotar(...)` de un texto: en qué línea empieza y qué lleva
/// dentro, **de paréntesis a paréntesis**.
///
/// # Por qué no se mira línea a línea
///
/// Porque una llamada larga se parte, y la primera línea no dice nada:
///
/// ```text
/// anotar(&format!(
///     "la frase era {f}"      // ← el secreto vive AQUÍ
/// ));
/// ```
///
/// Un vigilante que mirase solo la línea del `anotar(` daría por limpia esa
/// llamada y no se quejaría jamás: exactamente el fallo que esta prueba existe
/// para impedir, escondido en el propio vigilante. Se equilibran los paréntesis,
/// saltando lo que va entre comillas para que un `"("` de un texto no descuadre
/// la cuenta.
///
/// **Recibe TEXTO y no una ruta**, y esa es la costura por la que se prueba: sin
/// ella el caso rojo solo se podría fabricar ensuciando el código de verdad, y
/// un banco que solo mira archivos que hoy están limpios sale verde con esta
/// regla y con una regla ciega — los dos mundos dan la misma lista vacía.
fn llamadas(fuente: &str) -> Vec<(usize, String)> {
    let sin_comentarios = sin_comentarios(fuente);
    let bytes = sin_comentarios.as_bytes();
    let mut halladas = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = sin_comentarios[i..].find("anotar(") {
        let inicio = i + rel;
        i = inicio + "anotar(".len();
        // La definición no es una llamada: ahí `anotar` recibe la línea ya
        // hecha, no la construye.
        if sin_comentarios[..inicio].ends_with("fn ") {
            continue;
        }
        let mut j = i;
        let mut nivel = 1i32;
        let mut en_texto = false;
        while j < bytes.len() && nivel > 0 {
            match bytes[j] {
                b'\\' if en_texto => j += 1,
                b'"' => en_texto = !en_texto,
                b'(' if !en_texto => nivel += 1,
                b')' if !en_texto => nivel -= 1,
                _ => {}
            }
            j += 1;
        }
        let linea = sin_comentarios[..inicio].matches('\n').count() + 1;
        halladas.push((linea, sin_comentarios[inicio..j.min(bytes.len())].to_string()));
    }
    halladas
}

/// Las anotaciones sucias, con su número de línea y el veneno que las delata.
fn anotaciones_sucias(fuente: &str) -> Vec<(usize, String, &'static str)> {
    let mut sucias = Vec::new();
    for (linea, texto) in llamadas(fuente) {
        for veneno in PROHIBIDO {
            if texto.to_lowercase().contains(veneno) {
                sucias.push((linea, texto.replace('\n', " ").trim().to_string(), veneno));
                break;
            }
        }
    }
    sucias
}

/// Cuántas llamadas a `anotar` hay en un texto (limpias o no).
fn cuantas_anotaciones(fuente: &str) -> usize {
    llamadas(fuente).len()
}

#[test]
fn ninguna_anotacion_menciona_un_secreto() {
    let mut archivos = Vec::new();
    fuentes(&raiz().join("src"), &mut archivos);
    // Y los ejemplos: el arnés que dibuja la ventana anota por la misma
    // función. Un instrumento de diagnóstico que filtre secretos los filtra
    // igual que el producto, y encima corre con bóvedas de verdad delante.
    fuentes(&raiz().join("examples"), &mut archivos);
    assert!(!archivos.is_empty(), "no se halló ni un .rs: ¿se buscó bien?");

    let mut anotaciones = 0;
    let mut hallazgos = Vec::new();
    for archivo in &archivos {
        let fuente = std::fs::read_to_string(archivo).unwrap();
        anotaciones += cuantas_anotaciones(&fuente);
        let corto = archivo.strip_prefix(raiz()).unwrap_or(archivo).display().to_string();
        for (n, linea, veneno) in anotaciones_sucias(&fuente) {
            hallazgos.push(format!("{corto}:{n} menciona «{veneno}»:\n    {linea}"));
        }
    }

    assert!(
        hallazgos.is_empty(),
        "la bitácora responde a «¿llega la petición?» y eso no necesita ningún \
         secreto:\n  {}",
        hallazgos.join("\n  ")
    );

    // Si no encontrara ninguna llamada, la prueba pasaría por vacía: sería el
    // verde que no distingue de «no se comprobó».
    assert!(anotaciones >= 3, "solo se hallaron {anotaciones} anotaciones: ¿se buscó bien?");
}

/// El caso rojo, sobre fuente sintética: la regla tiene que VER una anotación
/// sucia, o el verde de arriba no significa nada.
///
/// Va contra la misma función que usa el camino real, no contra una copia — si
/// no, fallaría por el arnés y no por la vía real (directiva 33).
#[test]
fn la_regla_ve_una_anotacion_sucia() {
    let sucio = r#"
        fn ejemplo() {
            anotar(&format!("firma para {sitio}"));
            anotar(&format!(
                "la frase de paso era {f}"
            ));
            // anotar("esto es un comentario con clave dentro");
        }
    "#;
    let sucias = anotaciones_sucias(sucio);
    assert_eq!(sucias.len(), 1, "esperaba una sola sucia, salieron {sucias:?}");
    assert_eq!(sucias[0].2, "frase");
    // La sucia es la PARTIDA en dos líneas: si el vigilante mirase solo la línea
    // del `anotar(`, ésta pasaría limpia y el caso rojo se lo perdería.
    assert!(sucias[0].1.contains("la frase de paso"));

    // Y la pareja: una fuente con anotaciones LIMPIAS no produce hallazgos. Sin
    // esta mitad pasaría igual una regla que dijera que sí a todo.
    let limpio = r#"
        fn ejemplo() {
            anotar(&format!("ventana GET /nuevo cuerpo={n}"));
            anotar("firma pedida");
        }
    "#;
    assert!(anotaciones_sucias(limpio).is_empty(), "falso positivo sobre fuente limpia");
    assert_eq!(cuantas_anotaciones(limpio), 2);
}

#[test]
fn sin_la_variable_no_se_escribe_nada() {
    // La bitácora es opt-in. Un gestor de contraseñas que apunte por su cuenta
    // a dónde entra su dueño sería otro problema, aunque no anote ni un secreto.
    let fuente = std::fs::read_to_string(raiz().join(DEFINICION)).unwrap();

    let cuerpo = fuente
        .split_once("fn anotar(")
        .expect("la función de bitácora tiene que existir")
        .1;
    let cuerpo = &cuerpo[..cuerpo.find("\n}").unwrap_or(cuerpo.len())];

    assert!(
        cuerpo.contains("CHUSPA_BITACORA"),
        "la bitácora no mira ninguna variable: se estaría escribiendo siempre"
    );
    // La salida temprana tiene que ir ANTES de cualquier escritura.
    let corte = cuerpo.find("else { return }").expect("falta la salida temprana sin variable");
    let escritura = cuerpo.find("OpenOptions").expect("falta la escritura");
    assert!(
        corte < escritura,
        "se abre el archivo antes de comprobar la variable: se crearía igual"
    );
}

/// Y que la escritura esté en UN solo sitio.
///
/// Si mañana alguien abre el archivo de bitácora desde otro módulo, la regla de
/// arriba —que mira el cuerpo de `anotar`— seguiría verde vigilando una función
/// que ya no es la única que escribe.
///
/// Mira `src/` y no los ejemplos a propósito: un ejemplo puede NOMBRAR la
/// variable para negarse a correr sin ella —lo hace `ventana_de_prueba`— y eso
/// no es escribir. Lo que no puede hacer ninguno es abrir el archivo por su
/// cuenta, y para eso tendría que traerse el `OpenOptions` a `src/`.
#[test]
fn solo_un_sitio_abre_la_bitacora() {
    let mut archivos = Vec::new();
    fuentes(&raiz().join("src"), &mut archivos);

    let escritores: Vec<String> = archivos
        .iter()
        .filter(|a| {
            std::fs::read_to_string(a)
                .is_ok_and(|f| sin_comentarios(&f).contains("CHUSPA_BITACORA"))
        })
        // `DEFINICION` usa `/`; en Windows `display()` daría `\`. Se normaliza a
        // `/` para que la comparación mida el ARCHIVO, no el separador del SO.
        .map(|a| a.strip_prefix(raiz()).unwrap_or(a).display().to_string().replace('\\', "/"))
        .collect();

    assert_eq!(
        escritores,
        vec![DEFINICION.to_string()],
        "la bitácora se abre desde más de un sitio: la regla de «sin variable no \
         se escribe» solo vigila {DEFINICION}"
    );
}
