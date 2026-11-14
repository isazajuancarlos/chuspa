// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Comprueba un export REAL de Bitwarden sin revelar su contenido.
//!
//! ```text
//! cargo run --example comprobar_export -- /ruta/al/export.csv
//! ```
//!
//! Un export real es la única prueba de que el importador aguanta los datos de
//! verdad: 594 entradas con acentos, URIs larguísimas, notas multilínea y
//! contraseñas de 400 caracteres no salen de un fixture escrito a mano. Pero un
//! export real también es la bóveda entera en claro, así que este programa está
//! construido para no poder enseñarla: **no imprime ningún valor de ningún
//! campo**. Solo conteos, y el número de la fila cuando algo no cuadra.
//!
//! La comprobación que importa es celda a celda: por cada columna del CSV con
//! contenido, tiene que existir su destino en la entrada importada. Si una
//! columna se llenara y su destino quedara vacío, aquí sale la cuenta.

use chuspa::boveda::{Clase, Importacion, Origen};
use std::collections::BTreeMap;

fn main() {
    let Some(ruta) = std::env::args().nth(1) else {
        eprintln!("uso: comprobar_export <archivo.csv|archivo.json>");
        std::process::exit(2);
    };

    let texto = match std::fs::read_to_string(&ruta) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer «{ruta}»: {e}");
            std::process::exit(2);
        }
    };

    let es_json = texto.trim_start().starts_with('{');
    let importada = if es_json {
        println!("formato detectado: JSON\n");
        match chuspa::importar::bitwarden::importar(&texto) {
            Ok(i) => i,
            Err(e) => {
                // El error puede citar un nombre de campo del formato, nunca un
                // valor: los errores del importador están escritos así.
                eprintln!("la importación se detuvo: {e}");
                std::process::exit(1);
            }
        }
    } else {
        println!("formato detectado: CSV\n");
        match chuspa::importar::bitwarden_csv::importar(&texto) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("la importación se detuvo: {e}");
                std::process::exit(1);
            }
        }
    };

    resumir(&importada);

    // Cada formato se coteja con su propia sonda. Devolver 0 para el formato que
    // no se sabe cotejar produciría un «sin pérdidas» que en realidad significa
    // «no se miró»: el peor resultado posible en una herramienta cuyo trabajo es
    // justo ese.
    let (fallos, comprobadas) = if es_json {
        cotejar_json(&texto, &importada)
    } else {
        cotejar_csv(&texto, &importada)
    };

    println!("\n== avisos ==");
    for aviso in &importada.avisos {
        println!("  · {aviso}");
    }

    if fallos > 0 {
        eprintln!("\n{fallos} dato(s) del export sin destino en la bóveda importada.");
        std::process::exit(1);
    }
    println!("\nSin pérdidas: {comprobadas} comprobaciones, todas con destino.");
}

/// Cotejo del JSON: por cada ítem, el número de datos de su bloque específico
/// tiene que salir como campos estándar + URIs. Es la misma medida que usa la
/// suite de pruebas, aplicada aquí al archivo de verdad.
fn cotejar_json(texto: &str, importada: &Importacion) -> (usize, usize) {
    fn hojas(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::String(s) => usize::from(!s.is_empty()),
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) => 1,
            serde_json::Value::Null => 0,
            serde_json::Value::Array(a) => a.iter().map(hojas).sum(),
            serde_json::Value::Object(o) => o.values().map(hojas).sum(),
        }
    }

    let Ok(crudo) = serde_json::from_str::<serde_json::Value>(texto) else {
        return (1, 0);
    };
    let vacio = Vec::new();
    let items = crudo["items"].as_array().unwrap_or(&vacio);

    let (mut fallos, mut comprobadas) = (0usize, 0usize);
    // Los ítems de la papelera no producen entrada; se saltan igual que en el
    // importador para que los pares no se desalineen.
    let vivos = items.iter().filter(|i| i["deletedDate"].is_null());

    for (item, entrada) in vivos.zip(&importada.entradas) {
        let bloque = ["login", "card", "identity", "secureNote"]
            .iter()
            .find_map(|k| item.get(*k))
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let reglas = item["login"]["uris"]
            .as_array()
            .map(|a| a.iter().filter(|u| !u["match"].is_null()).count())
            .unwrap_or(0);

        let esperados = hojas(&bloque).saturating_sub(reglas);
        let obtenidos = entrada
            .campos
            .iter()
            .filter(|c| c.origen == Origen::Estandar)
            .count()
            + entrada.uris.len();

        comprobadas += 1;
        if esperados != obtenidos {
            // Se informa el índice y las cuentas, nunca el nombre del sitio.
            eprintln!(
                "ítem #{comprobadas}: el JSON trae {esperados} datos y llegaron {obtenidos}"
            );
            fallos += 1;
        }
    }
    (fallos, comprobadas)
}

fn resumir(i: &Importacion) {
    println!("entradas importadas: {}", i.entradas.len());

    let mut por_clase: BTreeMap<&str, usize> = BTreeMap::new();
    let mut por_campo: BTreeMap<String, usize> = BTreeMap::new();
    let (mut secretos, mut personalizados, mut uris) = (0usize, 0usize, 0usize);

    for e in &i.entradas {
        *por_clase.entry(e.clase.etiqueta()).or_default() += 1;
        uris += e.uris.len();
        for c in &e.campos {
            match c.origen {
                Origen::Estandar => *por_campo.entry(c.etiqueta.clone()).or_default() += 1,
                Origen::Personalizado => personalizados += 1,
            }
            if c.valor.es_sensible() {
                secretos += 1;
            }
        }
    }

    println!("\npor clase:");
    for (clase, n) in &por_clase {
        println!("  {clase:<12} {n}");
    }

    println!("\ncampos estándar presentes:");
    for (etiqueta, n) in &por_campo {
        println!("  {etiqueta:<24} {n}");
    }

    println!("\ncampos personalizados: {personalizados}");
    println!("valores marcados como secretos: {secretos}");
    println!("URIs: {uris}");
    println!(
        "con carpeta: {}",
        i.entradas.iter().filter(|e| e.carpeta.is_some()).count()
    );
    println!(
        "con notas: {}",
        i.entradas.iter().filter(|e| e.notas.is_some()).count()
    );
    println!(
        "favoritas: {} | archivadas: {} | con reprompt: {}",
        i.entradas.iter().filter(|e| e.favorita).count(),
        i.entradas.iter().filter(|e| e.archivada.is_some()).count(),
        i.entradas.iter().filter(|e| e.repreguntar).count(),
    );
    println!(
        "carpetas distintas: {}",
        i.entradas
            .iter()
            .filter_map(|e| e.carpeta.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
}

/// Por cada celda con contenido del CSV, comprueba que su destino existe en la
/// entrada importada. Informa el número de fila, nunca el contenido.
fn cotejar_csv(texto: &str, importada: &Importacion) -> (usize, usize) {
    let mut lector = csv::Reader::from_reader(texto.as_bytes());
    let cabecera: Vec<String> = match lector.headers() {
        Ok(h) => h.iter().map(String::from).collect(),
        Err(e) => {
            eprintln!("no se pudo releer la cabecera: {e}");
            return (1, 0);
        }
    };
    let col = |n: &str| cabecera.iter().position(|c| c == n);

    let (mut fallos, mut comprobadas) = (0usize, 0usize);
    for (n, registro) in lector.records().enumerate() {
        let Ok(registro) = registro else { continue };
        let Some(entrada) = importada.entradas.get(n) else {
            eprintln!("fila {}: no produjo entrada", n + 2);
            fallos += 1;
            continue;
        };
        let celda = |nombre: &str| -> &str {
            col(nombre).and_then(|i| registro.get(i)).unwrap_or("").trim()
        };

        let mut exigir = |lleno: bool, destino: bool, que: &str| {
            // Solo cuentan como comprobación las celdas que traían algo: exigir
            // un destino para una celda vacía no comprueba nada, e inflaría el
            // número que se le enseña al usuario.
            if !lleno {
                return;
            }
            comprobadas += 1;
            if !destino {
                eprintln!("fila {}: «{que}» tiene contenido y no llegó", n + 2);
                fallos += 1;
            }
        };

        exigir(!celda("name").is_empty(), !entrada.nombre.is_empty(), "name");
        exigir(!celda("folder").is_empty(), entrada.carpeta.is_some(), "folder");
        exigir(!celda("notes").is_empty(), entrada.notas.is_some(), "notes");
        exigir(
            !celda("archivedDate").is_empty(),
            entrada.archivada.is_some(),
            "archivedDate",
        );
        exigir(
            !celda("login_uri").is_empty(),
            !entrada.uris.is_empty(),
            "login_uri",
        );
        exigir(
            !celda("login_username").is_empty(),
            entrada.campo("acceso.usuario").is_some(),
            "login_username",
        );
        exigir(
            !celda("login_password").is_empty(),
            entrada.campo("acceso.clave").is_some(),
            "login_password",
        );
        exigir(
            !celda("login_totp").is_empty(),
            entrada.campo("acceso.totp").is_some(),
            "login_totp",
        );
        exigir(
            !celda("fields").is_empty(),
            entrada.campos.iter().any(|c| c.origen == Origen::Personalizado),
            "fields",
        );
        exigir(
            celda("favorite") == "1",
            entrada.favorita,
            "favorite",
        );
        exigir(
            celda("reprompt") == "1",
            entrada.repreguntar,
            "reprompt",
        );
        exigir(
            celda("type") == "note",
            entrada.clase == Clase::Nota,
            "type=note",
        );
    }
    (fallos, comprobadas)
}
