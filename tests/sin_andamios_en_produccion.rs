// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que no se cuele un andamio de pruebas en un binario que se instala.
//!
//! Nació de un susto real: para comprobar que la ventana creaba la bóveda le
//! inyecté un `with_initialization_script` que llamaba a `/api/crear` al cargar.
//! Al restaurar el archivo, la copia de vuelta no se aplicó — y el binario y el
//! RPM quedaron con ese script dentro. Habría creado una bóveda con una frase de
//! prueba en cuanto alguien abriera el programa.
//!
//! Lo cazó comprobar en vez de dar por hecho que el `cp` había funcionado. Esta
//! prueba lo convierte en algo que no depende de que alguien se acuerde de
//! comprobar: una directiva que hay que recordar vale menos que una prueba que
//! falla.

const BINARIOS: &[(&str, &str)] = &[
    ("chuspa-gtk", include_str!("../src/bin/chuspa-gtk.rs")),
    ("chuspa-puente", include_str!("../src/bin/chuspa-puente.rs")),
];

/// Lo que no puede aparecer en un binario que se instala en `/usr/bin`.
///
/// Cada patrón es una forma concreta de que código de prueba llegue al usuario,
/// no una categoría abierta de «cosas sospechosas».
const PROHIBIDOS: &[(&str, &str)] = &[
    (
        "with_initialization_script",
        "inyecta JavaScript al cargar la página: es el andamio que ya se coló una vez",
    ),
    (
        "with_devtools(true)",
        "las herramientas de desarrollo dejan las contraseñas a la vista con dos clics",
    ),
    ("[diag]", "traza de diagnóstico olvidada"),
    ("dbg!", "`dbg!` imprime el valor entero, y aquí los valores son secretos"),
    ("todo!", "un `todo!` en un binario instalado es un pánico esperando"),
];

#[test]
fn los_binarios_instalables_no_llevan_andamios() {
    let mut hallazgos = Vec::new();
    for (nombre, fuente) in BINARIOS {
        for (patron, motivo) in PROHIBIDOS {
            // Se ignoran los comentarios: este archivo y los propios binarios
            // mencionan los patrones al explicarlos.
            let en_codigo = fuente
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//") && !t.starts_with("*") && !t.starts_with("/*")
                })
                .any(|l| l.contains(patron));
            if en_codigo {
                hallazgos.push(format!("{nombre}: «{patron}» — {motivo}"));
            }
        }
    }
    assert!(
        hallazgos.is_empty(),
        "hay andamios de prueba en binarios que se instalan:\n  {}",
        hallazgos.join("\n  ")
    );
}
