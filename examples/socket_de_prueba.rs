// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Levanta el enlace con el navegador sin abrir ventana. **Solo para pruebas.**
//!
//! El enlace vive dentro de la aplicación, que pide la frase de paso por su
//! interfaz. Una prueba automática no puede teclearla ni abrir una ventana, así
//! que este arnés hace lo mismo por la vía corta: abre la bóveda y llama a
//! `escuchar_al_navegador`.
//!
//! Es un EJEMPLO y no un binario: no se instala, no va en el RPM y el guardián
//! de andamios no tiene que perseguirlo.

use chuspa::cifrado::{Acceso, Boveda};
use chuspa::gui::Aplicacion;
use std::sync::Arc;

fn main() {
    let ruta = std::env::args().nth(1).expect("ruta de la bóveda");
    let frase = std::env::var("CHUSPA_FRASE_DE_PRUEBA").expect("CHUSPA_FRASE_DE_PRUEBA");
    let minutos: u64 = std::env::args().nth(2).and_then(|m| m.parse().ok()).unwrap_or(5);

    let boveda = Boveda::abrir(&ruta, &Acceso::frase(&frase)).expect("abrir la bóveda");
    let app = Arc::new(Aplicacion::nueva(ruta.into()));
    *app.boveda.lock().unwrap() = Some(boveda);

    let socket = chuspa::navegador::escuchar_al_navegador(
        Arc::clone(&app),
        std::time::Duration::from_secs(minutos * 60),
    )
    .expect("levantar el socket");
    println!("escuchando en {}", socket.display());

    // El hilo del socket vive mientras viva el proceso.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
