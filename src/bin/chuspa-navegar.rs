// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! `chuspa-navegar`: abre una URL en el NAVEGADOR SEGURO (perfil cifrado),
//! nunca en el Firefox estándar.
//!
//! Pensado para registrarse como navegador por defecto del sistema, de modo que
//! un `/login`, un `xdg-open` o cualquier app que abra "el navegador" caigan en
//! el perfil protegido y no en la sesión estándar.
//!
//! Si el volumen seguro NO está montado, no cae al Firefox normal (eso
//! traicionaría el propósito): avisa y abre chuspa para que el usuario
//! desbloquee y monte. En esta versión la URL no se reabre sola tras montar; el
//! usuario reintenta. La transparencia total sin frase exigiría mantener el
//! volumen montado, que es justo lo que el diseño evita en reposo.

use std::process::{Command, ExitCode};

use chuspa::perfil::{self, Rutas};

fn main() -> ExitCode {
    // `--version` no abre nada, como en los demás binarios (directiva 28).
    chuspa::version::atender_peticion_de_version("chuspa-navegar");

    // El primer argumento es la URL (puede faltar: entonces solo abre el
    // navegador). Un navegador por defecto recibe la URL como único argumento.
    let url = std::env::args().nth(1);
    // La URL viene de fuera (chuspa-navegar es el navegador por defecto). Si hay
    // una, tiene que ser http/https: rechaza esquemas peligrosos y el
    // contrabando de flags (una "url" que empiece por `-`).
    if let Some(ref u) = url
        && !perfil::es_url_web(u)
    {
        eprintln!("URL no admitida (solo http/https): {u}");
        return ExitCode::FAILURE;
    }
    let rutas = Rutas::por_defecto();

    if !perfil::esta_montado(&rutas.clear) {
        let aviso = "El navegador seguro no está abierto. Ábrelo desde chuspa \
                     (botón «Abrir y navegar») y reintenta.";
        eprintln!("{aviso}");
        // Aviso en pantalla si el entorno lo permite (no es obligatorio).
        let _ = Command::new("notify-send")
            .arg("Chuspa — navegador seguro")
            .arg(aviso)
            .status();
        // Abrir chuspa para que el usuario monte; NO se cae al Firefox normal.
        let _ = Command::new("chuspa-gtk").spawn();
        return ExitCode::FAILURE;
    }

    match perfil::comando_firefox(&rutas.perfil(), url.as_deref()).spawn() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("no se pudo abrir el navegador seguro: {e}");
            ExitCode::FAILURE
        }
    }
}
