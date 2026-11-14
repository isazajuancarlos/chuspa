// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! # Chuspa
//!
//! Gestor de contraseñas **offline**: una bóveda local cifrada, sin nube y sin
//! cuenta. La criptografía la pone [Quipu]: Argon2id para derivar la clave
//! maestra de la frase de paso, subclave por entrada vía HKDF, y AEAD con
//! relleno Padmé sobre el contenedor.
//!
//! Una precisión que conviene no perder de vista: lo **post-cuántico** de Quipu
//! (ML-KEM) no interviene en el candado del día a día. Una bóveda local abierta
//! con frase de paso es cifrado simétrico, que ya resiste al adversario
//! cuántico por sí solo. ML-KEM aporta en la *recuperación* —cifrar la bóveda
//! también hacia una clave pública de respaldo—, y ahí sí es la diferencia.
//!
//! [Quipu]: https://github.com/isazajuancarlos/quipu

pub mod bitacora;
pub mod boveda;
pub mod cifrado;
pub mod copia;
pub mod fecha;
pub mod generador;
// El núcleo de la aplicación (estado `Aplicacion`, rutas `/api`, la firma
// pendiente y el despachador) vive aquí y **no** está atado al WebView: es Rust
// puro sobre `maud`, que no arrastra ningún motor web. Lo consume `navegador`
// —el enlace con la extensión— en el build por defecto (GTK puro), así que no
// puede ir tras `webview`. La ÚNICA pieza que necesita `wry` es `gui::atender`,
// gateada dentro del módulo (fase 1 de la migración a GTK: separar el núcleo de
// la capa wry).
pub mod gui;
pub mod importar;
pub mod memoria;
pub mod navegador;
pub mod nombre;
pub mod perfil;
pub mod respaldo;
pub mod salud;
pub mod totp;
pub mod version;
pub mod webauthn;
