// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Importador de las contraseñas guardadas en los navegadores hacia la bóveda.
//!
//! Se construye por fases (diseño 2026-09-12). La primera es el descifrado del
//! `os_crypt` de Chromium ([`oscrypt`]), una función pura probada con vectores
//! independientes. Las siguientes —lector SQLite mínimo, acceso al llavero por
//! Secret Service, fusión aditiva con dedup+reporte, botón en la bóveda, y
//! Firefox (`logins.json` + `key4.db`)— se añaden aquí.

pub mod oscrypt;
pub mod sqlite;
pub mod fusion;
pub mod llavero;

pub mod deteccion;

pub mod des3;

pub mod nss;
