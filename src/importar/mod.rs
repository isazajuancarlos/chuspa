// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Importadores de bóvedas externas.

pub mod bitwarden;
pub mod bitwarden_csv;
// Importar desde el llavero del SO (Secret Service / D-Bus sobre socket Unix):
// es Linux-only. En Windows Chromium cifra con DPAPI, que es otra vía (pendiente).
#[cfg(unix)]
pub mod navegadores;
