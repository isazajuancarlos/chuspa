// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Descubre qué navegadores de la familia Chromium están instalados y dónde
//! guardan sus contraseñas. Parte de la fase 5 del importador.
//!
//! En Linux cada navegador guarda su `Login Data` (una base SQLite) dentro de su
//! carpeta de configuración, un archivo por PERFIL (`Default`, `Profile 1`…). El
//! secreto para descifrarlas lo registra en el llavero con una ETIQUETA fija
//! (`brave`, `chrome`, `chromium`, `microsoft-edge`), que es la que
//! [`super::llavero`] necesita.

use std::path::{Path, PathBuf};

/// Un `Login Data` encontrado en el disco, con lo necesario para importarlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Perfil {
    /// Nombre del navegador, para enseñar (p.ej. «Brave»).
    pub navegador: &'static str,
    /// Etiqueta del secreto en el llavero (p.ej. «brave»).
    pub etiqueta_llavero: &'static str,
    /// Nombre del proceso del navegador (`comm`, ≤15 chars) para saber si está
    /// abierto: leer su `Login Data` con el navegador vivo puede dar una lectura
    /// a medio escribir.
    pub proceso: &'static str,
    /// Nombre del perfil (p.ej. «Default», «Profile 1»).
    pub perfil: String,
    /// Ruta del archivo `Login Data`.
    pub login_data: PathBuf,
}

impl Perfil {
    /// ¿Está el navegador de este perfil corriendo ahora mismo? Mira `/proc`.
    /// Un `true` dice «ciérralo antes de importar»; un `false` no es garantía
    /// absoluta (una carrera es posible), pero es la señal honesta que hay.
    pub fn navegador_abierto(&self) -> bool {
        hay_proceso(Path::new("/proc"), self.proceso)
    }
}

/// (subcarpeta bajo `~/.config`, nombre a mostrar, etiqueta del llavero, `comm`).
const CONOCIDOS: &[(&str, &str, &str, &str)] = &[
    ("google-chrome", "Google Chrome", "chrome", "chrome"),
    ("BraveSoftware/Brave-Browser", "Brave", "brave", "brave"),
    ("chromium", "Chromium", "chromium", "chromium"),
    ("microsoft-edge", "Microsoft Edge", "microsoft-edge", "msedge"),
];

/// ¿Hay algún proceso cuyo `comm` sea exactamente `objetivo` bajo `proc_root`?
/// `comm` (`/proc/<pid>/comm`) viene truncado a 15 caracteres por el núcleo y con
/// un salto de línea al final, que se recorta. Testeable con una raíz falsa.
fn hay_proceso(proc_root: &Path, objetivo: &str) -> bool {
    let Ok(entradas) = std::fs::read_dir(proc_root) else { return false };
    for e in entradas.flatten() {
        // Solo los directorios de PID (nombre numérico).
        let nombre = e.file_name();
        if !nombre.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(e.path().join("comm"))
            && comm.trim_end() == objetivo
        {
            return true;
        }
    }
    false
}

/// Los perfiles con contraseñas de todos los navegadores instalados del usuario.
/// Usa `~/.config` como raíz.
pub fn perfiles_instalados() -> Vec<Perfil> {
    let Some(config) = dir_de_configuracion() else {
        return Vec::new();
    };
    perfiles_en(&config)
}

/// La raíz de configuración: `$XDG_CONFIG_HOME` o `~/.config`.
fn dir_de_configuracion() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME")
        && !x.is_empty()
    {
        return Some(PathBuf::from(x));
    }
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config"))
}

/// La versión testeable: busca bajo una raíz de configuración dada.
pub fn perfiles_en(config: &Path) -> Vec<Perfil> {
    let mut salida = Vec::new();
    for (sub, navegador, etiqueta, proceso) in CONOCIDOS {
        let base = config.join(sub);
        if !base.is_dir() {
            continue;
        }
        // Un `Login Data` por perfil: se miran las subcarpetas directas (Default,
        // Profile 1…) que contengan el archivo. No se recorre en profundidad.
        let Ok(entradas) = std::fs::read_dir(&base) else { continue };
        let mut perfiles: Vec<PathBuf> = entradas
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("Login Data").is_file())
            .collect();
        perfiles.sort();
        for dir in perfiles {
            let perfil = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Default".into());
            salida.push(Perfil {
                navegador,
                etiqueta_llavero: etiqueta,
                proceso,
                perfil,
                login_data: dir.join("Login Data"),
            });
        }
    }
    salida
}

/// Un perfil de FIREFOX con contraseñas (fase 6). Firefox no usa el llavero: la
/// clave vive en `key4.db` y las credenciales en `logins.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfilFirefox {
    /// Nombre del perfil (p.ej. «gj7p8jks.default-release»).
    pub perfil: String,
    pub key4_db: PathBuf,
    pub logins_json: PathBuf,
}

impl PerfilFirefox {
    /// ¿Está Firefox corriendo? Leer su almacén con el navegador vivo puede dar
    /// una lectura a medio escribir.
    pub fn navegador_abierto(&self) -> bool {
        hay_proceso(Path::new("/proc"), "firefox") || hay_proceso(Path::new("/proc"), "firefox-esr")
    }
}

/// Perfiles de Firefox con contraseñas. Firefox guarda su carpeta en
/// `~/.mozilla/firefox` o —en algunas distros— `~/.config/mozilla/firefox`; se
/// miran las dos.
pub fn perfiles_firefox() -> Vec<PerfilFirefox> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let raices = [
        PathBuf::from(&home).join(".mozilla/firefox"),
        PathBuf::from(&home).join(".config/mozilla/firefox"),
    ];
    perfiles_firefox_en(&raices)
}

/// La versión testeable: busca perfiles Firefox bajo las raíces dadas. Un perfil
/// cuenta solo si tiene A LA VEZ `key4.db` y `logins.json` (sin el segundo no hay
/// contraseñas que importar).
pub fn perfiles_firefox_en(raices: &[PathBuf]) -> Vec<PerfilFirefox> {
    let mut salida = Vec::new();
    for raiz in raices {
        let Ok(entradas) = std::fs::read_dir(raiz) else { continue };
        let mut dirs: Vec<PathBuf> = entradas
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("key4.db").is_file() && p.join("logins.json").is_file())
            .collect();
        dirs.sort();
        for dir in dirs {
            let perfil = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "default".into());
            salida.push(PerfilFirefox {
                perfil,
                key4_db: dir.join("key4.db"),
                logins_json: dir.join("logins.json"),
            });
        }
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Crea una raíz de configuración falsa con dos navegadores y varios perfiles.
    fn arbol_falso() -> (tempdir::Guard, PathBuf) {
        let g = tempdir::nuevo("chuspa-deteccion");
        let raiz = g.ruta.clone();
        for (sub, perfiles) in [
            ("BraveSoftware/Brave-Browser", &["Default", "Profile 1"][..]),
            ("google-chrome", &["Default"][..]),
            ("chromium", &["Default"][..]), // sin Login Data → no debe aparecer
        ] {
            for (i, perfil) in perfiles.iter().enumerate() {
                let dir = raiz.join(sub).join(perfil);
                std::fs::create_dir_all(&dir).unwrap();
                // chromium/Default queda SIN Login Data a propósito.
                if !(sub == "chromium") {
                    std::fs::write(dir.join("Login Data"), b"SQLite format 3\0resto").unwrap();
                }
                let _ = i;
            }
        }
        (g, raiz)
    }

    #[test]
    fn encuentra_los_perfiles_con_login_data() {
        let (_g, raiz) = arbol_falso();
        let p = perfiles_en(&raiz);
        // Brave (2 perfiles) + Chrome (1) = 3; chromium sin Login Data no cuenta.
        assert_eq!(p.len(), 3);
        let etiquetas: Vec<_> = p.iter().map(|x| x.etiqueta_llavero).collect();
        assert!(etiquetas.contains(&"brave"));
        assert!(etiquetas.contains(&"chrome"));
        assert!(!etiquetas.contains(&"chromium"), "sin Login Data no aparece");
        // Brave trae sus dos perfiles.
        let perfiles_brave: Vec<_> =
            p.iter().filter(|x| x.etiqueta_llavero == "brave").map(|x| x.perfil.clone()).collect();
        assert_eq!(perfiles_brave, ["Default", "Profile 1"]);
    }

    #[test]
    fn una_config_vacia_no_encuentra_nada() {
        let g = tempdir::nuevo("chuspa-vacia");
        assert!(perfiles_en(&g.ruta).is_empty());
    }

    #[test]
    fn encuentra_perfiles_firefox_solo_con_ambos_archivos() {
        let g = tempdir::nuevo("chuspa-ff");
        let raiz = g.ruta.join(".mozilla/firefox");
        // Perfil completo (key4.db + logins.json) → cuenta.
        let completo = raiz.join("abc.default-release");
        std::fs::create_dir_all(&completo).unwrap();
        std::fs::write(completo.join("key4.db"), b"SQLite format 3\0").unwrap();
        std::fs::write(completo.join("logins.json"), b"{}").unwrap();
        // Perfil SIN logins.json (nunca guardó contraseñas) → NO cuenta.
        let sin = raiz.join("xyz.otro");
        std::fs::create_dir_all(&sin).unwrap();
        std::fs::write(sin.join("key4.db"), b"SQLite format 3\0").unwrap();

        let p = perfiles_firefox_en(std::slice::from_ref(&raiz));
        assert_eq!(p.len(), 1, "solo el perfil con logins.json");
        assert_eq!(p[0].perfil, "abc.default-release");
        assert!(p[0].key4_db.ends_with("key4.db"));
    }

    /// La aguja y su control (D33): un `/proc` falso con el proceso buscado
    /// TIENE que verse; sin él, NO. El caso rojo falla por la vía real —lectura
    /// de `<pid>/comm`— no por un atajo del arnés.
    #[test]
    fn detecta_el_navegador_abierto_y_solo_ese() {
        let g = tempdir::nuevo("chuspa-proc");
        let proc = g.ruta.clone();
        // PID con el navegador buscado, truncado a 15 chars como hace el núcleo.
        for (pid, comm) in [("1001", "brave\n"), ("1002", "gnome-shell\n"), ("1003", "chrome\n")] {
            let d = proc.join(pid);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("comm"), comm).unwrap();
        }
        // Una entrada NO numérica (como `/proc/self`) no debe romper ni contar.
        std::fs::create_dir_all(proc.join("self")).unwrap();

        assert!(hay_proceso(&proc, "brave"), "brave está abierto → se ve");
        assert!(hay_proceso(&proc, "chrome"), "chrome está abierto → se ve");
        // El control: un navegador que NO está entre los procesos no se ve.
        assert!(!hay_proceso(&proc, "chromium"), "chromium no corre → no se ve");
        assert!(!hay_proceso(&proc, "msedge"), "edge no corre → no se ve");
        // Y un `/proc` inexistente no es un pánico, es un `false`.
        assert!(!hay_proceso(Path::new("/no/existe/proc"), "brave"));
    }

    /// Mini-utilidad de directorio temporal que se borra al soltarse. Rust puro,
    /// sin dependencias, para no arrastrar `tempfile` al árbol.
    mod tempdir {
        use std::path::PathBuf;
        pub struct Guard {
            pub ruta: PathBuf,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.ruta);
            }
        }
        pub fn nuevo(etiqueta: &str) -> Guard {
            let ruta = std::env::temp_dir()
                .join(format!("{etiqueta}-{}-{}", std::process::id(), contador()));
            std::fs::create_dir_all(&ruta).unwrap();
            Guard { ruta }
        }
        fn contador() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            N.fetch_add(1, Ordering::Relaxed)
        }
    }
}
