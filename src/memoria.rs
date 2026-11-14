// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! ¿Puede acabar la clave maestra escrita en el disco?
//!
//! # La decisión, y por qué no se fija la memoria
//!
//! KeePassXC llama a `mlock` para impedir que el sistema pagine sus secretos al
//! archivo de intercambio. Chuspa no puede llamarlo directamente —`mlock` exige
//! `unsafe` y este crate lo prohíbe— y sí podría hacerlo con una dependencia que
//! lo encapsule (`memsec`, `region`). Se evaluó y **se descartó**, con estas
//! razones:
//!
//! 1. **`mlock` protege de una sola cosa: la paginación.** No impide leer la
//!    memoria del proceso con `ptrace` ni por `/proc/pid/mem`, ni evita que un
//!    volcado de core la escriba entera. Quien puede hacer eso ya tiene el
//!    proceso, y la memoria fijada se lee igual de bien.
//! 2. **La respuesta correcta a la paginación no es fijar páginas, es no tener
//!    intercambio sin cifrar.** Un swap cifrado protege la clave *y* todo lo
//!    demás que pase por memoria — el portapapeles, el búfer del navegador, la
//!    contraseña a medio teclear. Añadir un mecanismo que tapa un caso concreto
//!    de un problema que se resuelve entero en otro sitio es exactamente lo que
//!    no se debe hacer.
//! 3. En el equipo donde se desarrolla esto **no hay intercambio activo**
//!    (comprobado el 2026-08-01), así que hoy la dependencia no compraría nada.
//!
//! Lo que sí falta cuando no se fija la memoria es **saber si el riesgo existe**,
//! y eso no se puede suponer: el intercambio se activa solo al instalar una
//! distribución, al crear un `zram` con respaldo en disco o al configurar la
//! hibernación. Este módulo lo comprueba y lo dice.
//!
//! Si algún día el equipo tiene intercambio sin cifrar y no se puede cambiar,
//! entonces `mlock` sí compra algo y la decisión se revisa — con este mismo
//! razonamiento delante.

use std::path::Path;

/// Qué puede pasarle a la memoria del proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paginacion {
    /// No hay intercambio: nada de lo que esté en memoria puede acabar escrito
    /// en el disco por paginación.
    SinIntercambio,
    /// Hay intercambio y **todo** está cifrado.
    Cifrado {
        /// Los dispositivos encontrados.
        dispositivos: Vec<String>,
    },
    /// Hay intercambio sin cifrar: la clave maestra puede acabar en el disco, y
    /// quedarse ahí después de apagar.
    SinCifrar {
        /// Los que no están cifrados.
        dispositivos: Vec<String>,
    },
    /// Hay intercambio y no se pudo determinar si está cifrado.
    ///
    /// Es un estado propio y no se cuenta como «cifrado»: dar por seguro lo que
    /// no se ha comprobado es la forma de que un aviso deje de avisar.
    NoSeSabe {
        /// Los que no se pudieron clasificar.
        dispositivos: Vec<String>,
        /// Por qué.
        motivo: String,
    },
    /// El sistema no expone esta información (no es Linux, o no hay `/proc`).
    NoSePuedeComprobar,
}

impl Paginacion {
    /// Aviso para el usuario, o `None` si no hay nada que decir.
    pub fn aviso(&self) -> Option<String> {
        match self {
            Paginacion::SinIntercambio | Paginacion::Cifrado { .. } => None,
            Paginacion::SinCifrar { dispositivos } => Some(format!(
                "El intercambio ({}) NO está cifrado. La clave maestra puede acabar \
                 escrita en el disco y seguir ahí después de apagar. Cífralo, o \
                 desactívalo mientras uses la bóveda.",
                dispositivos.join(", ")
            )),
            Paginacion::NoSeSabe { dispositivos, motivo } => Some(format!(
                "Hay intercambio ({}) y no se pudo comprobar si está cifrado ({motivo}). \
                 Compruébalo a mano: si no lo está, la clave maestra puede acabar en \
                 el disco.",
                dispositivos.join(", ")
            )),
            Paginacion::NoSePuedeComprobar => Some(
                "No se pudo comprobar el estado del intercambio en este sistema. Si \
                 lo hay y no está cifrado, la clave maestra puede acabar en el disco."
                    .to_string(),
            ),
        }
    }
}

/// Comprueba si la memoria del proceso puede acabar escrita en el disco.
pub fn paginacion() -> Paginacion {
    estado_desde(Path::new("/proc/swaps"), Path::new("/sys/block"))
}

/// La lógica separada de las rutas del sistema, para poder probarla con
/// directorios de mentira en vez de tener que montar un swap.
fn estado_desde(swaps: &Path, sys_block: &Path) -> Paginacion {
    let Ok(contenido) = std::fs::read_to_string(swaps) else {
        return Paginacion::NoSePuedeComprobar;
    };

    // La primera línea es la cabecera de columnas.
    let dispositivos: Vec<String> = contenido
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .filter(|d| !d.is_empty())
        .map(String::from)
        .collect();

    if dispositivos.is_empty() {
        return Paginacion::SinIntercambio;
    }

    let (mut cifrados, mut sin_cifrar, mut dudosos) = (Vec::new(), Vec::new(), Vec::new());
    for dispositivo in dispositivos {
        match clasificar(&dispositivo, sys_block) {
            Some(true) => cifrados.push(dispositivo),
            Some(false) => sin_cifrar.push(dispositivo),
            None => dudosos.push(dispositivo),
        }
    }

    // El peor caso manda: un solo dispositivo sin cifrar basta para que la clave
    // pueda acabar en el disco, por muchos cifrados que haya al lado.
    if !sin_cifrar.is_empty() {
        Paginacion::SinCifrar { dispositivos: sin_cifrar }
    } else if !dudosos.is_empty() {
        Paginacion::NoSeSabe {
            dispositivos: dudosos,
            motivo: "no aparece como dispositivo dm-crypt ni como archivo conocido".into(),
        }
    } else {
        Paginacion::Cifrado { dispositivos: cifrados }
    }
}

/// `Some(true)` si está cifrado, `Some(false)` si seguro que no, `None` si no se
/// puede saber.
///
/// Un dispositivo mapeado por `dm-crypt` lleva un UUID que empieza por `CRYPT-`.
/// Es la señal fiable; lo demás son conjeturas, y una conjetura aquí produce un
/// «está cifrado» que nadie ha comprobado.
fn clasificar(dispositivo: &str, sys_block: &Path) -> Option<bool> {
    // Un archivo de intercambio (no un dispositivo) hereda el cifrado del
    // sistema de ficheros donde vive, y eso no se puede leer desde aquí.
    if !dispositivo.starts_with("/dev/") {
        return None;
    }
    let nombre = dispositivo.rsplit('/').next()?;

    // /dev/mapper/loquesea -> hay que resolver a qué dm-N apunta.
    let candidatos: Vec<std::path::PathBuf> = if dispositivo.starts_with("/dev/mapper/") {
        match std::fs::canonicalize(dispositivo) {
            Ok(real) => vec![sys_block.join(real.file_name()?)],
            // Sin poder resolverlo, no se afirma nada.
            Err(_) => return None,
        }
    } else {
        vec![sys_block.join(nombre)]
    };

    for base in candidatos {
        if let Ok(uuid) = std::fs::read_to_string(base.join("dm/uuid")) {
            return Some(uuid.starts_with("CRYPT-"));
        }
        // Existe como bloque y no es un mapeo dm: entonces es un disco o una
        // partición cruda, y un swap ahí no está cifrado.
        if base.exists() {
            return Some(false);
        }
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Monta un `/proc/swaps` y un `/sys/block` de mentira. Sin esto habría que
    /// crear un swap de verdad para probar, que es justo el tipo de prueba que
    /// nunca se escribe.
    struct Falso(std::path::PathBuf);

    impl Falso {
        fn nuevo(etiqueta: &str) -> Self {
            let d = std::env::temp_dir()
                .join(format!("chuspa-mem-{}-{etiqueta}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }

        fn swaps(&self, cuerpo: &str) -> std::path::PathBuf {
            let p = self.0.join("swaps");
            std::fs::write(&p, format!("Filename\t\t\t\tType\t\tSize\n{cuerpo}")).unwrap();
            p
        }

        /// Crea `/sys/block/<nombre>` y, si se da, su `dm/uuid`.
        fn bloque(&self, nombre: &str, uuid: Option<&str>) -> std::path::PathBuf {
            let base = self.0.join("sys").join(nombre);
            std::fs::create_dir_all(&base).unwrap();
            if let Some(u) = uuid {
                std::fs::create_dir_all(base.join("dm")).unwrap();
                std::fs::write(base.join("dm/uuid"), u).unwrap();
            }
            self.0.join("sys")
        }
    }

    impl Drop for Falso {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sin_lineas_es_sin_intercambio() {
        let f = Falso::nuevo("vacio");
        let swaps = f.swaps("");
        let sys = f.bloque("nada", None);
        assert_eq!(estado_desde(&swaps, &sys), Paginacion::SinIntercambio);
    }

    #[test]
    fn una_particion_cruda_es_intercambio_sin_cifrar() {
        let f = Falso::nuevo("crudo");
        let swaps = f.swaps("/dev/nvme0n1p2\t\t\t\tpartition\t8388604\t0\t-2\n");
        let sys = f.bloque("nvme0n1p2", None);
        match estado_desde(&swaps, &sys) {
            Paginacion::SinCifrar { dispositivos } => {
                assert_eq!(dispositivos, vec!["/dev/nvme0n1p2"]);
            }
            otro => panic!("una partición cruda no está cifrada: {otro:?}"),
        }
    }

    #[test]
    fn un_dm_crypt_es_intercambio_cifrado() {
        let f = Falso::nuevo("cifrado");
        let swaps = f.swaps("/dev/dm-1\t\t\t\tpartition\t8388604\t0\t-2\n");
        let sys = f.bloque("dm-1", Some("CRYPT-LUKS2-abcdef-swap\n"));
        assert!(matches!(
            estado_desde(&swaps, &sys),
            Paginacion::Cifrado { .. }
        ));
    }

    #[test]
    fn un_dm_que_no_es_crypt_no_cuenta_como_cifrado() {
        // Un volumen LVM es también dm, y no cifra nada. Tratarlo como cifrado
        // por venir de `dm` sería el falso negativo más fácil de cometer.
        let f = Falso::nuevo("lvm");
        let swaps = f.swaps("/dev/dm-0\t\t\t\tpartition\t8388604\t0\t-2\n");
        let sys = f.bloque("dm-0", Some("LVM-abcdef\n"));
        assert!(matches!(
            estado_desde(&swaps, &sys),
            Paginacion::SinCifrar { .. }
        ));
    }

    #[test]
    fn un_archivo_de_intercambio_queda_como_no_se_sabe() {
        // Un archivo hereda el cifrado del sistema de ficheros, y eso no se ve
        // desde aquí. Decir «cifrado» sería inventarlo y decir «sin cifrar»
        // asustaría sin motivo: se dice que no se sabe.
        let f = Falso::nuevo("archivo");
        let swaps = f.swaps("/swapfile\t\t\t\tfile\t\t2097148\t0\t-2\n");
        let sys = f.bloque("nada", None);
        match estado_desde(&swaps, &sys) {
            Paginacion::NoSeSabe { dispositivos, .. } => {
                assert_eq!(dispositivos, vec!["/swapfile"]);
            }
            otro => panic!("un archivo de intercambio no se puede clasificar: {otro:?}"),
        }
    }

    #[test]
    fn uno_sin_cifrar_entre_varios_manda() {
        let f = Falso::nuevo("mezcla");
        let swaps = f.swaps(
            "/dev/dm-1\t\tpartition\t100\t0\t-2\n/dev/nvme0n1p2\t\tpartition\t100\t0\t-3\n",
        );
        f.bloque("dm-1", Some("CRYPT-LUKS2-x\n"));
        let sys = f.bloque("nvme0n1p2", None);
        match estado_desde(&swaps, &sys) {
            Paginacion::SinCifrar { dispositivos } => {
                assert_eq!(dispositivos, vec!["/dev/nvme0n1p2"]);
            }
            otro => panic!("el peor caso manda: {otro:?}"),
        }
    }

    #[test]
    fn sin_proc_no_se_finge_seguridad() {
        let f = Falso::nuevo("sin-proc");
        let sys = f.bloque("nada", None);
        assert_eq!(
            estado_desde(Path::new("/no/existe/swaps"), &sys),
            Paginacion::NoSePuedeComprobar
        );
        assert!(Paginacion::NoSePuedeComprobar.aviso().is_some());
    }

    #[test]
    fn solo_avisa_cuando_hay_algo_que_decir() {
        assert!(Paginacion::SinIntercambio.aviso().is_none());
        assert!(Paginacion::Cifrado { dispositivos: vec![] }.aviso().is_none());
        assert!(
            Paginacion::SinCifrar { dispositivos: vec!["/dev/x".into()] }
                .aviso()
                .is_some()
        );
    }

    #[test]
    fn el_estado_real_de_este_equipo_se_puede_leer() {
        // No se afirma cuál es —depende de la máquina— sino que la comprobación
        // no entra en pánico ni devuelve algo absurdo en un sistema de verdad.
        let estado = paginacion();
        assert!(!matches!(estado, Paginacion::NoSePuedeComprobar) || !cfg!(target_os = "linux"));
    }
}
