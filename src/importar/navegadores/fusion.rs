// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Fusión de las contraseñas leídas de un navegador en la bóveda. Fase 4 del
//! importador.
//!
//! # La regla que no se negocia: NUNCA sobrescribe, NUNCA borra
//!
//! La ingesta es ADITIVA. Para cada credencial del navegador:
//! - si ya existe una entrada para el mismo sitio y usuario con **la misma
//!   contraseña**, se salta (duplicado exacto);
//! - si existe para el mismo sitio y usuario pero con **otra contraseña**, NO se
//!   pisa la que había: se añade una entrada NUEVA y se reporta el conflicto,
//!   para que la persona decida cuál conservar mirando las dos;
//! - si no hay ninguna que corresponda, se añade.
//!
//! Así, importar dos veces no duplica, y nunca se pierde una contraseña buena de
//! la bóveda por una vieja del navegador. La decisión de «añadir en vez de pisar»
//! la tomó Juan por delegación (2026-09-15): en un gestor, perder una contraseña
//! en silencio es peor que tener una de más que se ve y se borra a mano.
//!
//! # El informe se enseña; NO lleva secretos
//!
//! [`Reporte`] cuenta qué entró, qué se saltó, qué chocó y qué no se pudo
//! descifrar, con el NOMBRE del sitio, nunca una contraseña (D20: lo que no se
//! puede leer se dice; lo que se lee no se filtra).

use crate::boveda::Valor;
use crate::cifrado::{Boveda, BovedaError};

/// Una credencial ya DESCIFRADA, lista para fusionar. La contraseña va en
/// `Zeroizing`: es texto claro sensible y se borra de memoria al soltarse.
///
/// NO deriva `Debug`: `Zeroizing` reenvía su `Debug` al contenido (no lo
/// redacta), así que un `{:?}`/`dbg!`/`log` filtraría la contraseña. El `Debug`
/// manual redacta los campos sensibles para que la fuga sea imposible por
/// construcción (hallazgo del concilio, fase 6).
#[derive(Clone)]
pub struct LoginClaro {
    pub origin_url: String,
    pub usuario: String,
    pub clave: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for LoginClaro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginClaro")
            .field("origin_url", &self.origin_url)
            .field("usuario", &"[redactado]")
            .field("clave", &"[redactado]")
            .finish()
    }
}

/// Lo que la fusión hizo. Se enseña a la persona; no lleva ni una contraseña.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reporte {
    /// Entradas nuevas añadidas a la bóveda.
    pub importadas: usize,
    /// Duplicados exactos (mismo sitio+usuario+contraseña) que ya estaban.
    pub duplicadas: usize,
    /// Mismo sitio+usuario pero contraseña distinta: se añadió como NUEVA y se
    /// deja a la vista para que la persona resuelva. Nunca se pisó nada.
    pub conflictos: usize,
    /// Direcciones que no se pudieron interpretar: no se importan (no se adivina).
    pub ilegibles: usize,
    /// Blobs que no se pudieron descifrar (otro secreto, o v11 sin el llavero).
    pub sin_descifrar: usize,
    /// Líneas para enseñar (nombres de sitio, nunca secretos).
    pub detalles: Vec<String>,
}

/// Fusiona `logins` (ya descifrados) en `boveda`. No escribe en disco: eso lo
/// hace quien llama con `boveda.guardar()` una vez al final.
pub fn fusionar(boveda: &mut Boveda, logins: &[LoginClaro]) -> Result<Reporte, BovedaError> {
    let mut r = Reporte::default();
    for login in logins {
        let Some((origen, nombre)) = sitio(&login.origin_url) else {
            r.ilegibles += 1;
            r.detalles.push(format!("dirección ilegible, se omite: {}", login.origin_url));
            continue;
        };

        match cotejar(boveda, &login.origin_url, &login.usuario, &login.clave)? {
            Cotejo::DuplicadoExacto => {
                r.duplicadas += 1;
            }
            Cotejo::MismoUsuarioOtraClave => {
                anadir(boveda, &origen, &nombre, &login.usuario, &login.clave)?;
                r.conflictos += 1;
                r.detalles.push(format!(
                    "«{nombre}» ({}) ya tenía otra contraseña: se añadió la del navegador como entrada nueva; revisa cuál conservar",
                    login.usuario
                ));
            }
            Cotejo::Nueva => {
                anadir(boveda, &origen, &nombre, &login.usuario, &login.clave)?;
                r.importadas += 1;
            }
        }
    }
    Ok(r)
}

/// Lee un `Login Data` de Chromium, descifra cada contraseña con `secreto`
/// (`"peanuts"` para v10; el del llavero para v11, fase 3) y fusiona en la bóveda.
/// Ata las fases 2 (leer), 1 (descifrar) y 4 (fusionar).
pub fn importar_login_data(
    boveda: &mut Boveda,
    db: &[u8],
    secreto: &[u8],
) -> Result<Reporte, ErrorImportar> {
    let logins = super::sqlite::leer_logins(db).map_err(ErrorImportar::Sqlite)?;
    let clave = super::oscrypt::derivar_clave(secreto);
    let mut claros = Vec::new();
    let mut sin_descifrar = 0usize;
    for l in &logins {
        match super::oscrypt::descifrar(&l.password, &clave) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(clave_txt) => claros.push(LoginClaro {
                    origin_url: l.origin_url.clone(),
                    usuario: l.username.clone(),
                    clave: zeroize::Zeroizing::new(clave_txt),
                }),
                // Descifró pero no es texto: no se inventa una contraseña.
                Err(_) => sin_descifrar += 1,
            },
            Err(_) => sin_descifrar += 1,
        }
    }
    let mut r = fusionar(boveda, &claros).map_err(ErrorImportar::Boveda)?;
    r.sin_descifrar = sin_descifrar;
    if sin_descifrar > 0 {
        r.detalles.push(format!(
            "{sin_descifrar} contraseña(s) no se pudieron descifrar (¿otro secreto, o v11 sin el llavero?) y se omitieron"
        ));
    }
    Ok(r)
}

/// Importa desde un `Login Data` de un navegador Chromium obteniendo el secreto
/// v11 del LLAVERO (fase 3) y usando `"peanuts"` para las entradas v10. Es la vía
/// real: cada contraseña se descifra con la clave que le corresponde según su
/// prefijo. Ata las fases 3 (llavero) + 2 (leer) + 1 (descifrar) + 4 (fusionar).
///
/// `aplicacion` es la etiqueta del navegador en el llavero (`"brave"`, `"chrome"`,
/// `"chromium"`, `"microsoft-edge"`). Si el llavero no tiene su secreto, solo se
/// importan las entradas v10 (raras hoy) y el resto cuenta como no descifrable.
pub fn importar_de_navegador(
    boveda: &mut Boveda,
    db: &[u8],
    aplicacion: &str,
) -> Result<Reporte, ErrorImportar> {
    // El error del llavero NO se traga: un llavero BLOQUEADO y un navegador que
    // no usa v11 producen los dos «0 secretos», pero por causas opuestas, y el
    // usuario tiene que poder distinguirlas (D20). Se conserva para el informe.
    let secreto = super::llavero::secreto_de(aplicacion);
    let fallo_llavero = secreto.as_ref().err().map(diagnostico_llavero);
    let secreto_v11 = secreto.ok();
    let clave_v10 = super::oscrypt::derivar_clave(super::oscrypt::SECRETO_V10);
    let clave_v11 = secreto_v11.as_ref().map(|s| super::oscrypt::derivar_clave(s));

    let logins = super::sqlite::leer_logins(db).map_err(ErrorImportar::Sqlite)?;
    let mut claros = Vec::new();
    let mut sin_descifrar = 0usize;
    for l in &logins {
        let clave = match l.password.get(..3) {
            Some(b"v11") => clave_v11.as_deref(),
            Some(b"v10") => Some(&*clave_v10),
            _ => None,
        };
        let claro = clave
            .and_then(|k| super::oscrypt::descifrar(&l.password, k).ok())
            .and_then(|b| String::from_utf8(b).ok());
        match claro {
            Some(txt) => claros.push(LoginClaro {
                origin_url: l.origin_url.clone(),
                usuario: l.username.clone(),
                clave: zeroize::Zeroizing::new(txt),
            }),
            None => sin_descifrar += 1,
        }
    }
    let mut r = fusionar(boveda, &claros).map_err(ErrorImportar::Boveda)?;
    r.sin_descifrar = sin_descifrar;
    if sin_descifrar > 0 {
        // Si el llavero falló, se dice POR QUÉ (bloqueado, sin bus…), no se
        // culpa al navegador a ciegas. Si el llavero entregó el secreto y aun así
        // no descifró, entonces sí es cosa del `Login Data`.
        let motivo = match &fallo_llavero {
            Some(diag) => format!("no pude obtener el secreto de «{aplicacion}» del llavero: {diag}"),
            None => "¿el navegador estaba abierto al copiar el archivo?".to_string(),
        };
        r.detalles.push(format!("{sin_descifrar} contraseña(s) no se pudieron descifrar: {motivo}"));
    }
    Ok(r)
}

/// Traduce un fallo del llavero a una frase para el informe. Nunca lleva un
/// secreto —describe por qué NO se obtuvo—; el nombre de error de D-Bus
/// (p.ej. `…Secret.Error.IsLocked`) es justo lo que orienta al usuario.
fn diagnostico_llavero(e: &super::llavero::ErrorLlavero) -> String {
    use super::llavero::ErrorLlavero::*;
    match e {
        SinBus => "no hay bus de sesión de D-Bus (¿sesión sin systemd-user?)".to_string(),
        SinSecreto => "no hay ítem de ese navegador en el llavero (¿guarda en v10?)".to_string(),
        Dbus(nombre) => format!("el llavero respondió «{nombre}» (¿está bloqueado? ábrelo y reintenta)"),
        Io(err) => format!("no se pudo hablar con el llavero: {err}"),
        Protocolo(q) => format!("respuesta inesperada del llavero: {q}"),
    }
}

/// Importa las credenciales de un perfil de FIREFOX (fase 6). `key4_db` es el
/// archivo entero; `logins_json` su texto; `primaria` la contraseña primaria
/// (vacía = `b""`). Descifra por NSS (AES-256-CBC o 3DES según el perfil) y
/// fusiona igual que las de Chromium: aditivo, nunca pisa.
pub fn importar_de_firefox(
    boveda: &mut Boveda,
    key4_db: &[u8],
    logins_json: &str,
    primaria: &[u8],
) -> Result<Reporte, ErrorImportar> {
    let (creds, total) =
        super::nss::descifrar_perfil(key4_db, logins_json, primaria).map_err(ErrorImportar::Nss)?;
    let claros: Vec<LoginClaro> = creds
        .into_iter()
        .map(|c| LoginClaro {
            origin_url: c.url,
            usuario: c.usuario.to_string(),
            clave: zeroize::Zeroizing::new(c.clave.to_string()),
        })
        .collect();
    let sin_descifrar = total.saturating_sub(claros.len());
    let mut r = fusionar(boveda, &claros).map_err(ErrorImportar::Boveda)?;
    r.sin_descifrar = sin_descifrar;
    if sin_descifrar > 0 {
        r.detalles.push(format!(
            "{sin_descifrar} contraseña(s) de Firefox no se pudieron descifrar (¿contraseña primaria puesta?)"
        ));
    }
    Ok(r)
}

/// Error del importador de alto nivel.
#[derive(Debug)]
pub enum ErrorImportar {
    Sqlite(super::sqlite::ErrorSqlite),
    Nss(super::nss::ErrorNss),
    Boveda(BovedaError),
}

enum Cotejo {
    DuplicadoExacto,
    MismoUsuarioOtraClave,
    Nueva,
}

/// ¿Apuntan la URI guardada y la del navegador al MISMO sitio? Se compara por
/// host (sin `www.`), y NADA MÁS: es deliberadamente independiente de la regla de
/// oferta (`Regla`) y del esquema.
///
/// Deduplicar es una pregunta distinta de autocompletar. `corresponde` —la de
/// autocompletar— corta en seco una URI marcada `Regla::Nunca` («existe pero no
/// se ofrece sola») y rechaza el degradado https→http; usarla para el cotejo
/// hacía invisible al importador cualquier entrada que el usuario hubiera
/// apartado a propósito, de modo que se DUPLICABA en la primera sincronización y
/// la copia nueva salía SIN esa restricción (`Regla::Host`, auto-ofrecible). Una
/// credencial ya existente es la misma credencial la ofrezca el navegador o no.
fn mismo_host(guardada: &str, actual: &str) -> bool {
    use crate::navegador::coincidencia::Direccion;
    let sin_www = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_string();
    match (Direccion::analizar(guardada), Direccion::analizar(actual)) {
        (Some(g), Some(a)) => sin_www(&g.host) == sin_www(&a.host),
        _ => false,
    }
}

/// Mira si ya hay en la bóveda una entrada para este sitio y usuario, y si su
/// contraseña coincide.
fn cotejar(
    boveda: &Boveda,
    url: &str,
    usuario: &str,
    clave: &str,
) -> Result<Cotejo, BovedaError> {
    let mut mismo_usuario = false;
    for (indice, resumen) in boveda.listar().iter().enumerate() {
        let coincide_sitio = resumen.uris.iter().any(|u| mismo_host(&u.uri, url));
        if !coincide_sitio {
            continue;
        }
        let entrada = boveda.abrir_entrada(indice)?;
        // Un campo vacío NO se guarda como `""`, se guarda como AUSENTE (`poner`
        // en `gui::construir` descarta lo vacío). Así que «ausente» y «cadena
        // vacía» son el MISMO valor de usuario/clave: hay que tratarlos igual, o
        // una credencial sin usuario (22 reales de un Brave) no cotejaría con
        // nada y se reañadiría entera en cada sincronización.
        if texto_de(&entrada, "acceso.usuario").as_deref().unwrap_or("") != usuario {
            continue;
        }
        mismo_usuario = true;
        if texto_de(&entrada, "acceso.clave").as_deref().unwrap_or("") == clave {
            return Ok(Cotejo::DuplicadoExacto);
        }
    }
    Ok(if mismo_usuario { Cotejo::MismoUsuarioOtraClave } else { Cotejo::Nueva })
}

/// Construye y añade una entrada nueva (por el MISMO camino que la creación
/// manual: `gui::construir`, para que las fechas y el modelo salgan iguales).
fn anadir(
    boveda: &mut Boveda,
    origen: &str,
    nombre: &str,
    usuario: &str,
    clave: &str,
) -> Result<(), BovedaError> {
    let entrada = crate::gui::construir(
        crate::gui::EntradaEntrante {
            nombre: nombre.to_string(),
            usuario: Some(usuario.to_string()),
            clave: Some(clave.to_string()),
            uris: Some(origen.to_string()),
            ..Default::default()
        },
        None,
    );
    boveda.anadir(entrada)?;
    Ok(())
}

/// `(origen, nombre)` de una URL, o `None` si no se entiende sin adivinar. El
/// origen lleva el host tal cual; el nombre, sin `www.`, es lo que se reconoce
/// en una lista.
fn sitio(url: &str) -> Option<(String, String)> {
    let d = crate::navegador::coincidencia::Direccion::analizar(url)?;
    let nombre = d.host.strip_prefix("www.").unwrap_or(&d.host).to_string();
    Some((format!("{}://{}", d.esquema, d.host), nombre))
}

fn texto_de(entrada: &crate::boveda::Entrada, etiqueta: &str) -> Option<String> {
    entrada.campo(etiqueta).and_then(|c| match &c.valor {
        Valor::Texto(t) => Some(t.clone()),
        Valor::Secreto(s) => Some(s.to_string()),
        _ => None,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cifrado::{Acceso, Boveda};

    fn coste() -> quipu::kdf::KdfParams {
        quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
    }

    fn boveda_vacia(etiqueta: &str) -> Boveda {
        let dir = std::env::temp_dir().join(format!("chuspa-fusion-{}-{}", std::process::id(), etiqueta));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("f.chuspa");
        let _ = std::fs::remove_file(&ruta);
        Boveda::crear(&ruta, &Acceso::frase("la frase"), coste()).unwrap()
    }

    fn login(url: &str, u: &str, c: &str) -> LoginClaro {
        LoginClaro {
            origin_url: url.into(),
            usuario: u.into(),
            clave: zeroize::Zeroizing::new(c.into()),
        }
    }

    #[test]
    fn en_boveda_vacia_entra_todo() {
        let mut b = boveda_vacia("vacia");
        let logins = [
            login("https://banco.com/entrar", "juan", "clave-1"),
            login("https://correo.com/", "j@x", "clave-2"),
        ];
        let r = fusionar(&mut b, &logins).unwrap();
        assert_eq!(r.importadas, 2);
        assert_eq!(r.duplicadas, 0);
        assert_eq!(r.conflictos, 0);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn un_duplicado_exacto_no_se_reimporta() {
        let mut b = boveda_vacia("dup");
        let l = [login("https://banco.com/entrar", "juan", "clave-1")];
        fusionar(&mut b, &l).unwrap();
        // Segunda pasada idéntica: nada nuevo.
        let r = fusionar(&mut b, &l).unwrap();
        assert_eq!(r.importadas, 0);
        assert_eq!(r.duplicadas, 1);
        assert_eq!(b.len(), 1, "importar dos veces no duplica");
    }

    /// Regresión del hallazgo del concilio (fase 5): una entrada que el usuario
    /// marcó «no ofrecer sola» (`coincidencia = Some(5)` → `Regla::Nunca`) TIENE
    /// que verse en el cotejo como duplicado, no colarse como entrada nueva sin
    /// su restricción. Caso rojo por la vía real: sembramos la entrada marcada y
    /// sincronizamos la MISMA credencial.
    #[test]
    fn una_entrada_marcada_nunca_no_se_duplica_al_importar() {
        let mut b = boveda_vacia("nunca");
        // Sembrar a mano una entrada con su URI marcada `Nunca` (lo que `fusionar`
        // nunca produce, pero sí un export de Bitwarden o la edición del usuario).
        let mut ent = crate::gui::construir(
            crate::gui::EntradaEntrante {
                nombre: "banco.com".into(),
                usuario: Some("juan".into()),
                clave: Some("la-buena".into()),
                uris: Some("https://banco.com".into()),
                ..Default::default()
            },
            None,
        );
        assert_eq!(ent.uris.len(), 1);
        ent.uris[0].coincidencia = Some(5); // 5 = never
        b.anadir(ent).unwrap();

        // El navegador trae la MISMA credencial: debe reconocerse como duplicado.
        let r = fusionar(&mut b, &[login("https://banco.com/entrar", "juan", "la-buena")]).unwrap();
        assert_eq!(r.duplicadas, 1, "la entrada marcada Nunca debe verse en el cotejo");
        assert_eq!(r.importadas, 0, "no se crea una copia sin la restricción");
        assert_eq!(b.len(), 1, "sigue habiendo UNA sola entrada");
        // Y su restricción se conserva intacta.
        assert_eq!(b.abrir_entrada(0).unwrap().uris[0].coincidencia, Some(5));
    }

    /// Control del anterior (D33): el cotejo independiente de la regla NO puede
    /// sobre-emparejar — un sitio DISTINTO, aunque la bóveda tenga una entrada
    /// marcada `Nunca`, sigue entrando como nuevo.
    #[test]
    fn el_cotejo_por_host_no_empareja_sitios_distintos() {
        let mut b = boveda_vacia("nunca-control");
        let mut ent = crate::gui::construir(
            crate::gui::EntradaEntrante {
                nombre: "banco.com".into(),
                usuario: Some("juan".into()),
                clave: Some("la-buena".into()),
                uris: Some("https://banco.com".into()),
                ..Default::default()
            },
            None,
        );
        ent.uris[0].coincidencia = Some(5);
        b.anadir(ent).unwrap();

        let r = fusionar(&mut b, &[login("https://correo.com/", "juan", "otra")]).unwrap();
        assert_eq!(r.importadas, 1, "un sitio distinto entra como nuevo");
        assert_eq!(b.len(), 2);
    }

    /// Regresión del hallazgo del concilio (fable, conf 10, medido): una
    /// credencial con USUARIO vacío se guarda sin el campo `acceso.usuario`, y el
    /// cotejo la daba por «no vista» → se reañadía en CADA sincronización (22
    /// reales de un Brave). Idempotencia por la vía real: dos pasadas idénticas.
    /// Regresión del hallazgo del concilio (fable, conf 10): un llavero
    /// BLOQUEADO y un navegador SIN ítem v11 producen los dos «0 secretos», pero
    /// el usuario tiene que poder distinguirlos (D20). El diagnóstico no puede
    /// colapsarlos en la misma frase.
    #[test]
    fn el_diagnostico_del_llavero_distingue_bloqueado_de_sin_item() {
        use super::super::llavero::ErrorLlavero;
        let bloqueado = diagnostico_llavero(&ErrorLlavero::Dbus(
            "org.freedesktop.Secret.Error.IsLocked".to_string(),
        ));
        let sin_item = diagnostico_llavero(&ErrorLlavero::SinSecreto);
        assert!(bloqueado.contains("IsLocked") || bloqueado.contains("bloquead"));
        assert!(sin_item.contains("v10") || sin_item.contains("no hay ítem"));
        assert_ne!(bloqueado, sin_item, "bloqueado y sin ítem no pueden verse igual");
    }

    #[test]
    fn reimportar_con_usuario_o_clave_vacios_no_duplica() {
        let mut b = boveda_vacia("vacios");
        let lote = [
            login("https://a.com/", "", "clave-sin-usuario"), // usuario vacío
            login("https://b.com/", "juan", ""),              // clave vacía
        ];
        let r1 = fusionar(&mut b, &lote).unwrap();
        assert_eq!(r1.importadas, 2);
        assert_eq!(b.len(), 2);
        // Segunda pasada IDÉNTICA: nada nuevo, ambas son duplicado exacto.
        let r2 = fusionar(&mut b, &lote).unwrap();
        assert_eq!(r2.importadas, 0, "no se reañade la de usuario/clave vacío");
        assert_eq!(r2.conflictos, 0, "usuario/clave vacío no es un «conflicto»");
        assert_eq!(r2.duplicadas, 2);
        assert_eq!(b.len(), 2, "sigue habiendo DOS, no cuatro");
    }

    #[test]
    fn mismo_usuario_otra_clave_se_anade_sin_pisar() {
        let mut b = boveda_vacia("conflicto");
        fusionar(&mut b, &[login("https://banco.com/entrar", "juan", "la-buena")]).unwrap();
        // El navegador trae otra contraseña para el mismo sitio+usuario.
        let r = fusionar(&mut b, &[login("https://banco.com/otra", "juan", "la-del-navegador")]).unwrap();
        assert_eq!(r.conflictos, 1);
        assert_eq!(r.importadas, 0);
        assert_eq!(b.len(), 2, "se añade, no se pisa");
        // La contraseña original SIGUE en la bóveda (nunca se sobrescribe).
        let claves: Vec<Option<String>> =
            (0..b.len()).map(|i| texto_de(&b.abrir_entrada(i).unwrap(), "acceso.clave")).collect();
        assert!(claves.contains(&Some("la-buena".into())), "la contraseña buena no se perdió");
        assert!(claves.contains(&Some("la-del-navegador".into())));
    }

    /// Guardián del hallazgo del concilio (fase 6): imprimir un `LoginClaro` con
    /// `{:?}` NO puede filtrar la contraseña. Si alguien vuelve a `#[derive(Debug)]`
    /// esta prueba enrojece.
    #[test]
    fn el_debug_de_login_claro_no_filtra_la_clave() {
        let l = login("https://banco.com", "juan", "SECRETO-que-no-debe-salir");
        let d = format!("{l:?}");
        assert!(!d.contains("SECRETO"), "el Debug filtró la clave: {d}");
        assert!(d.contains("redactado"));
    }

    #[test]
    fn el_informe_no_lleva_ninguna_contrasena() {
        let mut b = boveda_vacia("informe");
        fusionar(&mut b, &[login("https://banco.com/", "juan", "SECRETO-que-no-debe-salir")]).unwrap();
        let r = fusionar(&mut b, &[login("https://banco.com/", "juan", "OTRO-SECRETO-distinto")]).unwrap();
        let texto = r.detalles.join("\n");
        assert!(!texto.contains("SECRETO"), "el informe filtró una contraseña: {texto}");
        assert!(!texto.contains("OTRO-SECRETO"));
    }

    #[test]
    fn una_direccion_ilegible_se_omite_ruidosamente() {
        let mut b = boveda_vacia("ilegible");
        let r = fusionar(&mut b, &[login("no-es-una-url", "x", "y")]).unwrap();
        assert_eq!(r.ilegibles, 1);
        assert_eq!(r.importadas, 0);
        assert_eq!(b.len(), 0);
    }

    // Prueba de EXTREMO A EXTREMO contra el navegador REAL: necesita un llavero
    // vivo (gnome-keyring) y un `Login Data` de Brave, que no existen en
    // CI/headless. Se corre a mano donde sí los hay, y NO imprime ninguna
    // contraseña — solo cuenta cuántas descifran. Cruza la frontera del programa
    // con el artefacto real (directiva 28):
    //   cargo test --release importar_de_brave_real -- --ignored --nocapture
    #[test]
    #[ignore = "necesita llavero vivo y un Login Data de Brave real"]
    fn importar_de_brave_real() {
        let origen = std::path::Path::new(
            &std::env::var("HOME").unwrap(),
        )
        .join(".config/BraveSoftware/Brave-Browser/Default/Login Data");
        if !origen.exists() {
            println!("no hay Login Data de Brave; se omite");
            return;
        }
        // Se copia (el navegador puede tenerlo bloqueado; el importador se corre
        // con el navegador cerrado, y copiar es inocuo).
        let tmp = std::env::temp_dir().join(format!("chuspa-brave-{}.db", std::process::id()));
        std::fs::copy(&origen, &tmp).unwrap();
        let db = std::fs::read(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let mut b = boveda_vacia("brave-real");
        let r = importar_de_navegador(&mut b, &db, "brave").unwrap();
        println!(
            "Brave real → importadas={} duplicadas={} conflictos={} sin_descifrar={} ilegibles={} (bóveda: {} entradas)",
            r.importadas, r.duplicadas, r.conflictos, r.sin_descifrar, r.ilegibles, b.len()
        );
        // La inmensa mayoría tiene que descifrar (v11 con el secreto del llavero).
        let total = r.importadas + r.duplicadas + r.conflictos + r.sin_descifrar;
        assert!(total > 0, "el Login Data tenía filas");
        assert!(
            r.sin_descifrar * 10 < total.max(1),
            "demasiadas sin descifrar ({} de {}): el secreto o el algoritmo fallan",
            r.sin_descifrar, total
        );
    }

    // Fase 5 de EXTREMO A EXTREMO: la cadena COMPLETA del botón «Sincronizar
    // desde los navegadores», con el artefacto real (directiva 28). Cruza cuatro
    // fronteras que la prueba de fase 3 no toca juntas: (1) DETECCIÓN — encuentra
    // el perfil de Brave en la config real; (2) importa por su etiqueta de
    // llavero; (3) PERSISTE con `guardar()`; (4) REABRE el archivo de disco y
    // comprueba que las entradas siguen ahí. NO imprime ninguna contraseña.
    //   cargo test --release fase5_boton_sincronizar_real -- --ignored --nocapture
    #[test]
    #[ignore = "necesita llavero vivo y un Brave real instalado"]
    fn fase5_boton_sincronizar_real() {
        use super::super::deteccion;

        // (1) Detección real: ¿hay algún perfil de Brave con Login Data?
        let perfiles = deteccion::perfiles_instalados();
        let Some(brave) = perfiles.iter().find(|p| p.etiqueta_llavero == "brave") else {
            println!("no hay perfil de Brave detectado; se omite");
            return;
        };
        println!(
            "detectado: {} — {} (abierto={})",
            brave.navegador, brave.perfil, brave.navegador_abierto()
        );

        // Vault nuevo en disco, con ruta, para poder guardar y reabrir.
        let dir = std::env::temp_dir().join(format!("chuspa-fase5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("boveda.chuspa");
        let _ = std::fs::remove_file(&ruta);
        let acceso = Acceso::frase("frase de la prueba fase 5");
        let mut b = Boveda::crear(&ruta, &acceso, coste()).unwrap();

        // (2)+(3): el MISMO camino que corre el botón. Se copia el Login Data
        // (Brave puede tenerlo bloqueado) y se importa por su etiqueta.
        let tmp = dir.join("Login Data");
        std::fs::copy(&brave.login_data, &tmp).unwrap();
        let bytes = std::fs::read(&tmp).unwrap();
        let r = importar_de_navegador(&mut b, &bytes, brave.etiqueta_llavero).unwrap();
        let anadidas = r.importadas + r.conflictos;
        println!(
            "importadas={} duplicadas={} conflictos={} sin_descifrar={} ilegibles={} → bóveda {} entradas",
            r.importadas, r.duplicadas, r.conflictos, r.sin_descifrar, r.ilegibles, b.len()
        );
        assert!(anadidas > 0, "no entró ninguna contraseña nueva");
        if anadidas > 0 {
            b.guardar().unwrap();
        }
        let esperadas = b.len();
        drop(b);

        // (4) Reabrir desde el disco: lo persistido tiene que seguir ahí.
        let reabierta = Boveda::abrir(&ruta, &acceso).unwrap();
        assert_eq!(reabierta.len(), esperadas, "lo guardado no se releyó igual");
        println!("reabierta desde disco: {} entradas ✓", reabierta.len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Fase 6 de EXTREMO A EXTREMO contra Firefox REAL (D28): detecta el perfil,
    // descifra por NSS, fusiona, PERSISTE y REABRE de disco. No imprime ninguna
    // contraseña, solo cuenta.
    //   cargo test --release importar_de_firefox_real -- --ignored --nocapture
    #[test]
    #[ignore = "necesita un perfil Firefox real con contraseñas"]
    fn importar_de_firefox_real() {
        use super::super::deteccion;
        let perfiles = deteccion::perfiles_firefox();
        let Some(ff) = perfiles.first() else {
            println!("no hay perfil Firefox; se omite");
            return;
        };
        let dir = std::env::temp_dir().join(format!("chuspa-ff6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("boveda.chuspa");
        let _ = std::fs::remove_file(&ruta);
        let acceso = Acceso::frase("frase de prueba fase 6");
        let mut b = Boveda::crear(&ruta, &acceso, coste()).unwrap();

        let key4 = std::fs::read(&ff.key4_db).unwrap();
        let json = std::fs::read_to_string(&ff.logins_json).unwrap();
        let r = importar_de_firefox(&mut b, &key4, &json, b"").unwrap();
        println!(
            "Firefox {} → importadas={} duplicadas={} conflictos={} sin_descifrar={} → bóveda {}",
            ff.perfil, r.importadas, r.duplicadas, r.conflictos, r.sin_descifrar, b.len()
        );
        assert!(r.importadas + r.duplicadas + r.conflictos > 0, "el perfil tenía logins");
        assert_eq!(r.sin_descifrar, 0, "todas deberían descifrar (contraseña primaria vacía)");
        if r.importadas + r.conflictos > 0 {
            b.guardar().unwrap();
        }
        let esperadas = b.len();
        drop(b);
        let re = Boveda::abrir(&ruta, &acceso).unwrap();
        assert_eq!(re.len(), esperadas, "lo guardado no se releyó igual");
        println!("reabierta: {} entradas ✓", re.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn el_pipeline_v10_lee_descifra_y_fusiona() {
        // Fases 2+1+4: del fixture de Login Data (41 filas, solo la del KAT
        // descifra con "peanuts"), importar a una bóveda vacía deja 1 entrada.
        const FIXTURE: &[u8] = include_bytes!("login_data_fixture.db");
        let mut b = boveda_vacia("pipeline");
        let r = importar_login_data(&mut b, FIXTURE, super::super::oscrypt::SECRETO_V10).unwrap();
        assert_eq!(r.importadas, 1, "solo la fila del KAT descifra con «peanuts»");
        assert_eq!(b.len(), 1);
        // La entrada importada tiene la contraseña del KAT.
        assert_eq!(
            texto_de(&b.abrir_entrada(0).unwrap(), "acceso.clave").as_deref(),
            Some("hunter2-contraseña")
        );
    }
}
