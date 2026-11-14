// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Importador del export JSON de Bitwarden.
//!
//! # La regla que gobierna este módulo
//!
//! **Ningún dato se descarta en silencio.** Un importador de contraseñas que
//! ignora un campo que no entiende produce una bóveda que *parece* completa: el
//! fallo no se ve al importar, se ve el día que hace falta la credencial y ya no
//! está el original. Es el caso exacto de la directiva 20 —ante un dato que no
//! se sabe interpretar, fallar ruidosamente— con el agravante de que aquí el
//! valor de relleno es la ausencia.
//!
//! Por eso la salvaguarda no está escrita en prosa sino en el TIPO: todos los
//! `struct` de este módulo llevan `#[serde(deny_unknown_fields)]`. Si Bitwarden
//! añade un campo en una versión futura, la importación se detiene con el nombre
//! del campo desconocido en el error. No hay ninguna ruta por la que un dato
//! nuevo se pierda sin que alguien lo lea.
//!
//! Lo mismo con los enteros de tipo: un `type` que no sea 1..=4, un tipo de
//! campo fuera de 0..=3 o un `reprompt` fuera de 0..=1 son errores, no valores
//! a ignorar. Enumerar lo que SÍ significa algo y mandar el resto a un error es
//! lo contrario de una categoría abierta con «en cualquier otro caso»
//! (directiva 23).
//!
//! # Lo que este formato NO contiene
//!
//! El export JSON de Bitwarden **no incluye los adjuntos** de los ítems: se
//! descargan aparte. Chuspa no puede importarlos porque no están en el archivo,
//! y lo avisa siempre —no se puede detectar cuáles faltan desde aquí.

use crate::boveda::{Campo, Clase, ClaveAnterior, Entrada, Importacion, Origen, Uri, Valor};
use serde::Deserialize;
use std::collections::HashMap;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("el archivo no es JSON válido: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "el export está CIFRADO (\"encrypted\": true). Chuspa importa el export \
         en claro: en Bitwarden, exporta con formato .json (no .encrypted_json). \
         El export cifrado con contraseña de cuenta se descifra solo con la clave \
         de la cuenta, que Chuspa no pide ni almacena."
    )]
    ExportCifrado,

    #[error(
        "campo desconocido en el export: {0}. Chuspa no importa lo que no \
         entiende, para no perderlo en silencio. Actualiza el importador antes \
         de continuar."
    )]
    CampoDesconocido(String),

    #[error("el ítem «{nombre}» tiene un tipo desconocido ({tipo}); no se importa nada para no perder datos")]
    TipoDeItemDesconocido { nombre: String, tipo: u8 },

    #[error("el ítem «{nombre}» tiene un campo personalizado de tipo desconocido ({tipo})")]
    TipoDeCampoDesconocido { nombre: String, tipo: u8 },

    #[error("el ítem «{nombre}» tiene reprompt={valor}, que Chuspa no conoce (se esperaba 0 o 1)")]
    RepromptDesconocido { nombre: String, valor: u8 },

    #[error("el ítem «{nombre}» dice ser de tipo {esperado} pero no trae el bloque «{bloque}» correspondiente")]
    BloqueAusente { nombre: String, esperado: &'static str, bloque: &'static str },
}

// ---------------------------------------------------------------------------
// Esquema del archivo. `deny_unknown_fields` en TODOS: es la salvaguarda.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    encrypted: bool,
    #[serde(default)]
    folders: Vec<Carpeta>,
    /// Solo aparece en exports que incluyen organizaciones.
    #[serde(default)]
    collections: Option<serde_json::Value>,
    items: Vec<Item>,
}

// Nota sobre `#[serde(default)]`: en serde, un campo `Option<T>` SIN `default`
// exige que la clave esté presente aunque sea con valor nulo. Un export real lo
// demostró: Bitwarden omite `uris[].match` por completo cuando no hay regla, y
// la importación se caía con «missing field `match`».
//
// Un campo AUSENTE no es lo mismo que un campo desconocido. El desconocido es un
// dato que no sabemos dónde poner —y por eso detiene la importación—; el ausente
// es simplemente que no hay dato. Por eso los opcionales llevan `default` y los
// obligatorios NO: si falta un `name` o una `password`, eso sí es un archivo
// roto y tiene que doler.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Carpeta {
    #[serde(default)]
    id: Option<String>,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Item {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    tipo: u8,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    reprompt: u8,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    collection_ids: Option<Vec<String>>,
    #[serde(default)]
    creation_date: Option<String>,
    #[serde(default)]
    revision_date: Option<String>,
    #[serde(default)]
    deleted_date: Option<String>,
    /// Bitwarden añadió el archivado después de las primeras versiones del
    /// formato. Se descubrió porque un export real lo traía y el importador lo
    /// rechazó por campo desconocido — que es exactamente lo que tenía que
    /// hacer, y por lo que este dato no se perdió.
    #[serde(default)]
    archived_date: Option<String>,
    #[serde(default)]
    fields: Option<Vec<CampoPersonalizado>>,
    #[serde(default)]
    password_history: Option<Vec<HistorialClave>>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    secure_note: Option<NotaSegura>,
    #[serde(default)]
    card: Option<Tarjeta>,
    #[serde(default)]
    identity: Option<Identidad>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CampoPersonalizado {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(rename = "type")]
    tipo: u8,
    #[serde(default)]
    linked_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistorialClave {
    #[serde(default)]
    last_used_date: Option<String>,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<UriLogin>>,
    #[serde(default)]
    fido2_credentials: Option<Vec<Passkey>>,
}

/// Los bloques que solo tienen campos opcionales llevan `default` en el
/// contenedor: ninguno de sus campos es obligatorio, así que la ausencia de
/// cualquiera de ellos es información válida, no un archivo roto.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct UriLogin {
    #[serde(rename = "match")]
    coincidencia: Option<u8>,
    uri: Option<String>,
}

/// Una passkey. `key_value` es **la clave privada**: perderla al importar es
/// perder el acceso al servicio, así que se trata como secreto y se conserva
/// entera, campo a campo.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Passkey {
    credential_id: Option<String>,
    key_type: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    key_value: Option<String>,
    rp_id: Option<String>,
    rp_name: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    counter: Option<String>,
    discoverable: Option<String>,
    creation_date: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct NotaSegura {
    #[serde(rename = "type")]
    tipo: u8,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Tarjeta {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Identidad {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversión
// ---------------------------------------------------------------------------

const TIPO_ACCESO: u8 = 1;
const TIPO_NOTA: u8 = 2;
const TIPO_TARJETA: u8 = 3;
const TIPO_IDENTIDAD: u8 = 4;

/// Importa un export JSON de Bitwarden.
///
/// Devuelve error —y no importa nada— ante cualquier estructura que no
/// entienda. Los datos que sí entiende pero que no puede representar (adjuntos,
/// pertenencia a colecciones) salen como avisos en [`Importacion::avisos`].
pub fn importar(json: &str) -> Result<Importacion, ImportError> {
    // Se mira `encrypted` antes de la deserialización estricta para poder dar el
    // error útil. Sin esto, un export cifrado fallaría con «campo desconocido:
    // encKeyValidation_DO_NOT_EDIT», que no le dice a nadie qué hacer.
    let crudo: serde_json::Value = serde_json::from_str(json)?;
    if crudo.get("encrypted").and_then(|v| v.as_bool()) == Some(true) {
        return Err(ImportError::ExportCifrado);
    }

    let export: Export = serde_json::from_value(crudo).map_err(traducir)?;
    if export.encrypted {
        return Err(ImportError::ExportCifrado);
    }

    let carpetas: HashMap<&str, &str> = export
        .folders
        .iter()
        .filter_map(|c| c.id.as_deref().map(|id| (id, c.name.as_str())))
        .collect();

    let mut out = Importacion::default();
    let mut en_papelera = 0usize;
    let mut de_organizacion = 0usize;
    let mut carpetas_no_resueltas = 0usize;

    for item in &export.items {
        // Un ítem en la papelera no entra en la bóveda nueva, pero tampoco
        // desaparece sin dejar rastro: se cuenta y se avisa.
        if item.deleted_date.is_some() {
            en_papelera += 1;
            continue;
        }
        if item.organization_id.is_some()
            || item.collection_ids.as_ref().is_some_and(|c| !c.is_empty())
        {
            de_organizacion += 1;
        }

        let carpeta = match item.folder_id.as_deref() {
            None => None,
            Some(id) => match carpetas.get(id) {
                Some(nombre) => Some((*nombre).to_string()),
                None => {
                    // La carpeta referenciada no está en el archivo. Se conserva
                    // el identificador crudo: es preferible una carpeta con
                    // nombre feo a una entrada que aterriza en la raíz como si
                    // nunca hubiera estado organizada.
                    carpetas_no_resueltas += 1;
                    Some(format!("(carpeta desconocida {id})"))
                }
            },
        };

        let repreguntar = match item.reprompt {
            0 => false,
            1 => true,
            otro => {
                return Err(ImportError::RepromptDesconocido {
                    nombre: item.name.clone(),
                    valor: otro,
                });
            }
        };

        let mut campos = Vec::new();
        let mut uris = Vec::new();

        let clase = match item.tipo {
            TIPO_ACCESO => {
                let login = item.login.as_ref().ok_or(ImportError::BloqueAusente {
                    nombre: item.name.clone(),
                    esperado: "acceso",
                    bloque: "login",
                })?;
                volcar_login(login, &mut campos, &mut uris);
                Clase::Acceso
            }
            TIPO_NOTA => {
                // El bloque `secureNote` solo lleva un discriminante que
                // Bitwarden mismo no usa hoy (siempre 0). Se conserva por
                // fidelidad, no porque signifique algo.
                if let Some(n) = &item.secure_note {
                    campos.push(Campo::estandar(
                        "nota.subtipo",
                        Valor::texto(n.tipo.to_string()),
                    ));
                }
                Clase::Nota
            }
            TIPO_TARJETA => {
                let t = item.card.as_ref().ok_or(ImportError::BloqueAusente {
                    nombre: item.name.clone(),
                    esperado: "tarjeta",
                    bloque: "card",
                })?;
                volcar_tarjeta(t, &mut campos);
                Clase::Tarjeta
            }
            TIPO_IDENTIDAD => {
                let i = item.identity.as_ref().ok_or(ImportError::BloqueAusente {
                    nombre: item.name.clone(),
                    esperado: "identidad",
                    bloque: "identity",
                })?;
                volcar_identidad(i, &mut campos);
                Clase::Identidad
            }
            otro => {
                return Err(ImportError::TipoDeItemDesconocido {
                    nombre: item.name.clone(),
                    tipo: otro,
                });
            }
        };

        // Los campos personalizados van DESPUÉS de los estándar y conservan su
        // nombre tal cual: son del usuario.
        for f in item.fields.iter().flatten() {
            let etiqueta = f.name.clone().unwrap_or_else(|| "(sin nombre)".to_string());
            let valor = match f.tipo {
                0 => Valor::texto(f.value.clone().unwrap_or_default()),
                1 => Valor::secreto(f.value.clone().unwrap_or_default()),
                2 => Valor::Booleano(f.value.as_deref() == Some("true")),
                3 => Valor::Referencia(f.linked_id.unwrap_or_default()),
                otro => {
                    return Err(ImportError::TipoDeCampoDesconocido {
                        nombre: item.name.clone(),
                        tipo: otro,
                    });
                }
            };
            campos.push(Campo { etiqueta, valor, origen: Origen::Personalizado });
        }

        out.entradas.push(Entrada {
            id_origen: item.id.clone(),
            nombre: item.name.clone(),
            clase,
            carpeta,
            favorita: item.favorite,
            archivada: item.archived_date.clone(),
            repreguntar,
            notas: item.notes.clone().map(Zeroizing::new),
            campos,
            uris,
            historial: item
                .password_history
                .iter()
                .flatten()
                .map(|h| ClaveAnterior {
                    clave: Zeroizing::new(h.password.clone()),
                    usada_hasta: h.last_used_date.clone(),
                })
                .collect(),
            creada: item.creation_date.clone(),
            revisada: item.revision_date.clone(),
        });
    }

    // El export JSON NUNCA trae los adjuntos. No se puede saber desde aquí si
    // había alguno, así que el aviso es incondicional: mejor una advertencia de
    // más que un archivo perdido.
    out.avisos.push(
        "Los ADJUNTOS de Bitwarden no viajan en el export JSON. Si tenías archivos \
         adjuntos, descárgalos por separado antes de borrar la cuenta."
            .to_string(),
    );
    out.avisos.push(
        "El archivo de export está EN CLARO: contiene todas tus contraseñas en \
         texto plano. Bórralo de forma segura en cuanto termine la importación."
            .to_string(),
    );
    if en_papelera > 0 {
        out.avisos.push(format!(
            "{en_papelera} ítem(s) estaban en la PAPELERA de Bitwarden y no se \
             importaron. Restáuralos allí y vuelve a exportar si los necesitas."
        ));
    }
    if de_organizacion > 0 {
        out.avisos.push(format!(
            "{de_organizacion} ítem(s) pertenecían a una organización. Se \
             importaron, pero la pertenencia a colecciones no tiene equivalente \
             en una bóveda personal y no se conserva."
        ));
    }
    if export.collections.as_ref().is_some_and(|c| !c.is_null()) {
        out.avisos.push(
            "El export incluye definiciones de COLECCIONES de organización. Una \
             bóveda personal no tiene colecciones: los ítems se importan, la \
             estructura de colecciones no."
                .to_string(),
        );
    }
    if carpetas_no_resueltas > 0 {
        out.avisos.push(format!(
            "{carpetas_no_resueltas} ítem(s) referencian una carpeta que no está \
             en el archivo; se les asignó una carpeta con el identificador crudo."
        ));
    }

    Ok(out)
}

/// Convierte el error de serde en `CampoDesconocido` cuando lo es, para que el
/// mensaje diga qué hacer en vez de soltar la jerga de serde.
fn traducir(e: serde_json::Error) -> ImportError {
    let texto = e.to_string();
    if texto.starts_with("unknown field") {
        ImportError::CampoDesconocido(texto)
    } else {
        ImportError::Json(e)
    }
}

/// Añade un campo solo si trae contenido. Un `Some("")` de Bitwarden es un
/// campo vacío, no un dato.
fn empujar(campos: &mut Vec<Campo>, etiqueta: &str, v: &Option<String>, secreto: bool) {
    let Some(s) = v.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let valor = if secreto { Valor::secreto(s) } else { Valor::texto(s) };
    campos.push(Campo::estandar(etiqueta, valor));
}

fn volcar_login(login: &Login, campos: &mut Vec<Campo>, uris: &mut Vec<Uri>) {
    empujar(campos, "acceso.usuario", &login.username, false);
    empujar(campos, "acceso.clave", &login.password, true);
    // El TOTP es un secreto compartido: quien lo tiene genera los códigos.
    empujar(campos, "acceso.totp", &login.totp, true);

    for u in login.uris.iter().flatten() {
        if let Some(uri) = u.uri.as_deref().filter(|s| !s.is_empty()) {
            uris.push(Uri { uri: uri.to_string(), coincidencia: u.coincidencia });
        }
    }

    for (i, pk) in login.fido2_credentials.iter().flatten().enumerate() {
        let p = |campo: &str| format!("passkey.{i}.{campo}");
        empujar(campos, &p("id"), &pk.credential_id, false);
        empujar(campos, &p("tipo"), &pk.key_type, false);
        empujar(campos, &p("algoritmo"), &pk.key_algorithm, false);
        empujar(campos, &p("curva"), &pk.key_curve, false);
        // La clave privada de la passkey.
        empujar(campos, &p("clave"), &pk.key_value, true);
        empujar(campos, &p("rp_id"), &pk.rp_id, false);
        empujar(campos, &p("rp_nombre"), &pk.rp_name, false);
        empujar(campos, &p("usuario_handle"), &pk.user_handle, false);
        empujar(campos, &p("usuario"), &pk.user_name, false);
        empujar(campos, &p("usuario_mostrado"), &pk.user_display_name, false);
        empujar(campos, &p("contador"), &pk.counter, false);
        empujar(campos, &p("descubrible"), &pk.discoverable, false);
        empujar(campos, &p("creada"), &pk.creation_date, false);
    }
}

fn volcar_tarjeta(t: &Tarjeta, campos: &mut Vec<Campo>) {
    empujar(campos, "tarjeta.titular", &t.cardholder_name, false);
    empujar(campos, "tarjeta.marca", &t.brand, false);
    empujar(campos, "tarjeta.numero", &t.number, true);
    empujar(campos, "tarjeta.mes", &t.exp_month, false);
    empujar(campos, "tarjeta.anio", &t.exp_year, false);
    empujar(campos, "tarjeta.cvv", &t.code, true);
}

fn volcar_identidad(i: &Identidad, campos: &mut Vec<Campo>) {
    empujar(campos, "identidad.tratamiento", &i.title, false);
    empujar(campos, "identidad.nombre", &i.first_name, false);
    empujar(campos, "identidad.segundo_nombre", &i.middle_name, false);
    empujar(campos, "identidad.apellidos", &i.last_name, false);
    empujar(campos, "identidad.direccion1", &i.address1, false);
    empujar(campos, "identidad.direccion2", &i.address2, false);
    empujar(campos, "identidad.direccion3", &i.address3, false);
    empujar(campos, "identidad.ciudad", &i.city, false);
    empujar(campos, "identidad.departamento", &i.state, false);
    empujar(campos, "identidad.codigo_postal", &i.postal_code, false);
    empujar(campos, "identidad.pais", &i.country, false);
    empujar(campos, "identidad.empresa", &i.company, false);
    empujar(campos, "identidad.correo", &i.email, false);
    empujar(campos, "identidad.telefono", &i.phone, false);
    // Documento de identidad: en Colombia, la cédula. Es dato personal
    // sensible aunque Bitwarden lo llame `ssn`.
    empujar(campos, "identidad.documento", &i.ssn, true);
    empujar(campos, "identidad.usuario", &i.username, false);
    empujar(campos, "identidad.pasaporte", &i.passport_number, true);
    empujar(campos, "identidad.licencia", &i.license_number, true);
}
