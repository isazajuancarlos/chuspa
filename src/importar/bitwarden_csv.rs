// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Importador del export **CSV** de Bitwarden.
//!
//! # Este formato pierde datos, y no es culpa del importador
//!
//! El CSV de Bitwarden tiene doce columnas fijas. Todo lo que no cabe en esas
//! doce columnas sencillamente no está en el archivo:
//!
//! - **Tarjetas e identidades**: no hay columna para el número, el CVV, la
//!   cédula ni el pasaporte. Si la bóveda las tenía, no viajan — y desde el CSV
//!   **no se puede detectar** que faltaban, porque no dejan ni una fila vacía.
//! - **Passkeys**: la clave privada no tiene columna. Perderla es perder el
//!   acceso al servicio.
//! - **Historial de contraseñas** y sus fechas.
//! - **Identificadores de los ítems**: sin ellos, reimportar duplica en vez de
//!   actualizar.
//! - **El tipo de los campos personalizados**: el CSV los aplana a
//!   `nombre: valor` y se pierde si eran texto, ocultos, booleanos o enlazados.
//!
//! Por eso este módulo avisa de todo ello **siempre**, sin condiciones: la
//! ausencia no es detectable, así que un aviso condicional no dispararía nunca.
//! Es el mismo criterio del importador JSON —no perder nada en silencio— llevado
//! a un formato donde la pérdida ya viene de fábrica: si no se puede evitar, al
//! menos que no sea silenciosa.
//!
//! **La recomendación es exportar en JSON.** Este importador existe porque el
//! CSV es lo que la gente tiene a mano, y porque es un formato común a otros
//! gestores, no porque sea buena idea usarlo.

use crate::boveda::{Campo, Clase, Entrada, Importacion, Origen, Uri, Valor};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CsvError {
    #[error("no se pudo leer el CSV: {0}")]
    Lectura(#[from] csv::Error),

    #[error(
        "el CSV trae columnas que Chuspa no conoce: {0}. No se importa nada: \
         una columna nueva puede ser un dato que se perdería sin que nadie lo \
         note. Actualiza el importador."
    )]
    ColumnasDesconocidas(String),

    #[error("al CSV le faltan columnas del formato de Bitwarden: {0}")]
    ColumnasAusentes(String),

    #[error("la fila {fila} («{nombre}») tiene un tipo desconocido: «{tipo}»")]
    TipoDesconocido { fila: usize, nombre: String, tipo: String },

    #[error("la fila {fila} («{nombre}») tiene reprompt=«{valor}», que no es 0 ni 1")]
    RepromptDesconocido { fila: usize, nombre: String, valor: String },
}

/// Las doce columnas del export CSV de Bitwarden, en el orden en que las emite.
///
/// `archivedDate` apareció en una versión posterior a las primeras. Está en la
/// lista porque un export real la traía; si mañana aparece otra, el importador
/// se detiene en vez de tragársela.
const COLUMNAS: &[&str] = &[
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "archivedDate",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
];

/// Columnas sin las que el archivo no es un export de Bitwarden. El resto puede
/// faltar en exports de versiones antiguas y eso no es un error.
const COLUMNAS_MINIMAS: &[&str] = &["type", "name"];

pub fn importar(csv_texto: &str) -> Result<Importacion, CsvError> {
    let mut lector = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(csv_texto.as_bytes());

    let cabecera = lector.headers()?.clone();
    let presentes: Vec<&str> = cabecera.iter().collect();

    // Una columna que no conocemos es un dato que no sabemos dónde poner. Igual
    // que en el importador JSON, eso detiene la importación entera: importar
    // "casi todo" es lo que produce una bóveda que parece completa.
    let desconocidas: Vec<&str> = presentes
        .iter()
        .filter(|c| !COLUMNAS.contains(c))
        .copied()
        .collect();
    if !desconocidas.is_empty() {
        return Err(CsvError::ColumnasDesconocidas(desconocidas.join(", ")));
    }

    let ausentes: Vec<&str> = COLUMNAS_MINIMAS
        .iter()
        .filter(|c| !presentes.contains(c))
        .copied()
        .collect();
    if !ausentes.is_empty() {
        return Err(CsvError::ColumnasAusentes(ausentes.join(", ")));
    }

    let indice = |nombre: &str| presentes.iter().position(|c| *c == nombre);
    let (i_folder, i_fav, i_type, i_name, i_notes, i_fields, i_reprompt, i_arch) = (
        indice("folder"),
        indice("favorite"),
        indice("type"),
        indice("name"),
        indice("notes"),
        indice("fields"),
        indice("reprompt"),
        indice("archivedDate"),
    );
    let (i_uri, i_user, i_pass, i_totp) = (
        indice("login_uri"),
        indice("login_username"),
        indice("login_password"),
        indice("login_totp"),
    );

    let mut out = Importacion::default();
    let mut con_campos_personalizados = 0usize;
    let mut con_uris_ambiguas = 0usize;

    for (n, registro) in lector.records().enumerate() {
        let registro = registro?;
        // Número de fila tal como lo vería el usuario en un editor: la cabecera
        // es la 1.
        let fila = n + 2;
        let dato = |i: Option<usize>| -> &str {
            i.and_then(|i| registro.get(i)).unwrap_or("").trim()
        };

        let nombre = dato(i_name).to_string();
        let tipo = dato(i_type);

        let clase = match tipo {
            "login" => Clase::Acceso,
            "note" => Clase::Nota,
            otro => {
                return Err(CsvError::TipoDesconocido {
                    fila,
                    nombre,
                    tipo: otro.to_string(),
                });
            }
        };

        let repreguntar = match dato(i_reprompt) {
            "" | "0" => false,
            "1" => true,
            otro => {
                return Err(CsvError::RepromptDesconocido {
                    fila,
                    nombre,
                    valor: otro.to_string(),
                });
            }
        };

        let mut campos = Vec::new();
        empujar(&mut campos, "acceso.usuario", dato(i_user), false);
        empujar(&mut campos, "acceso.clave", dato(i_pass), true);
        empujar(&mut campos, "acceso.totp", dato(i_totp), true);

        let crudo_fields = dato(i_fields);
        if !crudo_fields.is_empty() {
            con_campos_personalizados += 1;
            campos.extend(partir_campos(crudo_fields));
        }

        let crudo_uri = dato(i_uri);
        if crudo_uri.contains(',') {
            con_uris_ambiguas += 1;
        }
        let uris = partir_uris(crudo_uri);
        let carpeta = Some(dato(i_folder)).filter(|s| !s.is_empty()).map(String::from);
        let notas = Some(dato(i_notes))
            .filter(|s| !s.is_empty())
            .map(|s| Zeroizing::new(s.to_string()));

        out.entradas.push(Entrada {
            // El CSV no trae identificadores. No se inventa uno: un id fabricado
            // aquí no coincidiría con el de Bitwarden y daría la falsa impresión
            // de que se puede reconciliar una reimportación.
            id_origen: None,
            nombre,
            clase,
            carpeta,
            favorita: matches!(dato(i_fav), "1" | "true"),
            archivada: Some(dato(i_arch)).filter(|s| !s.is_empty()).map(String::from),
            repreguntar,
            notas,
            campos,
            uris,
            historial: Vec::new(),
            creada: None,
            revisada: None,
        });
    }

    out.avisos.push(format!(
        "Formato CSV: {} entradas importadas. El CSV es un formato REDUCIDO; \
         para no perder nada, exporta en JSON (.json, no .encrypted_json) y usa \
         el importador JSON.",
        out.entradas.len()
    ));
    out.avisos.push(
        "El CSV NO tiene columnas para TARJETAS ni IDENTIDADES. Si tu bóveda \
         tenía alguna, no está en este archivo — y no se puede detectar desde \
         aquí, porque no dejan rastro. Compruébalo en Bitwarden antes de borrar \
         la cuenta."
            .to_string(),
    );
    out.avisos.push(
        "El CSV NO lleva PASSKEYS (su clave privada), ni el HISTORIAL de \
         contraseñas, ni las fechas de creación y revisión."
            .to_string(),
    );
    out.avisos.push(
        "El CSV no trae IDENTIFICADORES de ítem: una segunda importación creará \
         duplicados en vez de actualizar."
            .to_string(),
    );
    if con_uris_ambiguas > 0 {
        out.avisos.push(format!(
            "{con_uris_ambiguas} entrada(s) tienen comas en la columna de URIs. \
             El CSV usa la coma como separador, así que se partieron ahí — pero \
             una URI puede contener una coma, y desde el CSV las dos lecturas son \
             indistinguibles. Si alguna URI queda cortada por la mitad, es esto; \
             el export JSON no tiene la ambigüedad."
        ));
    }
    if con_campos_personalizados > 0 {
        out.avisos.push(format!(
            "{con_campos_personalizados} entrada(s) traen campos personalizados. \
             El CSV los aplana a «nombre: valor» y pierde su tipo, así que se \
             importan como SECRETOS: en la duda se oculta, que es el error que no \
             expone nada. Revísalos y desmárcalos si no lo eran."
        ));
    }
    out.avisos.push(
        "Los ADJUNTOS no viajan en ningún export de Bitwarden. Descárgalos aparte."
            .to_string(),
    );
    out.avisos.push(
        "El archivo CSV está EN CLARO: contiene todas tus contraseñas en texto \
         plano. Bórralo de forma segura en cuanto termine la importación."
            .to_string(),
    );

    Ok(out)
}

fn empujar(campos: &mut Vec<Campo>, etiqueta: &str, valor: &str, secreto: bool) {
    if valor.is_empty() {
        return;
    }
    let v = if secreto { Valor::secreto(valor) } else { Valor::texto(valor) };
    campos.push(Campo::estandar(etiqueta, v));
}

/// El CSV aplana los campos personalizados a una línea `nombre: valor` por
/// campo.
///
/// El tipo se pierde por completo, así que **todos entran como secretos**. La
/// asimetría es deliberada: marcar como secreto algo que no lo era solo obliga a
/// pulsar «mostrar»; marcar como visible algo que sí lo era lo pinta en la
/// pantalla. La regla se probó contra el usuario legítimo, no contra el
/// atacante, y no le impide nada.
///
/// Si una línea no tiene `: `, no se puede saber cuál es el nombre y cuál el
/// valor. No se adivina: entra entera como valor bajo una etiqueta que dice
/// exactamente eso.
fn partir_campos(crudo: &str) -> Vec<Campo> {
    crudo
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|linea| match linea.split_once(": ") {
            Some((nombre, valor)) => {
                Campo::personalizado(nombre.trim(), Valor::secreto(valor))
            }
            None => Campo {
                etiqueta: "(campo sin nombre reconocible)".to_string(),
                valor: Valor::secreto(linea.trim()),
                origen: Origen::Personalizado,
            },
        })
        .collect()
}

/// El CSV separa varias URIs con comas, y esa separación es AMBIGUA.
///
/// Un export real lo demostró: una entrada cuyo JSON tenía **una** URI con una
/// coma dentro produjo **dos** al pasar por el CSV. Las dos lecturas —«dos URIs»
/// y «una URI que contiene una coma»— son indistinguibles desde el archivo,
/// porque el formato no escapa el separador.
///
/// Se parte por coma, que es la lectura mayoritaria, y se avisa del número de
/// entradas afectadas. Inventar una heurística —«no partir si el segundo trozo
/// no empieza por un esquema»— sería peor: acertaría en unos casos y fallaría en
/// otros sin decir en cuáles, que es justo lo que un aviso honesto evita.
///
/// Las URIs del CSV no llevan regla de coincidencia: esa columna no existe, y
/// por eso `coincidencia` queda en `None` —usar la de por defecto— en vez de
/// inventarse una.
fn partir_uris(crudo: &str) -> Vec<Uri> {
    crudo
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|uri| Uri { uri: uri.to_string(), coincidencia: None })
        .collect()
}
