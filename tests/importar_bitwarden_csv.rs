// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Pruebas del importador CSV de Bitwarden.
//!
//! Todos los datos de aquí son **inventados**. La estructura sí es la de un
//! export real —doce columnas, incluida `archivedDate`, que apareció en una
//! versión posterior a las primeras—, y algunos casos reproducen situaciones
//! observadas en un export de verdad: la URI con coma dentro y la entrada sin
//! contraseña.

use chuspa::boveda::{Clase, Origen};
use chuspa::importar::bitwarden_csv::{self, CsvError};

const CABECERA: &str = "folder,favorite,type,name,notes,fields,reprompt,archivedDate,\
                        login_uri,login_username,login_password,login_totp";

fn csv_con(filas: &[&str]) -> String {
    let mut s = String::from(CABECERA);
    for f in filas {
        s.push('\n');
        s.push_str(f);
    }
    s
}

#[test]
fn importa_una_entrada_completa() {
    let csv = csv_con(&[
        "Bancos,1,login,Banco,una nota,,1,,https://banco.example,juan,s3cr3t,otpauth://totp/x",
    ]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    assert_eq!(r.entradas.len(), 1);

    let e = &r.entradas[0];
    assert_eq!(e.nombre, "Banco");
    assert_eq!(e.clase, Clase::Acceso);
    assert_eq!(e.carpeta.as_deref(), Some("Bancos"));
    assert!(e.favorita);
    assert!(e.repreguntar);
    assert_eq!(e.notas.as_ref().map(|n| n.as_str()), Some("una nota"));
    assert_eq!(e.uris.len(), 1);
    assert!(e.campo("acceso.usuario").is_some());
    assert!(e.campo("acceso.clave").unwrap().valor.es_sensible());
    assert!(e.campo("acceso.totp").unwrap().valor.es_sensible());

    // Lo que el CSV no puede traer queda vacío, no inventado.
    assert!(e.id_origen.is_none(), "el CSV no trae identificadores");
    assert!(e.historial.is_empty(), "el CSV no trae historial");
    assert!(e.creada.is_none() && e.revisada.is_none());
}

#[test]
fn una_entrada_sin_contrasena_se_importa_igual() {
    // Observado en un export real: una entrada con passkey y sin contraseña.
    let csv = csv_con(&[",,login,Solo passkey,,,0,,https://x.example,juan,,"]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    let e = &r.entradas[0];
    assert!(e.campo("acceso.clave").is_none());
    assert!(e.campo("acceso.usuario").is_some());
    assert!(e.carpeta.is_none(), "una carpeta vacía no es una carpeta");
}

#[test]
fn los_campos_personalizados_entran_como_secretos() {
    // El CSV pierde el tipo del campo. En la duda se oculta: marcar de más solo
    // obliga a pulsar «mostrar»; marcar de menos lo pinta en la pantalla.
    let csv = csv_con(&[",,login,Sitio,,\"pregunta: mi mascota\",0,,,,clave,"]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    let campo = r.entradas[0].campo("pregunta").expect("falta el campo");
    assert_eq!(campo.origen, Origen::Personalizado);
    assert!(campo.valor.es_sensible());
}

#[test]
fn un_campo_sin_nombre_reconocible_no_se_descarta() {
    let csv = csv_con(&[",,login,Sitio,,\"sinseparador\",0,,,,clave,"]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    let personalizados: Vec<_> = r.entradas[0]
        .campos
        .iter()
        .filter(|c| c.origen == Origen::Personalizado)
        .collect();
    assert_eq!(personalizados.len(), 1, "el campo raro se conserva igual");
    assert!(personalizados[0].etiqueta.contains("sin nombre reconocible"));
}

#[test]
fn varias_uris_en_una_celda_se_separan() {
    let csv = csv_con(&[
        ",,login,Sitio,,,0,,\"https://a.example,https://b.example\",juan,clave,",
    ]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    assert_eq!(r.entradas[0].uris.len(), 2);
    // Y se avisa, porque la separación es ambigua.
    assert!(r.avisos.iter().any(|a| a.contains("comas")));
}

#[test]
fn la_separacion_por_comas_es_ambigua_y_se_dice() {
    // Caso real: en el JSON era UNA URI que contenía una coma; el CSV la parte.
    // El importador no puede distinguirlo, así que la partición se avisa.
    let csv = csv_con(&[
        ",,login,Sitio,,,0,,\"https://a.example/x,y\",juan,clave,",
    ]);
    let r = bitwarden_csv::importar(&csv).unwrap();
    assert_eq!(r.entradas[0].uris.len(), 2, "se parte por la lectura mayoritaria");
    assert!(
        r.avisos.iter().any(|a| a.contains("indistinguibles")),
        "pero el usuario tiene que enterarse de que pudo partirse mal"
    );
}

#[test]
fn avisa_de_todo_lo_que_el_formato_no_puede_llevar() {
    let r = bitwarden_csv::importar(&csv_con(&[",,login,X,,,0,,,,clave,"])).unwrap();
    let todo = r.avisos.join(" | ");
    for termino in [
        "TARJETAS",
        "IDENTIDADES",
        "PASSKEYS",
        "HISTORIAL",
        "IDENTIFICADORES",
        "ADJUNTOS",
        "EN CLARO",
        "JSON",
    ] {
        assert!(todo.contains(termino), "falta el aviso sobre {termino}");
    }
}

#[test]
fn importa_notas_seguras() {
    let r = bitwarden_csv::importar(&csv_con(&[",,note,Mi nota,el texto,,0,,,,,"])).unwrap();
    assert_eq!(r.entradas[0].clase, Clase::Nota);
    assert_eq!(r.entradas[0].notas.as_ref().map(|n| n.as_str()), Some("el texto"));
}

// ---------------------------------------------------------------------------
// Camino rojo
// ---------------------------------------------------------------------------

#[test]
fn rechaza_una_columna_desconocida() {
    let csv = format!("{CABECERA},columnaNueva\n,,login,X,,,0,,,,clave,,dato");
    match bitwarden_csv::importar(&csv) {
        Err(CsvError::ColumnasDesconocidas(m)) => assert!(m.contains("columnaNueva")),
        otro => panic!("una columna nueva debe detener la importación: {otro:?}"),
    }
}

#[test]
fn rechaza_un_tipo_desconocido() {
    let csv = csv_con(&[",,card,Visa,,,0,,,,,"]);
    match bitwarden_csv::importar(&csv) {
        // `card` no es un tipo que el CSV sepa representar: sus columnas no
        // existen. Aceptarlo produciría una tarjeta sin número.
        Err(CsvError::TipoDesconocido { tipo, .. }) => assert_eq!(tipo, "card"),
        otro => panic!("un tipo sin columnas no se importa vacío: {otro:?}"),
    }
}

#[test]
fn rechaza_un_reprompt_desconocido() {
    let csv = csv_con(&[",,login,X,,,7,,,,clave,"]);
    match bitwarden_csv::importar(&csv) {
        Err(CsvError::RepromptDesconocido { valor, .. }) => assert_eq!(valor, "7"),
        otro => panic!("un reprompt fuera de 0..=1 no se ignora: {otro:?}"),
    }
}

#[test]
fn rechaza_un_archivo_sin_las_columnas_minimas() {
    let csv = "folder,favorite\nBancos,1";
    match bitwarden_csv::importar(csv) {
        Err(CsvError::ColumnasAusentes(m)) => {
            assert!(m.contains("type") && m.contains("name"));
        }
        otro => panic!("sin type ni name no es un export de Bitwarden: {otro:?}"),
    }
}

#[test]
fn un_export_de_version_antigua_sin_archived_date_funciona() {
    // `archivedDate` no existía en las primeras versiones. Que falte una columna
    // OPCIONAL no es un error: lo que no puede pasar desapercibido es una de más.
    let cabecera_vieja = "folder,favorite,type,name,notes,fields,reprompt,\
                          login_uri,login_username,login_password,login_totp";
    let csv = format!("{cabecera_vieja}\nBancos,1,login,Banco,,,0,https://x.example,juan,clave,");
    let r = bitwarden_csv::importar(&csv).unwrap();
    assert_eq!(r.entradas.len(), 1);
    assert!(r.entradas[0].archivada.is_none());
}
