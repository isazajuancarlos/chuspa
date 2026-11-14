// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Pruebas del importador de Bitwarden.
//!
//! La promesa del importador es «ningún dato se pierde en silencio». Una prueba
//! que solo comprobara que el usuario y la contraseña llegan sería verde con un
//! importador que tira el TOTP, el CVV y la passkey — verde por la razón
//! equivocada.
//!
//! Por eso la prueba central ([`ningun_campo_del_json_se_queda_fuera`]) no
//! comprueba campos concretos: cuenta las hojas con contenido del JSON de origen
//! y exige que salga el mismo número de campos. Si mañana se añade un campo al
//! esquema y se olvida volcarlo, esta prueba se pone roja sin que nadie tenga
//! que acordarse de ampliarla.

use chuspa::boveda::{Clase, Origen, Valor};
use chuspa::importar::bitwarden::{self, ImportError};

/// Export con los cuatro tipos de ítem, campos personalizados de los cuatro
/// tipos, TOTP, passkey, historial de contraseñas, carpetas y favoritos.
const EXPORT: &str = r#"{
  "encrypted": false,
  "folders": [
    { "id": "f-1", "name": "Bancos" }
  ],
  "items": [
    {
      "id": "i-1",
      "name": "Banco",
      "type": 1,
      "folderId": "f-1",
      "favorite": true,
      "reprompt": 1,
      "notes": "clave del cajero",
      "creationDate": "2024-01-01T00:00:00.000Z",
      "revisionDate": "2025-06-01T00:00:00.000Z",
      "passwordHistory": [
        { "lastUsedDate": "2024-05-01T00:00:00.000Z", "password": "vieja1" },
        { "lastUsedDate": "2024-06-01T00:00:00.000Z", "password": "vieja2" }
      ],
      "fields": [
        { "name": "pregunta", "value": "primera mascota", "type": 0, "linkedId": null },
        { "name": "pin", "value": "4321", "type": 1, "linkedId": null },
        { "name": "activa", "value": "true", "type": 2, "linkedId": null },
        { "name": "enlazado", "value": null, "type": 3, "linkedId": 100 }
      ],
      "login": {
        "username": "juan",
        "password": "s3cr3t",
        "totp": "otpauth://totp/Banco:juan?secret=ABCDEF",
        "uris": [
          { "match": null, "uri": "https://banco.com" },
          { "match": 3, "uri": "https://m.banco.com" }
        ],
        "fido2Credentials": [
          {
            "credentialId": "cred-1",
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": "PRIVADA",
            "rpId": "banco.com",
            "rpName": "Banco",
            "userHandle": "uh-1",
            "userName": "juan",
            "userDisplayName": "Juan Carlos",
            "counter": "0",
            "discoverable": "true",
            "creationDate": "2025-01-01T00:00:00.000Z"
          }
        ]
      }
    },
    {
      "id": "i-2",
      "name": "Nota",
      "type": 2,
      "notes": "algo privado",
      "secureNote": { "type": 0 }
    },
    {
      "id": "i-3",
      "name": "Visa",
      "type": 3,
      "card": {
        "cardholderName": "JUAN C ISAZA",
        "brand": "Visa",
        "number": "4111111111111111",
        "expMonth": "12",
        "expYear": "2030",
        "code": "123"
      }
    },
    {
      "id": "i-4",
      "name": "Cédula",
      "type": 4,
      "identity": {
        "title": "Sr",
        "firstName": "Juan",
        "middleName": "Carlos",
        "lastName": "Isaza Arenas",
        "address1": "Calle 1",
        "address2": "Apto 2",
        "address3": "",
        "city": "Medellín",
        "state": "Antioquia",
        "postalCode": "050001",
        "country": "CO",
        "company": "Xiliux",
        "email": "j@example.com",
        "phone": "3000000000",
        "ssn": "71000000",
        "username": "jisaza",
        "passportNumber": "AZ123456",
        "licenseNumber": "L-1"
      }
    }
  ]
}"#;

fn importar_ok() -> chuspa::boveda::Importacion {
    bitwarden::importar(EXPORT).expect("el export de referencia debe importarse")
}

// ---------------------------------------------------------------------------
// La prueba que sostiene la promesa del módulo
// ---------------------------------------------------------------------------

/// Cuenta las hojas con contenido de un valor JSON: cadenas no vacías, números
/// y booleanos. Es la medida de «cuántos datos hay aquí dentro».
fn hojas_con_contenido(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::String(s) => usize::from(!s.is_empty()),
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => 1,
        serde_json::Value::Null => 0,
        serde_json::Value::Array(a) => a.iter().map(hojas_con_contenido).sum(),
        serde_json::Value::Object(o) => o.values().map(hojas_con_contenido).sum(),
    }
}

/// Para cada ítem del export, el número de datos que trae su bloque específico
/// (`login`/`card`/`identity`) tiene que coincidir exactamente con el número de
/// campos estándar + URIs que produce el importador.
///
/// Esta es la prueba que discrimina: envenenar el importador quitando el volcado
/// de UN solo campo —el CVV, el TOTP, la clave de la passkey— la pone roja.
#[test]
fn ningun_campo_del_json_se_queda_fuera() {
    let crudo: serde_json::Value = serde_json::from_str(EXPORT).unwrap();
    let items = crudo["items"].as_array().unwrap();
    let importadas = importar_ok().entradas;

    for (item, entrada) in items.iter().zip(&importadas) {
        let bloque = ["login", "card", "identity", "secureNote"]
            .iter()
            .find_map(|k| item.get(*k))
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        // `match` de una URI es una regla de coincidencia, no un dato con
        // identidad propia: viaja dentro de `Uri`, no como campo aparte.
        let matches = item["login"]["uris"]
            .as_array()
            .map(|a| a.iter().filter(|u| !u["match"].is_null()).count())
            .unwrap_or(0);

        let esperados = hojas_con_contenido(&bloque) - matches;
        let obtenidos = entrada
            .campos
            .iter()
            .filter(|c| c.origen == Origen::Estandar)
            .count()
            + entrada.uris.len();

        assert_eq!(
            esperados, obtenidos,
            "«{}»: el JSON trae {esperados} datos y se importaron {obtenidos}. \
             Falta volcar algún campo del esquema.",
            entrada.nombre
        );
    }
}

// ---------------------------------------------------------------------------
// Camino verde
// ---------------------------------------------------------------------------

#[test]
fn importa_los_cuatro_tipos() {
    let r = importar_ok();
    let clases: Vec<_> = r.entradas.iter().map(|e| e.clase).collect();
    assert_eq!(
        clases,
        vec![Clase::Acceso, Clase::Nota, Clase::Tarjeta, Clase::Identidad]
    );
}

#[test]
fn los_secretos_quedan_marcados_como_secretos() {
    let r = importar_ok();
    // Lo que no debe aparecer nunca en una pantalla ni en un registro.
    for (indice, etiqueta) in [
        (0, "acceso.clave"),
        (0, "acceso.totp"),
        (0, "passkey.0.clave"),
        (2, "tarjeta.numero"),
        (2, "tarjeta.cvv"),
        (3, "identidad.documento"),
        (3, "identidad.pasaporte"),
    ] {
        let campo = r.entradas[indice]
            .campo(etiqueta)
            .unwrap_or_else(|| panic!("falta el campo {etiqueta}"));
        assert!(campo.valor.es_sensible(), "{etiqueta} debería ser secreto");
    }
    // Y lo que sí puede mostrarse.
    assert!(!r.entradas[0].campo("acceso.usuario").unwrap().valor.es_sensible());
    assert!(!r.entradas[2].campo("tarjeta.marca").unwrap().valor.es_sensible());
}

#[test]
fn conserva_metadatos_de_la_entrada() {
    let e = &importar_ok().entradas[0];
    assert_eq!(e.nombre, "Banco");
    assert_eq!(e.carpeta.as_deref(), Some("Bancos"));
    assert!(e.favorita);
    assert!(e.repreguntar, "reprompt=1 debe exigir la maestra otra vez");
    assert_eq!(e.notas.as_ref().map(|n| n.as_str()), Some("clave del cajero"));
    assert_eq!(e.id_origen.as_deref(), Some("i-1"));
    assert_eq!(e.creada.as_deref(), Some("2024-01-01T00:00:00.000Z"));
}

#[test]
fn el_historial_de_contrasenas_no_se_tira() {
    let e = &importar_ok().entradas[0];
    let claves: Vec<&str> = e.historial.iter().map(|h| h.clave.as_str()).collect();
    assert_eq!(claves, vec!["vieja1", "vieja2"]);
    // Y la fecha con ella: sin fecha no se puede saber si una filtración
    // fechada afectaba a esta contraseña o a la siguiente.
    assert_eq!(
        e.historial[0].usada_hasta.as_deref(),
        Some("2024-05-01T00:00:00.000Z")
    );
}

#[test]
fn los_cuatro_tipos_de_campo_personalizado_sobreviven() {
    let e = &importar_ok().entradas[0];
    assert_eq!(e.campo("pregunta").unwrap().valor, Valor::texto("primera mascota"));
    assert_eq!(e.campo("pin").unwrap().valor, Valor::secreto("4321"));
    assert_eq!(e.campo("activa").unwrap().valor, Valor::Booleano(true));
    // Un campo enlazado no tiene valor propio: conservar la referencia es lo
    // único que impide que se convierta en un campo vacío indistinguible de un
    // dato ausente.
    assert_eq!(e.campo("enlazado").unwrap().valor, Valor::Referencia(100));
}

#[test]
fn conserva_las_uris_con_su_regla_de_coincidencia() {
    let e = &importar_ok().entradas[0];
    assert_eq!(e.uris.len(), 2);
    assert_eq!(e.uris[0].uri, "https://banco.com");
    assert_eq!(e.uris[0].coincidencia, None);
    assert_eq!(e.uris[1].coincidencia, Some(3));
}

#[test]
fn avisa_siempre_de_adjuntos_y_del_archivo_en_claro() {
    let r = importar_ok();
    assert!(r.avisos.iter().any(|a| a.contains("ADJUNTOS")));
    assert!(r.avisos.iter().any(|a| a.contains("EN CLARO")));
}

// ---------------------------------------------------------------------------
// Camino rojo: lo que el importador tiene que RECHAZAR
// ---------------------------------------------------------------------------

/// Sustituye un fragmento del export de referencia para construir un caso roto.
///
/// Exige que el fragmento aparezca **exactamente una vez**. Sin esa exigencia,
/// un fragmento ambiguo como `"type": 3,` muta el primer sitio donde aparece
/// —que puede ser un campo personalizado en vez del ítem— y la prueba acaba
/// midiendo otra cosa mientras parece medir la que dice. Ya pasó al escribir
/// estas pruebas: dos rojos que acusaban al importador y eran del arnés.
fn variante(de: &str, a: &str) -> String {
    let apariciones = EXPORT.matches(de).count();
    assert_eq!(
        apariciones, 1,
        "el fragmento «{de}» aparece {apariciones} veces en el export; \
         hace falta uno que identifique un solo sitio"
    );
    EXPORT.replacen(de, a, 1)
}

#[test]
fn rechaza_un_campo_que_no_conoce() {
    // El caso real: Bitwarden añade un campo en una versión futura.
    let roto = variante(r#""username": "juan","#, r#""username": "juan", "campoNuevo": "dato","#);
    match bitwarden::importar(&roto) {
        Err(ImportError::CampoDesconocido(m)) => assert!(m.contains("campoNuevo")),
        otro => panic!("un campo desconocido debe detener la importación: {otro:?}"),
    }
}

#[test]
fn rechaza_un_tipo_de_item_desconocido() {
    let roto = variante("\"name\": \"Visa\",\n      \"type\": 3,", "\"name\": \"Visa\",\n      \"type\": 5,");
    match bitwarden::importar(&roto) {
        Err(ImportError::TipoDeItemDesconocido { tipo, .. }) => assert_eq!(tipo, 5),
        otro => panic!("un tipo desconocido no se ignora: {otro:?}"),
    }
}

#[test]
fn rechaza_un_tipo_de_campo_personalizado_desconocido() {
    let roto = variante(r#""value": "4321", "type": 1"#, r#""value": "4321", "type": 9"#);
    match bitwarden::importar(&roto) {
        Err(ImportError::TipoDeCampoDesconocido { tipo, .. }) => assert_eq!(tipo, 9),
        otro => panic!("un tipo de campo desconocido no se ignora: {otro:?}"),
    }
}

#[test]
fn rechaza_un_reprompt_desconocido() {
    let roto = variante(r#""reprompt": 1,"#, r#""reprompt": 7,"#);
    match bitwarden::importar(&roto) {
        Err(ImportError::RepromptDesconocido { valor, .. }) => assert_eq!(valor, 7),
        otro => panic!("un reprompt fuera de 0..=1 no se ignora: {otro:?}"),
    }
}

#[test]
fn rechaza_un_item_sin_su_bloque() {
    // Una tarjeta declarada como acceso: el bloque `login` no existe.
    let roto = variante("\"name\": \"Visa\",\n      \"type\": 3,", "\"name\": \"Visa\",\n      \"type\": 1,");
    match bitwarden::importar(&roto) {
        Err(ImportError::BloqueAusente { bloque, .. }) => assert_eq!(bloque, "login"),
        otro => panic!("un ítem sin su bloque no se importa vacío: {otro:?}"),
    }
}

#[test]
fn el_export_cifrado_explica_que_hacer() {
    let cifrado = r#"{
      "encrypted": true,
      "passwordProtected": true,
      "salt": "",
      "kdfType": 0,
      "kdfIterations": 600000,
      "encKeyValidation_DO_NOT_EDIT": "2.abc|def|ghi",
      "data": "2.xxx|yyy|zzz"
    }"#;
    let e = bitwarden::importar(cifrado).unwrap_err();
    assert!(matches!(e, ImportError::ExportCifrado));
    // El mensaje tiene que decir qué hacer, no solo que falló.
    assert!(e.to_string().contains(".json"), "el error debe indicar el formato correcto");
}

#[test]
fn los_items_en_la_papelera_no_entran_pero_se_avisan() {
    let roto = variante(r#""name": "Visa","#, r#""name": "Visa", "deletedDate": "2025-01-01T00:00:00.000Z","#);
    let r = bitwarden::importar(&roto).unwrap();
    assert_eq!(r.entradas.len(), 3, "el ítem borrado no debe entrar");
    assert!(
        r.avisos.iter().any(|a| a.contains("PAPELERA")),
        "y tampoco debe desaparecer sin decirlo"
    );
}

#[test]
fn una_carpeta_que_falta_no_manda_la_entrada_a_la_raiz() {
    let roto = variante(r#"{ "id": "f-1", "name": "Bancos" }"#, r#"{ "id": "f-9", "name": "Otra" }"#);
    let r = bitwarden::importar(&roto).unwrap();
    let carpeta = r.entradas[0].carpeta.as_deref().unwrap();
    assert!(carpeta.contains("f-1"), "debe conservar el identificador crudo: {carpeta}");
    assert!(r.avisos.iter().any(|a| a.contains("carpeta")));
}

#[test]
fn los_items_de_organizacion_se_importan_avisando() {
    let roto = variante(r#""name": "Nota","#, r#""name": "Nota", "organizationId": "org-1","#);
    let r = bitwarden::importar(&roto).unwrap();
    assert_eq!(r.entradas.len(), 4);
    assert!(r.avisos.iter().any(|a| a.contains("organización")));
}
