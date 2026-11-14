// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que la extensión de Firefox y la de Chrome/Brave sigan siendo la misma.
//!
//! Los dos manifiestos NO se pueden fundir en uno: Chrome exige
//! `background.service_worker` y Firefox exige `background.scripts`. Todo lo
//! demás sí es común, y ahí está el peligro — es exactamente la forma del fallo
//! que ya mató las llaves de acceso una vez: una lista escrita a mano de algo
//! que crece se queda vieja, y el síntoma es «en Brave no funciona», sin un solo
//! error por ninguna parte.
//!
//! Aquí se comprueba que lo común coincide, y se comprueba **campo a campo
//! sobre lo que hay**, no contra una lista de campos esperados: un campo nuevo
//! que se añada solo a uno de los dos también tiene que ponerlo rojo.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn raiz() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn leer(nombre: &str) -> serde_json::Value {
    let ruta = raiz().join("extension").join(nombre);
    let crudo = std::fs::read_to_string(&ruta)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", ruta.display()));
    serde_json::from_str(&crudo).unwrap_or_else(|e| panic!("{nombre} no es JSON válido: {e}"))
}

/// Lo que cada navegador entiende a su manera y por eso no puede coincidir.
const PROPIOS: [&str; 4] = [
    // Firefox: el identificador, la versión mínima y los permisos de datos.
    "browser_specific_settings",
    // Chrome: la clave que fija el identificador y la versión mínima.
    "key",
    "minimum_chrome_version",
    // Distinto en cada uno: `scripts` contra `service_worker`.
    "background",
];

#[test]
fn todo_lo_que_no_es_propio_de_un_navegador_coincide() {
    let ff = leer("manifest.json");
    let cr = leer("manifest.chrome.json");
    let (ff, cr) = (ff.as_object().unwrap(), cr.as_object().unwrap());

    // La unión de las claves de los dos: así, un campo presente solo en uno
    // aparece igual y no se escapa por no estar en la lista de la que se parte.
    let claves: BTreeSet<&String> = ff.keys().chain(cr.keys()).collect();
    for clave in claves {
        if PROPIOS.contains(&clave.as_str()) {
            continue;
        }
        assert_eq!(
            ff.get(clave),
            cr.get(clave),
            "«{clave}» no dice lo mismo en los dos manifiestos.\n  \
             firefox: {:?}\n  chrome : {:?}",
            ff.get(clave),
            cr.get(clave),
        );
    }
}

#[test]
fn los_dos_cargan_los_mismos_archivos() {
    // Lo que de verdad rompió las passkeys: un archivo que llega a un empaquetado
    // y no al otro. Se compara el CONJUNTO de archivos que cada manifiesto
    // menciona, venga del campo que venga.
    fn archivos(v: &serde_json::Value, salida: &mut BTreeSet<String>) {
        match v {
            serde_json::Value::String(s) => {
                if s.ends_with(".js") || s.ends_with(".html") || s.ends_with(".css") {
                    salida.insert(s.clone());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| archivos(x, salida)),
            serde_json::Value::Object(o) => o.values().for_each(|x| archivos(x, salida)),
            _ => {}
        }
    }
    let (mut a, mut b) = (BTreeSet::new(), BTreeSet::new());
    archivos(&leer("manifest.json"), &mut a);
    archivos(&leer("manifest.chrome.json"), &mut b);

    assert_eq!(a, b, "los dos manifiestos no cargan los mismos archivos");
    assert!(a.len() >= 4, "solo se hallaron {} archivos: ¿se buscó bien?", a.len());
    for f in &a {
        assert!(
            raiz().join("extension").join(f).exists(),
            "el manifiesto menciona «{f}» y ese archivo no existe",
        );
    }
}

#[test]
fn cada_uno_arranca_su_fondo_como_lo_entiende_su_navegador() {
    let ff = leer("manifest.json");
    let cr = leer("manifest.chrome.json");

    // Firefox no admite `service_worker`; Chrome no admite `scripts`. Poner el
    // del otro no da error de carga: el script de fondo simplemente no corre, y
    // con él se cae el ORIGEN — que es la pieza contra el phishing.
    assert_eq!(ff["background"]["scripts"], serde_json::json!(["fondo.js"]));
    assert!(ff["background"].get("service_worker").is_none());
    assert_eq!(cr["background"]["service_worker"], "fondo.js");
    assert!(cr["background"].get("scripts").is_none());
}

#[test]
fn el_fondo_contesta_de_la_forma_que_entienden_los_dos() {
    // Un escuchador `async` que DEVUELVE la promesa funciona en Firefox y Chrome
    // lo ignora: la página recibe `undefined`, la firma no llega nunca y el
    // sitio acaba pidiendo una llave física. Es el mismo síntoma que dio el
    // fallo de los dos mundos, y otra vez sin un solo error.
    let fuente = std::fs::read_to_string(raiz().join("extension/fondo.js")).unwrap();
    // Los comentarios FUERA antes de mirar nada. La primera versión de esta
    // prueba buscaba «return true» en el archivo entero y el comentario que
    // explica por qué hace falta la satisfacía sola: se podía quitar del código
    // y seguía verde. Una prueba que mide la prosa mide la prosa.
    let codigo: String = fuente
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//") && !l.starts_with('*'))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        codigo.contains("return true"),
        "el escuchador no deja el canal abierto: sin `return true`, en Chrome la \
         respuesta se pierde",
    );
    assert!(
        codigo.contains("responder("),
        "no se contesta por `sendResponse`: devolver la promesa solo funciona en \
         Firefox",
    );
    assert!(
        !codigo.contains("onMessage.addListener(async"),
        "el escuchador es `async` y devuelve una promesa: eso solo lo entiende \
         Firefox. Hay que usar `sendResponse` y `return true`",
    );
}

#[test]
fn ningun_archivo_llama_a_browser_a_secas() {
    // `browser` no existe en Chrome ni en Brave. Cada archivo que use la API de
    // la extensión tiene que pasar por el mismo apaño, y hacerlo en uno y
    // olvidarlo en otro deja media extensión muerta en un navegador.
    // Lo que cuenta como «usar la API» son sus puntos de entrada, no la palabra
    // «navegador»: `passkeys.js` corre en el mundo de la página, no toca la API
    // y la menciona en su prosa. Buscar la palabra suelta acusaba a un archivo
    // inocente, y una alarma que resulta falsa dos veces es una que nadie mira.
    const ENTRADAS: [&str; 4] = ["runtime.", "tabs.", "scripting.", "permissions."];

    for nombre in ["fondo.js", "popup.js", "puente-passkeys.js", "passkeys.js"] {
        let fuente = std::fs::read_to_string(raiz().join("extension").join(nombre)).unwrap();
        let mut usa_api = false;
        for (n, linea) in fuente.lines().enumerate() {
            let l = linea.trim();
            if l.starts_with("//") || l.starts_with('*') {
                continue;
            }
            assert!(
                !l.contains("browser."),
                "{nombre}:{}: usa «browser.», que en Chrome no existe:\n  {l}",
                n + 1,
            );
            usa_api |= ENTRADAS.iter().any(|e| l.contains(&format!("navegador.{e}")));
        }
        if usa_api {
            assert!(
                fuente.contains("globalThis.browser ?? globalThis.chrome"),
                "{nombre} usa la API de la extensión sin el apaño de nombre",
            );
        }
    }
}

#[test]
fn el_paquete_de_mozilla_no_se_lleva_lo_que_no_es_suyo() {
    // El `.xpi` es lo que ve un revisor de Mozilla. Dentro no pintan nada ni el
    // banco de pruebas —servidores de mentira— ni el manifiesto de Chrome, que
    // es literalmente el de otro navegador. Colarse no rompe nada, y por eso
    // nadie se daría cuenta: el paquete se firma igual.
    let salida = std::process::Command::new("python3")
        .arg(raiz().join("empaque/empaquetar-extension.py"))
        .output()
        .expect("hace falta python3 para empaquetar la extensión");
    assert!(salida.status.success(), "el empaquetado falló: {:?}", salida);

    // Se listan los archivos del zip leyendo su directorio central: basta con
    // buscar los nombres, y así la prueba no necesita una librería de zip.
    let version = env!("CARGO_PKG_VERSION");
    let xpi = std::fs::read(raiz().join(format!("target/chuspa-{version}.xpi")))
        .expect("el paquete tiene que quedar en target/");
    let texto = String::from_utf8_lossy(&xpi);

    for prohibido in ["manifest.chrome.json", "banco/", "banco.py"] {
        assert!(
            !texto.contains(prohibido),
            "el paquete para Mozilla lleva «{prohibido}» dentro",
        );
    }
    // Y que sí lleve lo que la extensión necesita: comprobar solo lo que falta
    // pasaría igual con un paquete vacío.
    for hace_falta in ["manifest.json", "fondo.js", "popup.js", "puente-passkeys.js"] {
        assert!(texto.contains(hace_falta), "al paquete le falta «{hace_falta}»");
    }
}

#[test]
fn el_manifiesto_del_sistema_apunta_a_la_extension_de_verdad() {
    // El identificador de `allowed_origins` está escrito a mano en un archivo, y
    // se deriva de la clave pública que está en OTRO. Si se cambia la clave y no
    // el manifiesto, el puente deja de autorizar a la extensión: el navegador
    // dice «Access to the specified native messaging host is forbidden» y no hay
    // nada en el código que lo explique. Se recalcula aquí y se compara.
    let crudo = std::fs::read_to_string(raiz().join("empaque/com.xiliux.chuspa.chrome.json"))
        .expect("el manifiesto del puente para Chrome tiene que existir");
    let manifiesto: serde_json::Value = serde_json::from_str(&crudo).unwrap();

    let clave = leer("manifest.chrome.json")["key"].as_str().unwrap().to_string();
    let der = base64_decode(&clave);
    let esperado = identificador_chrome(&der);

    assert_eq!(
        manifiesto["allowed_origins"],
        serde_json::json!([format!("chrome-extension://{esperado}/")]),
        "el manifiesto del puente no autoriza a la extensión que produce esa clave",
    );
    // Y que no autorice a NADIE más: una entrada de más ahí es cualquier
    // complemento instalado pidiendo credenciales.
    assert_eq!(manifiesto["allowed_origins"].as_array().unwrap().len(), 1);
}

/// Base64 estándar, lo justo para leer la clave del manifiesto.
fn base64_decode(s: &str) -> Vec<u8> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).expect("la clave del manifiesto tiene que ser base64")
}

/// El identificador que Chrome deriva de una clave pública: los 128 primeros
/// bits de su SHA-256, con cada dígito hexadecimal traducido de `0-f` a `a-p`.
fn identificador_chrome(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(der);
    h.iter()
        .take(16)
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| (b'a' + n) as char)
        .collect()
}

#[test]
fn la_extension_lleva_la_version_del_programa() {
    // Estuvo cuatro versiones por detrás sin que nada lo dijera. La versión que
    // se ve en `about:addons` es la única pista que tiene quien informa de un
    // fallo, y una que miente manda a mirar el código equivocado.
    let esperada = env!("CARGO_PKG_VERSION");
    for nombre in ["manifest.json", "manifest.chrome.json"] {
        assert_eq!(
            leer(nombre)["version"].as_str().unwrap(),
            esperada,
            "{nombre} va por otra versión que el programa",
        );
    }
}
