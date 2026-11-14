// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que nadie firme sin que el usuario lo autorice, y que pueda elegir la cuenta.
//!
//! Antes, la aplicación firmaba en cuanto se lo pedían: con la bóveda abierta,
//! **cualquier página que se visitara podía pedir una aserción y llevársela en
//! silencio**. Eso convierte la passkey en una cookie —basta entrar en un sitio
//! para quedar autenticado ante él— y es justo lo que el mecanismo existe para
//! impedir. Y con dos cuentas en el mismo sitio se firmaba con la primera que
//! apareciera, así que en Gmail se entraba siempre con la misma sin preguntar.
//!
//! La prueba cruza los dos lados de verdad: un hilo hace de navegador pidiendo
//! la firma, y el principal hace de ventana leyendo la petición y decidiendo.
//! Medir solo uno de los dos no diría nada del conjunto.

use std::sync::Arc;
use std::time::Duration;

use chuspa::boveda::{Campo, Clase, ClaveAnterior, Entrada, Uri, Valor};
use chuspa::cifrado::{Acceso, Boveda};
use chuspa::gui::{decidir_firma, Aplicacion};
use chuspa::navegador::Agente;
use chuspa::navegador::protocolo::{Peticion as Pet, Respuesta};

fn coste() -> quipu::kdf::KdfParams {
    quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
}

/// Una passkey P-256 de mentira, en el mismo formato que deja el importador.
fn entrada_con_passkey(nombre: &str, rp_id: &str, usuario: &str) -> Entrada {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use base64ct::{Base64UrlUnpadded, Encoding};

    let secreta = SigningKey::random(&mut rand_core_compat());
    let der = secreta.to_pkcs8_der().unwrap();

    // EL FIXTURE NO PUEDE ESTAR VACÍO EN LOS CAMPOS QUE EL CASO ROJO TIENE QUE
    // MOVER, y lo estaba: `carpeta`, `uris`, `historial`, `notas` y las fechas
    // venían todos a `None`/vacío. La prueba de abajo existe, según su propio
    // comentario, porque reescribir entradas ya se llevó por delante el segundo
    // factor, la carpeta y la regla de cada URI — y con el fixture vacío, si
    // `anotar_el_contador` volviera a perderlos, seguiría VERDE. Es la
    // directiva 33 por el lado que no se mira: el instrumento estaba ciego
    // justo en lo que dice vigilar. Lo destapó la revisión del 2026-08-13.
    Entrada {
        id_origen: Some("bw-0f3a".into()),
        nombre: nombre.into(),
        clase: Clase::Acceso,
        carpeta: Some("Trabajo/Cuentas".into()),
        favorita: true,
        archivada: None,
        repreguntar: true,
        notas: Some(zeroize::Zeroizing::new(
            "nota que no se puede perder al anotar un contador".to_string(),
        )),
        campos: vec![
            Campo::estandar("passkey.0.id", Valor::texto("Y3JlZC1kZS1wcnVlYmEx")),
            Campo::estandar("passkey.0.rp_id", Valor::texto(rp_id)),
            Campo::estandar("passkey.0.usuario", Valor::texto(usuario)),
            Campo::estandar("passkey.0.contador", Valor::texto("1")),
            Campo::estandar(
                "passkey.0.clave",
                Valor::secreto(Base64UrlUnpadded::encode_string(der.as_bytes())),
            ),
        ],
        uris: vec![Uri { uri: format!("https://{rp_id}/entrar"), coincidencia: Some(1) }],
        historial: vec![ClaveAnterior {
            clave: zeroize::Zeroizing::new("la-de-antes".to_string()),
            usada_hasta: Some("2026-01-02T03:04:05Z".into()),
        }],
        creada: Some("2026-01-01T00:00:00Z".into()),
        revisada: Some("2026-02-02T00:00:00Z".into()),
    }
}

fn rand_core_compat() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    struct R;
    impl p256::elliptic_curve::rand_core::RngCore for R {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            quipu::aleatorio::llenar(&mut b).unwrap();
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            quipu::aleatorio::llenar(&mut b).unwrap();
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            quipu::aleatorio::llenar(d).unwrap();
        }
        fn try_fill_bytes(
            &mut self,
            d: &mut [u8],
        ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
            quipu::aleatorio::llenar(d).unwrap();
            Ok(())
        }
    }
    impl p256::elliptic_curve::rand_core::CryptoRng for R {}
    R
}

/// Una aplicación con dos cuentas del MISMO sitio, que es el caso de Gmail.
fn app_con_dos_cuentas(etiqueta: &str) -> Arc<Aplicacion> {
    let dir = std::env::temp_dir().join(format!("chuspa-firma-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join(format!("{etiqueta}.chuspa"));
    let _ = std::fs::remove_file(&ruta);

    let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase"), coste()).unwrap();
    b.anadir(entrada_con_passkey("Google personal", "google.com", "juan@gmail.com")).unwrap();
    b.anadir(entrada_con_passkey("Google trabajo", "google.com", "juan@empresa.com")).unwrap();
    b.anadir(entrada_con_passkey("GitHub", "github.com", "isazajuancarlos")).unwrap();

    let app = Arc::new(Aplicacion::nueva(ruta));
    *app.boveda.lock().unwrap() = Some(b);
    app
}

/// La firma pendiente, leída directo de la aplicación —lo mismo que hace el
/// diálogo GTK— (antes se pedía por la ventana web, retirada). Solo se usa para
/// «/api/firma».
fn get(app: &Aplicacion, _ruta: &str) -> serde_json::Value {
    let g = app.firma.lock().unwrap();
    match g.as_ref().filter(|f| f.elegida.is_none()) {
        None => serde_json::json!({ "hay": false }),
        Some(f) => serde_json::json!({
            "hay": true,
            "id": f.id,
            "rp_id": f.rp_id,
            "origen": f.origen,
            "candidatas": f.candidatas,
        }),
    }
}

/// Aplica la decisión de firma por el MISMO camino que el diálogo GTK
/// (`decidir_firma`); devuelve el código como hacía la ventana web.
fn post(app: &Aplicacion, _ruta: &str, cuerpo: &str) -> u16 {
    decidir_firma(app, cuerpo.as_bytes()).estado
}

/// Lanza la petición de firma en otro hilo y espera a que la ventana la vea.
fn pedir_firma_en_otro_hilo(
    app: &Arc<Aplicacion>,
    rp_id: &str,
) -> (std::sync::mpsc::Receiver<Respuesta>, serde_json::Value) {
    let agente = Agente::nuevo(app.clone(), Duration::from_secs(300));
    let (tx, rx) = std::sync::mpsc::channel();
    let rp = rp_id.to_string();
    std::thread::spawn(move || {
        let r = agente.atender(Pet::Autenticar {
            rp_id: rp,
            reto: "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw".into(),
            origen: "https://accounts.google.com".into(),
            permitidas: Vec::new(),
        });
        let _ = tx.send(r);
    });

    // Se espera a que la petición aparezca, sin dormir un plazo fijo: en una
    // máquina cargada un `sleep` corto da un rojo que no tiene nada que ver con
    // el código.
    for _ in 0..300 {
        let f = get(app, "/api/firma");
        if f["hay"] == true {
            return (rx, f);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("la aplicación nunca pidió permiso: firmó sola o se quedó colgada");
}

#[test]
fn se_ofrecen_todas_las_cuentas_del_sitio_no_la_primera() {
    let app = app_con_dos_cuentas("varias");
    let (_rx, f) = pedir_firma_en_otro_hilo(&app, "google.com");

    let candidatas = f["candidatas"].as_array().unwrap();
    assert_eq!(candidatas.len(), 2, "se ofrecieron {} cuentas: {f}", candidatas.len());

    let usuarios: Vec<&str> =
        candidatas.iter().map(|c| c["usuario"].as_str().unwrap()).collect();
    assert!(usuarios.contains(&"juan@gmail.com"), "falta la personal: {usuarios:?}");
    assert!(usuarios.contains(&"juan@empresa.com"), "falta la de trabajo: {usuarios:?}");

    // El origen que se enseña es el que puso el navegador, no el rp_id: es el
    // dato con el que una persona decide si la está engañando.
    assert_eq!(f["origen"], "https://accounts.google.com");
}

#[test]
fn sin_autorizacion_no_se_firma() {
    let app = app_con_dos_cuentas("rechazo");
    let (rx, f) = pedir_firma_en_otro_hilo(&app, "google.com");

    let id = f["id"].as_u64().unwrap();
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":null}})")), 400);
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":null}}")), 200);

    let r = rx.recv_timeout(Duration::from_secs(10)).expect("el hilo no contestó");
    match r {
        Respuesta::Error { mensaje } => {
            assert!(mensaje.contains("no se autorizó"), "otro error: {mensaje}")
        }
        otra => panic!("firmó sin autorización: {otra:?}"),
    }
}

#[test]
fn se_firma_con_la_cuenta_elegida() {
    let app = app_con_dos_cuentas("elegida");
    let (rx, f) = pedir_firma_en_otro_hilo(&app, "google.com");

    let id = f["id"].as_u64().unwrap();
    // La segunda de la lista, para que elegir la 0 por descuido no pase la
    // prueba: es justo el fallo que se está arreglando.
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":1}}")), 200);

    let r = rx.recv_timeout(Duration::from_secs(10)).expect("el hilo no contestó");
    assert!(matches!(r, Respuesta::Asercion { .. }), "no firmó: {r:?}");
}

#[test]
fn una_decision_de_otra_peticion_no_vale() {
    let app = app_con_dos_cuentas("id-viejo");
    let (rx, f) = pedir_firma_en_otro_hilo(&app, "google.com");
    let id = f["id"].as_u64().unwrap();

    // Sin comprobar el id, una decisión que llega tarde autorizaría la petición
    // SIGUIENTE — una firma que nadie llegó a mirar.
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{},\"elegida\":0}}", id + 7)), 409);
    // Y una cuenta fuera de la lista firmaría con otra distinta de la ofrecida.
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":99}}")), 400);

    // La petición sigue esperando: ninguna de las dos la resolvió.
    assert_eq!(get(&app, "/api/firma")["hay"], true);
    assert_eq!(post(&app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":null}}")), 200);
    let _ = rx.recv_timeout(Duration::from_secs(10));
}

#[test]
fn el_aviso_sale_cuando_una_firma_espera() {
    // La ventana puede estar detrás del navegador —es lo normal: el usuario
    // está mirando el sitio donde quiere entrar—, y entonces la espera se ve
    // igual que un fallo. Lo que se comprueba aquí es que el aviso SALE. Que el
    // gestor de ventanas obedezca no depende de nosotros y no se finge medirlo.
    let app = app_con_dos_cuentas("aviso");
    let veces = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let contador = Arc::clone(&veces);
    app.cuando_haya_que_preguntar(move || {
        contador.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });

    // Un sitio SIN llave no puede molestar a nadie: si avisara aquí, el aviso
    // se volvería ruido y a la tercera vez nadie miraría la ventana.
    let agente = Agente::nuevo(app.clone(), Duration::from_secs(300));
    let _ = agente.atender(Pet::Autenticar {
        rp_id: "sitio-que-no-tengo.example".into(),
        reto: "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw".into(),
        origen: "https://sitio-que-no-tengo.example".into(),
        permitidas: Vec::new(),
    });
    assert_eq!(
        veces.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "avisó por un sitio del que no hay ninguna llave que ofrecer"
    );

    // Y con llave, exactamente uno.
    let (rx, _) = pedir_firma_en_otro_hilo(&app, "google.com");
    assert_eq!(
        veces.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "una firma se quedó esperando sin que la ventana se enterara"
    );

    post(&app, "/api/firma", &format!("{{\"id\":{},\"elegida\":null}}", get(&app, "/api/firma")["id"]));
    let _ = rx.recv_timeout(Duration::from_secs(5));
}

#[test]
fn un_sitio_sin_passkey_no_llega_a_molestar_al_usuario() {
    // Preguntar por algo que no se puede conceder entrena a decir que sí.
    let app = app_con_dos_cuentas("sin-passkey");
    let agente = Agente::nuevo(app.clone(), Duration::from_secs(300));
    let r = agente.atender(Pet::Autenticar {
        rp_id: "sitio-que-no-tengo.example".into(),
        reto: "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw".into(),
        origen: "https://sitio-que-no-tengo.example".into(),
        permitidas: Vec::new(),
    });
    assert!(matches!(r, Respuesta::Error { .. }), "{r:?}");
    assert_eq!(get(&app, "/api/firma")["hay"], false, "pidió permiso sin tener nada que ofrecer");
}

// ---------------------------------------------------------------------------
// EL CONTADOR DE FIRMAS
//
// Es el detector de autenticadores clonados de WebAuthn (§7.2): el sitio guarda
// el último número que recibió y rechaza toda aserción que no lo supere. Si el
// contador no SUBE Y SE GUARDA, la passkey sirve exactamente una vez y a partir
// de ahí el servidor la ve como la copia de una llave robada.
//
// Es un fallo que no da error en ningún sitio: la firma es criptográficamente
// impecable, la bitácora dice «firma autorizada», y el rechazo llega del otro
// lado del mundo con un mensaje genérico («Something went wrong»). Estuvo vivo
// hasta el 2026-08-10 y solo se veía en los sitios que de verdad comprueban el
// contador —npm es uno—, lo que lo disfrazaba de problema de ESE sitio.
// ---------------------------------------------------------------------------

/// Firma de verdad y devuelve el contador que viajó hacia el navegador.
///
/// Se lee del ARTEFACTO —los bytes 33..37 de `authenticatorData`, que es lo que
/// el sitio va a comparar— y no del campo de la bóveda: mirar el campo mediría
/// que lo guardamos, no que lo mandamos.
fn firmar_y_leer_el_contador(app: &Arc<Aplicacion>, rp_id: &str, cual: usize) -> u32 {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let (rx, f) = pedir_firma_en_otro_hilo(app, rp_id);
    let id = f["id"].as_u64().unwrap();
    assert_eq!(post(app, "/api/firma", &format!("{{\"id\":{id},\"elegida\":{cual}}}")), 200);
    match rx.recv_timeout(Duration::from_secs(10)).expect("el hilo no contestó") {
        Respuesta::Asercion { authenticator_data, .. } => {
            let datos = Base64UrlUnpadded::decode_vec(&authenticator_data).unwrap();
            assert_eq!(datos.len(), 37, "authenticatorData mal formado: {} bytes", datos.len());
            u32::from_be_bytes(datos[33..37].try_into().unwrap())
        }
        otra => panic!("no firmó: {otra:?}"),
    }
}

/// Cierra la bóveda de la aplicación y la vuelve a abrir DESDE EL DISCO.
///
/// Sin esto, una versión que subiera el contador solo en memoria pasaría la
/// prueba y volvería a fallar en cuanto se cerrara la aplicación.
fn releer_del_disco(app: &Arc<Aplicacion>) -> Boveda {
    let ruta = app.ruta.clone();
    *app.boveda.lock().unwrap() = None;
    Boveda::abrir(&ruta, &Acceso::frase("la frase")).expect("la bóveda no se pudo releer")
}

fn contador_de(b: &Boveda, entrada: usize) -> String {
    let e = b.abrir_entrada(entrada).unwrap();
    match &e.campo("passkey.0.contador").expect("la entrada perdió el contador").valor {
        Valor::Texto(t) => t.clone(),
        otro => panic!("el contador dejó de ser texto: {otro:?}"),
    }
}

#[test]
fn dos_firmas_seguidas_no_llevan_el_mismo_contador() {
    let app = app_con_dos_cuentas("contador-sube");

    let primera = firmar_y_leer_el_contador(&app, "google.com", 1);
    let segunda = firmar_y_leer_el_contador(&app, "google.com", 1);

    assert!(
        segunda > primera,
        "las dos firmas llevaron el contador {primera} y {segunda}: para el sitio, la segunda \
         es una llave clonada y la rechaza"
    );

    // Y guardado en el ARCHIVO, no solo en memoria.
    let b = releer_del_disco(&app);
    assert_eq!(
        contador_de(&b, 1),
        segunda.to_string(),
        "el contador subió en memoria y el disco se quedó atrás: al reabrir la aplicación \
         se repetiría el número igual que antes"
    );
}

#[test]
fn firmar_no_toca_las_otras_passkeys_ni_el_resto_de_la_entrada() {
    // La pareja del anterior. Guardar la entrada para anotar un número es
    // reescribirla entera, y en este repositorio eso ya se llevó por delante el
    // segundo factor, la carpeta y la regla de cada URI: tres veces el mismo
    // fallo, y ninguna dio error.
    let app = app_con_dos_cuentas("contador-no-arrasa");

    let antes = {
        let g = app.boveda.lock().unwrap();
        let b = g.as_ref().unwrap();
        (b.abrir_entrada(0).unwrap(), b.abrir_entrada(1).unwrap(), b.abrir_entrada(2).unwrap())
    };

    let usado = firmar_y_leer_el_contador(&app, "google.com", 1);
    let b = releer_del_disco(&app);

    // La que NO se usó conserva su contador: si subieran todas, el número que
    // el sitio espera de cada una se despistaría sin que nadie lo viera.
    assert_eq!(contador_de(&b, 0), "1", "subió el contador de una passkey que no se usó");
    assert_eq!(contador_de(&b, 2), "1", "subió el contador de una passkey de otro sitio");
    assert_eq!(contador_de(&b, 1), usado.to_string());

    // Y LA ENTRADA FIRMADA, ENTERA. Antes esto comparaba seis campos elegidos a
    // mano, así que solo veía perderse lo que a alguien se le había ocurrido
    // nombrar. Ahora se construye la entrada que DEBERÍA haber quedado —la de
    // antes con el contador al día y nada más— y se comparan las dos completas:
    // cualquier campo que `anotar_el_contador` pierda o invente sale rojo, se
    // llame como se llame y lo haya previsto alguien o no.
    let ahora = b.abrir_entrada(1).unwrap();
    let mut esperada = antes.1.clone();
    esperada
        .campos
        .iter_mut()
        .find(|c| c.etiqueta == "passkey.0.contador")
        .expect("el fixture trae el contador")
        .valor = Valor::texto(usado.to_string());
    assert_eq!(
        ahora, esperada,
        "firmar cambió algo más que el contador de la passkey usada"
    );

    // Las entradas de al lado, intactas byte a byte.
    assert_eq!(b.abrir_entrada(0).unwrap(), antes.0);
    assert_eq!(b.abrir_entrada(2).unwrap(), antes.2);
}

/// Control POSITIVO del cierre del oráculo de origen (D33, la pareja del test
/// negativo `un_origen_que_no_corresponde…` de `navegador::mod`).
///
/// La bóveda TIENE passkeys para `google.com`, pero la petición viene de
/// `evil.example`. Tiene que rechazarse por ORIGEN con el mismo error genérico y
/// SIN dejar una firma esperando —exactamente igual que cuando no hay passkey—,
/// para que no quede ninguna diferencia observable (mensaje, diálogo) entre «hay
/// passkey» y «no hay». Si `comprobar_origen` dejara de ir al INICIO de
/// `autenticar`, aquí se encontraría la passkey y se abriría el diálogo.
#[test]
fn un_origen_cruzado_no_dispara_dialogo_aunque_exista_la_passkey() {
    let app = app_con_dos_cuentas("origen-cruzado-con-passkey");
    let agente = Agente::nuevo(app.clone(), Duration::from_secs(300));
    let r = agente.atender(Pet::Autenticar {
        rp_id: "google.com".into(),
        reto: "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw".into(),
        origen: "https://evil.example".into(),
        permitidas: Vec::new(),
    });
    match r {
        Respuesta::Error { mensaje } => {
            assert!(mensaje.contains("origen"), "debe rechazar por el origen: «{mensaje}»");
            assert!(
                !mensaje.contains("passkey"),
                "el error no puede revelar que la passkey existe: «{mensaje}»"
            );
        }
        otro => panic!("un origen cruzado no puede firmar ni con passkey guardada: {otro:?}"),
    }
    assert_eq!(
        get(&app, "/api/firma")["hay"], false,
        "un origen cruzado no puede dejar un diálogo de firma esperando"
    );
}
