// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Que una petición lenta no deje al resto esperando turno.
//!
//! Desde que una firma espera el visto bueno del usuario, esa petición se queda
//! **hasta noventa segundos** en el aire. Atendiendo las conexiones de una en
//! una, eso congelaba todo lo demás: el complemento decía «Consultando…» para
//! siempre mientras la aplicación respondía perfectamente si se le hablaba por
//! su socket. No estaba rota — estaba en cola.
//!
//! Es la clase de fallo que solo aparece con dos cosas a la vez, así que la
//! prueba habla por el socket **de verdad**, con dos clientes y un plazo: sin
//! plazo, una regresión aquí no se ve como un rojo sino como una prueba que no
//! termina, y eso se confunde con una compilación lenta.

use std::io::{Read, Write};
// El cliente del transporte, igual que el código de producción: socket `AF_UNIX`
// por `std::os::unix::net` en Linux y NAMED PIPE por `chuspa_ipc_win` en Windows.
// Así esta prueba de concurrencia mide el enlace en LAS DOS plataformas que se
// envían, no solo en Linux.
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use chuspa_ipc_win::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chuspa::boveda::{Campo, Clase, Entrada, Valor};
use chuspa::cifrado::{Acceso, Boveda};
use chuspa::gui::Aplicacion;
use chuspa::navegador::escuchar_en;

fn coste() -> quipu::kdf::KdfParams {
    quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
}

fn entrada_con_passkey(nombre: &str, rp_id: &str) -> Entrada {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;

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

    let der = SigningKey::random(&mut R).to_pkcs8_der().unwrap();
    Entrada {
        id_origen: None,
        nombre: nombre.into(),
        clase: Clase::Acceso,
        carpeta: None,
        favorita: false,
        archivada: None,
        repreguntar: false,
        notas: None,
        campos: vec![
            Campo::estandar("passkey.0.id", Valor::texto("Y3JlZC1kZS1wcnVlYmEx")),
            Campo::estandar("passkey.0.rp_id", Valor::texto(rp_id)),
            Campo::estandar("passkey.0.usuario", Valor::texto("juan@ejemplo.test")),
            Campo::estandar("passkey.0.contador", Valor::texto("1")),
            Campo::estandar(
                "passkey.0.clave",
                Valor::secreto(Base64UrlUnpadded::encode_string(der.as_bytes())),
            ),
        ],
        uris: Vec::new(),
        historial: Vec::new(),
        creada: None,
        revisada: None,
    }
}

/// Manda un mensaje por el socket y devuelve la respuesta, con plazo.
fn hablar(socket: &std::path::Path, mensaje: &serde_json::Value) -> serde_json::Value {
    let mut flujo = UnixStream::connect(socket).expect("no se pudo conectar al socket");
    flujo.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let cuerpo = serde_json::to_vec(mensaje).unwrap();
    flujo.write_all(&(cuerpo.len() as u32).to_le_bytes()).unwrap();
    flujo.write_all(&cuerpo).unwrap();
    flujo.flush().unwrap();

    let mut cabecera = [0u8; 4];
    flujo.read_exact(&mut cabecera).expect("el agente no contestó a tiempo");
    let n = u32::from_le_bytes(cabecera) as usize;
    let mut datos = vec![0u8; n];
    flujo.read_exact(&mut datos).unwrap();
    serde_json::from_slice(&datos).unwrap()
}

#[test]
fn el_popup_responde_mientras_una_firma_espera_permiso() {
    let dir = std::env::temp_dir().join(format!("chuspa-cola-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join("cola.chuspa");
    let _ = std::fs::remove_file(&ruta);

    let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase"), coste()).unwrap();
    b.anadir(entrada_con_passkey("Google", "google.com")).unwrap();

    let app = Arc::new(Aplicacion::nueva(ruta));
    *app.boveda.lock().unwrap() = Some(b);

    // Socket propio: usar el de siempre choca con la aplicación de verdad si
    // está abierta, y una prueba no puede depender de que no lo esté.
    let socket =
        escuchar_en(app.clone(), Duration::from_secs(300), dir.join("prueba.sock")).unwrap();

    // Un cliente pide una firma. Nadie va a autorizarla, así que se queda
    // esperando: es exactamente lo que pasa cuando la ventana está tapada.
    let socket_firma = socket.clone();
    std::thread::spawn(move || {
        let _ = hablar(
            &socket_firma,
            &serde_json::json!({
                "tipo": "autenticar",
                "rp_id": "google.com",
                "reto": "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw",
                "origen": "https://accounts.google.com",
                "permitidas": [],
            }),
        );
    });

    // Se espera a que la firma esté realmente esperando; si no, la prueba
    // pasaría por haber llegado antes, no por la concurrencia.
    let mut esperando = false;
    for _ in 0..300 {
        if app.firma.lock().unwrap().is_some() {
            esperando = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(esperando, "la firma nunca llegó a esperar permiso");

    // Y ahora lo que hace el complemento al abrirse. Antes se quedaba en cola
    // detrás de la firma hasta noventa segundos.
    let t0 = Instant::now();
    let estado = hablar(&socket, &serde_json::json!({ "tipo": "estado" }));
    let tardo = t0.elapsed();

    assert_eq!(estado["tipo"], "estado", "respuesta rara: {estado}");
    assert_eq!(estado["abierta"], true);
    assert!(
        tardo < Duration::from_secs(3),
        "el estado tardó {tardo:?}: quedó en cola detrás de la firma"
    );
}

#[test]
fn cien_peticiones_a_la_vez_mientras_una_firma_espera() {
    // La versión larga de lo anterior: no basta con que UNA petición pase por
    // delante, tienen que pasar todas y sin que ninguna se pierda. Con plazo,
    // porque una regresión aquí se manifiesta como algo que no termina.
    let dir = std::env::temp_dir().join(format!("chuspa-carga-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join("carga.chuspa");
    let _ = std::fs::remove_file(&ruta);

    let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase"), coste()).unwrap();
    b.anadir(entrada_con_passkey("Google", "google.com")).unwrap();
    let app = Arc::new(Aplicacion::nueva(ruta));
    *app.boveda.lock().unwrap() = Some(b);

    let socket =
        escuchar_en(app.clone(), Duration::from_secs(300), dir.join("carga.sock")).unwrap();

    let s2 = socket.clone();
    std::thread::spawn(move || {
        let _ = hablar(
            &s2,
            &serde_json::json!({
                "tipo": "autenticar", "rp_id": "google.com",
                "reto": "cmV0by1kZS1wcnVlYmEtZGUtdHJlaW50YS15LWRvcw",
                "origen": "https://accounts.google.com", "permitidas": [],
            }),
        );
    });
    for _ in 0..300 {
        if app.firma.lock().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(app.firma.lock().unwrap().is_some(), "la firma nunca llegó a esperar");

    // 120 peticiones desde 12 hilos, con la firma bloqueada todo el rato.
    let t0 = Instant::now();
    let fallos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut hilos = Vec::new();
    for _ in 0..12 {
        let socket = socket.clone();
        let fallos = fallos.clone();
        hilos.push(std::thread::spawn(move || {
            for _ in 0..10 {
                let r = hablar(&socket, &serde_json::json!({ "tipo": "estado" }));
                if r["tipo"] != "estado" || r["abierta"] != true {
                    fallos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }));
    }
    for h in hilos {
        h.join().expect("un hilo se cayó");
    }
    let tardo = t0.elapsed();

    assert_eq!(fallos.load(std::sync::atomic::Ordering::Relaxed), 0, "hubo respuestas malas");
    assert!(tardo < Duration::from_secs(20), "120 peticiones tardaron {tardo:?}");
    // Y la firma sigue esperando: ninguna de las 120 se la llevó por delante.
    assert!(app.firma.lock().unwrap().is_some(), "la firma pendiente se perdió");
}
