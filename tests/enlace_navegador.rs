// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Los tres procesos hablando de verdad: agente, puente y «Firefox».
//!
//! Las pruebas del módulo `navegador` llaman a `Agente::atender` directamente.
//! Eso mide la lógica y no mide el enlace: el formato de longitud de cuatro
//! bytes, los permisos del socket, que el agente levante, que el puente
//! encuentre el socket. Esta prueba arranca los binarios de verdad y les habla
//! como les habla Firefox — que es la única forma de saber que el conjunto
//! funciona.
//!
//! Es la lección del respaldo en papel aplicada aquí: 109 pruebas en verde y el
//! flujo real roto, porque ninguna cruzaba la frontera del programa.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

/// El arnés que levanta el socket sin abrir ventana.
///
/// `CARGO_BIN_EXE_` solo existe para binarios, y este es un ejemplo a propósito
/// —para que no se instale ni vaya al RPM—, así que la ruta se deriva del propio
/// ejecutable de prueba: `target/<perfil>/deps/…` → `target/<perfil>/examples/…`.
fn arnes() -> std::path::PathBuf {
    let yo = std::env::current_exe().expect("el ejecutable de prueba tiene ruta");
    let perfil = yo.parent().and_then(|p| p.parent()).expect("target/<perfil>");
    let ruta = perfil.join("examples").join("socket_de_prueba");
    assert!(
        ruta.exists(),
        "falta {}: compílalo con `cargo build --examples`",
        ruta.display()
    );
    ruta
}
const PUENTE: &str = env!("CARGO_BIN_EXE_chuspa-puente");
const FRASE: &str = "la frase del ensayo";

struct Entorno {
    dir: std::path::PathBuf,
    agente: Option<Child>,
}

impl Entorno {
    fn nuevo() -> Self {
        let dir = std::env::temp_dir().join(format!("chuspa-enlace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run")).unwrap();
        Self { dir, agente: None }
    }

    fn runtime(&self) -> std::path::PathBuf {
        self.dir.join("run")
    }

    fn boveda(&self) -> std::path::PathBuf {
        self.dir.join("v.chuspa")
    }

    /// Crea la bóveda con entradas conocidas usando la propia librería.
    fn crear_boveda(&self) {
        use chuspa::boveda::{Campo, Clase, Entrada, Uri, Valor};
        use chuspa::cifrado::{Acceso, Boveda};

        let entrada = |nombre: &str, uri: &str, usuario: &str, clave: &str| Entrada {
            id_origen: None,
            nombre: nombre.into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: vec![
                Campo::estandar("acceso.usuario", Valor::texto(usuario)),
                Campo::estandar("acceso.clave", Valor::secreto(clave)),
            ],
            uris: vec![Uri { uri: uri.into(), coincidencia: None }],
            historial: Vec::new(),
            creada: None,
            revisada: None,
        };

        let coste = quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 };
        let mut b = Boveda::crear(self.boveda(), &Acceso::frase(FRASE), coste).unwrap();
        b.anadir(entrada("Banco", "https://banco.example", "juan", "clave-del-banco")).unwrap();
        b.anadir(entrada("Correo", "https://correo.example", "j@x", "clave-del-correo")).unwrap();
        b.guardar().unwrap();
    }

    fn arrancar_agente(&mut self) {
        // Se arranca la APLICACIÓN, no un agente aparte: el enlace con Firefox
        // vive dentro de ella. Antes eran dos procesos y no podían coexistir
        // —el cerrojo del archivo lo impedía—, que es justo el fallo que esta
        // prueba tiene que impedir que vuelva.
        let hijo = Command::new(arnes())
            .arg(self.boveda())
            .env("XDG_RUNTIME_DIR", self.runtime())
            // Aísla el socket en TODAS las plataformas: en Windows `XDG_RUNTIME_DIR`
            // no lo mueve (el agente usaría el socket global de `%LOCALAPPDATA%` y
            // chocaría con la aplicación real), este override sí.
            .env("CHUSPA_RUNTIME_DIR", self.runtime())
            .env("CHUSPA_FRASE_DE_PRUEBA", FRASE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("el agente debe poder arrancar");
        self.agente = Some(hijo);

        // Se espera a que el agente esté LISTO para atender. En Unix el socket es
        // un archivo que aparece al ligar; en Windows es un named pipe (sin
        // archivo), así que se sondea intentando conectar: el connect falla rápido
        // mientras el pipe no exista y pasa en cuanto el agente lo publica.
        let socket = self.runtime().join("chuspa").join("agente.sock");
        for _ in 0..100 {
            #[cfg(unix)]
            let listo = socket.exists();
            #[cfg(windows)]
            let listo = chuspa_ipc_win::UnixStream::connect(&socket).is_ok();
            if listo {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("el agente no quedó listo en 5 s");
    }

    /// Lanza el puente y le habla como Firefox: cuatro bytes de longitud en
    /// orden nativo y detrás el JSON.
    fn hablar(&self, mensajes: &[&str]) -> Vec<serde_json::Value> {
        let mut puente = Command::new(PUENTE)
            .env("XDG_RUNTIME_DIR", self.runtime())
            .env("CHUSPA_RUNTIME_DIR", self.runtime())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("el puente debe poder arrancar");

        {
            // `take()` y no `as_mut()`: hay que SOLTAR el descriptor para que el
            // pipe se cierre al salir del bloque. El puente lee hasta el fin de
            // la entrada, así que con el descriptor todavía abierto se queda
            // esperando otro mensaje para siempre — y la prueba se cuelga sin
            // decir por qué. En Python `communicate()` lo cierra solo, y por eso
            // el mismo ensayo pasaba ahí y no aquí.
            let mut entrada = puente.stdin.take().unwrap();
            for m in mensajes {
                entrada.write_all(&(m.len() as u32).to_ne_bytes()).unwrap();
                entrada.write_all(m.as_bytes()).unwrap();
            }
        }
        let mut salida = Vec::new();
        puente.stdout.as_mut().unwrap().read_to_end(&mut salida).unwrap();
        let _ = puente.wait();

        let mut respuestas = Vec::new();
        let mut i = 0;
        while i + 4 <= salida.len() {
            let n = u32::from_ne_bytes(salida[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            respuestas.push(serde_json::from_slice(&salida[i..i + n]).unwrap());
            i += n;
        }
        respuestas
    }
}

impl Drop for Entorno {
    fn drop(&mut self) {
        if let Some(mut a) = self.agente.take() {
            let _ = a.kill();
            let _ = a.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn entorno() -> Entorno {
    let mut e = Entorno::nuevo();
    e.crear_boveda();
    e.arrancar_agente();
    e
}

#[test]
fn el_enlace_solo_hace_passkeys_y_no_entrega_contrasenas() {
    // Una sola prueba porque el agente escucha en una ruta fija por usuario: dos
    // en paralelo se pisarían el socket, y un socket por prueba ya no sería el
    // camino real.
    let e = entorno();

    // -- Estado: el enlace vive y dice lo justo ----------------------------
    let r = e.hablar(&[r#"{"tipo":"estado"}"#]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["abierta"], true);
    // El estado NO revela el conteo de entradas (retirado en 0.3.0).
    assert!(r[0].get("entradas").is_none(), "el estado no puede filtrar el conteo");

    // -- El agente YA NO sirve contraseñas ---------------------------------
    // Los mensajes del viejo autofill se retiraron del protocolo, así que el
    // agente los rechaza. Esto es lo que hace seguro alargar el plazo de
    // inactividad a 12 h (concilio 2026-09-15): una extensión comprometida ya no
    // tiene a quién pedirle contraseñas por el socket.
    for retirado in [
        r#"{"tipo":"buscar","url":"https://banco.example/"}"#,
        r#"{"tipo":"credencial","ficha":"00"}"#,
        r#"{"tipo":"generar","url":"https://tienda.example/alta"}"#,
        r#"{"tipo":"proponer","url":"https://otra.example/","clave":"x"}"#,
    ] {
        assert_eq!(
            e.hablar(&[retirado])[0]["tipo"], "error",
            "«{retirado}» ya no puede pedir ni guardar contraseñas"
        );
    }

    // -- Ni la frase ni un campo de más se cuelan --------------------------
    for hostil in [
        r#"{"tipo":"desbloquear","frase":"la frase del ensayo"}"#,
        r#"{"tipo":"estado","frase":"la frase del ensayo"}"#,
    ] {
        assert_eq!(
            e.hablar(&[hostil])[0]["tipo"], "error",
            "«{hostil}» tiene que rechazarse"
        );
    }

    // -- Autenticar SÍ se atiende ------------------------------------------
    // Es lo único que entrega un secreto, y con aprobación por uso en la ventana.
    // Sin passkey para el dominio el error es claro; lo que se prueba es que el
    // enlace ENTIENDE el mensaje y llega hasta buscar la llave.
    let r = e.hablar(&[
        r#"{"tipo":"autenticar","rp_id":"banco.example","reto":"AA","origen":"https://banco.example","permitidas":[]}"#,
    ]);
    assert_eq!(r[0]["tipo"], "error");
    assert!(
        r[0]["mensaje"].as_str().unwrap_or("").contains("passkey"),
        "el enlace llega hasta buscar la passkey: {:?}", r[0]
    );

    // -- Registrar: el enlace lo ENTIENDE, y los caminos que no piden permiso
    //    contestan al instante (no cuelgan el arnés) -----------------------
    // Un origen cruzado se rechaza antes de preguntar nada: un sitio de phishing
    // no registra «para el banco». No se prueba aquí el camino feliz porque
    // exigiría aprobar en la ventana, que en el arnés no existe.
    let r = e.hablar(&[
        r#"{"tipo":"registrar","rp_id":"banco.example","usuario_handle":"dQ","reto":"AA","origen":"https://banco.example.evil.test","algoritmos":[-7]}"#,
    ]);
    assert_eq!(r[0]["tipo"], "error", "un origen cruzado no puede registrar");
    // Y un algoritmo que no damos se devuelve al navegador, también sin preguntar.
    let r = e.hablar(&[
        r#"{"tipo":"registrar","rp_id":"banco.example","usuario_handle":"dQ","reto":"AA","origen":"https://banco.example","algoritmos":[-257]}"#,
    ]);
    assert_eq!(r[0]["tipo"], "error", "sin ES256 no se registra");

    // -- Permisos del socket -----------------------------------------------
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let socket = e.runtime().join("chuspa").join("agente.sock");
        let modo = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo(&socket), 0o600, "el socket da acceso a la bóveda");
        assert_eq!(modo(socket.parent().unwrap()), 0o700);
    }

    // -- Bloquear cierra ---------------------------------------------------
    assert_eq!(e.hablar(&[r#"{"tipo":"bloquear"}"#])[0]["tipo"], "hecho");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        e.hablar(&[r#"{"tipo":"estado"}"#])[0]["abierta"], false,
        "tras bloquear el enlace no atiende"
    );
}
