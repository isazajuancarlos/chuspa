// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Banco de extremo a extremo del perfil de navegador cifrado (`src/perfil.rs`).
//!
//! Usa gocryptfs **de verdad** (directiva 28: se cruza la frontera del
//! programa). Si gocryptfs no está instalado, cada prueba se OMITE con aviso en
//! vez de fallar —es una dependencia de ejecución de esta función, no de todo
//! chuspa—.
//!
//! El control que discrimina (directiva 33): el mismo secreto se ve LEGIBLE
//! montado y AUSENTE del texto cifrado en reposo; y una frase equivocada NO
//! monta. La prueba guardián lee `/proc` del daemon de gocryptfs y exige que la
//! passphrase no aparezca en su `argv` ni en su entorno —si alguien la pasara
//! por `-extpass` en vez de por `stdin`, esta prueba se pondría roja—.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chuspa::cifrado::{self, Acceso, Boveda};
use chuspa::perfil::{self, Rutas};

const FRASE: &str = "frase-secreta-del-banco-que-no-debe-filtrarse-9x7q";
const SECRETO: &str = "SESION-SECRETA-DEL-BANCO-abc123";

/// `true` si gocryptfs está instalado; si no, la prueba se omite.
fn hay_gocryptfs() -> bool {
    match Command::new("gocryptfs").arg("--version").output() {
        Ok(_) => true,
        Err(_) => {
            eprintln!("OMITIDA: gocryptfs no está instalado (dnf install gocryptfs)");
            false
        }
    }
}

/// Directorio temporal único para una corrida, con desmontaje y borrado al
/// soltarlo (aunque la prueba entre en pánico, no queda un montaje colgado).
struct Banco {
    raiz: PathBuf,
    rutas: Rutas,
}

impl Banco {
    fn nuevo(etiqueta: &str) -> Self {
        let raiz = std::env::temp_dir().join(format!(
            "chuspa-perfil-{etiqueta}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rutas = Rutas { cipher: raiz.join("cipher"), clear: raiz.join("clear") };
        std::fs::create_dir_all(&rutas.cipher).unwrap();
        std::fs::create_dir_all(&rutas.clear).unwrap();
        Self { raiz, rutas }
    }
}

impl Drop for Banco {
    fn drop(&mut self) {
        let _ = perfil::desmontar(&self.rutas.clear);
        let _ = std::fs::remove_dir_all(&self.raiz);
    }
}

#[test]
fn el_ciclo_cifra_en_reposo_y_restaura_al_remontar() {
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("ciclo");
    let frase = FRASE;

    perfil::iniciar(&banco.rutas, frase).expect("iniciar el volumen");
    assert!(perfil::volumen_iniciado(&banco.rutas.cipher), "debe quedar iniciado");
    let modo = std::fs::metadata(&banco.rutas.cipher).unwrap().permissions().mode() & 0o777;
    assert_eq!(modo, 0o700, "el volumen cifrado debe ser accesible solo por el dueño (0700)");

    // Montado: el secreto se escribe y se lee en claro.
    perfil::montar(&banco.rutas, frase).expect("montar");
    assert!(perfil::esta_montado(&banco.rutas.clear), "debe estar montado");
    let archivo = banco.rutas.perfil().join("sesion.txt");
    std::fs::write(&archivo, SECRETO).unwrap();
    assert_eq!(std::fs::read_to_string(&archivo).unwrap(), SECRETO);

    // En reposo: el secreto NO aparece en ningún byte del texto cifrado.
    perfil::desmontar(&banco.rutas.clear).expect("desmontar");
    assert!(!perfil::esta_montado(&banco.rutas.clear), "debe quedar desmontado");
    assert!(
        !algun_archivo_contiene(&banco.rutas.cipher, SECRETO.as_bytes()),
        "el secreto NO puede aparecer en claro en el volumen cifrado"
    );

    // Remontado: el secreto vuelve intacto.
    perfil::montar(&banco.rutas, frase).expect("remontar");
    assert_eq!(
        std::fs::read_to_string(&archivo).unwrap(),
        SECRETO,
        "al remontar, el secreto debe volver legible"
    );
}

#[test]
fn al_soltar_la_sesion_el_volumen_queda_desmontado() {
    // La RED DE SEGURIDAD: si la sesión se suelta sin un `cerrar` explícito (un
    // panic, un SIGTERM, una salida que no pase por la X de la ventana), el `Drop`
    // DEBE desmontar el volumen — o el perfil queda DESCIFRADO en disco, legible
    // por cualquiera. Se usa un `sleep` en lugar de Firefox: lo que se prueba es el
    // desmontaje, no el navegador. Cruza la frontera con un montaje REAL (D28).
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("sesion-drop");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar el volumen");
    perfil::montar(&banco.rutas, FRASE).expect("montar");
    assert!(perfil::esta_montado(&banco.rutas.clear), "debe estar montado");

    {
        let proceso = Command::new("sleep").arg("60").spawn().expect("lanzar sleep de prueba");
        let sesion = perfil::Sesion::_para_prueba(proceso, banco.rutas.clear.clone());
        // Mientras la sesión VIVE, sigue montado: así la prueba discrimina que es el
        // `Drop` —y no otra cosa— lo que desmonta (D33).
        assert!(perfil::esta_montado(&banco.rutas.clear), "sigue montado mientras la sesión vive");
        drop(sesion); // soltar la sesión SIN `cerrar`: dispara la red de seguridad
    }

    assert!(
        !perfil::esta_montado(&banco.rutas.clear),
        "al soltarse la sesión sin cerrar, el volumen tiene que quedar DESMONTADO"
    );
}

#[test]
fn desmontar_retira_la_ruta_aunque_el_volumen_este_ocupado() {
    // HALLAZGO del concilio (fable + haiku, 2026-10-19, reproducido con gocryptfs
    // real): si un proceso tiene un fd abierto DENTRO del montaje —un Firefox que
    // chuspa no lanzó como hijo propio—, `fusermount3 -u` falla con EBUSY y el perfil
    // queda EN CLARO, legible por ruta. `desmontar` cae al PEREZOSO (`-uz`), que
    // retira el punto de montaje aunque haya fds vivos. Aquí se fija por la VÍA REAL:
    // con un holder vivo, `desmontar` DEBE dejar `esta_montado` = false.
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("ocupado");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar");
    perfil::montar(&banco.rutas, FRASE).expect("montar");
    std::fs::create_dir_all(banco.rutas.perfil()).ok();
    let archivo = banco.rutas.perfil().join("abierto.txt");
    std::fs::write(&archivo, b"x").unwrap();
    // Un proceso ajeno mantiene un fd abierto dentro del montaje (como Firefox):
    // `exec 3< archivo` abre el fd 3 y `sleep` mantiene el proceso —y el fd— vivos.
    let mut holder = Command::new("sh")
        .arg("-c")
        .arg(format!("exec 3< '{}'; sleep 60", archivo.display()))
        .spawn()
        .expect("lanzar el holder de prueba");
    std::thread::sleep(std::time::Duration::from_millis(400)); // que abra el fd
    assert!(perfil::esta_montado(&banco.rutas.clear), "debe estar montado con el holder vivo");

    // `-u` normal daría EBUSY aquí; `desmontar` cae a `-uz` y retira la ruta.
    perfil::desmontar(&banco.rutas.clear).expect("el desmontaje perezoso no debe fallar");
    assert!(
        !perfil::esta_montado(&banco.rutas.clear),
        "la ruta en claro tiene que quedar retirada aunque el volumen estuviera OCUPADO"
    );

    let _ = holder.kill();
    let _ = holder.wait();
}

#[test]
fn tras_el_desmontaje_perezoso_el_clear_no_admite_escritura_en_claro() {
    // HALLAZGO del concilio (sonnet 8 + fable 9, 2026-10-20, MEDIDO con Firefox+
    // gocryptfs reales): tras `-uz`, `clear` vuelve a ser un directorio normal del
    // disco en CLARO; un Firefox vivo NO rastreado (el de `chuspa-navegar`) escribía
    // ahí el perfil —cookie de sesión y orígenes— sin cifrar. El banco de arriba solo
    // exigía `esta_montado == false`, que es COMPATIBLE con la fuga. Esta pareja fija
    // lo que de verdad importa: tras desmontar, una escritura NUEVA por ruta en claro
    // NO puede ocurrir. Caso rojo por la VÍA REAL (`desmontar` deja `clear` en 0o000).
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("fuga-en-claro");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar");
    perfil::montar(&banco.rutas, FRASE).expect("montar");
    std::fs::create_dir_all(banco.rutas.perfil()).ok();
    // Un holder con un fd vivo fuerza la caída a `-uz` (como el Firefox no rastreado).
    let archivo = banco.rutas.perfil().join("abierto.txt");
    std::fs::write(&archivo, b"x").unwrap();
    let mut holder = Command::new("sh")
        .arg("-c")
        .arg(format!("exec 3< '{}'; sleep 60", archivo.display()))
        .spawn()
        .expect("lanzar el holder");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(perfil::esta_montado(&banco.rutas.clear), "montado con el holder vivo");

    perfil::desmontar(&banco.rutas.clear).expect("desmontar (perezoso)");
    assert!(!perfil::esta_montado(&banco.rutas.clear), "desmontado");

    // Lo que haría el Firefox no rastreado: crea el árbol del perfil por RUTA
    // (`makeDirectory` con ancestros) y escribe dentro. Se replica igual —crear
    // `clear/perfil` y escribir— porque tras `-uz` el `clear` subyacente está VACÍO:
    // un `write` a secas fallaría por ENOENT y NO probaría nada (el mutante sin el
    // `chmod 000` también lo haría fallar). Con `clear` en 0o000, el `create_dir_all`
    // no puede siquiera crear el subdir: EACCES.
    let fuga = banco.rutas.perfil().join("recovery-fuga.txt");
    let intento = std::fs::create_dir_all(banco.rutas.perfil())
        .and_then(|()| std::fs::write(&fuga, b"COOKIE-DE-SESION-SECRETA"));
    assert!(
        intento.is_err(),
        "tras desmontar, el disco en claro NO debe admitir crear/escribir el perfil por ruta"
    );

    // Y el disco subyacente no contiene el secreto en claro. Para INSPECCIONAR hay que
    // devolver permiso de lectura al dueño (lo que hará `montar` la próxima vez).
    std::fs::set_permissions(&banco.rutas.clear, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        !algun_archivo_contiene(&banco.rutas.clear, b"COOKIE-DE-SESION-SECRETA"),
        "no debe quedar el secreto en claro en el disco subyacente"
    );

    let _ = holder.kill();
    let _ = holder.wait();
}

#[test]
fn desmontar_cierra_los_firefox_del_perfil_y_no_otros() {
    // Opción 1 (Juan, 2026-10-20): "cerrar el navegador seguro cierra TODO". Antes de
    // desmontar, `desmontar` termina los procesos con `--profile <perfil>` —incluido
    // el Firefox que lanzó `chuspa-navegar`, que NO es hijo de chuspa—, así el `-u`
    // limpio tiene éxito y no se llega al `-uz` que fuga. Pareja D33: el del perfil
    // muere; el de OTRO perfil NO se toca (específico, no "matar firefox").
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("cerrar-holders");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar");
    perfil::montar(&banco.rutas, FRASE).expect("montar");
    let perfil_dir = banco.rutas.perfil();
    let otro = banco.rutas.clear.join("otro-perfil");
    // Dos procesos que simulan Firefox: su argv lleva `--profile <ruta>` (sh ignora
    // los posicionales y duerme). Uno sobre ESTE perfil, otro sobre OTRO.
    // `sleep 60; :` (dos comandos) impide la "exec optimization" del shell: si fuera
    // un solo comando, el sh se reemplazaría por `sleep` y PERDERÍA el `--profile`
    // del argv (medido). Con dos, el sh conserva su argv —como un Firefox real—.
    let lanzar = |ruta: &std::path::Path| {
        Command::new("sh")
            .args(["-c", "sleep 60; :", "sh", "--profile"])
            .arg(ruta)
            .spawn()
            .expect("lanzar el proceso de prueba")
    };
    let mut objetivo = lanzar(&perfil_dir);
    let mut ajeno = lanzar(&otro);
    std::thread::sleep(std::time::Duration::from_millis(400));
    // "Vivo" se decide con `try_wait`, NO con `/proc/<pid>` existe: un proceso hijo
    // MUERTO queda ZOMBIE hasta que el padre lo reapea, y su `/proc/<pid>` sigue
    // existiendo —daría un falso "vivo"—. `try_wait` devuelve `Ok(Some)` cuando ya
    // terminó (y lo reapea). (Un Firefox real es huérfano, lo reapea init, sin zombie.)
    assert!(matches!(objetivo.try_wait(), Ok(None)), "el del perfil vive al empezar");
    assert!(matches!(ajeno.try_wait(), Ok(None)), "el de otro perfil vive al empezar");

    perfil::desmontar(&banco.rutas.clear).expect("desmontar");
    std::thread::sleep(std::time::Duration::from_millis(300));

    assert!(
        matches!(objetivo.try_wait(), Ok(Some(_))),
        "desmontar DEBE cerrar el proceso con `--profile <perfil>`"
    );
    assert!(
        matches!(ajeno.try_wait(), Ok(None)),
        "desmontar NO debe tocar un proceso con `--profile` de OTRO perfil"
    );
    let _ = objetivo.kill();
    let _ = objetivo.wait();
    let _ = ajeno.kill();
    let _ = ajeno.wait();
}

#[test]
fn una_frase_equivocada_no_monta() {
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("frase-mala");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar");

    let mala = perfil::montar(&banco.rutas, "frase-que-no-es-la-correcta");
    assert!(mala.is_err(), "con la frase equivocada NO debe montar");
    assert!(!perfil::esta_montado(&banco.rutas.clear), "no debe quedar montado");
}

#[test]
fn la_passphrase_no_viaja_en_argv_ni_en_el_entorno_del_daemon() {
    if !hay_gocryptfs() {
        return;
    }
    let banco = Banco::nuevo("no-fuga");
    perfil::iniciar(&banco.rutas, FRASE).expect("iniciar");
    perfil::montar(&banco.rutas, FRASE).expect("montar");
    assert!(perfil::esta_montado(&banco.rutas.clear), "debe estar montado para inspeccionar el daemon");

    // Buscar el daemon de gocryptfs que sirve ESTE montaje (su cmdline nombra la
    // ruta `clear`). Positivo de control: si no se encuentra, la prueba falla —
    // no se puede verificar "no hay fuga" sin haber recorrido el camino (D30).
    let clear_txt = banco.rutas.clear.to_string_lossy().to_string();
    let daemon = encontrar_daemon(&clear_txt)
        .expect("debe existir un proceso gocryptfs sirviendo el montaje");

    let cmdline = std::fs::read(format!("/proc/{daemon}/cmdline")).unwrap_or_default();
    let environ = std::fs::read(format!("/proc/{daemon}/environ")).unwrap_or_default();

    assert!(
        !contiene(&cmdline, FRASE.as_bytes()),
        "la passphrase NO puede estar en argv del daemon (iría por stdin)"
    );
    assert!(
        !contiene(&environ, FRASE.as_bytes()),
        "la passphrase NO puede estar en el entorno del daemon"
    );
}

#[test]
fn la_passphrase_del_volumen_se_crea_una_vez_y_se_reusa() {
    let banco = Banco::nuevo("passphrase");
    let ruta = banco.raiz.join("boveda.chuspa");
    let acceso = Acceso::frase("frase-maestra-del-banco");
    let mut boveda = Boveda::crear(&ruta, &acceso, cifrado::coste_por_defecto()).unwrap();
    assert_eq!(boveda.listar().len(), 0, "una bóveda nueva empieza vacía");

    let (p1, creada1) = perfil::passphrase(&mut boveda).expect("crear la passphrase");
    assert!(creada1, "la primera vez debe CREARLA");
    assert_eq!(boveda.listar().len(), 1, "crea exactamente una entrada");
    assert_eq!(p1.split('-').count(), 20, "20 palabras BIP-39");

    let (p2, creada2) = perfil::passphrase(&mut boveda).expect("releer la passphrase");
    assert!(!creada2, "la segunda vez NO debe crear nada");
    assert_eq!(&*p1, &*p2, "debe devolver la MISMA passphrase");
    assert_eq!(boveda.listar().len(), 1, "NO puede añadir una segunda entrada");
}

#[test]
fn el_perfil_se_endurece_con_user_js() {
    let banco = Banco::nuevo("endurece");
    let perfil = banco.raiz.join("perfil");
    perfil::sembrar_endurecimiento(&perfil).expect("sembrar el endurecimiento");
    let user_js = std::fs::read_to_string(perfil.join("user.js")).expect("user.js debe existir");
    for pref in [
        "\"browser.safebrowsing.malware.enabled\", false",
        "\"toolkit.telemetry.enabled\", false",
        "\"dom.security.https_only_mode\", true",
        "\"signon.rememberSignons\", false",
        "\"identity.fxaccounts.enabled\", false",
        "\"browser.translations.enabled\", false",
        "\"browser.sessionstore.resume_from_crash\", false",
    ] {
        assert!(user_js.contains(pref), "al endurecimiento le falta: {pref}");
    }
}

#[test]
fn el_comando_firefox_apunta_al_perfil_y_no_lleva_no_remote() {
    let cmd = perfil::comando_firefox(Path::new("/vol/perfil"), Some("https://ejemplo.test/login"));
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    assert!(args.iter().any(|a| a == "--profile"), "debe pasar --profile");
    assert!(args.iter().any(|a| a.contains("/vol/perfil")), "debe apuntar al perfil protegido");
    assert!(
        args.iter().any(|a| a == "https://ejemplo.test/login"),
        "debe pasar la URL para dirigirla al perfil protegido"
    );
    assert!(
        args.iter().any(|a| a == "--new-tab"),
        "la URL debe ir LIGADA a --new-tab (corta el contrabando de flags)"
    );
    assert!(
        !args.iter().any(|a| a == "--no-remote"),
        "SIN --no-remote: si no, no se podrían dirigir URLs a la instancia viva"
    );
}

#[test]
fn es_url_web_rechaza_flags_y_esquemas_peligrosos() {
    assert!(perfil::es_url_web("https://x.test/login"));
    assert!(perfil::es_url_web("http://x.test"));
    // El caso que motivó el hallazgo de la revisión: una "url" que es un flag.
    assert!(!perfil::es_url_web("-attacker"));
    assert!(!perfil::es_url_web("--profile"));
    assert!(!perfil::es_url_web("file:///etc/passwd"));
    assert!(!perfil::es_url_web("javascript:alert(1)"));
    assert!(!perfil::es_url_web(""));
}

// --- utilidades del banco ---

fn algun_archivo_contiene(dir: &Path, aguja: &[u8]) -> bool {
    let Ok(entradas) = std::fs::read_dir(dir) else { return false };
    for e in entradas.flatten() {
        let ruta = e.path();
        let encontrado = if ruta.is_dir() {
            algun_archivo_contiene(&ruta, aguja)
        } else {
            std::fs::read(&ruta).map(|b| contiene(&b, aguja)).unwrap_or(false)
        };
        if encontrado {
            return true;
        }
    }
    false
}

fn contiene(heno: &[u8], aguja: &[u8]) -> bool {
    if aguja.is_empty() || heno.len() < aguja.len() {
        return false;
    }
    heno.windows(aguja.len()).any(|v| v == aguja)
}

/// PID de un proceso cuyo `cmdline` menciona `marca` (la ruta del montaje) y es
/// gocryptfs. Devuelve el primero que encaje.
fn encontrar_daemon(marca: &str) -> Option<u32> {
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let nombre = e.file_name();
        let Some(pid) = nombre.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else { continue };
        let texto = String::from_utf8_lossy(&cmdline);
        if texto.contains("gocryptfs") && texto.contains(marca) {
            return Some(pid);
        }
    }
    None
}
