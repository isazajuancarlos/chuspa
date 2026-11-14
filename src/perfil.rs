// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Perfil de navegador sobre un volumen cifrado (gocryptfs).
//!
//! # Qué resuelve
//!
//! Firefox en modo privado olvida las sesiones al cerrar, así que hay que
//! re-loguearse en todo cada vez. Un Firefox NORMAL persiste, pero escribe
//! cookies, historial y `localStorage` en el disco **en claro** — en esta
//! máquina `/home` es btrfs sin cifrar, así que quien se lleve el disco lee todo.
//!
//! La respuesta es un perfil persistente que vive dentro de un volumen
//! `gocryptfs`: montado, Firefox lo usa como cualquier carpeta; desmontado (el
//! equipo apagado), todo queda cifrado en reposo. La **llave del volumen** no la
//! teclea nadie: es una passphrase aleatoria que chuspa guarda en la bóveda
//! (ver [`crate::perfil::passphrase`], capa 2) y entrega a gocryptfs por `stdin`.
//!
//! # El invariante que manda aquí
//!
//! `CLAUDE.md`: *«la frase de paso no viaja por variables de entorno (se heredan
//! a los hijos)»*. La passphrase del volumen es material igual de sensible, así
//! que viaja a gocryptfs **por `stdin` del proceso hijo, jamás por `argv` ni por
//! el entorno** — un `-extpass "echo …"` la dejaría en la línea de órdenes, que
//! cualquiera ve con `ps`. Lo vigila `tests/perfil_cifrado.rs`.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::boveda::{Campo, Clase, Entrada, Valor};
use crate::cifrado::{Boveda, BovedaError};
use crate::fecha;
use crate::generador::{self, GeneradorError};

#[derive(Debug, thiserror::Error)]
pub enum PerfilError {
    #[error("no se encontró `gocryptfs` en el PATH; instálalo (dnf install gocryptfs)")]
    SinGocryptfs,

    #[error("gocryptfs no pudo {accion}: {detalle}")]
    Gocryptfs { accion: &'static str, detalle: String },

    #[error("no se pudo desmontar {0}: {1}")]
    Desmontar(PathBuf, String),

    #[error("no se pudo lanzar el navegador: {0}")]
    Navegador(String),

    #[error("entrada/salida: {0}")]
    Io(#[from] std::io::Error),

    #[error("bóveda: {0}")]
    Boveda(#[from] BovedaError),

    #[error("generador: {0}")]
    Generador(#[from] GeneradorError),

    #[error("la entrada reservada del volumen está corrupta o le falta el campo secreto")]
    EntradaCorrupta,
}

/// Dónde vive el volumen. `cipher` guarda el texto cifrado en reposo; `clear` es
/// el punto de montaje donde Firefox ve el perfil en claro mientras está montado.
#[derive(Debug, Clone)]
pub struct Rutas {
    pub cipher: PathBuf,
    pub clear: PathBuf,
}

impl Rutas {
    /// Las rutas por defecto del volumen. `CHUSPA_NAVEGADOR_DIR` permite ponerlo
    /// en un disco que SOBREVIVA a reinstalar el sistema (p. ej. el nvme en
    /// `/mnt/data`, separado de `/` y `/home`); si no está, cae al directorio de
    /// datos del usuario (XDG). La ruta no es secreta, así que por entorno está
    /// bien —a diferencia de la frase, que nunca viaja por env—.
    pub fn por_defecto() -> Self {
        let base = std::env::var_os("CHUSPA_NAVEGADOR_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs_de_datos().join("navegador-seguro"));
        Self { cipher: base.join("cipher"), clear: base.join("clear") }
    }

    /// El directorio del perfil de Firefox, dentro del montaje.
    pub fn perfil(&self) -> PathBuf {
        self.clear.join("perfil")
    }
}

/// `$XDG_DATA_HOME` o `~/.local/share`. Sin dependencia externa: una sola regla.
fn dirs_de_datos() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(x)
    } else {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".local").join("share")
    }
}

/// `true` si el volumen ya fue inicializado (`gocryptfs.conf` presente).
pub fn volumen_iniciado(cipher: &Path) -> bool {
    cipher.join("gocryptfs.conf").is_file()
}

/// `true` si `clear` es ahora mismo un punto de montaje.
///
/// Se decide por el número de dispositivo: un punto de montaje tiene un `st_dev`
/// distinto al de su directorio padre. No lanza ningún proceso ni necesita
/// `unsafe` (`st_dev` sale de `MetadataExt`).
pub fn esta_montado(clear: &Path) -> bool {
    match (clear.metadata(), clear.parent().and_then(|p| p.metadata().ok())) {
        (Ok(aqui), Some(padre)) => aqui.dev() != padre.dev(),
        _ => false,
    }
}

/// El binario de gocryptfs, o un error si no está instalado.
fn gocryptfs() -> Result<Command, PerfilError> {
    // `Command::new` no comprueba existencia hasta el spawn; el error de spawn se
    // traduce luego. Aquí solo fijamos el nombre.
    Ok(Command::new("gocryptfs"))
}

/// Corre gocryptfs con `args`, entregando la passphrase por `stdin` (nunca por
/// `argv` ni entorno). Espera a que termine y traduce el fallo.
fn correr_con_frase(
    mut cmd: Command,
    accion: &'static str,
    frase: &str,
) -> Result<(), PerfilError> {
    cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    let mut hijo = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PerfilError::SinGocryptfs
        } else {
            PerfilError::Gocryptfs { accion, detalle: e.to_string() }
        }
    })?;
    // La passphrase y su salto de línea, al stdin del hijo. Nada en argv.
    {
        let entrada = hijo.stdin.as_mut().expect("stdin fue pedido como piped");
        entrada.write_all(frase.as_bytes())?;
        entrada.write_all(b"\n")?;
    }
    let salida = hijo.wait_with_output()?;
    if salida.status.success() {
        Ok(())
    } else {
        let detalle = String::from_utf8_lossy(&salida.stderr).trim().to_string();
        Err(PerfilError::Gocryptfs { accion, detalle })
    }
}

/// Inicializa un volumen nuevo en `cipher` con la passphrase dada.
///
/// gocryptfs genera su propia clave maestra aleatoria y la envuelve con la
/// passphrase (scrypt); lo que le damos es la passphrase, no la maestra.
pub fn iniciar(rutas: &Rutas, frase: &str) -> Result<(), PerfilError> {
    if let Some(base) = rutas.cipher.parent() {
        crear_dir_privado(base)?;
    }
    crear_dir_privado(&rutas.cipher)?;
    let mut cmd = gocryptfs()?;
    cmd.arg("-init").arg("-q").arg(&rutas.cipher);
    correr_con_frase(cmd, "inicializar el volumen", frase)
}

/// Monta el volumen en `clear`. Idempotente: si ya está montado, no hace nada.
pub fn montar(rutas: &Rutas, frase: &str) -> Result<(), PerfilError> {
    crear_dir_privado(&rutas.clear)?;
    if esta_montado(&rutas.clear) {
        return Ok(());
    }
    let mut cmd = gocryptfs()?;
    cmd.arg("-q").arg(&rutas.cipher).arg(&rutas.clear);
    correr_con_frase(cmd, "montar el volumen", frase)?;
    crear_dir_privado(&rutas.perfil())?;
    Ok(())
}

/// Crea un directorio (y sus padres) y lo deja accesible **solo por el dueño**
/// (`0700`): ningún otro usuario local puede entrar al volumen ni al perfil.
fn crear_dir_privado(dir: &Path) -> Result<(), PerfilError> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Desmonta el volumen. Idempotente: si no está montado, no hace nada.
///
/// **Primero intenta el desmontaje limpio (`-u`); si falla por OCUPADO, cae al
/// PEREZOSO (`-uz`).** El motivo es de seguridad, no de comodidad (hallazgo del
/// concilio, fable, 2026-10-19, reproducido con gocryptfs real): cuando un proceso
/// tiene fds abiertos dentro del montaje —p. ej. un Firefox que chuspa NO lanzó
/// como hijo propio, porque al relanzarse sobre un volumen ya montado la nueva
/// instancia traspasa la ventana a la viva y el hijo sale—, `fusermount3 -u`
/// devuelve EBUSY y **no puede** retirar la ruta: el perfil queda EN CLARO,
/// legible por `clear/perfil`, hasta el siguiente arranque. El desmontaje perezoso
/// `-uz` **sí** retira el punto de montaje del espacio de nombres aunque haya fds
/// vivos: la ruta en claro desaparece de inmediato (un acceso NUEVO por ruta ya no
/// ve el perfil descifrado). El proceso que tenía fds abiertos conserva SU acceso
/// hasta cerrarse, pero nadie MÁS lee el perfil por la ruta — que es justo la
/// garantía que el volumen cifrado existe para dar. Dejarlo montado y legible es
/// estrictamente peor.
pub fn desmontar(clear: &Path) -> Result<(), PerfilError> {
    if !esta_montado(clear) {
        return Ok(());
    }
    // Cerrar TODO Firefox que tenga ESTE perfil abierto, no solo el hijo que chuspa
    // lanzó: el de `chuspa-navegar` NO es hijo de chuspa y mantendría el volumen
    // ocupado, forzando el desmontaje perezoso `-uz` que deja el perfil EN CLARO
    // (hallazgo del concilio 2026-10-20). "Cerrar el navegador seguro" cierra TODO
    // el Firefox del perfil. Sin holder vivo, el `-u` limpio de abajo tiene éxito y
    // `clear` queda vacío, sin caer a `-uz` y sin la ventana de carrera residual.
    terminar_navegadores_del_perfil(&clear.join("perfil"), Duration::from_secs(5));
    // 1) Desmontaje limpio.
    let salida = Command::new("fusermount3").arg("-u").arg(clear).output()?;
    if salida.status.success() {
        return Ok(());
    }
    // 2) Falló (típicamente EBUSY). Perezoso: retira la ruta aunque haya fds vivos.
    let lazy = Command::new("fusermount3").arg("-uz").arg(clear).output()?;
    if lazy.status.success() {
        // CIERRE DE LA FUGA (concilio 2026-10-20, sonnet+fable, medido con Firefox
        // real): tras `-uz`, `clear` vuelve a ser un directorio NORMAL del disco en
        // claro. Un proceso que siga vivo —un Firefox que chuspa NO lanzó como hijo,
        // p. ej. el de `chuspa-navegar`— escribe el perfil por RUTA ABSOLUTA, y esas
        // escrituras NUEVAS caían en `clear/perfil/…` SIN CIFRAR (se midieron cookie
        // de sesión, orígenes visitados y URLs). Dejar `clear` en `0o000` corta todo
        // acceso NUEVO por ruta con EACCES —no se puede atravesar ni crear dentro—,
        // sin matar a ciegas un navegador del usuario (sus fds ya abiertos siguen
        // sobre el montaje desprendido y cifrado). `montar` restaura 0700 antes del
        // siguiente uso. Lo vigila `tests/perfil_cifrado.rs`.
        std::fs::set_permissions(clear, std::fs::Permissions::from_mode(0o000))?;
        return Ok(());
    }
    let detalle = String::from_utf8_lossy(&lazy.stderr).trim().to_string();
    Err(PerfilError::Desmontar(clear.to_path_buf(), detalle))
}

/// Construye el comando de Firefox para `perfil`, opcionalmente con una `url`.
///
/// SIN `--no-remote` a propósito: así una segunda invocación
/// (`chuspa-navegar <url>`) puede dirigir la URL a la instancia VIVA de este
/// perfil en vez de fallar por el cerrojo. El aislamiento del Firefox normal lo
/// da `--profile` —Firefox moderno enruta el remoting por perfil, así que una
/// instancia del perfil protegido no recibe lo del perfil por defecto—.
pub fn comando_firefox(perfil: &Path, url: Option<&str>) -> Command {
    let mut cmd = Command::new("firefox");
    cmd.arg("--profile").arg(perfil);
    if let Some(u) = url {
        // `--new-tab <url>` LIGA la url a la opción: Firefox la consume como
        // VALOR, jamás como flag, aunque empiece por `-`. chuspa-navegar es el
        // navegador por defecto y recibe URLs de fuentes NO confiables, así que
        // esto corta el contrabando de flags (argument injection). El esquema se
        // valida además en el llamante con `es_url_web`.
        cmd.arg("--new-tab").arg(u);
    }
    cmd
}

/// `true` si la cadena es una URL web (http/https). Rechaza esquemas peligrosos
/// (`file:`, `javascript:`) y, por el prefijo exigido, cualquier cosa que empiece
/// por `-` (contrabando de flags). Es la puerta de entrada de `chuspa-navegar`,
/// que recibe la URL de fuentes no confiables al ser el navegador por defecto.
pub fn es_url_web(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

/// Lanza Firefox sobre el perfil montado (sin URL). Devuelve el proceso hijo
/// para cerrarlo de forma ordenada luego.
pub fn lanzar_firefox(perfil: &Path) -> Result<Child, PerfilError> {
    comando_firefox(perfil, None)
        .spawn()
        .map_err(|e| PerfilError::Navegador(e.to_string()))
}

/// Prefs de endurecimiento que se siembran en `user.js` del perfil antes de
/// lanzar Firefox. Firefox las aplica al arrancar. Privacidad primero: sin
/// telemetría, sin Safe Browsing (que consulta a Google), sin prefetch ni
/// conexiones automáticas, HTTPS obligatorio, bloqueo de rastreo y cookies de
/// terceros, y sin gestor de contraseñas del navegador (eso es trabajo de la
/// bóveda). Se reescribe en cada apertura, así el endurecimiento no se puede
/// desactivar por accidente.
const USER_JS: &str = r#"// chuspa — endurecimiento del navegador seguro. Generado, NO editar a mano.

// Telemetría, reporte de datos y estudios
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

// Safe Browsing: consulta a Google. OFF por privacidad.
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

// Pocket y contenido patrocinado
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);

// Conexiones automáticas y especulación de red (filtran lo que vas a visitar)
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

// Geolocalización
user_pref("geo.enabled", false);
user_pref("permissions.default.geo", 2);

// Sugerencias de búsqueda (envían lo tecleado al buscador)
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);

// Protección de rastreo estricta y cookies de terceros bloqueadas
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("network.cookie.cookieBehavior", 5);

// HTTPS obligatorio
user_pref("dom.security.https_only_mode", true);

// Fuga de IP por WebRTC
user_pref("media.peerconnection.ice.default_address_only", true);

// Cuenta Firefox y Sync: no sincronizar con Mozilla (los datos viven cifrados
// en local, no en la nube) y no ofrecerlo en la interfaz
user_pref("identity.fxaccounts.enabled", false);
user_pref("browser.preferences.moreFromMozilla", false);

// Traducción integrada (descarga modelos desde Mozilla)
user_pref("browser.translations.enabled", false);
user_pref("browser.translations.automaticallyPopup", false);

// Cierre por chuspa (SIGTERM): no mostrar el recuperador de "crash" y restaurar
// la sesión anterior al abrir. Las cookies/logins persisten en el perfil cifrado
// igualmente; solo la lista de pestañas abiertas depende de esto.
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.startup.page", 3);

// El gestor de contraseñas lo hace chuspa, no Firefox
user_pref("signon.rememberSignons", false);
"#;

/// Escribe el `user.js` de endurecimiento en el perfil (lo crea si hace falta).
pub fn sembrar_endurecimiento(perfil: &Path) -> Result<(), PerfilError> {
    crear_dir_privado(perfil)?;
    std::fs::write(perfil.join("user.js"), USER_JS)?;
    Ok(())
}

/// Una sesión de navegador segura viva: el proceso de Firefox y el montaje que
/// hay que retirar al cerrarlo.
pub struct Sesion {
    firefox: Child,
    clear: PathBuf,
    /// Ya se limpió (Firefox terminado + volumen desmontado). Evita que `Drop`
    /// repita el trabajo tras un `cerrar` explícito.
    limpiada: bool,
}

impl Sesion {
    /// Abre el ciclo entero: monta el volumen y lanza Firefox. La passphrase se
    /// consume aquí y no se guarda en la estructura.
    pub fn abrir(rutas: &Rutas, frase: &Zeroizing<String>) -> Result<Self, PerfilError> {
        montar(rutas, frase)?;
        // Sembrar el endurecimiento ANTES de lanzar; si sembrar o el arranque
        // fallan, no dejar el volumen montado.
        let arranque = sembrar_endurecimiento(&rutas.perfil())
            .and_then(|()| lanzar_firefox(&rutas.perfil()));
        match arranque {
            Ok(firefox) => Ok(Self { firefox, clear: rutas.clear.clone(), limpiada: false }),
            Err(e) => {
                let _ = desmontar(&rutas.clear);
                Err(e)
            }
        }
    }

    /// Termina Firefox (SIGTERM, espera hasta `tope`) y desmonta. Idempotente: una
    /// segunda llamada no hace nada. Es la pieza que comparten el cierre explícito
    /// (`cerrar`) y la red de seguridad (`Drop`).
    fn limpiar(&mut self, tope: Duration) -> Result<(), PerfilError> {
        if self.limpiada {
            return Ok(());
        }
        terminar_suave(&mut self.firefox, tope);
        let r = desmontar(&self.clear);
        // Se marca `limpiada` SOLO si el desmontaje tuvo ÉXITO: si falló (p. ej. el
        // volumen seguía ocupado por un hijo de Firefox), un `cerrar` que falla NO
        // debe inhibir el reintento del `Drop` — si no, el perfil quedaría en claro.
        // `terminar_suave` sobre un Firefox ya terminado es inocuo (kill a un pid
        // muerto falla en silencio), así que reintentar no hace daño.
        if r.is_ok() {
            self.limpiada = true;
        }
        r
    }

    /// Cierre ordenado: pide a Firefox que cierre (SIGTERM, para que guarde la
    /// sesión), espera a que termine con un tope holgado, y desmonta. Pensado para
    /// correr cuando se cierra la ventana de chuspa.
    pub fn cerrar(mut self) -> Result<(), PerfilError> {
        self.limpiar(Duration::from_secs(20))
    }

    /// Constructor para pruebas de integración: envuelve un proceso cualquiera y un
    /// punto de montaje, para ejercer el ciclo de desmontaje (`Drop`/`cerrar`) con
    /// un montaje REAL pero sin abrir un navegador.
    #[doc(hidden)]
    pub fn _para_prueba(proceso: Child, clear: PathBuf) -> Self {
        Self { firefox: proceso, clear, limpiada: false }
    }
}

/// **Red de seguridad: el volumen cifrado se desmonta cuando la sesión se suelta
/// por una vía que DESENROLLA**, no solo en el cierre por la X de la ventana. Sin
/// esto, una salida del programa que no pase por `cerrar` (p. ej. el `Rc<Sesion>`
/// que se suelta al terminar el bucle, o un panic que desenrolla) dejaba el perfil
/// **DESCIFRADO y montado**. El tope es corto: un `Drop` no debe colgar el apagado.
///
/// **Lo que este `Drop` NO cubre, y por qué no basta solo:** un `panic` DENTRO de un
/// callback de GTK **aborta** el proceso sin desenrollar (no corre ningún `Drop`), y
/// `SIGKILL` tampoco se puede atrapar. Para esos dos casos la red es la **limpieza de
/// montaje huérfano al ARRANCAR** chuspa-gtk; y como un Firefox vivo deja el volumen
/// ocupado, esa limpieza se apoya en el desmontaje PEREZOSO de [`desmontar`] (ver su
/// doc: `-u` falla con EBUSY, `-uz` retira la ruta igual).
impl Drop for Sesion {
    fn drop(&mut self) {
        let _ = self.limpiar(Duration::from_secs(3));
    }
}

/// Pide a un hijo que termine con SIGTERM y espera hasta `tope`; si no cierra,
/// lo mata (SIGKILL). Sin `unsafe`: el SIGTERM se manda con `kill`, que en el
/// Linux donde corre `chuspa-gtk` siempre está.
fn terminar_suave(hijo: &mut Child, tope: Duration) {
    // Si el hijo YA terminó (p. ej. una segunda llamada desde `Drop` tras un
    // `cerrar` cuyo desmontaje falló), no se le manda SIGTERM: su pid podría estar
    // reutilizado por OTRO proceso. `try_wait` lo reapea y salimos. (Observación del
    // concilio, Paso 5, sonnet.)
    if matches!(hijo.try_wait(), Ok(Some(_))) {
        return;
    }
    let pid = hijo.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let inicio = Instant::now();
    loop {
        match hijo.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if inicio.elapsed() < tope => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => break,
        }
    }
    let _ = hijo.kill();
    let _ = hijo.wait();
}

/// Termina todo proceso que tenga ESTE perfil abierto (`--profile <perfil>` en su
/// argv): SIGTERM a todos, espera hasta `tope`, y SIGKILL a los que queden. Es
/// deliberadamente específico del perfil —nunca "matar firefox a secas"— para no
/// tocar el Firefox del perfil normal del usuario. Sin `unsafe`: las señales van
/// por `kill`, que en el Linux donde corre chuspa siempre está.
fn terminar_navegadores_del_perfil(perfil: &Path, tope: Duration) {
    let pids = pids_con_perfil(perfil);
    if pids.is_empty() {
        return;
    }
    for pid in &pids {
        let _ = Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
    }
    // Esperar a que no quede NINGUNO con el perfil. Se RE-CONSULTA cada vuelta en vez
    // de mirar los pids originales: si un pid muere y el SO lo reutiliza para otro
    // proceso, ese ya no tendrá `--profile <perfil>`, así que no lo contamos ni —lo
    // importante— lo matamos abajo. Inmune a la reutilización de pid.
    let inicio = Instant::now();
    while inicio.elapsed() < tope && !pids_con_perfil(perfil).is_empty() {
        std::thread::sleep(Duration::from_millis(100));
    }
    // SIGKILL solo a los que SIGUEN teniendo el perfil abierto (nunca a un pid reusado).
    for pid in pids_con_perfil(perfil) {
        let _ = Command::new("kill").arg("-KILL").arg(pid.to_string()).status();
    }
}

/// PIDs cuyo `/proc/<pid>/cmdline` lleva exactamente `--profile <perfil>`. El
/// cmdline es el argv separado por NUL; se reconstruye y se busca el par
/// (`--profile`, ruta del perfil) para no casar por subcadena.
fn pids_con_perfil(perfil: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entrada in dir.flatten() {
        let Some(pid) = entrada.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        for par in args.windows(2) {
            if par[0] == b"--profile" && Path::new(&String::from_utf8_lossy(par[1]).into_owned()) == perfil {
                pids.push(pid);
                break;
            }
        }
    }
    pids
}

/// Nombre de la entrada de la bóveda que custodia la passphrase del volumen.
pub const ENTRADA_VOLUMEN: &str = "Volumen cifrado · navegador (gocryptfs)";
/// Etiqueta del campo secreto dentro de esa entrada.
pub const CAMPO_PASSPHRASE: &str = "volumen.passphrase";

/// `true` si una entrada con este nombre es MATERIAL DE SISTEMA y NO debe
/// mostrarse en la lista de la ventana: la passphrase del volumen del navegador
/// seguro vive en la bóveda por necesidad, pero no es para que el usuario la vea
/// ni la edite, y ocultarla evita además que se borre por accidente con
/// «Eliminar…». Se oculta por FILTRO (la fila sigue en la lista, solo invisible),
/// de modo que los índices de fila siguen casando 1:1 con la bóveda y no se toca
/// la indexación de la UI.
pub fn es_entrada_de_sistema(nombre: &str) -> bool {
    nombre == ENTRADA_VOLUMEN
}

/// Cerrojo de INSTANCIA de chuspa (una GUI = una instancia viva). Mientras vive,
/// el pidfile existe; al soltarse, se borra. GApplication ya hace single-instance
/// CON bus de sesión; esto cubre el caso SIN bus (TTY/ssh), donde una 2ª
/// invocación correría la limpieza de montaje huérfano al arrancar y —con el
/// cierre de holders de [`desmontar`]— MATARÍA el navegador de la 1ª instancia viva.
pub struct CerrojoInstancia {
    ruta: PathBuf,
    tomado: bool,
}

impl Drop for CerrojoInstancia {
    fn drop(&mut self) {
        if self.tomado {
            let _ = std::fs::remove_file(&self.ruta);
        }
    }
}

/// `Some` si esta es la ÚNICA chuspa viva; `None` si ya hay otra (su pid existe).
/// Mismo patrón que el cerrojo de la bóveda: `O_EXCL` + pid dentro; un pidfile de
/// un proceso que ya murió se trata como huérfano y se reclama.
pub fn tomar_instancia() -> Option<CerrojoInstancia> {
    match ruta_de_pidfile() {
        Some(ruta) => tomar_instancia_en(ruta),
        // Sin un directorio per-usuario seguro, NO se usa `/tmp` compartido: un
        // pidfile ahí lo podría pre-crear otro usuario con un pid vivo ajeno para
        // que chuspa se creyera "no única" y se saltara la limpieza de seguridad
        // (DoS → perfil en claro). Se renuncia a la guarda (como antes de ella; el
        // caso sin XDG_RUNTIME_DIR en una GUI es rarísimo) — fail hacia "limpiar".
        None => Some(CerrojoInstancia { ruta: PathBuf::new(), tomado: false }),
    }
}

/// SOLO `$XDG_RUNTIME_DIR` (per-usuario, modo 0700: ningún otro usuario local
/// puede crear ahí un pidfile señuelo). `None` si no existe.
fn ruta_de_pidfile() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|d| PathBuf::from(d).join("chuspa-gtk.pid"))
}

/// Núcleo testeable (la ruta se inyecta, porque `set_var` de `XDG_RUNTIME_DIR`
/// sería `unsafe` y aquí está prohibido).
fn tomar_instancia_en(ruta: PathBuf) -> Option<CerrojoInstancia> {
    use std::io::Write;
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&ruta) {
        Ok(mut f) => {
            let _ = write!(f, "{}", std::process::id());
            Some(CerrojoInstancia { ruta, tomado: true })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let pid = std::fs::read_to_string(&ruta).ok().and_then(|s| s.trim().parse::<u32>().ok());
            match pid {
                Some(pid) if proceso_vivo(pid) => None, // otra instancia viva
                _ => {
                    let _ = std::fs::remove_file(&ruta); // huérfano: reclamar
                    tomar_instancia_en(ruta)
                }
            }
        }
        // Sin dónde escribir el pidfile: no bloquear el arranque; asumir única.
        Err(_) => Some(CerrojoInstancia { ruta, tomado: false }),
    }
}

/// `true` si el proceso sigue existiendo (`/proc/<pid>`). Un zombie cuenta como
/// "vivo" aquí a propósito: su pidfile no debe reclamarse hasta que el padre lo
/// reape.
fn proceso_vivo(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Lee la passphrase del volumen de la bóveda; la crea la primera vez.
///
/// La primera vez genera una frase BIP-39 de 20 palabras (220 bits), la guarda
/// en una entrada [`Clase::Nota`] reservada y persiste la bóveda. Las veces
/// siguientes devuelve la misma sin crear otra entrada. El `bool` del resultado
/// es `true` solo cuando la entrada se acaba de crear, para que la interfaz
/// recuerde al usuario respaldar (el papel de la clave maestra ya la cubre, pero
/// el usuario debe tenerlo al día).
///
/// La passphrase no la teclea nadie: es la llave aleatoria del volumen, y la
/// bóveda cifrada es su custodia. Quien abra la bóveda (su frase maestra) la
/// obtiene; nadie más.
pub fn passphrase(boveda: &mut Boveda) -> Result<(Zeroizing<String>, bool), PerfilError> {
    if let Some(i) = boveda.listar().iter().position(|r| r.nombre == ENTRADA_VOLUMEN) {
        let entrada = boveda.abrir_entrada(i)?;
        return match entrada.campo(CAMPO_PASSPHRASE).map(|c| &c.valor) {
            Some(Valor::Secreto(s)) => Ok((s.clone(), false)),
            _ => Err(PerfilError::EntradaCorrupta),
        };
    }

    let frase = generador::frase(20, '-')?;
    let entrada = Entrada {
        id_origen: None,
        nombre: ENTRADA_VOLUMEN.to_string(),
        clase: Clase::Nota,
        carpeta: None,
        favorita: false,
        archivada: None,
        repreguntar: false,
        notas: None,
        campos: vec![Campo::personalizado(CAMPO_PASSPHRASE, Valor::Secreto(frase.clone()))],
        uris: Vec::new(),
        historial: Vec::new(),
        creada: Some(fecha::ahora_utc()),
        revisada: None,
    };
    boveda.anadir(entrada)?;
    boveda.guardar()?;
    Ok((frase, true))
}


#[cfg(test)]
mod pruebas {
    use super::{es_entrada_de_sistema, tomar_instancia_en, ENTRADA_VOLUMEN};

    #[test]
    fn el_cerrojo_de_instancia_es_exclusivo() {
        let ruta = std::env::temp_dir().join(format!("chuspa-inst-test-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&ruta);
        let a = tomar_instancia_en(ruta.clone());
        assert!(a.is_some(), "la 1ª instancia toma el cerrojo");
        let b = tomar_instancia_en(ruta.clone());
        assert!(b.is_none(), "la 2ª NO lo toma mientras la 1ª vive (así no limpia huérfanos)");
        drop(a);
        let c = tomar_instancia_en(ruta.clone());
        assert!(c.is_some(), "tras soltar la 1ª (pidfile borrado), se puede tomar de nuevo");
        drop(c);
        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn solo_la_entrada_del_volumen_es_de_sistema() {
        assert!(es_entrada_de_sistema(ENTRADA_VOLUMEN), "la del volumen se oculta");
        assert!(!es_entrada_de_sistema("Mi banco"), "una entrada normal NO se oculta");
        assert!(!es_entrada_de_sistema(""), "el nombre vacío no es de sistema");
        assert!(
            !es_entrada_de_sistema("Volumen cifrado · navegador"),
            "un nombre que solo EMPIEZA parecido no es la reservada (comparación exacta)"
        );
    }
}
