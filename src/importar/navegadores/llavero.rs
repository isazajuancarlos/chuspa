// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Obtiene del LLAVERO (Secret Service, D-Bus) el secreto «Safe Storage» que
//! Chromium/Brave/Edge usan para cifrar sus contraseñas con `os_crypt` v11.
//! Fase 3 del importador.
//!
//! # Por qué D-Bus a mano
//!
//! El árbol de chuspa es Rust exclusivo (deny.toml). El crate `dbus` enlaza la C
//! `libdbus`, y `zbus` no está vendorizado. Hablar el protocolo D-Bus tiene una
//! superficie acotada para lo único que hace falta aquí: conectarse al bus de
//! sesión, abrir una sesión de secretos, buscar el ítem del navegador y leer su
//! valor. Eso es lo que implementa este módulo — no una librería D-Bus general.
//!
//! # Qué se hace y qué no
//!
//! - Sesión con algoritmo `plain`: el secreto viaja por el socket UNIX del bus
//!   de sesión del propio usuario, que ya es tan privado como el llavero. No se
//!   negocia cifrado de transporte (Dh-ietf1024…) porque no cruza la máquina.
//! - Si la colección está BLOQUEADA, hoy se falla ruidosamente pidiendo
//!   desbloquearla en el llavero (el flujo de `Prompt` con interacción se deja
//!   para cuando la UI lo necesite). En la práctica el llavero `login` se
//!   desbloquea al iniciar sesión.
//! - El secreto se devuelve en `Zeroizing`: se borra de memoria al soltarse.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum ErrorLlavero {
    /// No hay bus de sesión (`DBUS_SESSION_BUS_ADDRESS` ausente o ilegible).
    SinBus,
    /// Falló la conexión o el diálogo con el bus.
    Io(std::io::Error),
    /// El servidor D-Bus respondió con un error; se conserva su nombre.
    Dbus(String),
    /// No hay ningún ítem de este navegador en el llavero (quizá usa `v10`).
    SinSecreto,
    /// Una respuesta no tuvo la forma esperada.
    Protocolo(&'static str),
}

impl From<std::io::Error> for ErrorLlavero {
    fn from(e: std::io::Error) -> Self {
        ErrorLlavero::Io(e)
    }
}

/// El secreto «Safe Storage» de un navegador de la familia Chromium.
///
/// `aplicacion` es la etiqueta con la que el navegador registró el ítem en el
/// llavero: `"brave"`, `"chrome"`, `"chromium"`, `"microsoft-edge"`. Devuelve el
/// secreto en claro (bytes) para pasárselo a [`super::oscrypt`], o `SinSecreto`
/// si el navegador no guardó nada en el llavero (entonces el llamante prueba
/// `v10` con `"peanuts"`).
pub fn secreto_de(aplicacion: &str) -> Result<Zeroizing<Vec<u8>>, ErrorLlavero> {
    let ruta = ruta_del_bus()?;
    let mut c = Conexion::conectar(&ruta)?;
    c.saludar()?;
    let sesion = c.abrir_sesion()?;
    let item = c.buscar_item(aplicacion)?.ok_or(ErrorLlavero::SinSecreto)?;
    c.leer_secreto(&item, &sesion)
}

/// Saca la ruta del socket de `DBUS_SESSION_BUS_ADDRESS`
/// (`unix:path=/run/user/1000/bus`, o `unix:abstract=…` que aquí no se maneja).
fn ruta_del_bus() -> Result<String, ErrorLlavero> {
    let dir = std::env::var("DBUS_SESSION_BUS_ADDRESS").map_err(|_| ErrorLlavero::SinBus)?;
    parsear_ruta_del_bus(&dir).ok_or(ErrorLlavero::SinBus)
}

/// Saca el `path=` de un `DBUS_SESSION_BUS_ADDRESS`. La dirección es
/// "<transporte>:clave=valor,clave=valor[;otra…]"; los pares se separan por
/// comas, y `dbus-daemon --print-address` emite `guid` DETRÁS del `path`
/// (`unix:path=/run/user/1000/bus,guid=…`). Hay que partir por comas SIEMPRE:
/// un `strip_prefix("unix:path=")` ansioso se llevaría el `,guid=…` pegado a la
/// ruta y la conexión fallaría en cualquier sesión sin systemd-user (medido:
/// falla con `NotFound` y se disfraza de «sin secreto»). Aparte para probarlo
/// sin tocar el entorno global del proceso.
fn parsear_ruta_del_bus(dir: &str) -> Option<String> {
    for parte in dir.split(';') {
        let Some(pares) = parte.strip_prefix("unix:") else { continue };
        for kv in pares.split(',') {
            if let Some(p) = kv.strip_prefix("path=") {
                return Some(p.to_string());
            }
        }
    }
    None
}

// ───────────────────────── conexión y protocolo ─────────────────────────

const DBUS: &str = "org.freedesktop.DBus";
const SECRETS: &str = "org.freedesktop.secrets";
const RUTA_SECRETS: &str = "/org/freedesktop/secrets";
const IF_SERVICE: &str = "org.freedesktop.Secret.Service";
const IF_ITEM: &str = "org.freedesktop.Secret.Item";

struct Conexion {
    flujo: UnixStream,
    serial: u32,
}

impl Conexion {
    fn conectar(ruta: &str) -> Result<Self, ErrorLlavero> {
        let mut flujo = UnixStream::connect(ruta)?;
        autenticar(&mut flujo)?;
        Ok(Conexion { flujo, serial: 0 })
    }

    /// Un `METHOD_CALL` y su respuesta (el cuerpo, ya sin cabecera). Traduce un
    /// `ERROR` de D-Bus a [`ErrorLlavero::Dbus`].
    fn llamar(
        &mut self,
        ruta: &str,
        interfaz: &str,
        miembro: &str,
        destino: &str,
        firma: &str,
        cuerpo: &[u8],
    ) -> Result<Vec<u8>, ErrorLlavero> {
        self.serial += 1;
        let mensaje = armar_llamada(self.serial, ruta, interfaz, miembro, destino, firma, cuerpo);
        self.flujo.write_all(&mensaje)?;
        self.flujo.flush()?;
        // El bus intercala SEÑALES (tipo 4, p.ej. `NameAcquired`) y podría meter
        // otros mensajes; se saltan hasta llegar al RETORNO o ERROR de la llamada.
        // Un tope evita quedarse escuchando para siempre si algo va mal.
        for _ in 0..64 {
            let (tipo, campos, cuerpo) = leer_mensaje(&mut self.flujo)?;
            match tipo {
                2 => return Ok(cuerpo),                                     // METHOD_RETURN
                3 => return Err(ErrorLlavero::Dbus(nombre_de_error(&campos))), // ERROR
                _ => continue, // SIGNAL u otro: no es para esta llamada
            }
        }
        Err(ErrorLlavero::Protocolo("no llegó respuesta a la llamada"))
    }

    fn saludar(&mut self) -> Result<(), ErrorLlavero> {
        self.llamar("/org/freedesktop/DBus", DBUS, "Hello", DBUS, "", &[])?;
        Ok(())
    }

    /// `OpenSession("plain", <variant "">)` → ruta de la sesión.
    fn abrir_sesion(&mut self) -> Result<String, ErrorLlavero> {
        let mut m = Marshal::nuevo();
        m.cadena("plain"); // algoritmo
        m.variante_cadena_vacia(); // input: variant("")
        let r = self.llamar(RUTA_SECRETS, IF_SERVICE, "OpenSession", SECRETS, "sv", &m.datos)?;
        // Respuesta "vo": una variante (output) y la ruta de la sesión.
        let mut d = Demarshal::nuevo(&r);
        d.saltar_variante()?;
        d.ruta()
    }

    /// `SearchItems({"application": app})` → primer ítem, o `None`.
    fn buscar_item(&mut self, app: &str) -> Result<Option<String>, ErrorLlavero> {
        let mut m = Marshal::nuevo();
        m.dict_ss(&[("application", app)]);
        let r = self.llamar(RUTA_SECRETS, IF_SERVICE, "SearchItems", SECRETS, "a{ss}", &m.datos)?;
        // Respuesta "aoao": desbloqueados y bloqueados.
        let mut d = Demarshal::nuevo(&r);
        let desbloqueados = d.array_de_rutas()?;
        let bloqueados = d.array_de_rutas()?;
        Ok(desbloqueados.into_iter().next().or_else(|| bloqueados.into_iter().next()))
    }

    /// `Item.GetSecret(session)` → los bytes del valor.
    fn leer_secreto(
        &mut self,
        item: &str,
        sesion: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorLlavero> {
        let mut m = Marshal::nuevo();
        m.ruta(sesion);
        let r = self.llamar(item, IF_ITEM, "GetSecret", SECRETS, "o", &m.datos)?;
        extraer_secreto_oayays(&r)
    }
}

/// Extrae el valor de una respuesta `Item.GetSecret`, un struct `(oayays)`:
/// (session, params, **value**, content_type). El secreto es el TERCER campo; el
/// segundo (`params`) se salta. Está aparte de [`Conexion::leer_secreto`] para
/// poder probar el demarshalling con una respuesta sintética, sin un bus vivo —
/// es el hueco que ningún verde local cubría (el parseo de respuestas solo lo
/// tocaba el test `#[ignore]` contra el llavero real).
fn extraer_secreto_oayays(r: &[u8]) -> Result<Zeroizing<Vec<u8>>, ErrorLlavero> {
    let mut d = Demarshal::nuevo(r);
    d.entrar_struct()?;
    d.saltar_ruta()?; // session
    d.saltar_array_bytes()?; // params
    let valor = d.array_bytes()?; // value ← el secreto
    Ok(Zeroizing::new(valor))
}

/// Handshake SASL EXTERNAL: byte nulo, AUTH con el uid en hex, BEGIN.
fn autenticar(flujo: &mut UnixStream) -> Result<(), ErrorLlavero> {
    // El uid, sin `unsafe`: el dueño de /proc/self es el proceso.
    let uid = std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0);
    let uid_hex: String = uid.to_string().bytes().map(|b| format!("{b:02x}")).collect();
    flujo.write_all(&[0])?;
    flujo.write_all(format!("AUTH EXTERNAL {uid_hex}\r\n").as_bytes())?;
    flujo.flush()?;
    let linea = leer_linea(flujo)?;
    if !linea.starts_with("OK") {
        return Err(ErrorLlavero::Protocolo("el bus rechazó la autenticación"));
    }
    flujo.write_all(b"BEGIN\r\n")?;
    flujo.flush()?;
    Ok(())
}

fn leer_linea(flujo: &mut UnixStream) -> Result<String, ErrorLlavero> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    loop {
        flujo.read_exact(&mut b)?;
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            buf.push(b[0]);
        }
        if buf.len() > 512 {
            return Err(ErrorLlavero::Protocolo("línea de auth demasiado larga"));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Arma un mensaje `METHOD_CALL` completo (cabecera + cuerpo), little-endian.
fn armar_llamada(
    serial: u32,
    ruta: &str,
    interfaz: &str,
    miembro: &str,
    destino: &str,
    firma: &str,
    cuerpo: &[u8],
) -> Vec<u8> {
    // Campos de cabecera: array de (byte, variant).
    let mut campos = Marshal::nuevo();
    campos.campo_ruta(1, ruta);
    if !interfaz.is_empty() {
        campos.campo_cadena(2, interfaz);
    }
    campos.campo_cadena(3, miembro);
    campos.campo_cadena(6, destino);
    if !firma.is_empty() {
        campos.campo_firma(8, firma);
    }

    // little-endian ('l'), METHOD_CALL (1), flags (0), versión (1).
    let mut m = vec![b'l', 1, 0, 1];
    m.extend_from_slice(&(cuerpo.len() as u32).to_le_bytes());
    m.extend_from_slice(&serial.to_le_bytes());
    m.extend_from_slice(&(campos.datos.len() as u32).to_le_bytes());
    m.extend_from_slice(&campos.datos);
    while m.len() % 8 != 0 {
        m.push(0); // el cuerpo empieza alineado a 8
    }
    m.extend_from_slice(cuerpo);
    m
}

/// Lee un mensaje D-Bus del socket. Devuelve (tipo, bytes de campos, bytes de cuerpo).
fn leer_mensaje(flujo: &mut UnixStream) -> Result<(u8, Vec<u8>, Vec<u8>), ErrorLlavero> {
    let mut fijo = [0u8; 16];
    flujo.read_exact(&mut fijo)?;
    if fijo[0] != b'l' {
        return Err(ErrorLlavero::Protocolo("solo se maneja little-endian"));
    }
    let tipo = fijo[1];
    let cuerpo_len = u32::from_le_bytes([fijo[4], fijo[5], fijo[6], fijo[7]]) as usize;
    let campos_len = u32::from_le_bytes([fijo[12], fijo[13], fijo[14], fijo[15]]) as usize;
    if cuerpo_len > 16 * 1024 * 1024 || campos_len > 1024 * 1024 {
        return Err(ErrorLlavero::Protocolo("mensaje absurdamente grande"));
    }
    let mut campos = vec![0u8; campos_len];
    flujo.read_exact(&mut campos)?;
    // El cuerpo empieza alineado a 8 desde el inicio del mensaje.
    let hasta_cuerpo = 16 + campos_len;
    let relleno = (8 - hasta_cuerpo % 8) % 8;
    let mut basura = vec![0u8; relleno];
    flujo.read_exact(&mut basura)?;
    let mut cuerpo = vec![0u8; cuerpo_len];
    flujo.read_exact(&mut cuerpo)?;
    Ok((tipo, campos, cuerpo))
}

/// Saca el nombre del error (campo de cabecera ERROR_NAME = código 4) de forma
/// tolerante: recorre el array de campos buscando el par cuyo código es 4.
fn nombre_de_error(campos: &[u8]) -> String {
    // Cada campo: struct(byte código, variant). Aquí basta un rastreo simple:
    // buscamos la firma "s" de un ERROR_NAME. Como recuperación, si algo no cuadra
    // se devuelve un genérico.
    let mut d = Demarshal { datos: campos, pos: 0 };
    while d.pos + 1 < campos.len() {
        d.alinear(8);
        if d.pos >= campos.len() {
            break;
        }
        let codigo = campos[d.pos];
        d.pos += 1;
        // variante: firma (g) + valor
        let Ok(firma) = d.firma() else { break };
        match firma.as_str() {
            "s" | "o" => {
                let Ok(s) = d.cadena_val() else { break };
                if codigo == 4 {
                    return s;
                }
            }
            "u" => {
                d.alinear(4);
                d.pos += 4;
            }
            "g" => {
                let _ = d.firma();
            }
            _ => break,
        }
    }
    "org.freedesktop.DBus.Error (desconocido)".into()
}

// ───────────────────────── marshalling ─────────────────────────

struct Marshal {
    datos: Vec<u8>,
}

impl Marshal {
    fn nuevo() -> Self {
        Marshal { datos: Vec::new() }
    }
    fn alinear(&mut self, n: usize) {
        while !self.datos.len().is_multiple_of(n) {
            self.datos.push(0);
        }
    }
    fn cadena(&mut self, s: &str) {
        self.alinear(4);
        self.datos.extend_from_slice(&(s.len() as u32).to_le_bytes());
        self.datos.extend_from_slice(s.as_bytes());
        self.datos.push(0);
    }
    fn ruta(&mut self, s: &str) {
        self.cadena(s); // OBJECT_PATH se marshalla igual que STRING
    }
    fn firma_val(&mut self, s: &str) {
        self.datos.push(s.len() as u8);
        self.datos.extend_from_slice(s.as_bytes());
        self.datos.push(0);
    }
    /// Una variante que contiene la cadena vacía: firma "s" + string "".
    fn variante_cadena_vacia(&mut self) {
        self.firma_val("s");
        self.cadena("");
    }
    /// Un `a{ss}` con los pares dados.
    fn dict_ss(&mut self, pares: &[(&str, &str)]) {
        self.alinear(4);
        // Se marshalla el contenido aparte para conocer su longitud en bytes.
        let mut cont = Marshal::nuevo();
        for (k, v) in pares {
            cont.alinear(8); // cada DICT_ENTRY se alinea a 8
            cont.cadena(k);
            cont.cadena(v);
        }
        self.datos.extend_from_slice(&(cont.datos.len() as u32).to_le_bytes());
        // El primer elemento se alinea a 8 tras la longitud del array.
        self.alinear(8);
        self.datos.extend_from_slice(&cont.datos);
    }
    // Campos de cabecera: cada uno es struct(byte, variant), alineado a 8.
    fn campo_cadena(&mut self, codigo: u8, s: &str) {
        self.alinear(8);
        self.datos.push(codigo);
        self.firma_val("s");
        self.cadena(s);
    }
    fn campo_ruta(&mut self, codigo: u8, s: &str) {
        self.alinear(8);
        self.datos.push(codigo);
        self.firma_val("o");
        self.ruta(s);
    }
    fn campo_firma(&mut self, codigo: u8, s: &str) {
        self.alinear(8);
        self.datos.push(codigo);
        self.firma_val("g");
        self.firma_val(s);
    }
}

// ───────────────────────── demarshalling ─────────────────────────

struct Demarshal<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Demarshal<'a> {
    fn nuevo(datos: &'a [u8]) -> Self {
        Demarshal { datos, pos: 0 }
    }
    fn alinear(&mut self, n: usize) {
        while !self.pos.is_multiple_of(n) {
            self.pos += 1;
        }
    }
    fn u32(&mut self) -> Result<u32, ErrorLlavero> {
        self.alinear(4);
        let b = self.datos.get(self.pos..self.pos + 4).ok_or(ErrorLlavero::Protocolo("u32 corto"))?;
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn cadena_val(&mut self) -> Result<String, ErrorLlavero> {
        let n = self.u32()? as usize;
        let b = self.datos.get(self.pos..self.pos + n).ok_or(ErrorLlavero::Protocolo("cadena corta"))?;
        self.pos += n + 1; // + nul
        Ok(String::from_utf8_lossy(b).into_owned())
    }
    fn ruta(&mut self) -> Result<String, ErrorLlavero> {
        self.cadena_val()
    }
    fn saltar_ruta(&mut self) -> Result<(), ErrorLlavero> {
        self.cadena_val().map(|_| ())
    }
    fn firma(&mut self) -> Result<String, ErrorLlavero> {
        let n = *self.datos.get(self.pos).ok_or(ErrorLlavero::Protocolo("firma corta"))? as usize;
        self.pos += 1;
        let b = self.datos.get(self.pos..self.pos + n).ok_or(ErrorLlavero::Protocolo("firma corta"))?;
        self.pos += n + 1; // + nul
        Ok(String::from_utf8_lossy(b).into_owned())
    }
    /// Salta una variante (firma + valor) — solo los tipos que aparecen aquí.
    fn saltar_variante(&mut self) -> Result<(), ErrorLlavero> {
        let firma = self.firma()?;
        match firma.as_str() {
            "s" | "o" => {
                self.cadena_val()?;
            }
            "u" => {
                self.u32()?;
            }
            "g" => {
                self.firma()?;
            }
            "ay" => {
                self.saltar_array_bytes()?;
            }
            "" => {}
            _ => return Err(ErrorLlavero::Protocolo("variante de tipo no manejado")),
        }
        Ok(())
    }
    /// Un array de OBJECT_PATH (`ao`).
    fn array_de_rutas(&mut self) -> Result<Vec<String>, ErrorLlavero> {
        let n = self.u32()? as usize;
        let fin = self.pos + n;
        let mut v = Vec::new();
        while self.pos < fin {
            v.push(self.ruta()?);
        }
        self.pos = fin;
        Ok(v)
    }
    /// Un array de bytes (`ay`): devuelve los bytes.
    fn array_bytes(&mut self) -> Result<Vec<u8>, ErrorLlavero> {
        let n = self.u32()? as usize;
        let b = self.datos.get(self.pos..self.pos + n).ok_or(ErrorLlavero::Protocolo("ay corto"))?;
        self.pos += n;
        Ok(b.to_vec())
    }
    fn saltar_array_bytes(&mut self) -> Result<(), ErrorLlavero> {
        let n = self.u32()? as usize;
        self.pos += n;
        Ok(())
    }
    /// Entra en un struct: solo alinea a 8.
    fn entrar_struct(&mut self) -> Result<(), ErrorLlavero> {
        self.alinear(8);
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_cadena_se_marshalla_con_longitud_y_nul() {
        let mut m = Marshal::nuevo();
        m.cadena("plain");
        // u32(5) LE + "plain" + \0
        assert_eq!(&m.datos[..4], &5u32.to_le_bytes());
        assert_eq!(&m.datos[4..9], b"plain");
        assert_eq!(m.datos[9], 0);
    }

    #[test]
    fn el_dict_ss_alinea_y_mide() {
        let mut m = Marshal::nuevo();
        m.dict_ss(&[("application", "brave")]);
        // Longitud del array (u32) + contenido; el contenido empieza alineado a 8.
        let n = u32::from_le_bytes(m.datos[..4].try_into().unwrap()) as usize;
        assert_eq!(m.datos.len(), 8 + n, "tras el u32 hay 4 de relleno hasta 8, luego el contenido");
    }

    #[test]
    fn ida_y_vuelta_de_un_array_de_rutas() {
        // Marshalla "aoao" a mano y lo lee.
        let mut cont = Marshal::nuevo();
        cont.ruta("/org/freedesktop/secrets/collection/login/1");
        let mut m = Marshal::nuevo();
        m.datos.extend_from_slice(&(cont.datos.len() as u32).to_le_bytes());
        m.datos.extend_from_slice(&cont.datos);
        // segundo array vacío
        m.datos.extend_from_slice(&0u32.to_le_bytes());
        let mut d = Demarshal::nuevo(&m.datos);
        let a = d.array_de_rutas().unwrap();
        let b = d.array_de_rutas().unwrap();
        assert_eq!(a, ["/org/freedesktop/secrets/collection/login/1"]);
        assert!(b.is_empty());
    }

    #[test]
    fn la_firma_se_lee_con_su_longitud_de_un_byte() {
        let mut m = Marshal::nuevo();
        m.firma_val("a{ss}");
        let mut d = Demarshal::nuevo(&m.datos);
        assert_eq!(d.firma().unwrap(), "a{ss}");
    }

    /// Regresión del hallazgo del concilio (fable, conf 10, medido): la forma
    /// ESTÁNDAR con el `guid` detrás del `path` tiene que dar la ruta pelada, no
    /// arrastrar el `,guid=…`. Y su control: la forma con `guid` delante también.
    #[test]
    fn la_ruta_del_bus_ignora_el_guid_venga_donde_venga() {
        // guid DETRÁS (lo que emite dbus-daemon): el caso que rompía.
        assert_eq!(
            parsear_ruta_del_bus("unix:path=/run/user/1000/bus,guid=abc123").as_deref(),
            Some("/run/user/1000/bus")
        );
        // guid DELANTE (control): ya funcionaba, debe seguir.
        assert_eq!(
            parsear_ruta_del_bus("unix:guid=abc123,path=/run/user/1000/bus").as_deref(),
            Some("/run/user/1000/bus")
        );
        // Ruta pelada (Debian/GNOME): sin cambios.
        assert_eq!(
            parsear_ruta_del_bus("unix:path=/tmp/dbus-xyz").as_deref(),
            Some("/tmp/dbus-xyz")
        );
        // Sin `path` (p.ej. `unix:abstract=…`, no soportado): None, no una ruta falsa.
        assert_eq!(parsear_ruta_del_bus("unix:abstract=/tmp/dbus-abc,guid=z"), None);
    }

    /// Marshalla un array de bytes (`ay`): u32 de longitud (alineado a 4) + los
    /// bytes crudos, sin nul. Es lo que el bus manda para `params` y `value`.
    fn ay(m: &mut Marshal, bytes: &[u8]) {
        m.alinear(4);
        m.datos.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        m.datos.extend_from_slice(bytes);
    }

    /// Cierra el hueco que el concilio (fase 5) señaló: NINGÚN verde local
    /// vigilaba el demarshalling de la RESPUESTA de `GetSecret`. Construye una
    /// respuesta `(oayays)` sintética con los tres primeros campos DISTINGUIBLES
    /// y comprueba que sale el TERCERO (value), no el segundo (params). El caso
    /// rojo —quitar el salto de `params`— hace que salga `params`, y esta prueba
    /// lo detecta (D33), porque corre la MISMA `extraer_secreto_oayays` del código.
    #[test]
    fn el_secreto_es_el_tercer_campo_de_la_respuesta_no_el_segundo() {
        let mut m = Marshal::nuevo();
        m.ruta("/org/freedesktop/secrets/session/s1"); // session (o)
        ay(&mut m, &[0xAA, 0xBB, 0xCC]); // params (ay) — NO es el secreto
        let secreto_real: &[u8] = b"clave-os-crypt-de-treintaydos-by"; // value (ay)
        ay(&mut m, secreto_real);
        m.cadena("application/octet-stream"); // content_type (s), no se lee

        let out = extraer_secreto_oayays(&m.datos).unwrap();
        assert_eq!(&out[..], secreto_real, "debe salir el value (3.º), no params (2.º)");
        assert_ne!(&out[..], &[0xAA, 0xBB, 0xCC], "no debe confundir params con el secreto");
    }

    // La prueba contra el llavero REAL necesita un Secret Service vivo, que no
    // existe en CI/headless. Se corre a mano donde sí lo hay:
    //   cargo test --release llavero_vivo -- --ignored --nocapture
    #[test]
    #[ignore = "necesita un Secret Service (gnome-keyring) vivo"]
    fn llavero_vivo() {
        match secreto_de("brave") {
            Ok(s) => {
                assert!(!s.is_empty(), "el secreto no puede venir vacío");
                println!("OK: secreto de Brave, {} bytes (no se imprime)", s.len());
            }
            Err(ErrorLlavero::SinSecreto) => println!("no hay ítem de Brave en el llavero (¿v10?)"),
            Err(e) => panic!("fallo hablando con el llavero: {e:?}"),
        }
    }
}
