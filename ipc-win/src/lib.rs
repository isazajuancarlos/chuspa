// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Transporte local provider<->agente de Chuspa en Windows, sobre **named pipes**.
//!
//! Da la misma forma de API que `std::os::unix::net`, para que el núcleo
//! (`chuspa::navegador`) use `#[cfg(windows)] use chuspa_ipc_win::{UnixListener,
//! UnixStream}` y el cuerpo de `escuchar_en`/`consultar_al_agente` no cambie:
//!
//! - [`UnixStream::connect`] (cliente), [`UnixStream::try_clone`],
//!   [`UnixStream::set_read_timeout`], y `Read`/`Write`.
//! - [`UnixListener::bind`] (crea ya la primera instancia, como hace `bind` con el
//!   socket) e [`UnixListener::incoming`] (bloquea hasta que un cliente conecta).
//!
//! La RUTA que recibe la API no es un archivo: se usa como **clave** y se deriva
//! de ella un nombre de pipe determinista (`\\.\pipe\chuspa.<hash>`). Así el
//! agente y el provider —que pasan la misma `ruta_del_socket()`— acaban en el
//! mismo pipe, y una prueba que pasa una ruta temporal propia obtiene un pipe
//! aislado sin tocar el real. El marco de 4 bytes + JSON del `protocolo` viaja
//! idéntico sobre el pipe en modo BYTE.
//!
//! Todo el `unsafe` del FFI Win32 vive aquí; `chuspa` conserva `forbid(unsafe)`.

#![cfg(windows)]

use std::cell::Cell;
use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

// ── Constantes Win32 ─────────────────────────────────────────────────────────
const INVALID_HANDLE_VALUE: isize = -1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const PIPE_ACCESS_DUPLEX: u32 = 0x3;
// modo BYTE (0) + espera bloqueante (0) + rechazar clientes remotos (0x8).
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const DUPLICATE_SAME_ACCESS: u32 = 0x2;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_USER_CLASS: i32 = 1; // TOKEN_INFORMATION_CLASS::TokenUser
const SDDL_REVISION_1: u32 = 1;
const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_BROKEN_PIPE: u32 = 109;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
const ERROR_IO_PENDING: u32 = 997;
const ERROR_PIPE_CONNECTED: u32 = 535;

// Anti-okupación del nombre de pipe (concilio 2026-10-10): `\\.\pipe\` es un
// espacio GLOBAL de la máquina y el nombre es derivable, así que otro principal
// local podría crear el pipe ANTES que el agente y recibir las peticiones. La
// DACL protege las instancias del agente, no el NOMBRE. Dos defensas:
//  - el agente crea su PRIMERA instancia con FIRST_PIPE_INSTANCE → si el nombre ya
//    existe, `CreateNamedPipeW` falla con ACCESS_DENIED (detecta al okupa / a un
//    segundo agente, restaurando la semántica Unix de «address in use»);
//  - el cliente abre con SQOS=IDENTIFICATION (el servidor no puede IMPERSONARLO) y
//    verifica que el SID dueño del proceso servidor es el suyo (cubre el caso en que
//    el agente no corre y el cliente se toparía con el pipe del okupa).
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000; // SecurityIdentification (1) << 16
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

// Buffers del pipe: holgados para un mensaje CTAP2 (pequeño) sin trocear.
const BUF: u32 = 64 * 1024;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: isize,
}

impl Overlapped {
    fn con_evento(ev: isize) -> Self {
        Overlapped { internal: 0, internal_high: 0, offset: 0, offset_high: 0, h_event: ev }
    }
}

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct TokenUser {
    user: SidAndAttributes,
}

unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer: u32,
        in_buffer: u32,
        default_timeout: u32,
        security: *const SecurityAttributes,
    ) -> isize;
    fn ConnectNamedPipe(h: isize, overlapped: *mut Overlapped) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: isize,
    ) -> isize;
    fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
    fn ReadFile(h: isize, buf: *mut u8, n: u32, read: *mut u32, overlapped: *mut Overlapped) -> i32;
    fn WriteFile(h: isize, buf: *const u8, n: u32, written: *mut u32, overlapped: *mut Overlapped) -> i32;
    fn GetOverlappedResult(h: isize, overlapped: *mut Overlapped, n: *mut u32, wait: i32) -> i32;
    fn CancelIoEx(h: isize, overlapped: *mut Overlapped) -> i32;
    fn CreateEventW(security: *const c_void, manual: i32, initial: i32, name: *const u16) -> isize;
    fn ResetEvent(h: isize) -> i32;
    fn WaitForSingleObject(h: isize, ms: u32) -> u32;
    fn CloseHandle(h: isize) -> i32;
    fn DuplicateHandle(
        src_proc: isize,
        src: isize,
        tgt_proc: isize,
        tgt: *mut isize,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn GetCurrentProcess() -> isize;
    fn GetLastError() -> u32;
    fn LocalFree(h: *mut c_void) -> *mut c_void;
    fn GetNamedPipeServerProcessId(pipe: isize, pid: *mut u32) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(proc: isize, access: u32, token: *mut isize) -> i32;
    fn GetTokenInformation(token: isize, class: i32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        psd: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}

// ── Utilidades ───────────────────────────────────────────────────────────────

fn err_ultimo() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn a_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Lee una cadena UTF-16 NUL-terminada que devolvió una API Win32.
///
/// # Safety
/// `p` apunta a una cadena de anchos válida y NUL-terminada.
unsafe fn de_wide(p: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: recorrido hasta el NUL de una cadena válida (contrato del llamante).
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    let s = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(s)
}

/// Nombre de pipe determinista a partir de la ruta-clave. Minúsculas para que dos
/// formas de la misma ruta coincidan; hash estable (djb2) para quedar corto y
/// válido. El nombre es PÚBLICO y adivinable, así que NO da aislamiento por sí
/// solo: la exclusividad la da `FIRST_PIPE_INSTANCE` en `bind` (detecta al que
/// ocupa el nombre antes) y la verificación del SID dueño del servidor en
/// `connect`; la confidencialidad del contenido, la DACL de cada instancia.
fn nombre_pipe(ruta: &Path) -> Vec<u16> {
    let clave = ruta.to_string_lossy().to_lowercase();
    let mut h: u64 = 5381;
    for b in clave.bytes() {
        h = (h.wrapping_shl(5).wrapping_add(h)) ^ u64::from(b);
    }
    a_wide(&format!(r"\\.\pipe\chuspa.{h:016x}"))
}

/// Descriptor de seguridad que concede SOLO al usuario dueño, SYSTEM y
/// Administradores (paridad con el `0600` del socket Unix). Sin esto el pipe daría
/// lectura a Everyone, que para un IPC de passkeys sería una fuga de confidencialidad.
struct Descriptor {
    psd: *mut c_void,
}

/// El SID (como cadena `S-1-5-…`) del usuario de un token ya abierto.
///
/// # Safety
/// `token` es un handle de token válido abierto con `TOKEN_QUERY`.
unsafe fn sid_de_token(token: isize) -> io::Result<String> {
    unsafe {
        // Primer `GetTokenInformation` FALLA a propósito para dar el tamaño.
        let mut len: u32 = 0;
        GetTokenInformation(token, TOKEN_USER_CLASS, ptr::null_mut(), 0, &mut len);
        if len == 0 {
            return Err(err_ultimo());
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(token, TOKEN_USER_CLASS, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(err_ultimo());
        }
        let tu = &*(buf.as_ptr() as *const TokenUser);
        let mut sid_str: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(tu.user.sid, &mut sid_str) == 0 {
            return Err(err_ultimo());
        }
        let s = de_wide(sid_str);
        LocalFree(sid_str.cast());
        Ok(s)
    }
}

/// El SID del usuario de ESTE proceso.
fn sid_actual() -> io::Result<String> {
    // SAFETY: token del proceso propio; se cierra siempre antes de salir.
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(err_ultimo());
        }
        let r = sid_de_token(token);
        CloseHandle(token);
        r
    }
}

/// El SID del usuario DUEÑO del proceso `pid`. Un fallo al abrir/consultar (p. ej.
/// el proceso es de OTRO usuario y no se puede abrir) se propaga como error, y el
/// llamante lo trata como «no verificable» = rechazar (fail-closed).
fn sid_de_proceso(pid: u32) -> io::Result<String> {
    // SAFETY: handles de proceso y token cerrados en todas las salidas.
    unsafe {
        let hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if hp == 0 {
            return Err(err_ultimo());
        }
        let mut token: isize = 0;
        if OpenProcessToken(hp, TOKEN_QUERY, &mut token) == 0 {
            let e = err_ultimo();
            CloseHandle(hp);
            return Err(e);
        }
        let r = sid_de_token(token);
        CloseHandle(token);
        CloseHandle(hp);
        r
    }
}

impl Descriptor {
    fn solo_usuario() -> io::Result<Descriptor> {
        let sid = sid_actual()?;
        // GA = GENERIC_ALL; SY = LocalSystem; BA = Administradores. `P` = DACL
        // protegida (no hereda ACEs), así que NADIE más entra.
        let sddl = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)");
        let sddl_w = a_wide(&sddl);
        let mut psd: *mut c_void = ptr::null_mut();
        // SAFETY: SDDL NUL-terminado; `psd` out-param que libera `Drop` con `LocalFree`.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(err_ultimo());
        }
        Ok(Descriptor { psd })
    }

    fn atributos(&self) -> SecurityAttributes {
        SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: self.psd,
            b_inherit_handle: 0,
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: `psd` lo asignó `ConvertString...SecurityDescriptor...`, que pide
        // liberarlo con `LocalFree`.
        unsafe {
            LocalFree(self.psd);
        }
    }
}

// El SD es solo un puntero que se mueve con el listener a su hilo de `accept`.
unsafe impl Send for Descriptor {}

fn crear_evento() -> io::Result<isize> {
    // Manual-reset, sin señalar: cada operación hace `ResetEvent` antes de empezar.
    let h = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if h == 0 {
        return Err(err_ultimo());
    }
    Ok(h)
}

// ── UnixStream (named pipe, dúplex) ──────────────────────────────────────────

/// Una conexión de pipe. Lee y escribe por I/O superpuesta (overlapped) sobre el
/// MISMO handle; el `set_read_timeout` acota la lectura (la respuesta del agente
/// puede tardar hasta 90 s mientras el usuario aprueba la firma).
pub struct UnixStream {
    h: isize,
    ev: isize,
    timeout: Option<Duration>,
}

// Un handle de pipe es un valor de kernel; moverlo entre hilos es seguro (el
// núcleo lo hace: una conexión se atiende en su propio hilo).
unsafe impl Send for UnixStream {}

impl UnixStream {
    /// Cliente: abre el pipe que el agente publicó para esta ruta-clave.
    ///
    /// `ERROR_FILE_NOT_FOUND` = no hay agente escuchando → falla YA (como un
    /// `connect` Unix a un socket inexistente). `ERROR_PIPE_BUSY` = el pipe existe
    /// pero todas sus instancias están ocupadas → espera una instancia libre con
    /// tope (D39), que es el patrón de cliente de named pipe ante ráfagas.
    pub fn connect<P: AsRef<Path>>(ruta: P) -> io::Result<UnixStream> {
        let nombre = nombre_pipe(ruta.as_ref());
        // El SID propio, para verificar que el servidor del pipe es de este usuario
        // (anti-okupación: un impostor de otro principal tendría otro SID). Se calcula
        // una vez; si no se puede, no se conecta (fail-closed).
        let sid_mio = sid_actual()?;
        let limite = Instant::now() + Duration::from_secs(30);
        loop {
            let h = unsafe {
                CreateFileW(
                    nombre.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    // SQOS=IDENTIFICATION: el servidor puede IDENTIFICAR al cliente pero
                    // NO impersonarlo, cortando la escalada por `ImpersonateNamedPipeClient`.
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    0,
                )
            };
            if h != INVALID_HANDLE_VALUE {
                // Verifica que el DUEÑO del proceso servidor es este mismo usuario. Si
                // no se puede confirmar (proceso de otro usuario que no se puede abrir,
                // o SID distinto), se rechaza: no se le habla a un impostor.
                let mut pid: u32 = 0;
                if unsafe { GetNamedPipeServerProcessId(h, &mut pid) } == 0 {
                    let e = err_ultimo();
                    unsafe { CloseHandle(h) };
                    return Err(e);
                }
                match sid_de_proceso(pid) {
                    Ok(sid_srv) if sid_srv == sid_mio => {}
                    _ => {
                        unsafe { CloseHandle(h) };
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "el servidor del pipe no pertenece a este usuario (posible suplantación)",
                        ));
                    }
                }
                let ev = match crear_evento() {
                    Ok(ev) => ev,
                    Err(e) => {
                        unsafe { CloseHandle(h) };
                        return Err(e);
                    }
                };
                return Ok(UnixStream { h, ev, timeout: None });
            }
            let e = unsafe { GetLastError() };
            if e == ERROR_PIPE_BUSY && Instant::now() < limite {
                // Espera a que una instancia quede libre; 250 ms y reintenta.
                unsafe { WaitNamedPipeW(nombre.as_ptr(), 250) };
                continue;
            }
            return Err(io::Error::from_raw_os_error(e as i32));
        }
    }

    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.timeout = dur;
        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<UnixStream> {
        let mut dup: isize = 0;
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.h,
                GetCurrentProcess(),
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(err_ultimo());
        }
        let ev = match crear_evento() {
            Ok(ev) => ev,
            Err(e) => {
                unsafe { CloseHandle(dup) };
                return Err(e);
            }
        };
        Ok(UnixStream { h: dup, ev, timeout: self.timeout })
    }
}

impl Read for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        unsafe { ResetEvent(self.ev) };
        let mut ov = Overlapped::con_evento(self.ev);
        let mut leidos: u32 = 0;
        let n = buf.len().min(u32::MAX as usize) as u32;
        let r = unsafe { ReadFile(self.h, buf.as_mut_ptr(), n, &mut leidos, &mut ov) };
        if r != 0 {
            return Ok(leidos as usize);
        }
        let e = unsafe { GetLastError() };
        if e != ERROR_IO_PENDING {
            // El par cerró su extremo: para un stream es EOF (`Ok(0)`), como en Unix.
            if e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let ms = self.timeout.map_or(INFINITE, |d| d.as_millis().min(u128::from(u32::MAX - 1)) as u32);
        if unsafe { WaitForSingleObject(self.ev, ms) } != WAIT_OBJECT_0 {
            // Tope vencido: cancela la lectura pendiente y recógela antes de salir,
            // para que `ov` no quede viva tras volver (la pila la reclama).
            unsafe {
                CancelIoEx(self.h, &mut ov);
                let mut _d: u32 = 0;
                GetOverlappedResult(self.h, &mut ov, &mut _d, 1);
            }
            return Err(io::Error::new(io::ErrorKind::TimedOut, "lectura del pipe agotó el plazo"));
        }
        let mut hechos: u32 = 0;
        if unsafe { GetOverlappedResult(self.h, &mut ov, &mut hechos, 1) } == 0 {
            let e2 = unsafe { GetLastError() };
            if e2 == ERROR_BROKEN_PIPE || e2 == ERROR_PIPE_NOT_CONNECTED {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(e2 as i32));
        }
        Ok(hechos as usize)
    }
}

impl Write for UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        unsafe { ResetEvent(self.ev) };
        let mut ov = Overlapped::con_evento(self.ev);
        let mut escritos: u32 = 0;
        let n = buf.len().min(u32::MAX as usize) as u32;
        let r = unsafe { WriteFile(self.h, buf.as_ptr(), n, &mut escritos, &mut ov) };
        if r != 0 {
            return Ok(escritos as usize);
        }
        let e = unsafe { GetLastError() };
        if e != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        // La escritura no tiene tope aparte: espera a que el núcleo la complete.
        unsafe { WaitForSingleObject(self.ev, INFINITE) };
        let mut hechos: u32 = 0;
        if unsafe { GetOverlappedResult(self.h, &mut ov, &mut hechos, 1) } == 0 {
            return Err(err_ultimo());
        }
        Ok(hechos as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No se usa `FlushFileBuffers`: en un pipe BLOQUEA hasta que el par lee todo
        // lo pendiente, y aquí el envío ya salió con `WriteFile`. Igual que el Unix.
        Ok(())
    }
}

impl Drop for UnixStream {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.h);
            CloseHandle(self.ev);
        }
    }
}

// ── UnixListener (named pipe) ────────────────────────────────────────────────

/// Escucha en el pipe de una ruta-clave. `bind` crea YA la primera instancia (como
/// `bind` de un socket hace existir el archivo), así que un `connect` inmediato no
/// ve `FILE_NOT_FOUND`. Cada `accept` entrega la instancia conectada y deja otra
/// escuchando, para que el nombre nunca quede sin instancia.
pub struct UnixListener {
    nombre: Vec<u16>,
    sd: Descriptor,
    siguiente: Cell<isize>, // instancia pre-creada a la espera (0 = ninguna)
}

unsafe impl Send for UnixListener {}

impl UnixListener {
    pub fn bind<P: AsRef<Path>>(ruta: P) -> io::Result<UnixListener> {
        let nombre = nombre_pipe(ruta.as_ref());
        let sd = Descriptor::solo_usuario()?;
        let primera = crear_instancia(&nombre, &sd, true).map_err(|e| {
            // El nombre ya existía (FIRST_PIPE_INSTANCE + ACCESS_DENIED): otro agente
            // vivo o un impostor ocupa el pipe. Como el `bind` de un socket Unix sobre
            // una dirección en uso, se avisa en vez de robarle el sitio ni sumarse.
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "el pipe de chuspa ya está ocupado (otro agente vivo, o un impostor adelantándose)",
                )
            } else {
                e
            }
        })?;
        Ok(UnixListener { nombre, sd, siguiente: Cell::new(primera) })
    }

    /// Bloquea hasta que un cliente conecta y devuelve su conexión.
    pub fn accept(&self) -> io::Result<UnixStream> {
        // Toma la instancia a la espera (o crea una si faltara).
        let h = match self.siguiente.replace(0) {
            0 => crear_instancia(&self.nombre, &self.sd, false)?,
            h => h,
        };
        // Deja otra instancia escuchando ANTES de bloquear en esta, para que una
        // ráfaga de clientes reciba ERROR_PIPE_BUSY (que el cliente reintenta) en
        // vez de ERROR_FILE_NOT_FOUND (que falla).
        match crear_instancia(&self.nombre, &self.sd, false) {
            Ok(n) => self.siguiente.set(n),
            Err(_) => self.siguiente.set(0),
        }

        let ev = crear_evento()?;
        let mut ov = Overlapped::con_evento(ev);
        let r = unsafe { ConnectNamedPipe(h, &mut ov) };
        let ok = if r != 0 {
            true
        } else {
            let e = unsafe { GetLastError() };
            if e == ERROR_PIPE_CONNECTED {
                // Un cliente conectó entre `CreateNamedPipe` y `ConnectNamedPipe`.
                true
            } else if e == ERROR_IO_PENDING {
                unsafe { WaitForSingleObject(ev, INFINITE) };
                let mut _d: u32 = 0;
                unsafe { GetOverlappedResult(h, &mut ov, &mut _d, 1) != 0 }
            } else {
                false
            }
        };
        unsafe { CloseHandle(ev) };
        if !ok {
            let e = err_ultimo();
            unsafe { CloseHandle(h) };
            return Err(e);
        }
        let ev_flujo = match crear_evento() {
            Ok(ev) => ev,
            Err(e) => {
                unsafe { CloseHandle(h) };
                return Err(e);
            }
        };
        Ok(UnixStream { h, ev: ev_flujo, timeout: None })
    }

    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { lis: self }
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        let h = self.siguiente.replace(0);
        if h != 0 {
            unsafe { CloseHandle(h) };
        }
    }
}

/// Iterador de conexiones entrantes, gemelo de `std::os::unix::net::Incoming`.
pub struct Incoming<'a> {
    lis: &'a UnixListener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<UnixStream>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.lis.accept())
    }
}

/// Crea una instancia del named pipe en modo BYTE + overlapped, con la DACL del
/// descriptor. El par del cliente se conecta con `CreateFileW`.
fn crear_instancia(nombre: &[u16], sd: &Descriptor, primera: bool) -> io::Result<isize> {
    let sa = sd.atributos();
    // La PRIMERA instancia (la de `bind`) lleva FIRST_PIPE_INSTANCE: si el nombre ya
    // existe (okupa o un segundo agente), `CreateNamedPipeW` falla con ACCESS_DENIED
    // y el agente lo detecta en vez de sumarse en silencio al pipe ajeno.
    let open_mode =
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if primera { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    let h = unsafe {
        CreateNamedPipeW(
            nombre.as_ptr(),
            open_mode,
            PIPE_REJECT_REMOTE_CLIENTS, // modo BYTE (0) + bloqueante (0)
            PIPE_UNLIMITED_INSTANCES,
            BUF,
            BUF,
            0,
            &sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(err_ultimo());
    }
    Ok(h)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ruta_unica(tag: &str) -> std::path::PathBuf {
        let n = std::process::id();
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chuspa-ipc-{tag}-{n}-{t}.sock"))
    }

    /// Enmarca como el `protocolo`: u32 nativo + cuerpo. Round-trip por el pipe real.
    fn escribir(f: &mut UnixStream, msg: &[u8]) {
        f.write_all(&(msg.len() as u32).to_ne_bytes()).unwrap();
        f.write_all(msg).unwrap();
        f.flush().unwrap();
    }
    fn leer(f: &mut UnixStream) -> Vec<u8> {
        let mut cab = [0u8; 4];
        f.read_exact(&mut cab).unwrap();
        let n = u32::from_ne_bytes(cab) as usize;
        let mut cuerpo = vec![0u8; n];
        f.read_exact(&mut cuerpo).unwrap();
        cuerpo
    }

    #[test]
    fn ida_y_vuelta_enmarcado_por_el_pipe_real() {
        let ruta = ruta_unica("rt");
        let lis = UnixListener::bind(&ruta).unwrap();
        let servidor = std::thread::spawn(move || {
            let mut c = lis.accept().unwrap();
            let pedido = leer(&mut c);
            // eco en mayúsculas, para que la respuesta DIFIERA del pedido.
            let resp: Vec<u8> = pedido.iter().map(|b| b.to_ascii_uppercase()).collect();
            escribir(&mut c, &resp);
        });

        let mut cli = UnixStream::connect(&ruta).unwrap();
        escribir(&mut cli, b"hola-agente");
        assert_eq!(leer(&mut cli), b"HOLA-AGENTE");
        servidor.join().unwrap();
    }

    #[test]
    fn connect_sin_agente_falla_ya() {
        // Nadie hizo `bind`: el pipe no existe → connect falla rápido, no cuelga.
        let ruta = ruta_unica("vacio");
        let t0 = Instant::now();
        let r = UnixStream::connect(&ruta);
        assert!(r.is_err(), "connect a un pipe inexistente debe fallar");
        assert!(t0.elapsed() < Duration::from_secs(2), "debe fallar YA, no reintentar 30 s");
    }

    #[test]
    fn el_plazo_de_lectura_vence_cuando_el_par_calla() {
        // El par acepta pero NO responde: la lectura con tope debe vencer (TimedOut),
        // no bloquear para siempre. Caso rojo del `set_read_timeout`.
        let ruta = ruta_unica("plazo");
        let lis = UnixListener::bind(&ruta).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let servidor = std::thread::spawn(move || {
            let _c = lis.accept().unwrap();
            // Retiene la conexión abierta sin escribir hasta que la prueba termina.
            let _ = rx.recv();
        });
        let mut cli = UnixStream::connect(&ruta).unwrap();
        cli.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut cab = [0u8; 4];
        let t0 = Instant::now();
        let r = cli.read(&mut cab);
        assert!(matches!(r, Err(ref e) if e.kind() == io::ErrorKind::TimedOut), "esperaba TimedOut, fue {r:?}");
        assert!(t0.elapsed() < Duration::from_secs(5), "venció tarde");
        let _ = tx.send(());
        servidor.join().unwrap();
    }

    #[test]
    fn muchas_conexiones_en_rafaga_se_atienden_todas() {
        // Gemelo de `una_firma_lenta_no_congela_el_resto`: la ráfaga choca con
        // ERROR_PIPE_BUSY y el cliente reintenta; todas deben completar.
        let ruta = ruta_unica("rafaga");
        let lis = UnixListener::bind(&ruta).unwrap();
        let servidor = std::thread::spawn(move || {
            for _ in 0..60 {
                let mut c = match lis.accept() {
                    Ok(c) => c,
                    Err(_) => break,
                };
                std::thread::spawn(move || {
                    let p = leer(&mut c);
                    escribir(&mut c, &p);
                });
            }
        });
        let mut hilos = Vec::new();
        for i in 0..60u32 {
            let ruta = ruta.clone();
            hilos.push(std::thread::spawn(move || {
                let mut cli = UnixStream::connect(&ruta).unwrap();
                let msg = format!("n{i}");
                escribir(&mut cli, msg.as_bytes());
                assert_eq!(leer(&mut cli), msg.as_bytes());
            }));
        }
        for h in hilos {
            h.join().unwrap();
        }
        servidor.join().unwrap();
    }

    #[test]
    fn el_nombre_es_determinista_y_distinto_por_ruta() {
        let a = nombre_pipe(Path::new(r"C:\Users\x\AppData\Local\chuspa\agente.sock"));
        let a2 = nombre_pipe(Path::new(r"C:\Users\X\AppData\Local\chuspa\agente.sock")); // mayúsc.
        let b = nombre_pipe(Path::new(r"C:\Temp\otra.sock"));
        assert_eq!(a, a2, "la misma ruta (sin importar caja) da el mismo pipe");
        assert_ne!(a, b, "rutas distintas dan pipes distintos");
    }

    /// Guardián anti-okupación (concilio 2026-10-10): un SEGUNDO `bind` sobre el
    /// MISMO nombre DEBE fallar con `AddrInUse`. Simula tanto «ya hay otro agente»
    /// como «un impostor ocupó el nombre primero»: en los dos casos el nombre existe
    /// cuando el segundo intenta crear su primera instancia, y `FIRST_PIPE_INSTANCE`
    /// lo rechaza. CASO ROJO que discrimina: el mutante que quita
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` de la primera instancia hace que este segundo
    /// `bind` devuelva `Ok` (= la okupación silenciosa), y la prueba se pone roja.
    #[test]
    fn un_segundo_bind_en_el_mismo_nombre_se_rechaza() {
        let ruta = ruta_unica("okupa");
        let primero = UnixListener::bind(&ruta).expect("el primer bind liga");
        match UnixListener::bind(&ruta) {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            Err(e) => panic!("el segundo bind debía dar AddrInUse, dio {:?}", e.kind()),
            Ok(_) => panic!("el segundo bind sobre un nombre ocupado NO debe ligar (okupación silenciosa)"),
        }
        drop(primero); // libera el nombre
    }

    /// El round-trip normal sigue funcionando CON la verificación del dueño del
    /// servidor activa: en la misma máquina/usuario, `connect` confirma que el SID
    /// dueño del proceso servidor es el propio y conecta. (Si la verificación
    /// rechazara al mismo usuario, este test —y los E2E de navegador— se pondrían
    /// rojos: es el control positivo de que el fix no rompe el camino legítimo.)
    #[test]
    fn el_mismo_usuario_pasa_la_verificacion_de_dueno() {
        let ruta = ruta_unica("dueno");
        let lis = UnixListener::bind(&ruta).unwrap();
        let servidor = std::thread::spawn(move || {
            let mut c = lis.accept().unwrap();
            let p = leer(&mut c);
            escribir(&mut c, &p);
        });
        let mut cli = UnixStream::connect(&ruta).expect("mismo usuario: connect verifica dueño y pasa");
        escribir(&mut cli, b"ping");
        assert_eq!(leer(&mut cli), b"ping");
        servidor.join().unwrap();
    }
}
