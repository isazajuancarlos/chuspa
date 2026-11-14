// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! El enlace entre la aplicación y el navegador.
//!
//! La extensión no es un gestor: es un **enlace** con la aplicación, que es
//! quien tiene la bóveda. Ver [`protocolo`] para el reparto de poderes entre los
//! tres procesos, y [`coincidencia`] para la decisión que sostiene todo lo demás
//! —a qué página le corresponde cada credencial—.

pub mod coincidencia;
pub mod protocolo;

use crate::bitacora::anotar;
use crate::boveda::Valor;
use crate::gui::Aplicacion;
use std::sync::Arc;
use protocolo::{Peticion, Razon, Respuesta};

/// La parte de la aplicación que atiende al navegador.
///
/// **Comparte la bóveda con la interfaz**, no tiene la suya. Antes eran dos
/// procesos —`chuspa-gui` y `chuspa-agente`— y no podían funcionar a la vez: el
/// cerrojo del archivo impide abrir la misma bóveda dos veces, así que arrancar
/// el agente con la ventana abierta daba «ocupada», y arrancarlo antes dejaba a
/// la ventana sin poder abrirla. Firefox decía «no se pudo hablar con la
/// aplicación» y era cierto: la aplicación que hablaba con él no era la que el
/// usuario tenía delante.
///
/// El puente que Firefox lanza sigue sin decidir nada: solo transporta.
pub struct Agente {
    app: Arc<Aplicacion>,
    /// Cuánto aguanta atendiendo al navegador sin que se sepa de nadie.
    ///
    /// El reloj no está aquí: está en la [`Aplicacion`], compartido con la
    /// ventana. Aquí solo vive el plazo.
    inactividad: std::time::Duration,
}

impl Agente {
    /// `inactividad` es cuánto sigue atendiendo al navegador sin que nadie
    /// pregunte nada.
    ///
    /// No tiene defecto a propósito. Un gestor que decide por su cuenta cuánto
    /// deja disponible la bóveda está tomando la decisión de seguridad más
    /// visible del programa sin preguntar.
    pub fn nuevo(app: Arc<Aplicacion>, inactividad: std::time::Duration) -> Self {
        Self { app, inactividad }
    }

    /// `true` si se sigue atendiendo al navegador Y la bóveda está abierta.
    ///
    /// Las dos condiciones: si el usuario cierra la bóveda en la ventana, la
    /// extensión deja de recibir credenciales en el acto, sin esperar a que
    /// venza ningún plazo.
    pub fn abierta(&self) -> bool {
        self.por_que_no().is_none()
    }

    /// Por qué no se atiende al navegador, o `None` si sí se atiende.
    ///
    /// El orden importa: sin bóveda se dice *sin bóveda* aunque también haya
    /// vencido el plazo, porque es lo que el usuario tiene que hacer.
    ///
    /// El reloj que se mira es el de la **aplicación**, no uno propio. Con uno
    /// propio, la cuenta empezaba al arrancar el proceso —antes de que hubiera
    /// bóveda que atender— y solo la refrescaba el navegador: quince minutos
    /// trabajando en la ventana bastaban para que el complemento dijera que la
    /// bóveda estaba cerrada teniéndola abierta delante. Y no se recuperaba, que
    /// era lo peor: la comprobación cortaba antes de refrescar el reloj, así que
    /// ninguna petición del navegador podía revivirlo. Solo reiniciar.
    pub fn por_que_no(&self) -> Option<Razon> {
        if self.app.boveda.lock().unwrap().is_none() {
            return Some(Razon::SinBoveda);
        }
        if !self.app.alguien_hace_menos_de(self.inactividad) {
            return Some(Razon::Inactividad);
        }
        None
    }

    /// La respuesta para cuando no se atiende. Nunca dice cuántas entradas hay.
    fn no_se_atiende(&self, razon: Razon) -> Respuesta {
        Respuesta::Estado { abierta: false, razon: Some(razon) }
    }

    /// Atiende una petición.
    ///
    /// Devuelve `None` cuando el agente debe terminar —la bóveda se cerró—, para
    /// que quien lo llama suelte la `Boveda` y con ella la clave maestra.
    pub fn atender(&self, peticion: Peticion) -> Respuesta {
        anotar(&match &peticion {
            Peticion::Estado {} => "entra estado".to_string(),
            Peticion::Bloquear {} => "entra bloquear".to_string(),
            Peticion::Autenticar { rp_id, origen, permitidas, .. } => format!(
                "entra autenticar rp_id={rp_id} origen={origen} permitidas={}",
                permitidas.len()
            ),
            Peticion::Registrar { rp_id, origen, excluidas, .. } => format!(
                "entra registrar rp_id={rp_id} origen={origen} excluidas={}",
                excluidas.len()
            ),
        });
        // La caducidad se comprueba ANTES de nada: si pasó el tiempo, ni
        // siquiera se mira qué se estaba pidiendo.
        if let Some(razon) = self.por_que_no() {
            return self.no_se_atiende(razon);
        }

        let respuesta = match peticion {
            Peticion::Estado {} => Respuesta::Estado { abierta: true, razon: None },
            Peticion::Autenticar { rp_id, reto, origen, permitidas } => {
                self.autenticar(&rp_id, &reto, &origen, &permitidas)
            }
            Peticion::Registrar {
                rp_id,
                rp_nombre,
                usuario_handle,
                usuario,
                usuario_mostrado,
                reto,
                origen,
                algoritmos,
                excluidas,
            } => self.registrar(Solicitud {
                rp_id: &rp_id,
                rp_nombre: rp_nombre.as_deref(),
                usuario_handle: &usuario_handle,
                usuario: usuario.as_deref(),
                usuario_mostrado: usuario_mostrado.as_deref(),
                reto: &reto,
                origen: &origen,
                algoritmos: &algoritmos,
                excluidas: &excluidas,
            }),
            Peticion::Bloquear {} => {
                // Se fuerza la caducidad: la próxima petición encontrará
                // cerrado. Vuelve a abrirse volviendo a la ventana, que es lo
                // que promete el aviso; la bóveda no se toca, porque cerrarla
                // desde el navegador sería dejarle decidir al proceso que menos
                // poder tiene.
                self.app.olvidar_la_presencia();
                return Respuesta::Hecho;
            }
        };
        // Atender al navegador NO sella presencia. Antes sí —«usar el navegador
        // también es estar delante»—, pero eso convertía el plazo en una defensa
        // que solo lo parece: una extensión comprometida que sondeara `estado`
        // mantenía el enlace vivo para siempre sola (medido, concilio 2026-09-15).
        // La presencia la sella la INTERACCIÓN real en la ventana —desbloquear,
        // filtrar, y AUTORIZAR una firma (`aplicar_firma`)—, que es la única señal
        // de que hay una persona. Una firma legítima reseña por esa vía; un sondeo
        // del navegador, no. Es el mismo principio que ya aplica el sondeo de la
        // ventana, que tampoco cuenta: solo la interacción real llama a
        // `hay_alguien`.
        respuesta
    }

    /// Firma un reto de WebAuthn con la passkey que corresponda.
    ///
    /// Busca entre TODAS las entradas la passkey registrada para ese dominio. No
    /// se pide al usuario que elija: el sitio ya dice qué identificadores acepta,
    /// y con las passkeys no hay ambigüedad como con las contraseñas.
    fn autenticar(
        &self,
        rp_id: &str,
        reto_b64: &str,
        origen: &str,
        permitidas: &[String],
    ) -> Respuesta {
        use crate::webauthn::Passkey;

        // El ORIGEN se comprueba ANTES que nada, y aquí, no solo dentro de
        // `firmar` tras la aprobación. El `rp_id` lo pone la PÁGINA (`passkeys.js`
        // manda `pk.rpId ?? location.hostname`), así que sin esto una página en
        // `evil.example` podía pedir `rp_id = "banco.com"` y, aunque nunca llegara
        // a firmar (firmar lo rechaza igual), conseguía dos cosas: (1) un diálogo
        // engañoso «evil.example pide una passkey de banco.com», y (2) un ORÁCULO
        // de existencia por tiempo —error inmediato si no hay passkey, diálogo de
        // 90 s si la hay—. Rechazar aquí, antes de mirar la bóveda, cierra las dos:
        // la respuesta es la misma exista o no una passkey para ese dominio. El
        // plazo de inactividad de 12 h multiplicaba esa ventana, así que va con
        // ese cambio (concilio 2026-09-15). `firmar` mantiene su comprobación como
        // defensa en profundidad.
        if crate::webauthn::comprobar_origen(rp_id, origen).is_err() {
            return Respuesta::Error {
                mensaje: "el origen de la página no corresponde al dominio pedido".into(),
            };
        }

        let reto = match base64url(reto_b64) {
            Some(r) => r,
            None => {
                return Respuesta::Error { mensaje: "el reto no está en base64url".into() };
            }
        };

        // Se recogen TODAS las candidatas, no la primera. Con dos cuentas en el
        // mismo sitio —lo normal en Google— quedarse con la primera significa
        // entrar siempre con la misma, y el usuario no puede ni enterarse de
        // que había otra.
        let candidatas = {
            let guard = self.app.boveda.lock().unwrap();
            let Some(boveda) = guard.as_ref() else {
                return self.no_se_atiende(Razon::SinBoveda);
            };
            candidatas_para(boveda, rp_id, permitidas)
        };

        anotar(&format!("firma candidatas={} rp_id={rp_id}", candidatas.len()));
        if candidatas.is_empty() {
            return Respuesta::Error {
                mensaje: format!("no hay ninguna passkey guardada para «{rp_id}»"),
            };
        }

        // A partir de aquí manda el usuario. Firmar sin preguntar convertía la
        // passkey en una cookie: con la bóveda abierta, cualquier página que se
        // visitara podía pedir una aserción y llevársela en silencio.
        let Some(elegida) = self.pedir_permiso(rp_id, origen, candidatas) else {
            anotar("firma SIN AUTORIZAR (se dijo que no, o venció el plazo)");
            return Respuesta::Error {
                mensaje: "la firma no se autorizó en la aplicación".into(),
            };
        };
        anotar("firma autorizada");

        let mut guard = self.app.boveda.lock().unwrap();
        let Some(boveda) = guard.as_mut() else {
            return self.no_se_atiende(Razon::SinBoveda);
        };
        let Ok(entrada) = boveda.abrir_entrada(elegida.entrada) else {
            return Respuesta::Error { mensaje: "la entrada elegida ya no está".into() };
        };
        let Ok(pk) = Passkey::de_entrada(&entrada, elegida.passkey) else {
            return Respuesta::Error { mensaje: "la passkey elegida ya no está".into() };
        };
        // Se vuelve a comprobar el destino con la passkey que de verdad se va a
        // usar. La elección viaja por la interfaz, y una comprobación hecha
        // solo antes de preguntar es una comprobación sobre otra cosa.
        if pk.rp_id != rp_id {
            return Respuesta::Error { mensaje: "la passkey elegida no es de este sitio".into() };
        }

        let a = match pk.firmar(rp_id, &reto, origen) {
            Ok(a) => a,
            Err(e) => return Respuesta::Error { mensaje: e.to_string() },
        };

        // El contador SUBE Y SE GUARDA, y sin esto la passkey solo sirve una vez.
        //
        // El sitio recuerda el último contador que le llegó y rechaza cualquier
        // aserción que no lo supere: es su detector de autenticadores clonados
        // (WebAuthn §7.2). Hasta el 2026-08-10 aquí se calculaba `guardado + 1`
        // y se tiraba al suelo, así que todas las firmas de una misma passkey
        // llevaban el MISMO número. La primera entraba —subía de 0 a 1— y todas
        // las siguientes eran, para el servidor, la copia de una llave robada.
        //
        // El fallo no daba error por ninguna parte: la firma es criptográficamente
        // impecable, la bitácora dice «firma autorizada», y el rechazo llega del
        // otro lado del mundo con un mensaje genérico. Solo se ve en los sitios
        // que de verdad comprueban el contador —npm es uno—; los que lo ignoran
        // funcionaban, que es lo que lo hacía parecer un problema «de npm».
        if let Err(e) = anotar_el_contador(
            boveda,
            elegida.entrada,
            entrada,
            elegida.passkey,
            a.contador,
        ) {
            // No se entrega la aserción. Firmar sin poder anotar el contador es
            // fabricar exactamente el fallo de arriba: entraría hoy y dejaría la
            // cuenta sin passkey mañana, sin que nadie relacione una cosa con la
            // otra. Es preferible un «no» que se lee ahora (directiva 20).
            anotar(&format!("firma DESCARTADA: no se pudo anotar el contador: {e}"));
            return Respuesta::Error {
                mensaje: format!(
                    "la firma no se entrega: el contador no se pudo guardar en la bóveda ({e}). \
                     Entregarla ahora dejaría esta passkey inservible en el sitio."
                ),
            };
        }

        Respuesta::Asercion {
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
            client_data: Passkey::client_data(&reto, origen),
            user_handle: a.user_handle,
        }
    }

    /// Registra una passkey nueva y la guarda en la bóveda.
    ///
    /// El orden es el mismo que en `autenticar`, y por los mismos motivos: el
    /// ORIGEN se comprueba lo primero —una página en `evil.example` no registra
    /// «para banco.com»—, y NADA se genera ni se escribe hasta que el usuario lo
    /// aprueba en la ventana. Crear una passkey liga una cuenta a este
    /// dispositivo y escribe en la bóveda: no puede pasar a espaldas de nadie.
    fn registrar(&self, s: Solicitud) -> Respuesta {
        use crate::webauthn;

        if webauthn::comprobar_origen(s.rp_id, s.origen).is_err() {
            return Respuesta::Error {
                mensaje: "el origen de la página no corresponde al dominio pedido".into(),
            };
        }
        let reto = match base64url(s.reto) {
            Some(r) => r,
            None => return Respuesta::Error { mensaje: "el reto no está en base64url".into() },
        };
        if !s.algoritmos.contains(&webauthn::ES256) {
            // No es un fallo: el sitio no ofrece ES256, así que la llamada vuelve
            // al navegador (la extensión reconoce que no es una credencial).
            return Respuesta::Error {
                mensaje: "el sitio no acepta ES256; lo atiende el navegador".into(),
            };
        }

        // A partir de aquí manda el usuario. Se pide permiso ANTES de mirar
        // `excludeCredentials`, y el orden es de seguridad, no de comodidad.
        //
        // Comprobar la exclusión antes —que es lo natural, «para no molestar con
        // una pregunta cuyo resultado ya se sabe»— convierte el registro en un
        // ORÁCULO DE RECONOCIMIENTO: la página del RP llama a `create` con los
        // identificadores que conoce y, si el usuario ya tiene una passkey nuestra
        // para esa cuenta, recibe un error INMEDIATO y sin ninguna interacción;
        // si no la tiene, aparece el diálogo. La diferencia —silencio contra
        // diálogo— le dice si nos conoce a este usuario, sin que este toque nada.
        // Es justo lo que WebAuthn §6.3.2 prohíbe al exigir prueba de presencia
        // ANTES de revelar «credencial excluida». Con la aprobación por delante,
        // la existencia solo se revela tras el gesto del usuario. (Concilio
        // 2026-09-16, fable.)
        if !self.pedir_permiso_registro(s.rp_id, s.rp_nombre, s.origen, s.usuario) {
            anotar("registro SIN AUTORIZAR (se dijo que no, o venció el plazo)");
            return Respuesta::Error {
                mensaje: "el registro de la passkey no se autorizó en la aplicación".into(),
            };
        }
        anotar("registro autorizado");

        // Ya con el gesto hecho: si el sitio dice que ya tiene una de nuestras
        // passkeys para esta cuenta (`excludeCredentials`), no se crea otra
        // —duplicar deja al usuario con dos llaves para lo mismo y una cuenta
        // confundida—. La respuesta es la misma que da un autenticador de verdad,
        // pero solo DESPUÉS de la aprobación (ver arriba).
        if !s.excluidas.is_empty() {
            let guard = self.app.boveda.lock().unwrap();
            if let Some(boveda) = guard.as_ref() {
                for indice in 0..boveda.len() {
                    let Ok(entrada) = boveda.abrir_entrada(indice) else { continue };
                    for n in 0..webauthn::Passkey::cuantas(&entrada) {
                        let Ok(pk) = webauthn::Passkey::de_entrada(&entrada, n) else { continue };
                        if pk.rp_id == s.rp_id && s.excluidas.contains(&pk.credential_id) {
                            return Respuesta::Error {
                                mensaje: "ya hay una passkey de este dispositivo para esa cuenta"
                                    .into(),
                            };
                        }
                    }
                }
            }
        }

        let reg = match webauthn::registrar(s.rp_id, &reto, s.origen, s.algoritmos) {
            Ok(r) => r,
            Err(e) => return Respuesta::Error { mensaje: e.to_string() },
        };

        // Se guarda una entrada NUEVA con la passkey. Se hace con la bóveda ya
        // abierta; si se cerró entretanto, no se entrega la credencial: el sitio
        // la asociaría a la cuenta y aquí no quedaría la privada para volver a
        // entrar (el mismo fallo de «entra hoy, inservible mañana» que el
        // contador). Preferible un «no» que se lee ahora (directiva 20).
        let entrada = crate::boveda::Entrada {
            id_origen: None,
            nombre: s.rp_nombre.filter(|n| !n.is_empty()).unwrap_or(s.rp_id).to_string(),
            clase: crate::boveda::Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: campos_de_passkey(&DatosPasskey {
                credential_id: &reg.credential_id,
                clave_privada: reg.clave_privada.as_str(),
                rp_id: s.rp_id,
                rp_nombre: s.rp_nombre,
                usuario: s.usuario,
                usuario_mostrado: s.usuario_mostrado,
                usuario_handle: s.usuario_handle,
            }),
            uris: vec![crate::boveda::Uri {
                uri: format!("https://{}", s.rp_id),
                coincidencia: None,
            }],
            historial: Vec::new(),
            creada: Some(crate::fecha::ahora_utc()),
            revisada: None,
        };

        {
            let mut guard = self.app.boveda.lock().unwrap();
            let Some(boveda) = guard.as_mut() else {
                return self.no_se_atiende(Razon::SinBoveda);
            };
            if let Err(e) = boveda.anadir(entrada).and_then(|_| boveda.guardar()) {
                anotar(&format!("registro DESCARTADO: no se pudo guardar: {e}"));
                return Respuesta::Error {
                    mensaje: format!(
                        "la passkey no se entrega: no se pudo guardar en la bóveda ({e}). \
                         Entregarla dejaría la cuenta sin poder volver a entrar."
                    ),
                };
            }
        }
        anotar(&format!("registro guardado rp_id={} id={}", s.rp_id, reg.credential_id));
        // La passkey nació en el hilo del agente, fuera de la ventana. Se marca el
        // cambio para que el sondeo de la ventana repueble la lista; sin esto la
        // entrada se guarda pero no aparece hasta una edición manual o reabrir.
        self.app.marcar_cambio_boveda();

        Respuesta::Credencial {
            credential_id: reg.credential_id,
            attestation_object: reg.attestation_object,
            client_data: reg.client_data,
        }
    }

    /// El gemelo de [`Agente::pedir_permiso`] para un registro: deja la petición
    /// a la vista de la ventana y espera un sí/no. Devuelve `true` solo si el
    /// usuario aprobó a tiempo.
    fn pedir_permiso_registro(
        &self,
        rp_id: &str,
        rp_nombre: Option<&str>,
        origen: &str,
        usuario: Option<&str>,
    ) -> bool {
        use std::time::Duration;
        const PLAZO: Duration = Duration::from_secs(90);

        let id = {
            static SIGUIENTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            SIGUIENTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        };

        let mut guard = self.app.registro.lock().unwrap();
        *guard = Some(crate::gui::RegistroPendiente {
            id,
            rp_id: rp_id.to_string(),
            rp_nombre: rp_nombre.map(str::to_string),
            origen: origen.to_string(),
            usuario: usuario.map(str::to_string),
            aprobado: None,
        });
        self.app.avisar_de_pregunta();

        let (mut guard, expiro) = self
            .app
            .decidida
            .wait_timeout_while(guard, PLAZO, |r| {
                r.as_ref().is_some_and(|r| r.id == id && r.aprobado.is_none())
            })
            .unwrap();

        let aprobado = guard
            .as_ref()
            .filter(|r| r.id == id)
            .and_then(|r| r.aprobado)
            .unwrap_or(false);

        if guard.as_ref().is_some_and(|r| r.id == id) {
            *guard = None;
        }
        drop(guard);

        !expiro.timed_out() && aprobado
    }

    /// Deja la petición a la vista de la ventana y espera a que alguien decida.
    ///
    /// Devuelve la candidata elegida, o `None` si se dijo que no o si nadie
    /// contestó a tiempo. El plazo es generoso porque al otro lado hay una
    /// persona leyendo; lo que no puede es ser infinito, o un sitio abandonado
    /// dejaría la aplicación pidiendo permiso para siempre.
    fn pedir_permiso(
        &self,
        rp_id: &str,
        origen: &str,
        candidatas: Vec<crate::gui::Candidata>,
    ) -> Option<crate::gui::Candidata> {
        use std::time::Duration;
        const PLAZO: Duration = Duration::from_secs(90);

        let id = {
            // Un contador basta: solo sirve para no confundir una decisión que
            // llega tarde con la petición siguiente.
            static SIGUIENTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            SIGUIENTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        };

        let mut guard = self.app.firma.lock().unwrap();
        // Si ya había una esperando, se descarta: la de ahora es la que el
        // usuario tiene delante.
        *guard = Some(crate::gui::FirmaPendiente {
            id,
            rp_id: rp_id.to_string(),
            origen: origen.to_string(),
            candidatas: candidatas.clone(),
            elegida: None,
        });

        // Que la ventana se anuncie. El usuario está mirando el sitio donde
        // quiere entrar, no esta aplicación, y si la ventana quedó detrás del
        // navegador la espera se ve igual que un fallo: el sitio dice
        // «verificando» y nadie sabe que hay algo que pulsar. El aviso se manda
        // con el candado de `firma` tomado a propósito —solo empuja un evento a
        // la cola de la ventana, no toca la bóveda— para que no pueda colarse
        // entre dejar la petición y ponerse a esperarla.
        self.app.avisar_de_pregunta();

        let (mut guard, expiro) = self
            .app
            .decidida
            .wait_timeout_while(guard, PLAZO, |f| {
                f.as_ref().is_some_and(|f| f.id == id && f.elegida.is_none())
            })
            .unwrap();

        let decision = guard
            .as_ref()
            .filter(|f| f.id == id)
            .and_then(|f| f.elegida)
            .flatten();

        // La petición se retira siempre, haya salido bien, mal o por plazo: una
        // pendiente olvidada deja la ventana preguntando por algo que ya no
        // espera respuesta.
        if guard.as_ref().is_some_and(|f| f.id == id) {
            *guard = None;
        }
        drop(guard);

        if expiro.timed_out() {
            return None;
        }
        decision.and_then(|i| candidatas.into_iter().nth(i))
    }
}

/// Escucha al navegador en un hilo aparte, compartiendo la bóveda de la ventana.
///
/// Se llama al arrancar la aplicación y vive mientras ella viva. Si la bóveda
/// está cerrada, responde que está cerrada: no la abre —eso solo pasa en la
/// ventana, tecleando la frase— y por eso no hace falta que el navegador tenga
/// ninguna credencial.
// El canal: en Linux un socket de dominio Unix (`std::os::unix::net`); en Windows
// un NAMED PIPE por nuestro crate `chuspa-ipc-win`, que da la misma forma de API.
// Se cambió el AF_UNIX nativo (`uds_windows`) por el named pipe el 2026-10-10: el
// `connect` AF_UNIX fallaba con WSAEINVAL en ciertos contextos de proceso de
// Windows, y el named pipe es más robusto y cruza ese límite sin problema. El
// aislamiento es la paridad de siempre: permisos del archivo (Unix) / DACL propia
// del pipe (Windows). Ver `ruta_del_socket` y `solo_el_dueno`.
pub fn escuchar_al_navegador(
    app: Arc<Aplicacion>,
    inactividad: std::time::Duration,
) -> std::io::Result<std::path::PathBuf> {
    escuchar_en(app, inactividad, ruta_del_socket()?)
}

/// Lo mismo, en el socket que se le diga.
///
/// La ruta va como parámetro y no como constante para que una prueba pueda
/// levantar su propio agente sin tocar el de la sesión de verdad. La primera
/// versión de la prueba de concurrencia usaba la ruta de siempre y chocó con la
/// aplicación que estaba abierta — se salvó porque el socket solo se borra si
/// NADIE responde en él, no porque la prueba estuviera bien.
pub fn escuchar_en(
    app: Arc<Aplicacion>,
    inactividad: std::time::Duration,
    socket: std::path::PathBuf,
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::net::{UnixListener, UnixStream};
    #[cfg(windows)]
    use chuspa_ipc_win::{UnixListener, UnixStream};

    // Un socket huérfano de una sesión anterior impediría escuchar. Se borra
    // solo si NADIE responde en él: si hay alguien, `bind` fallará después y se
    // avisa en vez de robarle el sitio.
    if socket.exists() && UnixStream::connect(&socket).is_err() {
        std::fs::remove_file(&socket)?;
    }
    let escucha = UnixListener::bind(&socket)?;
    solo_el_dueno(&socket)?;

    let ruta = socket.clone();
    std::thread::spawn(move || {
        // Cada conexión va en su propio hilo.
        //
        // En serie no valía: desde que una firma espera el visto bueno del
        // usuario, esa petición se queda hasta minuto y medio en el aire, y
        // atendiéndolas de una en una eso CONGELA todo lo demás. El síntoma era
        // el complemento diciendo «Consultando…» para siempre mientras la
        // aplicación respondía perfectamente si se le hablaba por su socket:
        // no estaba rota, estaba en cola.
        //
        // El agente se comparte tras un `Mutex`, así que sigue habiendo un solo
        // dueño del estado; lo que ya no se comparte es el turno.
        let agente = Arc::new(Agente::nuevo(app, inactividad));
        // Tope de conexiones a la vez: sin él, abrir sockets y no hablar basta
        // para llenar la máquina de hilos parados.
        let vivos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        const A_LA_VEZ: usize = 32;

        for conexion in escucha.incoming() {
            let Ok(mut flujo) = conexion else { continue };
            if vivos.load(std::sync::atomic::Ordering::Relaxed) >= A_LA_VEZ {
                let _ = protocolo::escribir_respuesta(
                    &mut flujo,
                    &Respuesta::Error { mensaje: "demasiadas peticiones a la vez".into() },
                );
                continue;
            }
            let Ok(copia) = flujo.try_clone() else { continue };
            let agente = agente.clone();
            let vivos = vivos.clone();
            vivos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::spawn(move || {
                let mut lector = std::io::BufReader::new(copia);
                match protocolo::leer_mensaje(&mut lector) {
                    Ok(peticion) => {
                        let respuesta = agente.atender(peticion);
                        let _ = protocolo::escribir_respuesta(&mut flujo, &respuesta);
                    }
                    Err(protocolo::TransporteError::Cerrado) => {}
                    Err(e) => {
                        let _ = protocolo::escribir_respuesta(
                            &mut flujo,
                            &Respuesta::Error { mensaje: e.to_string() },
                        );
                    }
                }
                let _ = flujo.flush();
                vivos.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    Ok(ruta)
}

/// El socket del agente, en un directorio propio del usuario:
/// `$XDG_RUNTIME_DIR/chuspa/agente.sock` en Linux (dir a 0700),
/// `%LOCALAPPDATA%\chuspa\agente.sock` en Windows (dir con la ACL del perfil).
pub fn ruta_del_socket() -> std::io::Result<std::path::PathBuf> {
    // Override explícito, válido en TODAS las plataformas. Dos usos: reubicar el
    // socket, y —sobre todo— que una prueba de extremo a extremo levante su propio
    // agente sin chocar con la aplicación de verdad. En Windows el sitio por
    // defecto es un ÚNICO socket global (`%LOCALAPPDATA%\chuspa`), así que sin
    // este override dos agentes (el real y el de la prueba) pelearían por él. No
    // cambia el comportamiento por defecto: solo actúa si la variable está puesta.
    let base = if let Some(dir) = std::env::var_os("CHUSPA_RUNTIME_DIR") {
        std::path::PathBuf::from(dir)
    } else {
        #[cfg(unix)]
        {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    let uid = std::env::var("UID").unwrap_or_else(|_| "0".into());
                    std::env::temp_dir().join(format!("chuspa-{uid}"))
                })
        }
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
        }
    };
    let dir = base.join("chuspa");
    std::fs::create_dir_all(&dir)?;
    solo_el_dueno(&dir)?;
    Ok(dir.join("agente.sock"))
}

/// En Unix, restringe la ruta a su dueño (dir 0700 / socket 0600).
#[cfg(unix)]
fn solo_el_dueno(ruta: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let modo = if ruta.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(ruta, std::fs::Permissions::from_mode(modo))
}

/// En Windows la ruta no es un archivo (es la CLAVE de la que `chuspa-ipc-win`
/// deriva el nombre del named pipe), así que aquí no hay nada que restringir: el
/// aislamiento lo pone la DACL del propio pipe (usuario dueño + SYSTEM +
/// Administradores, sin Everyone), construida en `chuspa-ipc-win` —donde vive el
/// `unsafe` del Win32— para que este crate conserve `unsafe_code = "forbid"`.
#[cfg(windows)]
fn solo_el_dueno(_ruta: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

fn base64url(s: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s.trim_end_matches('=')).ok()
}

/// Los datos de un registro que pide el sitio, con las cadenas prestadas para no
/// copiarlas al despachar. Es un struct y no ocho argumentos sueltos porque
/// ocho argumentos del mismo tipo son ocho sitios donde equivocar el orden.
struct Solicitud<'a> {
    rp_id: &'a str,
    rp_nombre: Option<&'a str>,
    usuario_handle: &'a str,
    usuario: Option<&'a str>,
    usuario_mostrado: Option<&'a str>,
    reto: &'a str,
    origen: &'a str,
    algoritmos: &'a [i64],
    excluidas: &'a [String],
}

/// Lo que hace falta para GUARDAR una passkey nueva en la bóveda. Separa el QUÉ
/// guardar del CÓMO se obtuvo, para que [`campos_de_passkey`] tenga un solo camino.
struct DatosPasskey<'a> {
    credential_id: &'a str,
    clave_privada: &'a str,
    rp_id: &'a str,
    rp_nombre: Option<&'a str>,
    usuario: Option<&'a str>,
    usuario_mostrado: Option<&'a str>,
    usuario_handle: &'a str,
}

/// Recoge TODAS las passkeys de la bóveda registradas para `rp_id`, respetando
/// `permitidas` (si no está vacía). Lo usa el flujo del navegador
/// ([`Agente::autenticar`]): se recogen TODAS, no la primera, porque con dos
/// cuentas en el mismo sitio quedarse con una sola la haría invisible.
fn candidatas_para(
    boveda: &crate::cifrado::Boveda,
    rp_id: &str,
    permitidas: &[String],
) -> Vec<crate::gui::Candidata> {
    use crate::webauthn::Passkey;
    let mut candidatas = Vec::new();
    for indice in 0..boveda.len() {
        let Ok(entrada) = boveda.abrir_entrada(indice) else { continue };
        for n in 0..Passkey::cuantas(&entrada) {
            let Ok(pk) = Passkey::de_entrada(&entrada, n) else { continue };
            if pk.rp_id != rp_id {
                continue;
            }
            // Si el sitio dice qué credenciales acepta, se respeta: mandar otra
            // solo consigue un rechazo confuso.
            if !permitidas.is_empty() && !permitidas.contains(&pk.credential_id) {
                continue;
            }
            candidatas.push(crate::gui::Candidata {
                entrada: indice,
                passkey: n,
                nombre: entrada.nombre.clone(),
                usuario: pk.usuario.clone(),
            });
        }
    }
    candidatas
}

/// Arma los campos `passkey.0.*` de una passkey recién registrada, con el MISMO
/// esquema que deja el importador de Bitwarden —así una passkey creada aquí y
/// una importada se leen por el mismo camino (`Passkey::de_entrada`)—.
///
/// La clave privada va como SECRETO; lo demás es público (el sitio ya lo tiene).
fn campos_de_passkey(d: &DatosPasskey) -> Vec<crate::boveda::Campo> {
    use crate::boveda::{Campo, Valor};
    let mut campos = vec![
        Campo::estandar("passkey.0.id", Valor::texto(d.credential_id.to_string())),
        Campo::estandar("passkey.0.clave", Valor::secreto(d.clave_privada.to_string())),
        Campo::estandar("passkey.0.rp_id", Valor::texto(d.rp_id.to_string())),
        Campo::estandar("passkey.0.algoritmo", Valor::texto("-7".to_string())),
        Campo::estandar("passkey.0.usuario_handle", Valor::texto(d.usuario_handle.to_string())),
        Campo::estandar("passkey.0.contador", Valor::texto("0".to_string())),
        Campo::estandar("passkey.0.creada", Valor::texto(crate::fecha::ahora_utc())),
    ];
    if let Some(u) = d.usuario.filter(|u| !u.is_empty()) {
        campos.push(Campo::estandar("passkey.0.usuario", Valor::texto(u.to_string())));
    }
    if let Some(u) = d.usuario_mostrado.filter(|u| !u.is_empty()) {
        campos.push(Campo::estandar("passkey.0.usuario_mostrado", Valor::texto(u.to_string())));
    }
    if let Some(n) = d.rp_nombre.filter(|n| !n.is_empty()) {
        campos.push(Campo::estandar("passkey.0.rp_nombre", Valor::texto(n.to_string())));
    }
    campos
}

/// Deja en la bóveda el contador de firmas que acaba de usarse.
///
/// Se edita la entrada YA DESCIFRADA y se devuelve entera, sin reconstruirla a
/// partir de lo que alguna interfaz sepa decir: es la misma trampa que se ha
/// cobrado aquí el segundo factor, la carpeta y la regla de cada URI —lo que no
/// se sabe transportar se pierde al guardar, y sin error—. Aquí solo se toca un
/// campo de los que ya venían.
///
/// Si el campo no existe se AÑADE: una bóveda importada de Bitwarden puede no
/// traerlo, y entonces el contador arrancaba en 0 en cada firma.
fn anotar_el_contador(
    boveda: &mut crate::cifrado::Boveda,
    indice: usize,
    mut entrada: crate::boveda::Entrada,
    passkey: usize,
    contador: u32,
) -> Result<(), String> {
    let etiqueta = format!("passkey.{passkey}.contador");
    let valor = Valor::texto(contador.to_string());
    match entrada.campos.iter_mut().find(|c| c.etiqueta == etiqueta) {
        Some(c) => c.valor = valor,
        None => entrada.campos.push(crate::boveda::Campo::estandar(etiqueta, valor)),
    }
    boveda.reemplazar(indice, entrada).map_err(|e| e.to_string())?;
    boveda.guardar().map_err(|e| e.to_string())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::boveda::{Campo, Clase, Entrada, Uri};
    use crate::cifrado::{Acceso, Boveda};

    fn coste() -> quipu::kdf::KdfParams {
        quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
    }

    fn entrada(nombre: &str, uri: &str, usuario: &str, clave: &str) -> Entrada {
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
                Campo::estandar("acceso.usuario", Valor::texto(usuario)),
                Campo::estandar("acceso.clave", Valor::secreto(clave)),
            ],
            uris: vec![Uri { uri: uri.into(), coincidencia: None }],
            historial: Vec::new(),
            creada: None,
            revisada: None,
        }
    }

    fn agente(etiqueta: &str, inactividad: std::time::Duration) -> Agente {
        agente_y_ventana(etiqueta, inactividad).0
    }

    /// El agente y la aplicación que comparte con la ventana.
    ///
    /// Devuelve las dos mitades porque el plazo de inactividad cuenta lo que
    /// pasa en las DOS: mirarlo solo desde el agente es lo que dejó pasar el
    /// fallo de la bóveda abierta en pantalla y el complemento diciendo que
    /// estaba cerrada.
    fn agente_y_ventana(
        etiqueta: &str,
        inactividad: std::time::Duration,
    ) -> (Agente, Arc<Aplicacion>) {
        let (app, b) = ventana(etiqueta);
        *app.boveda.lock().unwrap() = Some(b);
        (Agente::nuevo(Arc::clone(&app), inactividad), app)
    }

    /// Una aplicación con su bóveda **sin abrir**, como al arrancar el programa.
    fn ventana(etiqueta: &str) -> (Arc<Aplicacion>, Boveda) {
        let dir = std::env::temp_dir().join(format!("chuspa-nav-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join(format!("{etiqueta}.chuspa"));
        let _ = std::fs::remove_file(&ruta);
        let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase"), coste()).unwrap();
        b.anadir(entrada("Banco", "https://banco.com", "juan", "clave-del-banco")).unwrap();
        b.anadir(entrada("Correo", "https://correo.example", "j@x", "otra-clave")).unwrap();
        (Arc::new(Aplicacion::nueva(ruta)), b)
    }

    fn largo() -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }

    #[test]
    fn tras_la_inactividad_no_se_entrega_nada() {
        // Una bóveda que se queda abierta toda la noche es una bóveda abierta.
        // Ni siquiera una firma de passkey se atiende tras caducar el enlace.
        let a = agente("inactividad", std::time::Duration::from_millis(80));
        std::thread::sleep(std::time::Duration::from_millis(120));

        assert!(!a.abierta());
        match a.atender(Peticion::Autenticar {
            rp_id: "banco.com".into(),
            reto: "AA".into(),
            origen: "https://banco.com".into(),
            permitidas: Vec::new(),
        }) {
            Respuesta::Estado { abierta, .. } => assert!(!abierta),
            otro => panic!("tras caducar no se atiende nada: {otro:?}"),
        }
    }

    /// El fallo tal como apareció: 598 entradas en pantalla y los dos
    /// navegadores diciendo «la bóveda está cerrada».
    ///
    /// La aplicación llevaba seis horas abierta y el usuario había estado
    /// trabajando en la ventana toda la mañana. El agente solo miraba SU
    /// reloj —el que refresca el navegador—, así que quince minutos sin abrir
    /// el complemento bastaban para darlo por ausente.
    #[test]
    fn el_plazo_no_corre_antes_de_que_haya_boveda() {
        let (app, b) = ventana("tarde");
        let a = Agente::nuevo(Arc::clone(&app), std::time::Duration::from_millis(80));
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert_eq!(a.por_que_no(), Some(Razon::SinBoveda));

        // Ahora el usuario teclea la frase.
        *app.boveda.lock().unwrap() = Some(b);
        app.hay_alguien();
        assert_eq!(a.por_que_no(), None, "acaba de abrirla: el enlace tiene que atender");
    }

    /// Caducar no puede ser definitivo.
    ///
    /// Antes lo era, y en silencio: la comprobación cortaba **antes** de
    /// refrescar el reloj, así que ninguna petición podía revivirlo. La única
    /// salida era reiniciar la aplicación, y nada lo decía.
    #[test]
    fn dice_si_no_hay_boveda_o_si_es_por_inactividad() {
        let (a, app) = agente_y_ventana("por-que", std::time::Duration::from_millis(60));
        std::thread::sleep(std::time::Duration::from_millis(100));
        match a.atender(Peticion::Estado {}) {
            Respuesta::Estado { razon, .. } => assert_eq!(razon, Some(Razon::Inactividad)),
            otro => panic!("{otro:?}"),
        }

        *app.boveda.lock().unwrap() = None;
        match a.atender(Peticion::Estado {}) {
            Respuesta::Estado { razon, .. } => assert_eq!(razon, Some(Razon::SinBoveda)),
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn bloquear_cierra_de_inmediato() {
        let a = agente("bloquear", largo());
        assert!(a.abierta());
        assert!(matches!(a.atender(Peticion::Bloquear {}), Respuesta::Hecho));
        assert!(!a.abierta());
        // Y una firma pedida después tampoco se atiende.
        assert!(matches!(
            a.atender(Peticion::Autenticar {
                rp_id: "banco.com".into(),
                reto: "AA".into(),
                origen: "https://banco.com".into(),
                permitidas: Vec::new(),
            }),
            Respuesta::Estado { abierta: false, .. }
        ));
    }

    #[test]
    fn el_estado_no_dice_nada_del_contenido_cuando_esta_cerrada() {
        let a = agente("estado-cerrado", std::time::Duration::from_millis(1));
        std::thread::sleep(std::time::Duration::from_millis(20));
        match a.atender(Peticion::Estado {}) {
            Respuesta::Estado { abierta, razon } => {
                assert!(!abierta);
                // Decir POR QUÉ no se atiende no es decir qué hay dentro. Y desde
                // 0.3.0 ni cuando está abierta se dice el conteo de entradas.
                assert_eq!(razon, Some(Razon::Inactividad));
            }
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn un_origen_que_no_corresponde_se_rechaza_antes_de_mirar_la_boveda() {
        // Una página en `evil.example` pide firmar para `banco.com`. Se rechaza
        // por el ORIGEN, sin llegar a buscar passkeys, así que la respuesta es la
        // misma exista o no una passkey para ese dominio: sin oráculo de
        // existencia por tiempo y sin diálogo engañoso. (La bóveda de prueba no
        // tiene passkeys; el discriminante es QUÉ error sale.)
        let a = agente("origen-cruzado", largo());
        match a.atender(Peticion::Autenticar {
            rp_id: "banco.com".into(),
            reto: "AA".into(),
            origen: "https://evil.example".into(),
            permitidas: Vec::new(),
        }) {
            Respuesta::Error { mensaje } => {
                assert!(
                    mensaje.contains("origen"),
                    "debe rechazar por el origen: «{mensaje}»"
                );
                // Sin el chequeo temprano, el error sería «no hay ninguna passkey
                // guardada para banco.com» — que revela la ausencia. No puede.
                assert!(
                    !mensaje.contains("passkey"),
                    "el mensaje no puede revelar si hay o no passkey: «{mensaje}»"
                );
            }
            otro => panic!("un origen cruzado no puede llegar a firmar: {otro:?}"),
        }
    }

    #[test]
    fn sondear_no_mantiene_vivo_el_enlace() {
        // Atender al navegador no sella presencia: una extensión comprometida que
        // sondee `estado` NO puede mantener el enlace vivo por su cuenta. Con el
        // sellado viejo en `atender`, estos sondeos lo habrían revivido y la
        // prueba saldría roja.
        let a = agente("sondeo", std::time::Duration::from_millis(80));
        for _ in 0..5 {
            let _ = a.atender(Peticion::Estado {});
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        assert!(
            !a.abierta(),
            "sondear estado no puede mantener vivo el enlace tras el plazo"
        );
    }

    // ---- Registro de passkeys por el agente ----

    /// Aprueba (o rechaza) el registro en cuanto el agente lo deja esperando.
    /// Es lo que hace el usuario en la ventana, hecho desde un hilo para que el
    /// `atender` que bloquea pueda seguir. Acotado en el tiempo: si el registro
    /// no llega —porque la petición falló antes—, el hilo termina y no cuelga.
    fn aprobar_registro(app: Arc<Aplicacion>, aprobado: bool) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for _ in 0..1000 {
                let id = app
                    .registro
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|r| r.aprobado.is_none())
                    .map(|r| r.id);
                if let Some(id) = id {
                    let cuerpo = format!("{{\"id\":{id},\"aprobado\":{aprobado}}}");
                    crate::gui::decidir_registro(&app, cuerpo.as_bytes());
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        })
    }

    fn b64(b: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Base64UrlUnpadded::encode_string(b)
    }

    fn peticion_registrar(rp_id: &str, origen: &str, usuario: &str) -> Peticion {
        peticion_registrar_con(rp_id, origen, usuario, Vec::new())
    }

    fn peticion_registrar_con(
        rp_id: &str,
        origen: &str,
        usuario: &str,
        excluidas: Vec<String>,
    ) -> Peticion {
        Peticion::Registrar {
            rp_id: rp_id.into(),
            rp_nombre: Some(format!("{rp_id} S.A.")),
            usuario_handle: b64(b"usuario-1"),
            usuario: Some(usuario.into()),
            usuario_mostrado: Some(usuario.into()),
            reto: b64(b"reto de registro de 32 bytes!!!!"),
            origen: origen.into(),
            algoritmos: vec![crate::webauthn::ES256],
            excluidas,
        }
    }

    /// EL bucle entero por el agente: se registra una passkey aprobándola desde
    /// la ventana, se guarda en la bóveda, y la que quedó guardada SIRVE para
    /// firmar. Es crear → almacenar → usar, cruzando el agente de verdad.
    #[test]
    fn registrar_una_passkey_la_guarda_y_queda_usable() {
        let (a, app) = agente_y_ventana("registro-ok", largo());
        let antes = app.boveda.lock().unwrap().as_ref().unwrap().len();
        let gen_antes = app.generacion_boveda();

        let aprobador = aprobar_registro(Arc::clone(&app), true);
        let r = a.atender(peticion_registrar("nube.example", "https://nube.example", "juan@x"));
        aprobador.join().unwrap();

        let cred_id = match r {
            Respuesta::Credencial { credential_id, attestation_object, client_data } => {
                assert!(!attestation_object.is_empty());
                assert!(client_data.contains("webauthn.create"));
                assert!(client_data.contains("https://nube.example"));
                credential_id
            }
            otro => panic!("se esperaba una credencial: {otro:?}"),
        };

        // Se guardó UNA entrada nueva, y su passkey se lee y FIRMA.
        let guard = app.boveda.lock().unwrap();
        let boveda = guard.as_ref().unwrap();
        assert_eq!(boveda.len(), antes + 1, "el registro tiene que añadir una entrada");

        let mut encontrada = false;
        for i in 0..boveda.len() {
            let entrada = boveda.abrir_entrada(i).unwrap();
            for n in 0..crate::webauthn::Passkey::cuantas(&entrada) {
                let pk = crate::webauthn::Passkey::de_entrada(&entrada, n).unwrap();
                if pk.rp_id == "nube.example" {
                    encontrada = true;
                    assert_eq!(pk.credential_id, cred_id, "el id guardado y el entregado difieren");
                    assert_eq!(pk.contador, 0, "una passkey nueva nace con el contador en 0");
                    // Y sirve para lo suyo: firma sin error por el camino normal.
                    assert!(
                        pk.firmar("nube.example", b"un reto", "https://nube.example").is_ok(),
                        "la passkey registrada no sirve para firmar"
                    );
                }
            }
        }
        assert!(encontrada, "la passkey registrada no está en la bóveda");

        // Y SUBE la generación: es la señal con la que la ventana sabe que debe
        // repoblar la lista (la passkey nació en el hilo del agente, no en la
        // ventana). Sin esto, la entrada se guarda pero no aparece hasta reabrir.
        assert_eq!(
            app.generacion_boveda(),
            gen_antes + 1,
            "un registro guardado tiene que subir la generación de la bóveda"
        );
    }

    /// Caso rojo del control de acceso: si el usuario RECHAZA, no se crea nada.
    /// Sin la puerta de aprobación, cualquier página con la bóveda abierta
    /// registraría passkeys a espaldas del usuario.
    #[test]
    fn un_registro_rechazado_no_toca_la_boveda() {
        let (a, app) = agente_y_ventana("registro-no", largo());
        let antes = app.boveda.lock().unwrap().as_ref().unwrap().len();
        let gen_antes = app.generacion_boveda();

        let aprobador = aprobar_registro(Arc::clone(&app), false);
        let r = a.atender(peticion_registrar("nube.example", "https://nube.example", "juan@x"));
        aprobador.join().unwrap();

        assert!(matches!(r, Respuesta::Error { .. }), "un rechazo no puede dar credencial");
        assert_eq!(
            app.boveda.lock().unwrap().as_ref().unwrap().len(),
            antes,
            "un registro rechazado no puede añadir nada"
        );
        // Y NO sube la generación: la pareja del caso verde (D33). Si subiera sin
        // guardar, la ventana repoblaría de balde y la señal no discriminaría.
        assert_eq!(
            app.generacion_boveda(),
            gen_antes,
            "un registro rechazado no puede subir la generación"
        );
    }

    /// Un sitio de phishing no registra, y se rechaza ANTES de preguntar: no debe
    /// llegar a molestar al usuario con un diálogo. Por eso aquí no hay hilo
    /// aprobador: si el código pidiera permiso, el test colgaría hasta el plazo.
    #[test]
    fn un_origen_cruzado_no_registra_y_no_pregunta() {
        let (a, app) = agente_y_ventana("registro-phishing", largo());
        let t0 = std::time::Instant::now();
        let r = a.atender(peticion_registrar("banco.example", "https://banco.example.evil.test", "v"));
        // El rechazo tiene que ser INMEDIATO. Es lo que hace que esta prueba
        // discrimine el guardián de origen DEL AGENTE (no solo el de
        // `webauthn::registrar`): si se quita el chequeo temprano de `registrar`,
        // el flujo llega hasta `pedir_permiso_registro`, que muestra el diálogo y
        // se queda 90 s esperando una respuesta que nadie dará. Sin esta cota, esa
        // mutación dejaba la prueba VERDE —el `matches!(Error)` se cumple igual
        // porque el núcleo reverifica— pero tras 90 s y habiendo preguntado, que
        // es justo lo que el nombre promete que NO pasa (D33, hallazgo del
        // concilio 2026-09-16: la sonda de `registro` miraba tras el plazo, que ya
        // lo había limpiado).
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(30),
            "un origen cruzado no puede llegar a la ventana de aprobación de 90 s"
        );
        assert!(matches!(r, Respuesta::Error { .. }));
        assert!(
            app.registro.lock().unwrap().is_none(),
            "un origen cruzado no puede haber dejado una pregunta pendiente"
        );
    }

    /// `excludeCredentials`: si el sitio dice que ya tiene una passkey nuestra
    /// para esa cuenta, no se crea otra. Se registra una, y un segundo intento
    /// que la excluye se rechaza sin duplicar.
    #[test]
    fn no_se_duplica_una_passkey_que_el_sitio_ya_tiene() {
        let (a, app) = agente_y_ventana("registro-dup", largo());

        let aprobador = aprobar_registro(Arc::clone(&app), true);
        let primero = a.atender(peticion_registrar("nube.example", "https://nube.example", "juan@x"));
        aprobador.join().unwrap();
        let Respuesta::Credencial { credential_id, .. } = primero else {
            panic!("el primer registro tenía que crear la passkey");
        };
        let n = app.boveda.lock().unwrap().as_ref().unwrap().len();

        // Segundo intento excluyendo la que ya existe. AHORA exige aprobación: el
        // duplicado NO se revela sin que el usuario toque nada (§6.3.2). Se
        // comprueba justo eso —que el intento excluido LLEGA al diálogo—, no solo
        // que acabe en error. Si se revirtiera el arreglo (exclusión antes de
        // pedir permiso), la exclusión retornaría sin poblar `registro` y
        // `vio_dialogo` se quedaría en falso.
        let excluida = credential_id;
        std::thread::scope(|scope| {
            let manejador = scope.spawn(|| {
                a.atender(peticion_registrar_con(
                    "nube.example",
                    "https://nube.example",
                    "juan@x",
                    vec![excluida.clone()],
                ))
            });

            let mut vio_dialogo = false;
            for _ in 0..2000 {
                if app.registro.lock().unwrap().as_ref().is_some_and(|r| r.aprobado.is_none()) {
                    vio_dialogo = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert!(
                vio_dialogo,
                "el duplicado se resolvió SIN pedir aprobación: oráculo de reconocimiento abierto"
            );

            let id = app.registro.lock().unwrap().as_ref().unwrap().id;
            crate::gui::decidir_registro(
                &app,
                format!("{{\"id\":{id},\"aprobado\":true}}").as_bytes(),
            );
            let r = manejador.join().unwrap();
            assert!(matches!(r, Respuesta::Error { .. }), "no debía crear una segunda");
        });

        assert_eq!(
            app.boveda.lock().unwrap().as_ref().unwrap().len(),
            n,
            "excludeCredentials tenía que impedir la duplicación"
        );
    }

    /// Al RECHAZAR, un registro excluido es indistinguible de uno fresco: los dos
    /// devuelven «no autorizado», no el «ya hay una passkey». Sin esto, un no del
    /// usuario seguiría filtrando si la credencial existía —el mismo oráculo por
    /// la otra puerta—.
    #[test]
    fn un_registro_excluido_rechazado_no_revela_que_existia() {
        let (a, app) = agente_y_ventana("registro-dup-no", largo());

        let aprobador = aprobar_registro(Arc::clone(&app), true);
        let primero = a.atender(peticion_registrar("nube.example", "https://nube.example", "juan@x"));
        aprobador.join().unwrap();
        let Respuesta::Credencial { credential_id, .. } = primero else {
            panic!("el primer registro tenía que crear la passkey");
        };

        // Segundo intento excluyendo la que existe, pero el usuario RECHAZA.
        let rechazador = aprobar_registro(Arc::clone(&app), false);
        let r = a.atender(peticion_registrar_con(
            "nube.example",
            "https://nube.example",
            "juan@x",
            vec![credential_id],
        ));
        rechazador.join().unwrap();

        match r {
            Respuesta::Error { mensaje } => assert!(
                mensaje.contains("no se autorizó"),
                "un rechazo no puede revelar que la passkey ya existía: «{mensaje}»"
            ),
            otro => panic!("un rechazo tiene que dar error: {otro:?}"),
        }
    }

}

