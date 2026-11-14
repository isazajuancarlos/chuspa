// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! El NÚCLEO de la aplicación, compartido por la ventana y el agente del
//! navegador.
//!
//! Aquí ya no hay interfaz: la pantalla es GTK4 nativo (`src/bin/chuspa-gtk.rs`),
//! sin WebView, sin HTML, sin puerto. Este módulo guarda el estado compartido
//! (`Aplicacion`: la bóveda abierta, la firma pendiente, la presencia) y la
//! lógica que la ventana y el agente REUSAN en un solo sitio:
//! `decidir_firma` (aplica la decisión del usuario a la firma que espera el
//! navegador) y `construir`/`tres_estados` (funden una entrada del formulario
//! con la anterior). Desde 0.3.0 la extensión es solo passkeys: el agente ya no
//! propone guardar ni crear contraseñas, así que ese subsistema se retiró.
//!
//! # Lo que sigue sin cubrirse
//!
//! Un proceso local con tu usuario. Puede leer el archivo de la bóveda, hacer
//! `ptrace` al programa o leer el portapapeles. Ninguna interfaz lo evita: es
//! una limitación del escritorio sin aislamiento, y se dice en vez de fingir que
//! se cubre.
//!
//! *(La interfaz vieja por WebView —tao+wry, plantillas `maud` + htmx— se retiró
//! en la fase 3 de la migración a GTK, al alcanzar paridad la ventana nativa.)*

use crate::boveda::Valor;
use crate::cifrado::Boveda;
use serde::Deserialize;
use std::sync::Mutex;

/// Estado compartido entre la ventana y la lógica.
pub struct Aplicacion {
    pub ruta: std::path::PathBuf,
    pub boveda: Mutex<Option<Boveda>>,
    /// La firma que está esperando a que el usuario diga que sí.
    ///
    /// Vive aquí porque la piden dos sitios a la vez: el hilo del socket la
    /// deja y se queda esperando, y la ventana la lee para preguntar. Ver
    /// [`FirmaPendiente`].
    pub firma: Mutex<Option<FirmaPendiente>>,
    /// El registro de passkey que está esperando el visto bueno del usuario.
    ///
    /// Es el gemelo de [`Aplicacion::firma`] para `navigator.credentials.create`:
    /// crear una passkey también escribe en la bóveda y liga una cuenta a este
    /// dispositivo, así que no se hace sin que una persona lo apruebe en la
    /// ventana. Ver [`RegistroPendiente`].
    pub registro: Mutex<Option<RegistroPendiente>>,
    /// Para despertar al hilo del socket en cuanto el usuario decide, en vez de
    /// que sondee. La comparte la firma y el registro: cada hilo comprueba por su
    /// `id` si la decisión es la suya.
    pub decidida: std::sync::Condvar,
    /// Qué hacer cuando llega una firma a esperar permiso.
    ///
    /// Lo instala el binario de la ventana, y por eso es un cierre y no una
    /// llamada directa: esta biblioteca no sabe de ventanas —no depende de
    /// `tao`— y así las pruebas pueden comprobar que **el aviso sale** sin
    /// abrir ninguna. Lo que haga el gestor de ventanas con él ya no es cosa
    /// nuestra.
    avisar: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// Cuándo se supo por última vez que hay **una persona** delante.
    ///
    /// Lo lee el agente del navegador para decidir si sigue atendiendo, y lo
    /// sella tanto la ventana como el propio navegador: son las dos formas que
    /// tiene el usuario de estar usando el programa. Vive aquí, y no dentro del
    /// agente, porque el agente solo veía SU mitad — y con la ventana en uso
    /// toda la mañana el enlace se daba por caducado igual, contestándole al
    /// navegador que la bóveda estaba cerrada cuando estaba abierta en pantalla.
    ///
    /// Lo que **no** cuenta es el sondeo de la ventana (`GET /api/firma`, una
    /// vez por segundo) ni las peticiones del navegador: si contaran, el plazo no
    /// vencería nunca y quedaría una defensa que solo lo parece. Solo la
    /// INTERACCIÓN real la sella, llamando a [`Aplicacion::hay_alguien`].
    /// `None` = no se sabe de nadie, y no es lo mismo que «hace mucho».
    presencia: Mutex<Option<std::time::Instant>>,
    /// Lo que la importación o la restauración dejaron por decir.
    ///
    /// Vive en la aplicación y no en la respuesta de `crear` porque la pantalla
    /// nueva se teje en el servidor: un aviso que solo viajara en la respuesta
    /// de una petición desaparecería en el siguiente intercambio de htmx, que es
    /// justo cuando el usuario todavía no lo ha leído. Se quita cuando se
    /// descarta, que es una acción suya.
    ///
    /// La interfaz de Angular no los lee de aquí —los toma de la respuesta de
    /// `crear`, como siempre—, así que llenarlos no le cambia nada.
    avisos: Mutex<Vec<String>>,
    /// Contador que SUBE cada vez que el AGENTE (navegador) muta la bóveda en su
    /// hilo —hoy, registrar una passkey—. La ventana lo vigila en su sondeo para
    /// repoblar la lista cuando una passkey nace desde el navegador: sin esto la
    /// entrada se guarda pero no aparece hasta una acción manual o reabrir. Las
    /// ediciones DESDE la ventana NO lo tocan (ya repueblan ellas mismas), así que
    /// el sondeo no refresca de más ni le pierde la selección a una edición manual.
    generacion_boveda: std::sync::atomic::AtomicU64,
}

/// Una passkey que podría servir para lo que el sitio está pidiendo.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Candidata {
    /// Posición en la bóveda. No sale de la aplicación… salvo a la ventana, que
    /// ya puede ver la bóveda entera.
    pub entrada: usize,
    pub passkey: usize,
    pub nombre: String,
    pub usuario: Option<String>,
}

/// Una petición de firma esperando el visto bueno del usuario.
///
/// # Por qué existe
///
/// Sin esto, la aplicación firmaba **en cuanto se lo pedían**: con la bóveda
/// abierta, cualquier página que se visitara podía pedir una aserción y
/// obtenerla en silencio. Eso convierte la passkey en una cookie — basta con
/// entrar en un sitio para quedar autenticado ante él— y es justo lo que el
/// mecanismo existe para impedir. Y de paso, con varias cuentas para el mismo
/// sitio, se firmaba con la primera que apareciera sin preguntar cuál.
#[derive(Debug)]
pub struct FirmaPendiente {
    /// Identifica esta petición. Que la respuesta traiga el mismo evita que una
    /// decisión llegue tarde y se aplique a la petición siguiente.
    pub id: u64,
    pub rp_id: String,
    pub origen: String,
    pub candidatas: Vec<Candidata>,
    /// `None` mientras nadie ha dicho nada. `Some(None)` es un no.
    pub elegida: Option<Option<usize>>,
}

/// Una petición de REGISTRO esperando el visto bueno del usuario.
///
/// A diferencia de la firma, aquí no hay varias cuentas entre las que elegir: el
/// sitio pide crear UNA passkey, y la decisión es sí o no. Se muestra para qué
/// sitio y con qué cuenta, para que el usuario reconozca lo que va a guardar y no
/// autorice una passkey que una página abrió a su espalda.
#[derive(Debug, Clone)]
pub struct RegistroPendiente {
    pub id: u64,
    pub rp_id: String,
    /// El nombre legible del sitio, si lo dio (`rp.name`).
    pub rp_nombre: Option<String>,
    pub origen: String,
    /// La cuenta para la que se registra (`user.name`), para reconocerla.
    pub usuario: Option<String>,
    /// `None` mientras nadie ha dicho nada. `Some(false)` es un no.
    pub aprobado: Option<bool>,
}

impl Aplicacion {
    pub fn nueva(ruta: std::path::PathBuf) -> Self {
        Self {
            ruta,
            boveda: Mutex::new(None),
            firma: Mutex::new(None),
            registro: Mutex::new(None),
            decidida: std::sync::Condvar::new(),
            avisar: Mutex::new(None),
            // Se arranca sellada, no vacía: los arneses de prueba y los ejemplos
            // meten la bóveda a mano sin pasar por la ventana, y con `None` el
            // enlace nacería muerto para ellos. En la aplicación de verdad da
            // igual: abrir la bóveda sella la presencia de nuevo.
            presencia: Mutex::new(Some(std::time::Instant::now())),
            avisos: Mutex::new(Vec::new()),
            generacion_boveda: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Los avisos pendientes de leer.
    pub fn avisos(&self) -> Vec<String> {
        self.avisos.lock().unwrap().clone()
    }

    /// La generación actual de la bóveda (ver el campo `generacion_boveda`). La
    /// ventana compara este valor entre sondeos para saber si el AGENTE añadió algo.
    pub fn generacion_boveda(&self) -> u64 {
        self.generacion_boveda.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Marca que la bóveda cambió DESDE EL HILO DEL AGENTE (registro de passkey),
    /// para que la ventana repueble la lista en su próximo sondeo.
    pub fn marcar_cambio_boveda(&self) {
        self.generacion_boveda.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Deja constancia de que el usuario acaba de hacer algo.
    pub fn hay_alguien(&self) {
        *self.presencia.lock().unwrap() = Some(std::time::Instant::now());
    }

    /// ¿Se supo de alguien hace menos de `plazo`?
    ///
    /// Se pregunta así, y no «cuánto hace», porque *nunca* no es una duración:
    /// tras un bloqueo no hay ningún instante que devolver, y fabricar uno
    /// —restarle un año a `Instant::now()`— desborda en una máquina recién
    /// arrancada, que es justo cuando nadie lo probaría.
    pub fn alguien_hace_menos_de(&self, plazo: std::time::Duration) -> bool {
        matches!(*self.presencia.lock().unwrap(), Some(t) if t.elapsed() < plazo)
    }

    /// Da la presencia por vencida ahora mismo, pase el plazo que pase.
    ///
    /// Lo pide el navegador con `Bloquear`. No cierra la bóveda: eso solo pasa
    /// en la ventana.
    pub fn olvidar_la_presencia(&self) {
        *self.presencia.lock().unwrap() = None;
    }

    /// Instala el aviso que se dispara cuando algo se queda esperando respuesta
    /// del usuario: una firma que autorizar o una credencial que guardar.
    ///
    /// La ventana puede estar detrás del navegador —es lo normal, porque el
    /// usuario está mirando el sitio donde va a entrar—, y entonces la espera
    /// es indistinguible de un fallo: el sitio se queda «verificando» y no hay
    /// nada que diga dónde mirar.
    pub fn cuando_haya_que_preguntar(&self, aviso: impl Fn() + Send + 'static) {
        *self.avisar.lock().unwrap() = Some(Box::new(aviso));
    }

    /// Dispara el aviso, si hay alguno instalado.
    ///
    /// Sin nadie escuchando no pasa nada: el arnés de pruebas y el ejemplo del
    /// socket corren sin ventana, y una firma tiene que poder esperar igual.
    pub fn avisar_de_pregunta(&self) {
        if let Some(aviso) = self.avisar.lock().unwrap().as_ref() {
            aviso();
        }
    }
}

/// Lo que la ventana tiene que preguntar, si hay algo.
///
/// Devuelve `{"hay": false}` cuando no hay nada pendiente. Nunca lleva un
/// secreto: solo el sitio que pide, el origen que puso el navegador, y los
/// nombres de cuenta entre los que elegir.
pub fn decidir_firma(app: &Aplicacion, cuerpo: &[u8]) -> Salida {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cuerpo {
        id: u64,
        /// Ausente o `null` es un no.
        #[serde(default)]
        elegida: Option<usize>,
    }
    let Ok(c) = serde_json::from_slice::<Cuerpo>(cuerpo) else {
        return Salida::error(400, "cuerpo inválido");
    };

    let mut guard = app.firma.lock().unwrap();
    let Some(f) = guard.as_mut() else {
        return Salida::error(409, "ya no hay ninguna firma esperando");
    };
    if f.id != c.id {
        return Salida::error(409, "esa decisión es de otra petición");
    }
    // Elegir una candidata que no está en la lista firmaría con otra cuenta.
    if let Some(i) = c.elegida
        && i >= f.candidatas.len()
    {
        return Salida::error(400, "esa cuenta no está entre las ofrecidas");
    }
    f.elegida = Some(c.elegida);
    app.decidida.notify_all();
    Salida::json(200, serde_json::json!({ "hecho": true }))
}

/// Aplica la decisión del usuario sobre un REGISTRO pendiente. El gemelo de
/// [`decidir_firma`]: mismas comprobaciones de `id` (una decisión tardía no vale
/// para la petición siguiente), y `aprobado` en vez de una candidata elegida.
pub fn decidir_registro(app: &Aplicacion, cuerpo: &[u8]) -> Salida {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cuerpo {
        id: u64,
        aprobado: bool,
    }
    let Ok(c) = serde_json::from_slice::<Cuerpo>(cuerpo) else {
        return Salida::error(400, "cuerpo inválido");
    };

    let mut guard = app.registro.lock().unwrap();
    let Some(r) = guard.as_mut() else {
        return Salida::error(409, "ya no hay ningún registro esperando");
    };
    if r.id != c.id {
        return Salida::error(409, "esa decisión es de otra petición");
    }
    r.aprobado = Some(c.aprobado);
    app.decidida.notify_all();
    Salida::json(200, serde_json::json!({ "hecho": true }))
}

/// Lo que devuelve `decidir_firma`: un código, un tipo y el cuerpo. La app GTK
/// la llama y descarta la respuesta; el código lo usaba la ventana web ya
/// retirada.
#[derive(Debug)]
pub struct Salida {
    pub estado: u16,
    pub tipo: String,
    pub cuerpo: Vec<u8>,
}

impl Salida {
    fn json(estado: u16, valor: serde_json::Value) -> Self {
        Self {
            estado,
            tipo: "application/json".into(),
            cuerpo: serde_json::to_vec(&valor).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    fn error(estado: u16, mensaje: impl std::fmt::Display) -> Self {
        Self::json(estado, serde_json::json!({ "error": mensaje.to_string() }))
    }
}

/// Lo que la interfaz manda al guardar una entrada, con los campos sueltos: la
/// app GTK la arma en `entrada_del_formulario` (y la ventana web la
/// deserializaba). `construir` la funde con la entrada anterior.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct EntradaEntrante {
    pub nombre: String,
    pub usuario: Option<String>,
    pub clave: Option<String>,
    pub totp: Option<String>,
    pub notas: Option<String>,
    /// Una URI por línea, como se teclean.
    pub uris: Option<String>,
    pub carpeta: Option<String>,
}

fn texto_de(entrada: &crate::boveda::Entrada, etiqueta: &str) -> Option<String> {
    entrada.campo(etiqueta).and_then(|c| match &c.valor {
        Valor::Texto(t) => Some(t.clone()),
        Valor::Secreto(s) => Some(s.to_string()),
        _ => None,
    })
}

/// Traduce un campo del formulario a la semántica de tres estados, la ÚNICA
/// regla que aplica la app GTK (`entrada_del_formulario`): vacío o solo-espacios
/// sin «Quitar» → `None` (no tocar); vacío con «Quitar» → `Some("")` (borrar);
/// con valor real → `Some(valor)`; valor real Y «Quitar» a la vez → `Err`. El
/// `trim()` impide que un espacio suelto —invisible en un campo enmascarado—
/// pase por «poner» y acabe borrando el secreto.
///
/// El error es `()` a propósito: solo hay una forma de fallar (valor+quitar), y
/// el mensaje para el usuario lo pone la interfaz.
#[allow(clippy::result_unit_err)]
pub fn tres_estados(valor: &str, quitar: bool) -> Result<Option<String>, ()> {
    match (valor.trim().is_empty(), quitar) {
        (false, true) => Err(()),
        (_, true) => Ok(Some(String::new())),
        (true, false) => Ok(None),
        (false, false) => Ok(Some(valor.to_string())),
    }
}

pub fn construir(e: EntradaEntrante, anterior: Option<crate::boveda::Entrada>) -> crate::boveda::Entrada {
    use crate::boveda::{Campo, Clase, Entrada, Uri};

    let mut campos = Vec::new();
    let mut poner = |etiqueta: &str, valor: Option<String>, secreto: bool| {
        if let Some(v) = valor.filter(|v| !v.trim().is_empty()) {
            let valor = if secreto { Valor::secreto(v) } else { Valor::texto(v) };
            campos.push(Campo::estandar(etiqueta, valor));
        }
    };
    poner("acceso.usuario", e.usuario, false);

    // La contraseña sigue la MISMA regla que el segundo factor, y por el mismo
    // motivo: la pantalla nueva no la devuelve al editar —dejarla escrita en el
    // formulario sería dejarla en el DOM de una ventana que se queda abierta—,
    // así que «no viene» no puede significar «bórrala».
    //
    // Angular no se entera: manda siempre el campo, así que para él nada cambia.
    match e.clave.clone() {
        // El cierre `poner` tiene prestado `campos`, así que la rama que
        // conserva la anterior no puede tocarlo aquí: se resuelve a un valor y
        // se pone por el mismo sitio que todo lo demás.
        None => poner(
            "acceso.clave",
            anterior.as_ref().and_then(|a| texto_de(a, "acceso.clave")),
            true,
        ),
        Some(c) => poner("acceso.clave", Some(c), true),
    }

    // El segundo factor se trata distinto de los otros dos, y hace falta.
    //
    // El detalle devuelve el CÓDIGO de seis dígitos, no el secreto: el secreto
    // no sale nunca de la bóveda hacia la ventana, porque pegar el código en esa
    // casilla lo destruiría. Consecuencia: la ventana no puede devolver lo que
    // no recibió, así que manda el campo vacío al corregir cualquier otra cosa —
    // y «vacío» valía como «bórralo». Corregir el NOMBRE de una entrada le
    // destruía el segundo factor, sin error y sin que nada se viera raro hasta
    // el día que hiciera falta entrar.
    //
    // Ahora se distinguen las dos cosas, que es lo que el campo `Option` ya
    // sabía decir y nadie estaba escuchando:
    //
    //   ausente o `null` → **no se toca**: el dato no viene, no se sustituye
    //   `""`             → **se quita**, y eso lo pide el usuario a propósito
    //
    // Los otros dos campos no necesitan esto porque el detalle SÍ los devuelve:
    // si llegan vacíos es porque alguien los vació.
    match e.totp {
        None => {
            if let Some(a) = &anterior
                && let Some(c) = a.campo("acceso.totp")
            {
                campos.push(c.clone());
            }
        }
        Some(t) => poner("acceso.totp", Some(t), true),
    }

    // Todo lo que la interfaz no toca se conserva tal cual.
    //
    // **El espacio `acceso.*` es del PROGRAMA, venga el campo de donde venga.**
    // Antes esta condición era `!gestionado || es_personalizado`, y ese `||` era
    // una puerta trasera: un export de Bitwarden puede traer un campo
    // personalizado llamado exactamente `acceso.clave` —el importador conserva
    // el nombre crudo del archivo—, y entonces marcar «Quitar la contraseña»
    // devolvía 200 y la entrada se quedaba con la contraseña del import. El
    // usuario cree que borró un secreto y el secreto sigue ahí, que es el peor
    // lado por el que puede fallar esto. Lo encontró la revisión de seguridad de
    // esta rama.
    //
    // Un campo personalizado que invada el espacio del programa se descarta
    // aquí: lo que decide qué vale como `acceso.clave` es `construir`, y solo
    // `construir`.
    if let Some(a) = &anterior {
        for campo in &a.campos {
            let gestionado = matches!(
                campo.etiqueta.as_str(),
                "acceso.usuario" | "acceso.clave" | "acceso.totp"
            );
            if !gestionado {
                campos.push(campo.clone());
            }
        }
    }

    // La regla de coincidencia de cada URI **no viaja por la interfaz** —allí una
    // dirección es una línea de texto— así que se recupera de la entrada
    // anterior emparejando por el texto de la URI.
    //
    // Sin esto, editar el NOMBRE de una entrada le cambiaba a qué páginas sirve:
    // toda regla importada volvía al defecto. Y no solo estrechaba. Una URI
    // marcada como `Nunca` —la que Bitwarden usa para «no ofrecer sola», y a la
    // que van a parar también las de expresión regular— pasaba a ofrecerse en
    // cualquier página del host. Ningún error, ningún aviso: una credencial que
    // el usuario había apartado a propósito volvía a salir sola.
    //
    // Una línea que no estaba antes no hereda nada, y es correcto: no se puede
    // saber de cuál venía, y suponerlo sería inventar el dato en vez de dejar el
    // hueco.
    let uris = e
        .uris
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| Uri {
            uri: l.to_string(),
            coincidencia: anterior
                .as_ref()
                .and_then(|a| a.uris.iter().find(|u| u.uri == l))
                .and_then(|u| u.coincidencia),
        })
        .collect();

    // La contraseña que se sustituye NO se tira: pasa al historial con la fecha
    // en que dejó de servir. Es exactamente para lo que existe ese campo, y sin
    // esto corregir la contraseña de hoy borraba la de ayer sin dar ningún
    // error — el fallo solo se descubre el día que hace falta la vieja. Vale
    // igual para la ventana que para lo que llega del navegador: si la regla
    // solo cubriera un camino, el otro seguiría perdiendo datos.
    // Y **quitarla también es dejar de usarla**: si no, la vigente desaparecía sin
    // rastro mientras las anteriores seguían en el historial, así que la entrada
    // acababa guardando la contraseña de hace dos cambios y perdiendo la última.
    // `ClaveAnterior` responde a «ante una filtración fechada, ¿era ésta?», y esa
    // pregunta no deja de tener sentido porque el usuario haya vaciado el campo.
    // Lo encontró la revisión de seguridad de esta rama.
    let mut historial = anterior.as_ref().map(|a| a.historial.clone()).unwrap_or_default();
    if let Some(a) = &anterior
        && let Some(vieja) = texto_de(a, "acceso.clave")
        && match e.clave.as_deref() {
            // Ausente = no se toca: no hay sustitución que apuntar.
            None => false,
            // Vacía = se quita. Deja de estar en uso, y eso se apunta.
            Some(nueva) if nueva.trim().is_empty() => true,
            Some(nueva) => nueva != vieja,
        }
    {
        historial.insert(
            0,
            crate::boveda::ClaveAnterior {
                clave: zeroize::Zeroizing::new(vieja),
                usada_hasta: Some(crate::fecha::ahora_utc()),
            },
        );
    }

    Entrada {
        id_origen: anterior.as_ref().and_then(|a| a.id_origen.clone()),
        nombre: e.nombre.trim().to_string(),
        clase: anterior.as_ref().map(|a| a.clase).unwrap_or(Clase::Acceso),
        // Y la carpeta, que es la tercera de la misma familia. El detalle **no
        // la devuelve**, así que la ventana no puede devolverla al guardar:
        // corregir el nombre de una entrada la sacaba de su carpeta, sin error
        // y sin que nada se viera raro. Ausente = no se toca; `""` = se quita.
        carpeta: match &e.carpeta {
            None => anterior.as_ref().and_then(|a| a.carpeta.clone()),
            Some(c) if c.trim().is_empty() => None,
            Some(c) => Some(c.clone()),
        },
        favorita: anterior.as_ref().is_some_and(|a| a.favorita),
        archivada: anterior.as_ref().and_then(|a| a.archivada.clone()),
        repreguntar: anterior.as_ref().is_some_and(|a| a.repreguntar),
        notas: e
            .notas
            .filter(|n| !n.trim().is_empty())
            .map(zeroize::Zeroizing::new),
        campos,
        uris,
        historial,
        // Solo se fecha lo que NACE aquí. A una entrada importada sin fecha no
        // se le inventa una por editarla: sería un dato falso, y un dato falso
        // no se nota nunca — a diferencia de un hueco, que sí.
        creada: match &anterior {
            Some(a) => a.creada.clone(),
            None => Some(crate::fecha::ahora_utc()),
        },
        revisada: anterior.as_ref().and_then(|a| a.revisada.clone()),
    }
}

