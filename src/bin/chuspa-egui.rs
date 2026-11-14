// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Frontal de escritorio de chuspa en **egui** (migración 2026-10-04, Fase 1).
//!
//! Reusa el NÚCLEO tal cual —`cifrado::Boveda`, `boveda::Entrada`, `totp::Totp`—
//! sin tocar una línea de la criptografía; esto es solo la capa de vista. El tema
//! lo pone `huitaca` (compartido con boza y con la web vía los mismos tokens que
//! `boi`). Convive con `chuspa-gtk` durante la migración (cada bin tras su
//! feature). Un solo `.exe`, sin runtime que empaquetar en Windows.
//!
//! Fase 1: desbloqueo + lista con filtro + detalle (usuario / contraseña
//! revelar-copiar / TOTP en vivo). Solo LECTURA de la bóveda.
//!
//! Fase 2 (2026-10-04): crear / editar / borrar entrada, con el generador de
//! contraseñas integrado en el formulario. La escritura reusa el NÚCLEO sin
//! reinventarlo: `gui::construir` (que ya resuelve la semántica de tres estados
//! —ausente = no tocar, vacío = quitar, con valor = poner— sobre la que se han
//! roto tantas cosas en este repo) y `Boveda::{anadir,reemplazar,borrar,guardar}`.
//! Clave y segundo factor **no se vuelcan al editor**: igual que en la pantalla
//! web, «no viene» significa «consérvalo», y quitarlos es una casilla explícita.

// Sin consola: es una app GUI. Sin esto, Windows abre un símbolo del sistema
// detrás de la ventana. En otras plataformas el atributo se ignora. Para
// depurar sigue estando `CHUSPA_BITACORA`, no la salida estándar.
#![windows_subsystem = "windows"]

use eframe::egui;
use egui::{vec2, CornerRadius, Margin, RichText};
use huitaca::Paleta;

use chuspa::boveda::{Entrada, Valor};
use chuspa::cifrado::{Acceso, Boveda};
use chuspa::copia;
use chuspa::generador::{self, Composicion};
use chuspa::gui::{construir, decidir_firma, decidir_registro, tres_estados, Aplicacion, EntradaEntrante};
use chuspa::importar::{bitwarden, bitwarden_csv};
use chuspa::navegador;
use chuspa::salud::{self, Informe};
use chuspa::totp::Totp;
use std::path::PathBuf;
use std::sync::Arc;

/// Ruta de bóveda por defecto en Windows: `%APPDATA%\chuspa\boveda.chuspa`.
/// (En Linux el bin GTK usa `~/.local/share/chuspa`; aquí priorizamos el host.)
fn ruta_por_defecto() -> String {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_DATA_HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("chuspa").join("boveda.chuspa").to_string_lossy().into_owned()
}

/// Saca el texto de un campo (sea `Texto` o `Secreto`). Las contraseñas son
/// `Secreto`; solo se pintan tras pulsar «Revelar».
fn texto_campo(e: &Entrada, etiqueta: &str) -> Option<String> {
    e.campo(etiqueta).and_then(|c| match &c.valor {
        Valor::Texto(t) => Some(t.clone()),
        Valor::Secreto(s) => Some(s.to_string()),
        _ => None,
    })
}

/// La longitud (en caracteres) de un campo de texto o secreto, SIN materializar
/// su valor a un `String` plano. Para los puntos de una contraseña oculta no hace
/// falta sacar el secreto de su envoltura `Zeroizing` (deref a `str`).
fn longitud_campo(e: &Entrada, etiqueta: &str) -> Option<usize> {
    e.campo(etiqueta).and_then(|c| match &c.valor {
        Valor::Texto(t) => Some(t.chars().count()),
        Valor::Secreto(s) => Some(s.chars().count()),
        _ => None,
    })
}

fn copiar(ui: &egui::Ui, texto: &str) {
    ui.ctx().copy_text(texto.to_owned());
}

#[derive(PartialEq)]
enum Pantalla {
    Bloqueada,
    Abierta,
}

/// Lo que el formulario del editor le pide a `App` al terminar un fotograma.
/// El editor muta sus propios campos dentro de la UI, pero guardar o cancelar
/// tocan `self` entero, así que se devuelven como acción y se procesan fuera del
/// panel (evita el doble préstamo de `self`).
enum AccionEditor {
    Ninguna,
    Guardar,
    Cancelar,
}

/// Lo que el informe de salud le pide a `App`: cerrarlo, o saltar a una entrada.
enum AccionSalud {
    Ninguna,
    Cerrar,
    Saltar(usize),
}

/// Lo que la pantalla de copia le pide a `App`.
enum AccionCopia {
    Ninguna,
    Crear,
    Cerrar,
}

/// Lo que la sección de passkeys le pide a `App`. Se procesa FUERA del panel
/// (como `AccionEditor`): quitar una passkey toca `self` entero —abre la
/// entrada, la muta y guarda— y eso choca con el préstamo de `self.entrada` que
/// la propia tarjeta tiene vivo mientras dibuja.
enum AccionPasskey {
    Ninguna,
    /// El usuario pulsó «Quitar» en la passkey `n`: pedir confirmación.
    Confirmar(usize),
    /// Confirmó: quitar la passkey `n` y persistir.
    Quitar(usize),
    /// Canceló la confirmación.
    Cancelar,
}

/// Estado de la pantalla de copia de seguridad. La frase cifra la copia (puede
/// ser la maestra u otra); se confirma dos veces para no cifrar con un typo —no
/// se puede validar contra la bóveda abierta porque reabrirla choca con su
/// cerrojo de archivo—.
#[derive(Default)]
struct EstadoCopia {
    frase: String,
    confirmar: String,
    ruta: Option<String>,
    resultado: Option<String>,
}

/// Estado de «restaurar desde una copia», en la pantalla de desbloqueo: toma un
/// `.chuspacopia` + su frase y escribe una bóveda nueva en `destino` con una
/// frase nueva (confirmada dos veces). No toca ninguna bóveda existente.
#[derive(Default)]
struct EstadoRestaurar {
    copia: Option<String>,
    frase_copia: String,
    destino: Option<String>,
    frase_nueva: String,
    confirmar: String,
    resultado: Option<String>,
}

/// Estado del formulario de crear/editar. `indice = None` es una entrada nueva;
/// `Some(i)` edita la de ese índice.
///
/// **Clave y TOTP arrancan vacíos también al editar**, a propósito: el secreto no
/// se saca de la bóveda hacia un `String` plano del formulario (coherente con
/// `unsafe_code = forbid` y con no esparcir secretos), y así «campo vacío»
/// significa «no lo toques» —exactamente lo que `gui::construir` espera—. Para
/// quitarlos hay una casilla.
struct Editor {
    indice: Option<usize>,
    nombre: String,
    usuario: String,
    uris: String,
    carpeta: String,
    notas: String,
    clave: String,
    quitar_clave: bool,
    revelar_clave: bool,
    totp: String,
    quitar_totp: bool,
    gen_largo: usize,
    gen_mayusculas: bool,
    gen_digitos: bool,
    gen_simbolos: bool,
    gen_sin_ambiguos: bool,
    error: Option<String>,
}

impl Editor {
    fn nueva() -> Self {
        Self {
            indice: None,
            nombre: String::new(),
            usuario: String::new(),
            uris: String::new(),
            carpeta: String::new(),
            notas: String::new(),
            clave: String::new(),
            quitar_clave: false,
            revelar_clave: false,
            totp: String::new(),
            quitar_totp: false,
            gen_largo: 20,
            gen_mayusculas: true,
            gen_digitos: true,
            gen_simbolos: true,
            gen_sin_ambiguos: false,
            error: None,
        }
    }

    /// Pre-rellena desde una entrada existente **todo menos los secretos**:
    /// nombre, usuario, direcciones, carpeta y notas vienen del detalle; clave y
    /// segundo factor se dejan vacíos (ver la nota del tipo).
    fn de(e: &Entrada, i: usize) -> Self {
        let mut ed = Self::nueva();
        ed.indice = Some(i);
        ed.nombre = e.nombre.clone();
        ed.usuario = texto_campo(e, "acceso.usuario").unwrap_or_default();
        ed.carpeta = e.carpeta.clone().unwrap_or_default();
        ed.notas = e.notas.as_ref().map(|n| n.to_string()).unwrap_or_default();
        ed.uris = e.uris.iter().map(|u| u.uri.clone()).collect::<Vec<_>>().join("\n");
        ed
    }

    fn composicion(&self) -> Composicion {
        Composicion {
            minusculas: true,
            mayusculas: self.gen_mayusculas,
            digitos: self.gen_digitos,
            simbolos: self.gen_simbolos,
            sin_ambiguos: self.gen_sin_ambiguos,
        }
    }
}

struct App {
    pantalla: Pantalla,
    ruta: String,
    frase: String,
    error: Option<String>,
    /// El NÚCLEO compartido con el agente del navegador (Fase C). La bóveda ya no
    /// vive aquí sino en `nucleo.boveda.lock()`, para que la ventana y el agente
    /// la compartan tras un solo cerrojo —el de archivo impide abrirla dos veces—.
    /// El agente lee esta misma bóveda para firmar las passkeys que pide el
    /// navegador, y la firma espera la aprobación del usuario en esta ventana.
    nucleo: Arc<Aplicacion>,
    /// La petición (firma o registro) para la que ya se trajo la ventana al frente,
    /// para no robar el foco en cada fotograma mientras el diálogo está abierto.
    /// Se identifica por el `id` de la pendiente, que es único por petición.
    presentada: Option<u64>,
    filtro: String,
    sel: usize,
    revelar: bool,
    entrada: Option<Entrada>,
    totp: Option<Totp>,
    editor: Option<Editor>,
    confirmar_borrado: bool,
    /// Índice de la passkey para la que se está pidiendo confirmación de borrado
    /// (`None` = ninguna). Se limpia al cambiar de entrada (`cargar_entrada`).
    confirmar_quitar_passkey: Option<usize>,
    aviso: Option<String>,
    salud: Option<Informe>,
    copia: Option<EstadoCopia>,
    /// Resultado de la última importación: cuántas entradas y los avisos (que
    /// deben llegar al usuario, no quedarse en un log).
    importe: Option<(usize, Vec<String>)>,
    restaurar: Option<EstadoRestaurar>,
    frames_maximizar: u8,
}

impl Default for App {
    fn default() -> Self {
        Self {
            pantalla: Pantalla::Bloqueada,
            ruta: ruta_por_defecto(),
            frase: String::new(),
            error: None,
            nucleo: Arc::new(Aplicacion::nueva(PathBuf::from(ruta_por_defecto()))),
            presentada: None,
            filtro: String::new(),
            sel: 0,
            revelar: false,
            entrada: None,
            totp: None,
            editor: None,
            confirmar_borrado: false,
            confirmar_quitar_passkey: None,
            aviso: None,
            salud: None,
            copia: None,
            importe: None,
            restaurar: None,
            frames_maximizar: 3,
        }
    }
}

impl App {
    /// Crea la app y arranca el enlace con el navegador (Fase C). El agente
    /// escucha desde el arranque —no desde el desbloqueo— igual que el frontal
    /// GTK: con la bóveda cerrada responde «cerrada» y no la abre, así que no
    /// hace falta que el navegador tenga ninguna credencial ni que la ventana
    /// esté desbloqueada para que el socket exista.
    ///
    /// El plazo de inactividad es de 12 h, el mismo que GTK: la presencia la
    /// sella la interacción real del usuario (ver `update`), no el repintado.
    fn new(ctx: &egui::Context) -> Self {
        let app = Self::default();
        match navegador::escuchar_al_navegador(
            Arc::clone(&app.nucleo),
            std::time::Duration::from_secs(12 * 60 * 60),
        ) {
            Ok(socket) => eprintln!("Atendiendo al navegador en {}", socket.display()),
            Err(e) => eprintln!("AVISO: la extensión no podrá conectarse ({e})"),
        }
        // Despertar el repintado cuando el agente deja una firma/registro a la
        // espera: el cierre corre en el hilo del agente (con el candado de
        // `firma`/`registro` tomado), así que hace lo MÍNIMO y nada que vuelva a
        // tomar ese candado —solo pedir un repintado—. La pantalla abierta ya
        // repinta de continuo por el TOTP, pero esto cubre el resto sin coste.
        let repintar = ctx.clone();
        app.nucleo.cuando_haya_que_preguntar(move || repintar.request_repaint());
        app
    }

    /// Intenta abrir la bóveda con la frase actual. Reusa el núcleo (Argon2id vía
    /// quipu dentro de `Boveda::abrir`). La bóveda abierta se deja en el núcleo
    /// compartido (`nucleo.boveda`), que es de donde la lee el agente.
    fn desbloquear(&mut self) {
        match Boveda::abrir(&self.ruta, &Acceso::frase(&self.frase)) {
            Ok(b) => {
                *self.nucleo.boveda.lock().unwrap() = Some(b);
                self.nucleo.hay_alguien(); // acabar de teclear la frase es presencia
                self.frase.clear(); // no retener la frase en memoria más de lo necesario
                self.sel = 0;
                self.revelar = false;
                self.error = None;
                self.cargar_entrada();
                self.pantalla = Pantalla::Abierta;
            }
            Err(e) => self.error = Some(format!("{e}")),
        }
    }

    /// Restaura una copia (`copia::restaurar`) a una bóveda nueva. No toca ninguna
    /// bóveda abierta ni existente: escribe un archivo nuevo en `destino`. Al
    /// terminar deja ese destino cargado para que el usuario lo abra con su frase.
    fn restaurar_copia(&mut self) {
        let Some(est) = self.restaurar.as_ref() else { return };
        let problema = if est.copia.is_none() {
            Some("Elige el archivo de copia.")
        } else if est.frase_copia.is_empty() {
            Some("Escribe la frase de la copia.")
        } else if est.destino.is_none() {
            Some("Elige dónde guardar la bóveda restaurada.")
        } else if est.frase_nueva.is_empty() {
            Some("Escribe la frase para la bóveda nueva.")
        } else if est.frase_nueva != est.confirmar {
            Some("Las dos frases nuevas no coinciden.")
        } else {
            None
        };
        if let Some(msg) = problema {
            if let Some(est) = self.restaurar.as_mut() {
                est.resultado = Some(msg.to_string());
            }
            return;
        }
        let copia_ruta = est.copia.clone().unwrap_or_default();
        let destino = est.destino.clone().unwrap_or_default();
        let frase_copia = est.frase_copia.clone();
        let frase_nueva = est.frase_nueva.clone();
        let res = (|| -> Result<copia::Ficha, String> {
            let bytes = std::fs::read(&copia_ruta).map_err(|e| format!("no se pudo leer la copia: {e}"))?;
            copia::restaurar(
                &bytes,
                &Acceso::frase(&frase_copia),
                &destino,
                &Acceso::frase(&frase_nueva),
            )
            .map_err(|e| format!("{e}"))
        })();
        match res {
            Ok(f) => {
                self.ruta = destino;
                self.restaurar = None;
                self.error = None;
                self.aviso = Some(format!("Bóveda restaurada ({} entradas). Ábrela con su frase nueva.", f.entradas));
            }
            Err(msg) => {
                if let Some(est) = self.restaurar.as_mut() {
                    est.resultado = Some(format!("No se pudo restaurar: {msg}"));
                }
            }
        }
    }

    /// El formulario de restaurar, en la pantalla de desbloqueo. Devuelve
    /// `(restaurar_pedido, volver)`.
    fn ui_restaurar(&mut self, ui: &mut egui::Ui, p: &Paleta) -> (bool, bool) {
        let Some(est) = self.restaurar.as_mut() else { return (false, false) };
        let (mut hacer, mut volver) = (false, false);
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.label(RichText::new("Restaurar desde una copia").size(26.0).strong().color(p.acento));
                ui.label(RichText::new("Crea una bóveda nueva; no toca ninguna existente").size(13.0).color(p.suave));
                ui.add_space(20.0);
            });
            ui.vertical_centered(|ui| {
                ui.set_max_width(520.0);
                egui::Frame::new()
                    .fill(p.tarjeta)
                    .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                    .inner_margin(Margin::same(16))
                    .stroke(egui::Stroke::new(1.0_f32, p.borde))
                    .show(ui, |ui| {
                        ui.label(RichText::new("Archivo de copia").size(12.0).color(p.suave));
                        if ui.add(egui::Button::new(RichText::new("Elegir copia…").size(13.0)).fill(p.tarjeta)).clicked()
                            && let Some(elegido) = rfd::FileDialog::new().add_filter("Copia chuspa", &["chuspacopia"]).pick_file()
                        {
                            est.copia = Some(elegido.to_string_lossy().into_owned());
                        }
                        ui.add_space(3.0);
                        ui.label(RichText::new(est.copia.clone().unwrap_or_else(|| "(ninguna elegida)".into())).size(11.0).color(p.tenue).monospace());
                        ui.add_space(10.0);
                        ui.label(RichText::new("Frase de la copia").size(12.0).color(p.suave));
                        ui.add(egui::TextEdit::singleline(&mut est.frase_copia).password(true).desired_width(f32::INFINITY));
                        ui.add_space(14.0);

                        ui.label(RichText::new("Guardar la bóveda restaurada en").size(12.0).color(p.suave));
                        if ui.add(egui::Button::new(RichText::new("Elegir destino…").size(13.0)).fill(p.tarjeta)).clicked()
                            && let Some(elegido) = rfd::FileDialog::new().add_filter("Bóveda chuspa", &["chuspa"]).set_file_name("boveda.chuspa").save_file()
                        {
                            est.destino = Some(elegido.to_string_lossy().into_owned());
                        }
                        ui.add_space(3.0);
                        ui.label(RichText::new(est.destino.clone().unwrap_or_else(|| "(ninguno elegido)".into())).size(11.0).color(p.tenue).monospace());
                        ui.add_space(10.0);
                        ui.label(RichText::new("Frase para la bóveda nueva").size(12.0).color(p.suave));
                        ui.add(egui::TextEdit::singleline(&mut est.frase_nueva).password(true).desired_width(f32::INFINITY));
                        ui.add_space(8.0);
                        ui.label(RichText::new("Confirmar frase nueva").size(12.0).color(p.suave));
                        ui.add(egui::TextEdit::singleline(&mut est.confirmar).password(true).desired_width(f32::INFINITY));
                        ui.add_space(14.0);
                        if ui.add_sized([ui.available_width(), 34.0], egui::Button::new(RichText::new("Restaurar").size(14.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                            hacer = true;
                        }
                    });
                if let Some(r) = &est.resultado {
                    ui.add_space(12.0);
                    ui.label(RichText::new(r).size(12.0).color(egui::Color32::from_rgb(0xE0, 0x7B, 0x7B)));
                }
                ui.add_space(12.0);
                if ui.add(egui::Button::new(RichText::new("Volver").size(13.0)).fill(p.tarjeta)).clicked() {
                    volver = true;
                }
            });
        });
        (hacer, volver)
    }

    /// (Re)descifra la entrada seleccionada y reinterpreta su TOTP. `res` sale
    /// owned, así que el préstamo de `self.boveda` termina antes de mutar.
    fn cargar_entrada(&mut self) {
        let res = self.nucleo.boveda.lock().unwrap().as_ref().and_then(|b| {
            if self.sel < b.len() {
                b.abrir_entrada(self.sel).ok()
            } else {
                None
            }
        });
        self.totp = res
            .as_ref()
            .and_then(|e| texto_campo(e, "acceso.totp"))
            .and_then(|s| Totp::interpretar(&s).ok());
        self.entrada = res;
        self.revelar = false;
        self.confirmar_quitar_passkey = None;
    }

    /// Construye la entrada desde el formulario y la persiste (añadir o
    /// reemplazar, luego `guardar` al disco). Toda la semántica delicada —qué
    /// hacer con un secreto que no viene, el historial de contraseñas, las reglas
    /// de coincidencia de cada URI— vive en `gui::construir`; aquí solo se arma el
    /// `EntradaEntrante` y se escribe.
    fn guardar_editor(&mut self) {
        let ed = match self.editor.as_ref() {
            Some(e) => e,
            None => return,
        };
        if ed.nombre.trim().is_empty() {
            if let Some(ed) = self.editor.as_mut() {
                ed.error = Some("El nombre no puede quedar vacío.".to_string());
            }
            return;
        }
        // Tres estados para los dos secretos (reusa la lógica del núcleo): vacío =
        // conservar, con valor = poner, casilla «Quitar» = quitar. Escribir un
        // valor Y marcar «Quitar» es contradictorio y se rechaza.
        let (clave, totp) = match (tres_estados(&ed.clave, ed.quitar_clave), tres_estados(&ed.totp, ed.quitar_totp)) {
            (Ok(c), Ok(t)) => (c, t),
            _ => {
                if let Some(ed) = self.editor.as_mut() {
                    ed.error = Some("No escribas un valor y marques «Quitar» a la vez.".to_string());
                }
                return;
            }
        };
        let entrante = EntradaEntrante {
            nombre: ed.nombre.trim().to_string(),
            usuario: Some(ed.usuario.clone()),
            clave,
            totp,
            notas: Some(ed.notas.clone()),
            uris: Some(ed.uris.clone()),
            carpeta: Some(ed.carpeta.clone()),
        };
        let indice = ed.indice;
        // Fin del préstamo de `ed`: lo que sigue toca `self.boveda`.
        //
        // Al EDITAR hay que leer la entrada anterior para conservar lo que NO
        // viaja por el formulario: los secretos vacíos (= «conservar»), el
        // historial de contraseñas, los campos personalizados, `id_origen`,
        // `creada`… Si `abrir_entrada` falla aquí, NO se sigue con `None`: eso
        // colapsaría «no hay anterior» (entrada nueva) con «no se pudo leer la
        // anterior» (D20/D32), y `construir(.., None)` convertiría «conservar» en
        // «borrar» en silencio —la clase de fallo que este repo documenta—. Se
        // aborta, igual que hace `revisar_salud` con el mismo error.
        let anterior = match indice {
            None => None,
            Some(i) => match self.nucleo.boveda.lock().unwrap().as_ref().map(|b| b.abrir_entrada(i)) {
                Some(Ok(e)) => Some(e),
                Some(Err(e)) => {
                    if let Some(ed) = self.editor.as_mut() {
                        ed.error = Some(format!("No se pudo leer la entrada actual ({e}); no se guarda para no perder datos."));
                    }
                    return;
                }
                None => {
                    if let Some(ed) = self.editor.as_mut() {
                        ed.error = Some("La bóveda no está abierta.".to_string());
                    }
                    return;
                }
            },
        };
        let entrada = construir(entrante, anterior);
        let resultado = {
            let mut guard = self.nucleo.boveda.lock().unwrap();
            match guard.as_mut() {
                None => Err("la bóveda no está abierta".to_string()),
                Some(b) => {
                    let idx = match indice {
                        Some(i) => b.reemplazar(i, entrada).map(|()| i),
                        None => b.anadir(entrada),
                    };
                    idx.and_then(|i| b.guardar().map(|()| i)).map_err(|e| format!("{e}"))
                }
            }
        };
        match resultado {
            Ok(idx) => {
                self.nucleo.hay_alguien(); // guardar es interacción real
                self.editor = None;
                self.sel = idx;
                self.cargar_entrada();
            }
            Err(msg) => {
                if let Some(ed) = self.editor.as_mut() {
                    ed.error = Some(format!("No se pudo guardar: {msg}"));
                }
            }
        }
    }

    /// Borra la entrada seleccionada y persiste. Ajusta la selección para que no
    /// apunte fuera de rango tras encoger la lista.
    fn borrar_actual(&mut self) {
        let i = self.sel;
        let resultado = {
            let mut guard = self.nucleo.boveda.lock().unwrap();
            match guard.as_mut() {
                None => Err("la bóveda no está abierta".to_string()),
                Some(b) => b.borrar(i).and_then(|()| b.guardar()).map_err(|e| format!("{e}")),
            }
        };
        self.confirmar_borrado = false;
        match resultado {
            Ok(()) => {
                self.nucleo.hay_alguien(); // borrar es interacción real
                let n = self.nucleo.boveda.lock().unwrap().as_ref().map(Boveda::len).unwrap_or(0);
                self.sel = if n == 0 { 0 } else { self.sel.min(n - 1) };
                self.cargar_entrada();
            }
            Err(msg) => self.aviso = Some(format!("No se pudo borrar: {msg}")),
        }
    }

    /// Quita la passkey `n` de la entrada seleccionada y persiste. Mismo patrón
    /// que `guardar_editor`: abrir la entrada (owned), mutarla con la lógica que
    /// vive en `webauthn` —que reindexa las que queden—, reemplazar y `guardar`.
    fn quitar_passkey_actual(&mut self, n: usize) {
        let i = self.sel;
        let resultado = {
            let mut guard = self.nucleo.boveda.lock().unwrap();
            match guard.as_mut() {
                None => Err("la bóveda no está abierta".to_string()),
                Some(b) => match b.abrir_entrada(i) {
                    Err(e) => Err(format!("{e}")),
                    Ok(mut entrada) => {
                        if chuspa::webauthn::Passkey::quitar_de_entrada(&mut entrada, n) {
                            b.reemplazar(i, entrada).and_then(|()| b.guardar()).map_err(|e| format!("{e}"))
                        } else {
                            Err("esa passkey ya no existe".to_string())
                        }
                    }
                },
            }
        };
        self.confirmar_quitar_passkey = None;
        match resultado {
            Ok(()) => {
                self.nucleo.hay_alguien(); // quitar es interacción real
                self.cargar_entrada();
            }
            Err(msg) => {
                // Tras un fallo de `guardar`, `reemplazar` YA mutó la bóveda en
                // memoria (reindexando las passkeys que quedan), pero la vista
                // seguía mostrando la lista vieja: un 2.º clic en «Quitar n»
                // abriría la entrada ya reindexada y quitaría la passkey que
                // ahora ocupa el índice n — una DISTINTA, borrada sin aviso
                // (hallazgo del concilio 2026-10-06). `cargar_entrada` re-lee la
                // entrada de la bóveda y re-sincroniza la vista, así que el
                // índice que ve el usuario vuelve a casar con el de la bóveda.
                //
                // NO prueba guardián: el fallo vive en el flujo de la ventana
                // egui (binario sin arnés de UI; el único test del binario lo
                // arranca para `--version`). La lógica de bóveda que SÍ se puede
                // probar —`quitar_de_entrada` reindexa, `reemplazar`/`guardar`—
                // ya lo está; lo que falta es el arnés de la App, que es un
                // refactor aparte, no parte de esta mitigación.
                //
                // La divergencia memoria↔disco que deja un `guardar` fallido es
                // preexistente y común a `guardar_editor`/`borrar_actual`: este
                // fix corta el borrado-de-otra, no rediseña esa transacción.
                self.aviso = Some(format!("No se pudo quitar la passkey: {msg}"));
                self.cargar_entrada();
            }
        }
    }

    /// Descifra todas las entradas y arma el informe de salud. Aborta con aviso si
    /// alguna no descifra, para no mostrar un informe con los índices corridos
    /// (el `indice` de cada ficha es la posición en la bóveda y se usa para saltar).
    fn revisar_salud(&mut self) {
        let resultado: Result<Vec<Entrada>, String> = {
            let guard = self.nucleo.boveda.lock().unwrap();
            match guard.as_ref() {
                None => return,
                Some(b) => {
                    let mut entradas = Vec::with_capacity(b.len());
                    let mut err = None;
                    for i in 0..b.len() {
                        match b.abrir_entrada(i) {
                            Ok(e) => entradas.push(e),
                            Err(e) => {
                                err = Some(format!("{e}"));
                                break;
                            }
                        }
                    }
                    match err {
                        Some(e) => Err(e),
                        None => Ok(entradas),
                    }
                }
            }
        };
        let entradas = match resultado {
            Ok(v) => v,
            Err(e) => {
                self.aviso = Some(format!("No se pudo revisar la salud: {e}"));
                return;
            }
        };
        self.salud = Some(salud::revisar(&entradas));
        self.editor = None;
        self.confirmar_borrado = false;
        self.aviso = None;
    }

    /// Dibuja el informe de salud. Solo lee (`&self`); las acciones salen como
    /// `AccionSalud` y las procesa quien tiene `&mut self`.
    fn ui_salud(&self, ui: &mut egui::Ui, p: &Paleta) -> AccionSalud {
        let Some(informe) = self.salud.as_ref() else { return AccionSalud::Ninguna };
        let mut accion = AccionSalud::Ninguna;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("Salud de la bóveda").size(24.0).strong().color(p.texto));
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "{} revisadas · {} con problemas · {} sin contraseña",
                    informe.revisadas,
                    informe.con_problemas(),
                    informe.sin_contrasena
                ))
                .size(13.0)
                .color(p.suave),
            );
            ui.add_space(14.0);

            if informe.fichas.is_empty() {
                ui.label(RichText::new("Sin hallazgos. Todo en orden.").size(14.0).color(p.ok));
            }

            // Más graves primero.
            let mut orden: Vec<&salud::Ficha> = informe.fichas.iter().collect();
            orden.sort_by_key(|f| std::cmp::Reverse(f.gravedad()));

            for ficha in orden {
                egui::Frame::new()
                    .fill(p.tarjeta)
                    .corner_radius(CornerRadius::same(huitaca::R as u8))
                    .inner_margin(Margin::same(12))
                    .stroke(egui::Stroke::new(1.0_f32, p.borde))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new(RichText::new(&ficha.nombre).size(15.0).strong().color(p.acento)).fill(p.tarjeta).stroke(egui::Stroke::NONE)).clicked() {
                                accion = AccionSalud::Saltar(ficha.indice);
                            }
                        });
                        for h in &ficha.hallazgos {
                            let color = match h.gravedad() {
                                3 => egui::Color32::from_rgb(0xE0, 0x7B, 0x7B),
                                2 => p.acento,
                                _ => p.suave,
                            };
                            ui.label(RichText::new(format!("• {}", h.explicacion())).size(12.0).color(color));
                        }
                    });
                ui.add_space(6.0);
            }

            ui.add_space(10.0);
            if ui.add(egui::Button::new(RichText::new("Cerrar").size(13.0)).fill(p.tarjeta)).clicked() {
                accion = AccionSalud::Cerrar;
            }
            ui.add_space(12.0);
        });
        accion
    }

    /// Crea la copia de seguridad: `copia::crear` desde la bóveda abierta, la
    /// escribe, y la **verifica** con `comprobar` (una copia que no se puede abrir
    /// no sirve, y suponer que sirve sin probarlo es el fallo que este repo evita).
    fn crear_copia(&mut self) {
        let Some(est) = self.copia.as_ref() else { return };
        let problema = if est.frase.is_empty() {
            Some("Escribe una frase para cifrar la copia.")
        } else if est.frase != est.confirmar {
            Some("Las dos frases no coinciden.")
        } else if est.ruta.is_none() {
            Some("Elige un destino para la copia.")
        } else {
            None
        };
        if let Some(msg) = problema {
            if let Some(est) = self.copia.as_mut() {
                est.resultado = Some(msg.to_string());
            }
            return;
        }
        let frase = est.frase.clone();
        let ruta = est.ruta.clone().unwrap_or_default();
        let res = (|| -> Result<copia::Ficha, String> {
            let guard = self.nucleo.boveda.lock().unwrap();
            let b = guard.as_ref().ok_or_else(|| "la bóveda no está abierta".to_string())?;
            let acceso = Acceso::frase(&frase);
            let bytes = copia::crear(b, &acceso).map_err(|e| format!("{e}"))?;
            copia::escribir(&bytes, &ruta).map_err(|e| format!("{e}"))?;
            copia::comprobar(&bytes, &acceso).map_err(|e| format!("{e}"))
        })();
        if let Some(est) = self.copia.as_mut() {
            match res {
                Ok(f) => {
                    est.frase.clear();
                    est.confirmar.clear();
                    est.resultado = Some(format!(
                        "Copia creada y verificada: {} entradas, {} KB en disco.",
                        f.entradas,
                        f.bytes_archivo / 1024
                    ));
                }
                Err(msg) => est.resultado = Some(format!("No se pudo crear la copia: {msg}")),
            }
        }
    }

    /// Pantalla de copia de seguridad. Muta `self.copia` (campos y, por `rfd`, el
    /// destino); crear y cerrar salen como `AccionCopia`.
    fn ui_copia(&mut self, ui: &mut egui::Ui, p: &Paleta) -> AccionCopia {
        let Some(est) = self.copia.as_mut() else { return AccionCopia::Ninguna };
        let mut accion = AccionCopia::Ninguna;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("Copia de seguridad").size(24.0).strong().color(p.texto));
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "La copia va cifrada. Se abre con la frase que escribas aquí \
                     (normalmente, tu frase maestra). Guárdala en un lugar seguro.",
                )
                .size(13.0)
                .color(p.suave),
            );
            ui.add_space(14.0);

            egui::Frame::new()
                .fill(p.tarjeta)
                .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                .inner_margin(Margin::same(16))
                .stroke(egui::Stroke::new(1.0_f32, p.borde))
                .show(ui, |ui| {
                    ui.set_max_width(520.0);
                    ui.label(RichText::new("Frase para cifrar la copia").size(12.0).color(p.suave));
                    ui.add(egui::TextEdit::singleline(&mut est.frase).password(true).desired_width(f32::INFINITY));
                    ui.add_space(8.0);
                    ui.label(RichText::new("Confirmar frase").size(12.0).color(p.suave));
                    ui.add(egui::TextEdit::singleline(&mut est.confirmar).password(true).desired_width(f32::INFINITY));
                    ui.add_space(12.0);

                    if ui.add(egui::Button::new(RichText::new("Elegir destino…").size(13.0)).fill(p.tarjeta)).clicked()
                        && let Some(elegido) = rfd::FileDialog::new()
                            .add_filter("Copia chuspa", &["chuspacopia"])
                            .set_file_name("copia.chuspacopia")
                            .set_title("Guardar la copia de seguridad")
                            .save_file()
                    {
                        est.ruta = Some(elegido.to_string_lossy().into_owned());
                    }
                    ui.add_space(3.0);
                    let destino = est.ruta.clone().unwrap_or_else(|| "(ningún destino elegido)".to_string());
                    let color = if est.ruta.is_some() { p.suave } else { p.tenue };
                    ui.label(RichText::new(destino).size(11.0).color(color).monospace());
                    ui.add_space(14.0);

                    if ui.add_sized([ui.available_width(), 34.0], egui::Button::new(RichText::new("Crear copia").size(14.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                        accion = AccionCopia::Crear;
                    }
                });

            if let Some(r) = &est.resultado {
                ui.add_space(12.0);
                ui.label(RichText::new(r).size(13.0).color(p.texto));
            }

            ui.add_space(16.0);
            if ui.add(egui::Button::new(RichText::new("Cerrar").size(13.0)).fill(p.tarjeta)).clicked() {
                accion = AccionCopia::Cerrar;
            }
            ui.add_space(12.0);
        });
        accion
    }

    /// Importa un export de Bitwarden (JSON o CSV, según la extensión) y añade sus
    /// entradas a la bóveda abierta. Los avisos de la importación se guardan para
    /// mostrarlos: una importación que «sale bien» pero deja cosas fuera sin
    /// decirlo es justo el fallo que el tipo `Importacion` existe para impedir.
    fn importar_archivo(&mut self) {
        let Some(ruta) = rfd::FileDialog::new()
            .add_filter("Export de Bitwarden", &["json", "csv"])
            .set_title("Elegir archivo a importar")
            .pick_file()
        else {
            return;
        };
        let texto = match std::fs::read_to_string(&ruta) {
            Ok(t) => t,
            Err(e) => {
                self.aviso = Some(format!("No se pudo leer el archivo: {e}"));
                return;
            }
        };
        let es_csv = ruta.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv"));
        let importacion = if es_csv {
            bitwarden_csv::importar(&texto).map_err(|e| format!("{e}"))
        } else {
            bitwarden::importar(&texto).map_err(|e| format!("{e}"))
        };
        let importacion = match importacion {
            Ok(i) => i,
            Err(e) => {
                self.aviso = Some(format!("No se pudo importar: {e}"));
                return;
            }
        };
        let avisos = importacion.avisos.clone();
        let total = importacion.entradas.len();
        let res = (|| -> Result<(), String> {
            let mut guard = self.nucleo.boveda.lock().unwrap();
            let b = guard.as_mut().ok_or_else(|| "la bóveda no está abierta".to_string())?;
            for entrada in importacion.entradas {
                b.anadir(entrada).map_err(|e| format!("{e}"))?;
            }
            b.guardar().map_err(|e| format!("{e}"))
        })();
        match res {
            Ok(()) => {
                self.nucleo.hay_alguien(); // importar es interacción real
                self.sel = 0;
                self.cargar_entrada();
                self.importe = Some((total, avisos));
                self.editor = None;
                self.salud = None;
                self.copia = None;
            }
            Err(e) => self.aviso = Some(format!("Importación incompleta: {e}")),
        }
    }

    /// Muestra el resultado de la importación (total + avisos). Devuelve `true` si
    /// se pidió cerrar.
    fn ui_importe(&self, ui: &mut egui::Ui, p: &Paleta) -> bool {
        let Some((total, avisos)) = self.importe.as_ref() else { return false };
        let mut cerrar = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("Importación").size(24.0).strong().color(p.texto));
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Se añadieron {total} entradas.")).size(14.0).color(p.ok));
            if !avisos.is_empty() {
                ui.add_space(12.0);
                ui.label(RichText::new(format!("{} avisos:", avisos.len())).size(13.0).color(p.acento));
                ui.add_space(4.0);
                for a in avisos {
                    ui.label(RichText::new(format!("• {a}")).size(12.0).color(p.suave));
                }
            }
            ui.add_space(16.0);
            if ui.add(egui::Button::new(RichText::new("Cerrar").size(13.0)).fill(p.tarjeta)).clicked() {
                cerrar = true;
            }
            ui.add_space(12.0);
        });
        cerrar
    }

    /// El formulario de crear/editar. Muta `self.editor` directamente (los campos
    /// de texto y el generador); guardar y cancelar salen como `AccionEditor`.
    fn ui_editor(&mut self, ui: &mut egui::Ui, p: &Paleta) -> AccionEditor {
        let ed = match self.editor.as_mut() {
            Some(e) => e,
            None => return AccionEditor::Ninguna,
        };
        let mut accion = AccionEditor::Ninguna;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            let titulo = if ed.indice.is_some() { "Editar entrada" } else { "Nueva entrada" };
            ui.label(RichText::new(titulo).size(24.0).strong().color(p.texto));
            ui.add_space(14.0);

            campo_texto(ui, p, "Nombre", &mut ed.nombre, "Nombre de la cuenta o sitio");
            ui.add_space(10.0);
            campo_texto(ui, p, "Usuario", &mut ed.usuario, "usuario@ejemplo.com");
            ui.add_space(10.0);

            // Contraseña: vacío = conservar la actual al editar; casilla para quitar.
            let hint_clave = if ed.indice.is_some() { "(vacío: conservar la actual)" } else { "Contraseña" };
            ui.label(RichText::new("Contraseña").size(12.0).color(p.suave));
            ui.horizontal(|ui| {
                let salida = egui::TextEdit::singleline(&mut ed.clave)
                    .password(!ed.revelar_clave)
                    .hint_text(hint_clave)
                    .desired_width(ui.available_width() - 180.0);
                ui.add(salida);
                let t = if ed.revelar_clave { "Ocultar" } else { "Ver" };
                if ui.add(egui::Button::new(RichText::new(t).size(12.0)).fill(p.tarjeta)).clicked() {
                    ed.revelar_clave = !ed.revelar_clave;
                }
                if ui.add(egui::Button::new(RichText::new("Generar").size(12.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                    let comp = ed.composicion();
                    match generador::contrasena(ed.gen_largo, comp) {
                        Ok(c) => {
                            ed.clave = c.to_string();
                            ed.quitar_clave = false;
                            ed.revelar_clave = true;
                            ed.error = None;
                        }
                        Err(e) => ed.error = Some(format!("Generador: {e}")),
                    }
                }
            });
            // Opciones del generador.
            egui::Frame::new()
                .fill(p.tarjeta)
                .corner_radius(CornerRadius::same(huitaca::R as u8))
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Largo").size(12.0).color(p.suave));
                        ui.add(egui::Slider::new(&mut ed.gen_largo, 8..=64));
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.checkbox(&mut ed.gen_mayusculas, RichText::new("A-Z").size(12.0));
                        ui.checkbox(&mut ed.gen_digitos, RichText::new("0-9").size(12.0));
                        ui.checkbox(&mut ed.gen_simbolos, RichText::new("símbolos").size(12.0));
                        ui.checkbox(&mut ed.gen_sin_ambiguos, RichText::new("sin ambiguos").size(12.0));
                    });
                });
            if ed.indice.is_some() {
                ui.checkbox(&mut ed.quitar_clave, RichText::new("Quitar la contraseña").size(12.0).color(p.suave));
            }
            ui.add_space(10.0);

            // Segundo factor (TOTP): mismo trato que la contraseña.
            let hint_totp = if ed.indice.is_some() { "(vacío: conservar el actual)" } else { "otpauth://… o clave base32" };
            campo_texto(ui, p, "Segundo factor (TOTP)", &mut ed.totp, hint_totp);
            if ed.indice.is_some() {
                ui.checkbox(&mut ed.quitar_totp, RichText::new("Quitar el segundo factor").size(12.0).color(p.suave));
            }
            ui.add_space(10.0);

            campo_texto(ui, p, "Carpeta", &mut ed.carpeta, "(opcional)");
            ui.add_space(10.0);

            ui.label(RichText::new("Direcciones (una por línea)").size(12.0).color(p.suave));
            ui.add(egui::TextEdit::multiline(&mut ed.uris).hint_text("https://ejemplo.com").desired_width(f32::INFINITY).desired_rows(2));
            ui.add_space(10.0);

            ui.label(RichText::new("Notas").size(12.0).color(p.suave));
            ui.add(egui::TextEdit::multiline(&mut ed.notas).desired_width(f32::INFINITY).desired_rows(3));

            if let Some(err) = &ed.error {
                ui.add_space(10.0);
                ui.label(RichText::new(err).size(12.0).color(egui::Color32::from_rgb(0xE0, 0x7B, 0x7B)));
            }

            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(RichText::new("Guardar").size(14.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                    accion = AccionEditor::Guardar;
                }
                if ui.add(egui::Button::new(RichText::new("Cancelar").size(14.0)).fill(p.tarjeta)).clicked() {
                    accion = AccionEditor::Cancelar;
                }
            });
            ui.add_space(12.0);
        });
        accion
    }

    fn ui_bloqueada(&mut self, ui: &mut egui::Ui, p: &Paleta) {
        // Flujo de restaurar: ocupa la pantalla de desbloqueo mientras está activo.
        if self.restaurar.is_some() {
            let (hacer, volver) = self.ui_restaurar(ui, p);
            if hacer {
                self.restaurar_copia();
            }
            if volver {
                self.restaurar = None;
            }
            return;
        }

        ui.vertical_centered(|ui| {
            ui.add_space(64.0);
            ui.label(RichText::new("chuspa").size(34.0).strong().color(p.acento));
            ui.label(RichText::new("bóveda local cifrada").size(13.0).color(p.suave));
            ui.add_space(28.0);
        });

        // La tarjeta de desbloqueo va centrada horizontalmente bajo el título.
        // El ancho fijo en el `ui` centrado es lo que la centra; el marco lo
        // rellena.
        ui.vertical_centered(|ui| {
            ui.set_max_width(460.0);
            egui::Frame::new()
                .fill(p.tarjeta)
                .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                .inner_margin(Margin::same(18))
                .stroke(egui::Stroke::new(1.0_f32, p.borde))
                .show(ui, |ui| {
                    ui.label(RichText::new("Archivo de bóveda").size(12.0).color(p.suave));
                    if ui.add(egui::Button::new(RichText::new("Examinar…").size(13.0)).fill(p.tarjeta)).clicked()
                        && let Some(elegido) = rfd::FileDialog::new()
                            .add_filter("Bóveda chuspa", &["chuspa"])
                            .set_title("Elegir archivo de bóveda")
                            .pick_file()
                    {
                        self.ruta = elegido.to_string_lossy().into_owned();
                        self.error = None;
                    }
                    ui.add_space(3.0);
                    let elegida = if self.ruta.is_empty() { "(ningún archivo elegido)".to_string() } else { self.ruta.clone() };
                    let color = if self.ruta.is_empty() { p.tenue } else { p.suave };
                    ui.label(RichText::new(elegida).size(11.0).color(color).monospace());
                    ui.add_space(10.0);
                    ui.label(RichText::new("Frase maestra").size(12.0).color(p.suave));
                    let campo = ui.add(
                        egui::TextEdit::singleline(&mut self.frase)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                    let enter = campo.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.add_space(14.0);
                    let abrir = ui
                        .add_sized(
                            [ui.available_width(), 34.0],
                            egui::Button::new(
                                RichText::new("Abrir bóveda").size(14.0).color(p.acento_texto),
                            )
                            .fill(p.acento)
                            .stroke(egui::Stroke::NONE),
                        )
                        .clicked();
                    if (abrir || enter) && !self.frase.is_empty() {
                        self.desbloquear();
                    }
                    if let Some(err) = &self.error {
                        ui.add_space(10.0);
                        ui.label(RichText::new(format!("No se pudo abrir: {err}")).size(12.0).color(egui::Color32::from_rgb(0xE0, 0x7B, 0x7B)));
                    }
                });
        });

        ui.add_space(14.0);
        ui.vertical_centered(|ui| {
            if ui.add(egui::Button::new(RichText::new("Restaurar desde una copia").size(12.0).color(p.suave)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).clicked() {
                self.restaurar = Some(EstadoRestaurar::default());
            }
            if let Some(a) = &self.aviso {
                ui.add_space(10.0);
                ui.label(RichText::new(a).size(12.0).color(p.ok));
            }
        });
    }

    fn ui_abierta(&mut self, ctx: &egui::Context, p: &Paleta) {
        // Datos de la lista, clonados fuera del préstamo de `boveda` para poder
        // mutar `self.sel` dentro de la UI.
        let filtro = self.filtro.to_lowercase();
        let lista: Vec<(usize, String, String)> = self
            .nucleo
            .boveda
            .lock()
            .unwrap()
            .as_ref()
            .map(|b| {
                b.listar()
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        filtro.is_empty()
                            || r.nombre.to_lowercase().contains(&filtro)
                            || r.usuario.as_deref().is_some_and(|u| u.to_lowercase().contains(&filtro))
                    })
                    // El subtítulo (usuario -> carpeta -> clase) lo decide el
                    // núcleo: `Resumen::subtitulo`, compartido con chuspa-gtk.
                    .map(|(i, r)| (i, r.nombre.clone(), r.subtitulo()))
                    .collect()
            })
            .unwrap_or_default();

        let mut nueva_sel: Option<usize> = None;

        egui::SidePanel::left("lista").resizable(false).exact_width(400.0).show(ctx, |ui| {
            ui.add_space(6.0);
            ui.label(RichText::new("chuspa").size(22.0).strong().color(p.acento));
            ui.label(RichText::new("bóveda local").size(12.0).color(p.suave));
            ui.add_space(10.0);
            ui.add(egui::TextEdit::singleline(&mut self.filtro).hint_text("Buscar…").desired_width(f32::INFINITY));
            ui.add_space(8.0);
            if ui.add_sized([ui.available_width(), 30.0], egui::Button::new(RichText::new("+  Nueva entrada").size(13.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                self.editor = Some(Editor::nueva());
                self.confirmar_borrado = false;
                self.aviso = None;
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let ancho = (ui.available_width() - 6.0) / 2.0;
                if ui.add_sized([ancho, 26.0], egui::Button::new(RichText::new("Revisar salud").size(12.0)).fill(p.tarjeta)).clicked() {
                    self.revisar_salud();
                }
                if ui.add_sized([ancho, 26.0], egui::Button::new(RichText::new("Copia").size(12.0)).fill(p.tarjeta)).clicked() {
                    self.copia = Some(EstadoCopia::default());
                    self.editor = None;
                    self.salud = None;
                    self.importe = None;
                    self.confirmar_borrado = false;
                }
            });
            ui.add_space(6.0);
            if ui.add_sized([ui.available_width(), 26.0], egui::Button::new(RichText::new("Importar de Bitwarden").size(12.0)).fill(p.tarjeta)).clicked() {
                self.importar_archivo();
            }
            ui.add_space(8.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, nombre, sub) in &lista {
                    if fila_lista(ui, p, nombre, sub, *i == self.sel) {
                        nueva_sel = Some(*i);
                    }
                    ui.add_space(3.0);
                }
                if lista.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Sin entradas").size(12.0).color(p.tenue));
                }
            });
        });

        let mut accion_editor = AccionEditor::Ninguna;
        let mut accion_salud = AccionSalud::Ninguna;
        let mut accion_copia = AccionCopia::Ninguna;
        let mut accion_passkey = AccionPasskey::Ninguna;
        let mut cerrar_importe = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.editor.is_some() {
                accion_editor = self.ui_editor(ui, p);
                return;
            }
            if self.salud.is_some() {
                accion_salud = self.ui_salud(ui, p);
                return;
            }
            if self.copia.is_some() {
                accion_copia = self.ui_copia(ui, p);
                return;
            }
            if self.importe.is_some() {
                cerrar_importe = self.ui_importe(ui, p);
                return;
            }
            if let Some(aviso) = self.aviso.clone() {
                ui.add_space(4.0);
                ui.label(RichText::new(aviso).size(12.0).color(egui::Color32::from_rgb(0xE0, 0x7B, 0x7B)));
                ui.add_space(6.0);
            }
            match &self.entrada {
                None => {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("Selecciona una entrada o crea una nueva").size(14.0).color(p.suave));
                    });
                }
                Some(e) => {
                    ui.add_space(4.0);
                    ui.label(RichText::new(&e.nombre).size(26.0).strong().color(p.texto));
                    if let Some(carpeta) = &e.carpeta {
                        egui::Frame::new()
                            .fill(p.tarjeta)
                            .corner_radius(CornerRadius::same((huitaca::R_SM + 2.0) as u8))
                            .inner_margin(Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(RichText::new(carpeta).size(12.0).color(p.acento));
                            });
                    }
                    ui.add_space(14.0);

                    let usuario = texto_campo(e, "acceso.usuario");
                    // La contraseña NO se materializa a un `String` plano en cada
                    // fotograma: oculta —el caso normal, y `ui_abierta` repinta a
                    // ~60 fps— basta su longitud, que se lee del `Secreto` sin
                    // sacarlo de su envoltura `Zeroizing`. Se materializa solo al
                    // REVELAR (para dibujarla) o al pulsar «Copiar».
                    let clave_long = longitud_campo(e, "acceso.clave");

                    if usuario.is_some() || clave_long.is_some() {
                        egui::Frame::new()
                            .fill(p.tarjeta)
                            .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                            .inner_margin(Margin::same(14))
                            .stroke(egui::Stroke::new(1.0_f32, p.borde))
                            .show(ui, |ui| {
                                if let Some(u) = &usuario {
                                    fila_dato(ui, p, "Usuario", u, false);
                                    ui.add_space(4.0);
                                }
                                if let Some(len) = clave_long {
                                    ui.horizontal(|ui| {
                                        ui.allocate_ui_with_layout(vec2(90.0, 22.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                            ui.label(RichText::new("Contraseña").color(p.suave).size(13.0));
                                        });
                                        let mostrada = if self.revelar {
                                            texto_campo(e, "acceso.clave").unwrap_or_default()
                                        } else {
                                            "•".repeat(len.min(24))
                                        };
                                        ui.label(RichText::new(mostrada).monospace().color(p.texto));
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.add(egui::Button::new(RichText::new("Copiar").size(12.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked()
                                                && let Some(c) = texto_campo(e, "acceso.clave")
                                            {
                                                copiar(ui, &c);
                                            }
                                            let t = if self.revelar { "Ocultar" } else { "Revelar" };
                                            if ui.add(egui::Button::new(RichText::new(t).size(12.0)).fill(p.tarjeta)).clicked() {
                                                self.revelar = !self.revelar;
                                            }
                                        });
                                    });
                                }
                            });
                    }

                    // TOTP en vivo.
                    if let Some(totp) = &self.totp
                        && let Ok(codigo) = totp.codigo()
                    {
                        let restante = totp.segundos_restantes().unwrap_or(0);
                        let periodo = totp.periodo.max(1) as f32;
                        ui.add_space(12.0);
                        egui::Frame::new()
                            .fill(p.tarjeta)
                            .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                            .inner_margin(Margin::same(14))
                            .stroke(egui::Stroke::new(1.0_f32, p.borde))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Código TOTP").size(12.0).color(p.suave));
                                ui.horizontal(|ui| {
                                    // Espacio cada 3 dígitos, como en la maqueta.
                                    let mostrado = if codigo.len() == 6 {
                                        format!("{} {}", &codigo[..3], &codigo[3..])
                                    } else {
                                        codigo.clone()
                                    };
                                    ui.label(RichText::new(mostrado).size(30.0).strong().monospace().color(p.ok));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(RichText::new("Copiar").size(12.0)).fill(p.tarjeta)).clicked() {
                                            copiar(ui, &codigo);
                                        }
                                        ui.label(RichText::new(format!("{restante:>2}s")).size(16.0).color(if restante <= 5 { p.acento } else { p.suave }));
                                    });
                                });
                                ui.add(egui::ProgressBar::new(restante as f32 / periodo).fill(if restante <= 5 { p.acento } else { p.ok }));
                            });
                    }

                    // Passkeys guardadas en esta entrada. La bóveda las guarda
                    // como campos `passkey.N.*`; hasta ahora no había forma de
                    // VERLAS ni de quitarlas desde la ventana —solo asomaban en el
                    // diálogo de aprobación del navegador—. Listarlas sirve para
                    // auditar la bóveda y para quitar una passkey HUÉRFANA: la que
                    // el navegador canceló después de que esta bóveda ya la hubiera
                    // escrito (p. ej. Windows Hello robando el foco a la ceremonia).
                    let passkeys = chuspa::webauthn::Passkey::resumen_de_entrada(e);
                    if !passkeys.is_empty() {
                        ui.add_space(12.0);
                        egui::Frame::new()
                            .fill(p.tarjeta)
                            .corner_radius(CornerRadius::same(huitaca::R_LG as u8))
                            .inner_margin(Margin::same(14))
                            .stroke(egui::Stroke::new(1.0_f32, p.borde))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Passkeys").size(12.0).color(p.suave));
                                for (n, pk) in passkeys.iter().enumerate() {
                                    ui.add_space(6.0);
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new(&pk.rp_id).size(14.0).color(p.texto));
                                            let sub = match &pk.usuario {
                                                Some(u) => format!("{u} · usada {} veces", pk.contador),
                                                None => format!("usada {} veces", pk.contador),
                                            };
                                            ui.label(RichText::new(sub).size(11.0).color(p.tenue));
                                        });
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if self.confirmar_quitar_passkey == Some(n) {
                                                if ui.add(egui::Button::new(RichText::new("Sí, quitar").size(12.0).color(p.acento_texto)).fill(egui::Color32::from_rgb(0xC0, 0x4B, 0x4B)).stroke(egui::Stroke::NONE)).clicked() {
                                                    accion_passkey = AccionPasskey::Quitar(n);
                                                }
                                                if ui.add(egui::Button::new(RichText::new("Cancelar").size(12.0)).fill(p.tarjeta)).clicked() {
                                                    accion_passkey = AccionPasskey::Cancelar;
                                                }
                                            } else if ui.add(egui::Button::new(RichText::new("Quitar").size(12.0)).fill(p.tarjeta)).clicked() {
                                                accion_passkey = AccionPasskey::Confirmar(n);
                                            }
                                        });
                                    });
                                }
                            });
                    }

                    ui.add_space(16.0);
                    if self.confirmar_borrado {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("¿Borrar esta entrada?").size(13.0).color(p.texto));
                            if ui.add(egui::Button::new(RichText::new("Sí, borrar").size(12.0).color(p.acento_texto)).fill(egui::Color32::from_rgb(0xC0, 0x4B, 0x4B)).stroke(egui::Stroke::NONE)).clicked() {
                                self.borrar_actual();
                            }
                            if ui.add(egui::Button::new(RichText::new("Cancelar").size(12.0)).fill(p.tarjeta)).clicked() {
                                self.confirmar_borrado = false;
                            }
                        });
                    } else {
                        // La closure solo marca intención: usar `e` y mutar
                        // `self.entrada` dentro del mismo cierre choca con el
                        // préstamo. Se procesa fuera, con campos disjuntos.
                        let (mut editar, mut borrar, mut cerrar) = (false, false, false);
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new(RichText::new("Editar").size(12.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                                editar = true;
                            }
                            if ui.add(egui::Button::new(RichText::new("Borrar").size(12.0)).fill(p.tarjeta)).clicked() {
                                borrar = true;
                            }
                            if ui.add(egui::Button::new(RichText::new("Cerrar bóveda").size(12.0)).fill(p.tarjeta)).clicked() {
                                cerrar = true;
                            }
                        });
                        if editar {
                            self.editor = Some(Editor::de(e, self.sel));
                            self.aviso = None;
                        }
                        if borrar {
                            self.confirmar_borrado = true;
                        }
                        if cerrar {
                            // Soltar la bóveda del núcleo compartido: el agente la
                            // verá cerrada y responderá «cerrada» al navegador, sin
                            // abrirla (eso solo pasa tecleando la frase aquí). Y
                            // olvidar la presencia, para que una firma en vuelo no
                            // encuentre una ventana que ya nadie atiende.
                            *self.nucleo.boveda.lock().unwrap() = None;
                            self.nucleo.olvidar_la_presencia();
                            self.entrada = None;
                            self.totp = None;
                            self.editor = None;
                            self.confirmar_borrado = false;
                            self.aviso = None;
                            self.pantalla = Pantalla::Bloqueada;
                        }
                    }
                }
            }
        });

        // Con el editor abierto, pulsar una fila no cambia el detalle de debajo.
        // Con el informe de salud abierto, seleccionar lo cierra y muestra la
        // entrada.
        if self.editor.is_none()
            && let Some(i) = nueva_sel
            && i != self.sel
        {
            self.sel = i;
            self.cargar_entrada();
            self.confirmar_borrado = false;
            self.aviso = None;
            self.salud = None;
            self.copia = None;
            self.importe = None;
        }

        match accion_editor {
            AccionEditor::Guardar => self.guardar_editor(),
            AccionEditor::Cancelar => self.editor = None,
            AccionEditor::Ninguna => {}
        }

        match accion_passkey {
            AccionPasskey::Confirmar(n) => self.confirmar_quitar_passkey = Some(n),
            AccionPasskey::Quitar(n) => self.quitar_passkey_actual(n),
            AccionPasskey::Cancelar => self.confirmar_quitar_passkey = None,
            AccionPasskey::Ninguna => {}
        }

        match accion_salud {
            AccionSalud::Cerrar => self.salud = None,
            AccionSalud::Saltar(i) => {
                self.salud = None;
                self.sel = i;
                self.cargar_entrada();
                self.confirmar_borrado = false;
            }
            AccionSalud::Ninguna => {}
        }

        match accion_copia {
            AccionCopia::Crear => self.crear_copia(),
            AccionCopia::Cerrar => self.copia = None,
            AccionCopia::Ninguna => {}
        }

        if cerrar_importe {
            self.importe = None;
        }
    }

    /// El diálogo de aprobación de passkey (Fase C). Cuando el agente del navegador
    /// deja una firma o un registro a la espera, esta ventana —que suele estar
    /// DETRÁS del navegador, porque el usuario está mirando el sitio— se trae al
    /// frente y pregunta. «Nadie firma sin aprobación en la ventana» es el
    /// invariante que separa una passkey de una cookie; aquí se dibuja la pregunta,
    /// y la decisión la aplica el NÚCLEO (`decidir_firma`/`decidir_registro`), el
    /// mismo código que usa el frontal GTK.
    ///
    /// Se copia bajo el candado solo lo justo para dibujar —nunca un secreto: el
    /// sitio, el origen que puso el navegador y los nombres de cuenta— y se SUELTA
    /// el candado antes de pintar, porque el agente lo necesita para dejar y retirar
    /// la pendiente, y pintar con él tomado lo bloquearía. Devuelve `true` si hay
    /// algo a la espera.
    fn ui_aprobacion(&mut self, ctx: &egui::Context, p: &Paleta) -> bool {
        enum Pendiente {
            Firma {
                id: u64,
                rp_id: String,
                origen: String,
                /// `(índice en candidatas, nombre, usuario)`. El índice es lo que
                /// espera `decidir_firma` como `elegida`.
                candidatas: Vec<(usize, String, Option<String>)>,
            },
            Registro {
                id: u64,
                rp_id: String,
                rp_nombre: Option<String>,
                origen: String,
                usuario: Option<String>,
            },
        }

        // La firma tiene prioridad sobre el registro, igual que en GTK. El candado
        // de `firma` se suelta (fin del bloque interno) antes de tomar el de
        // `registro`: nunca se tienen los dos a la vez.
        let pendiente = 'buscar: {
            {
                let firma = self.nucleo.firma.lock().unwrap();
                if let Some(f) = firma.as_ref().filter(|f| f.elegida.is_none()) {
                    break 'buscar Some(Pendiente::Firma {
                        id: f.id,
                        rp_id: f.rp_id.clone(),
                        origen: f.origen.clone(),
                        candidatas: f
                            .candidatas
                            .iter()
                            .enumerate()
                            .map(|(i, c)| (i, c.nombre.clone(), c.usuario.clone()))
                            .collect(),
                    });
                }
            }
            let registro = self.nucleo.registro.lock().unwrap();
            registro.as_ref().filter(|r| r.aprobado.is_none()).map(|r| Pendiente::Registro {
                id: r.id,
                rp_id: r.rp_id.clone(),
                rp_nombre: r.rp_nombre.clone(),
                origen: r.origen.clone(),
                usuario: r.usuario.clone(),
            })
        };

        let Some(pendiente) = pendiente else {
            // Nada a la espera: olvidar qué petición se trajo al frente, para que la
            // siguiente vuelva a enfocar.
            self.presentada = None;
            return false;
        };

        let id = match &pendiente {
            Pendiente::Firma { id, .. } | Pendiente::Registro { id, .. } => *id,
        };
        // Traer la ventana al frente UNA vez por petición: enfocar cada fotograma
        // robaría el foco sin parar mientras el diálogo está abierto.
        if self.presentada != Some(id) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.presentada = Some(id);
        }

        // Oscurecer el fondo y tragarse sus clics. Va en `Order::Middle` (encima de
        // los paneles, que están en `Background`) y ANTES que la ventana, que al
        // mostrarse después queda por encima dentro del mismo orden.
        egui::Area::new(egui::Id::new("aprobacion_fondo"))
            .order(egui::Order::Middle)
            .fixed_pos(egui::Pos2::ZERO)
            .interactable(true)
            .show(ctx, |ui| {
                let r = ctx.input(|i| i.content_rect());
                ui.painter().rect_filled(r, 0.0, egui::Color32::from_black_alpha(170));
                ui.allocate_rect(r, egui::Sense::click_and_drag());
            });

        enum Decision {
            Firmar(u64, usize),
            RechazarFirma(u64),
            Crear(u64),
            RechazarRegistro(u64),
        }
        let mut decision: Option<Decision> = None;

        let titulo = match &pendiente {
            Pendiente::Firma { .. } => "Autorizar passkey",
            Pendiente::Registro { .. } => "Crear una passkey",
        };
        egui::Window::new(titulo)
            .collapsible(false)
            .resizable(false)
            .movable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(
                egui::Frame::window(&ctx.style_of(egui::Theme::Dark))
                    .fill(p.tarjeta)
                    .stroke(egui::Stroke::new(1.0_f32, p.acento)),
            )
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                match &pendiente {
                    Pendiente::Firma { id, rp_id, origen, candidatas } => {
                        ui.label(RichText::new("Un sitio pide entrar con una passkey").size(13.0).color(p.suave));
                        ui.add_space(6.0);
                        ui.label(RichText::new(origen).size(15.0).strong().color(p.acento).monospace());
                        if rp_id != origen {
                            ui.label(RichText::new(format!("({rp_id})")).size(11.0).color(p.tenue).monospace());
                        }
                        ui.add_space(12.0);
                        if candidatas.is_empty() {
                            ui.label(RichText::new("No hay ninguna passkey guardada para este sitio.").size(12.0).color(p.suave));
                        } else {
                            ui.label(RichText::new("Firmar con:").size(12.0).color(p.suave));
                            ui.add_space(4.0);
                            for (i, nombre, usuario) in candidatas {
                                let texto = match usuario {
                                    Some(u) if !u.is_empty() => format!("{nombre}  ·  {u}"),
                                    _ => nombre.clone(),
                                };
                                if ui
                                    .add_sized(
                                        [ui.available_width(), 32.0],
                                        egui::Button::new(RichText::new(texto).size(13.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE),
                                    )
                                    .clicked()
                                {
                                    decision = Some(Decision::Firmar(*id, *i));
                                }
                                ui.add_space(4.0);
                            }
                        }
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new(RichText::new("Rechazar").size(13.0)).fill(p.tarjeta)).clicked() {
                            decision = Some(Decision::RechazarFirma(*id));
                        }
                    }
                    Pendiente::Registro { id, rp_id, rp_nombre, origen, usuario } => {
                        ui.label(RichText::new("Un sitio pide crear una passkey nueva").size(13.0).color(p.suave));
                        ui.add_space(6.0);
                        let sitio = rp_nombre.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| origen.clone());
                        ui.label(RichText::new(sitio).size(15.0).strong().color(p.acento));
                        ui.label(RichText::new(origen).size(11.0).color(p.tenue).monospace());
                        if rp_id != origen {
                            ui.label(RichText::new(format!("({rp_id})")).size(11.0).color(p.tenue).monospace());
                        }
                        if let Some(u) = usuario.as_ref().filter(|u| !u.is_empty()) {
                            ui.add_space(8.0);
                            ui.label(RichText::new(format!("Para la cuenta: {u}")).size(12.0).color(p.texto));
                        }
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new(RichText::new("Crear la passkey").size(13.0).color(p.acento_texto)).fill(p.acento).stroke(egui::Stroke::NONE)).clicked() {
                                decision = Some(Decision::Crear(*id));
                            }
                            if ui.add(egui::Button::new(RichText::new("Rechazar").size(13.0)).fill(p.tarjeta)).clicked() {
                                decision = Some(Decision::RechazarRegistro(*id));
                            }
                        });
                    }
                }
            });

        if let Some(d) = decision {
            // Decidir es interacción real: sella presencia (como GTK en
            // `aplicar_firma`/`aplicar_registro`). Se arma el mismo cuerpo JSON y se
            // resuelve por el núcleo, sin escribir los campos a mano.
            self.nucleo.hay_alguien();
            match d {
                Decision::Firmar(id, i) => {
                    let cuerpo = format!("{{\"id\":{id},\"elegida\":{i}}}");
                    let _ = decidir_firma(&self.nucleo, cuerpo.as_bytes());
                }
                Decision::RechazarFirma(id) => {
                    let cuerpo = format!("{{\"id\":{id},\"elegida\":null}}");
                    let _ = decidir_firma(&self.nucleo, cuerpo.as_bytes());
                }
                Decision::Crear(id) => {
                    let cuerpo = format!("{{\"id\":{id},\"aprobado\":true}}");
                    let _ = decidir_registro(&self.nucleo, cuerpo.as_bytes());
                }
                Decision::RechazarRegistro(id) => {
                    let cuerpo = format!("{{\"id\":{id},\"aprobado\":false}}");
                    let _ = decidir_registro(&self.nucleo, cuerpo.as_bytes());
                }
            }
            self.presentada = None;
        }
        true
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        // Maximizar al arrancar: la ventana nace en estado «no maximizada» (ver
        // `main`), y el comando en los primeros fotogramas la maximiza de verdad.
        // Se insiste unos pocos frames porque en el frame 0 winit aún no lo acepta.
        if self.frames_maximizar > 0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
            self.frames_maximizar -= 1;
            ctx.request_repaint();
        }
        huitaca::aplicar_tema(ctx, huitaca::Modo::Oscuro);
        let p = huitaca::paleta(huitaca::Modo::Oscuro);
        match self.pantalla {
            Pantalla::Bloqueada => {
                egui::CentralPanel::default().show(ctx, |ui| self.ui_bloqueada(ui, &p));
            }
            Pantalla::Abierta => {
                self.ui_abierta(ctx, &p);
                // El diálogo de aprobación de passkey, encima de todo. Solo aparece
                // si el agente dejó una firma/registro a la espera.
                self.ui_aprobacion(ctx, &p);
                // Presencia: SOLO interacción real (tecla, texto, pegar, clic,
                // rueda), nunca el repintado ni el sondeo por fotograma. Sellar por
                // temporizador o por tener el foco sería la «defensa que solo lo
                // parece» que este repo documenta: con la ventana en uso toda la
                // mañana, el enlace se daría por caducado igual. Un repintado no
                // genera eventos de entrada, así que queda fuera por construcción.
                let hubo_input = ctx.input(|i| {
                    i.events.iter().any(|e| {
                        matches!(
                            e,
                            egui::Event::Key { pressed: true, .. }
                                | egui::Event::Text(_)
                                | egui::Event::Paste(_)
                                | egui::Event::PointerButton { pressed: true, .. }
                                | egui::Event::MouseWheel { .. }
                        )
                    })
                });
                if hubo_input {
                    self.nucleo.hay_alguien();
                }
                ctx.request_repaint(); // TOTP en vivo + sondeo de la firma pendiente
            }
        }
    }

    /// Al cerrar la ventana, soltar la bóveda del núcleo compartido para que el
    /// `Drop` de `Boveda` borre su cerrojo (`.lock`).
    ///
    /// Hace falta porque el agente del navegador tiene un `Arc<Aplicacion>`
    /// clonado y vivo: al salir, el refcount NO llega a 0, así que ese `Drop` no
    /// correría solo y quedaría un `.lock` huérfano con el PID de este proceso.
    /// En la siguiente apertura, si el SO reusó ese PID, el cerrojo se daría por
    /// «Ocupada» y la bóveda no abriría hasta borrarlo a mano. El frontal GTK
    /// hace exactamente esto en `connect_close_request`. (Lo caza la revisión del
    /// concilio 2026-10-04.)
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        *self.nucleo.boveda.lock().unwrap() = None;
    }
}

// Fila de la lista: alineada a la izquierda, ancho completo, dos líneas.
fn fila_lista(ui: &mut egui::Ui, p: &Paleta, nombre: &str, sub: &str, sel: bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 44.0), egui::Sense::click());
    let rounding = CornerRadius::same(huitaca::R as u8);
    if sel {
        ui.painter().rect_filled(rect, rounding, egui::Color32::from_rgba_unmultiplied(p.acento.r(), p.acento.g(), p.acento.b(), 45));
        ui.painter().rect_stroke(rect, rounding, egui::Stroke::new(1.0_f32, p.acento), egui::StrokeKind::Inside);
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, rounding, p.tarjeta_hover);
    }
    let x = rect.left() + 12.0;
    let c = rect.center().y;
    ui.painter().text(egui::pos2(x, c - 8.0), egui::Align2::LEFT_CENTER, nombre, egui::FontId::proportional(15.0), p.texto);
    ui.painter().text(egui::pos2(x, c + 9.0), egui::Align2::LEFT_CENTER, sub, egui::FontId::proportional(11.0), p.suave);
    resp.clicked()
}

// Campo de texto de una línea con su etiqueta encima, ancho completo. Para el
// formulario del editor.
fn campo_texto(ui: &mut egui::Ui, p: &Paleta, etiqueta: &str, valor: &mut String, hint: &str) {
    ui.label(RichText::new(etiqueta).size(12.0).color(p.suave));
    ui.add(egui::TextEdit::singleline(valor).hint_text(hint).desired_width(f32::INFINITY));
}

fn fila_dato(ui: &mut egui::Ui, p: &Paleta, etiqueta: &str, valor: &str, _secreto: bool) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(vec2(90.0, 22.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(etiqueta).color(p.suave).size(13.0));
        });
        ui.label(RichText::new(valor).color(p.texto));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(egui::Button::new(RichText::new("Copiar").size(12.0)).fill(p.tarjeta)).clicked() {
                copiar(ui, valor);
            }
        });
    });
}

fn main() -> eframe::Result {
    // `--version`/`-V` ANTES de abrir la ventana: el binario que se instala en
    // Windows es éste, y tiene que poder decir de qué commit sale sin pedir la
    // frase ni dibujar nada (directiva 31, el mismo sello que `chuspa-gtk` y
    // `chuspa-puente`). Si pide versión, imprime y sale.
    chuspa::version::atender_peticion_de_version("chuspa-egui");

    // Ojo: NO se usa `with_maximized(true)` aquí. En Windows eso arranca el
    // ESTADO de la ventana en «maximizada» pero con el tamaño pequeño de
    // `inner_size`, y como el estado ya es true, el comando `Maximized(true)` del
    // primer fotograma queda en no-op y la ventana se queda chica hasta tocar la
    // barra de tareas (medido: título reportaba `max=Some(true)` con ventana
    // pequeña). Arrancando en false, el comando hace la transición de verdad.
    let mut vp = egui::ViewportBuilder::default()
        .with_inner_size([760.0, 500.0])
        .with_min_inner_size([520.0, 360.0])
        .with_title("chuspa");
    if let Ok(icono) = eframe::icon_data::from_png_bytes(include_bytes!("../../empaque/chuspa.png")) {
        vp = vp.with_icon(std::sync::Arc::new(icono));
    }
    let opts = eframe::NativeOptions { viewport: vp, ..Default::default() };
    eframe::run_native(
        "chuspa",
        opts,
        Box::new(|cc| {
            huitaca::aplicar_fuentes(&cc.egui_ctx);
            Ok(Box::new(App::new(&cc.egui_ctx)))
        }),
    )
}
