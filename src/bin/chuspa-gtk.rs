// SPDX-License-Identifier: AGPL-3.0-or-later
//! chuspa como aplicación de ESCRITORIO NATIVA (GTK4) — el estándar de escritorio
//! de Xiliux (como boza). Sustituye progresivamente a la ventana tao+wry: aquí
//! la UI son widgets GTK de verdad, sin HTML ni WebView, para poder crecer en
//! funciones con clipboard, foco y accesibilidad nativos.
//!
//! Esta primera versión cubre la espina: desbloquear la bóveda, listar y filtrar
//! las entradas, y ver sus campos con revelar/copiar. Añadir y editar vienen
//! encima, sobre el mismo núcleo (`chuspa::cifrado::Boveda`).

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use chuspa::boveda::{Entrada, Valor};
use chuspa::cifrado::{Acceso, Boveda};
use chuspa::gui::{tres_estados, Aplicacion, EntradaEntrante};
use gtk::prelude::*;
use gtk::{glib, Application, ApplicationWindow};

const APP_ID: &str = "com.xiliux.chuspa";

/// La bóveda abierta, la firma pendiente y la presencia viven en
/// `chuspa::gui::Aplicacion` —el MISMO núcleo que usa la ventana web—, para
/// poder hospedar el agente del navegador (fase 3) sin reinventar ese estado.
/// La `ruta` de `Aplicacion` es el destino por defecto; el archivo que el
/// usuario abre de verdad se sigue aparte en `ruta_abierta` (el diálogo permite
/// elegir cualquiera), y es lo que usa el guard de la copia de seguridad.
type Nucleo = Arc<Aplicacion>;

fn main() -> glib::ExitCode {
    // Antes de abrir nada: `--version` no arranca la aplicación GTK. Un binario
    // instalado tiene que poder decir de qué commit sale (directiva 28), como
    // chuspa-gui y chuspa-puente.
    chuspa::version::atender_peticion_de_version("chuspa-gtk");

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(construir);
    app.run()
}

/// `~/.local/share/chuspa/boveda.chuspa`, el destino por defecto (igual que
/// `chuspa-gui`); el usuario puede abrir cualquier otro con «Elegir bóveda…».
fn ruta_por_defecto() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("chuspa")
        .join("boveda.chuspa")
}

fn construir(app: &Application) {
    // Tema OSCURO por defecto. chuspa-gtk es GTK4 puro (sin libadwaita), así que
    // sin esto seguiría el tema del sistema y en un escritorio claro saldría
    // claro. Paridad con chuspa-egui, que ya es siempre oscuro
    // (`huitaca::paleta(Modo::Oscuro)`). El usuario puede volver al claro desde
    // el tema del sistema si quiere; esto solo fija el DEFECTO.
    if let Some(settings) = gtk::Settings::default() {
        settings.set_gtk_application_prefer_dark_theme(true);
    }

    let nucleo: Nucleo = Arc::new(Aplicacion::nueva(ruta_por_defecto()));
    // El archivo realmente abierto (el diálogo deja elegir cualquiera).
    let ruta_abierta: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    // El filtro de la lista, sin `unsafe`: los nombres viven en un `Vec` paralelo
    // a las filas (indexado por `ListBoxRow::index`) y la consulta en una celda
    // compartida. `set_filter_func` es la vía nativa de GTK —no hay que guardar
    // datos crudos en el widget, que exigiría `unsafe` y aquí está prohibido
    // (`unsafe_code = "forbid"`)—.
    let nombres: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let consulta: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
    // La sesión de navegador seguro viva (volumen cifrado montado + Firefox), si
    // la hay. Se cierra de forma ordenada al cerrar la ventana.
    let sesion: Rc<RefCell<Option<chuspa::perfil::Sesion>>> = Rc::new(RefCell::new(None));

    // Cerrojo de INSTANCIA: GApplication hace single-instance con bus de sesión,
    // pero SIN bus (TTY/ssh) una 2ª invocación correría la limpieza de abajo y, con
    // el cierre de holders de `desmontar`, MATARÍA el navegador de la 1ª instancia
    // viva. Solo la instancia que tiene el cerrojo limpia huérfanos. Se guarda en un
    // `Rc` capturado por el `close_request` para que viva mientras la ventana.
    let cerrojo_instancia = Rc::new(chuspa::perfil::tomar_instancia());

    // Red de seguridad al ARRANCAR: si un cierre anterior NO limpio (SIGKILL, crash,
    // corte de luz) dejó montado el volumen del navegador seguro —el perfil en CLARO
    // en disco—, desmontarlo ahora. SOLO si soy la única instancia (si no, otra
    // chuspa viva lo está usando y desmontar aquí le mataría el navegador).
    if cerrojo_instancia.is_some() {
        let rutas = chuspa::perfil::Rutas::por_defecto();
        if chuspa::perfil::esta_montado(&rutas.clear) {
            match chuspa::perfil::desmontar(&rutas.clear) {
                Ok(()) => eprintln!(
                    "AVISO: se desmontó el volumen del navegador seguro que había quedado \
                     montado de una sesión anterior (cierre no limpio)."
                ),
                Err(e) => eprintln!(
                    "AVISO: el volumen del navegador seguro quedó montado de una sesión \
                     anterior y no se pudo desmontar ahora: {e}"
                ),
            }
        }
    } else {
        eprintln!("AVISO: ya hay otra instancia de chuspa; esta no tocará el navegador seguro.");
    }

    let ventana = ApplicationWindow::builder()
        .application(app)
        .title("chuspa")
        .default_width(880)
        .default_height(620)
        .build();

    // Barra de título propia (CSD) para OCULTAR la X: solo el icono y los botones
    // de minimizar y maximizar. Cerrar pasa por el botón "Cerrar" (o Alt+F4), que
    // dispara el cierre ordenado — así no se puede salir saltándose el desmontaje
    // del volumen cifrado.
    let barra = gtk::HeaderBar::new();
    barra.set_decoration_layout(Some("icon:minimize,maximize"));
    ventana.set_titlebar(Some(&barra));

    // Dos páginas: desbloqueo y bóveda.
    let pila = gtk::Stack::new();
    pila.set_transition_type(gtk::StackTransitionType::Crossfade);

    // ---- página de DESBLOQUEO ----
    let desbloqueo = gtk::Box::new(gtk::Orientation::Vertical, 12);
    desbloqueo.set_halign(gtk::Align::Center);
    desbloqueo.set_valign(gtk::Align::Center);
    desbloqueo.set_width_request(360);

    let titulo = gtk::Label::new(Some("chuspa"));
    titulo.add_css_class("title-1");
    let sub = gtk::Label::new(Some("Abre tu bóveda"));
    sub.add_css_class("dim-label");

    let ruta_lbl = gtk::Label::new(Some("(ninguna bóveda elegida)"));
    ruta_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    ruta_lbl.set_xalign(0.0);
    ruta_lbl.set_hexpand(true);
    let btn_elegir = gtk::Button::with_label("Elegir bóveda…");
    let fila_ruta = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_ruta.append(&ruta_lbl);
    fila_ruta.append(&btn_elegir);

    let frase = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .placeholder_text("Frase de la bóveda")
        .build();
    let btn_abrir = gtk::Button::with_label("Abrir");
    btn_abrir.add_css_class("suggested-action");
    // Abrir la bóveda y, acto seguido, el navegador sobre su perfil cifrado.
    let btn_navegar = gtk::Button::with_label("Abrir y navegar");
    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_wrap(true);
    error.set_xalign(0.0);

    // Para quien todavía no tiene bóveda: crear la primera, y elegir dónde.
    let sep = gtk::Separator::new(gtk::Orientation::Horizontal);
    sep.set_margin_top(8);
    sep.set_margin_bottom(8);
    let btn_crear_boveda = gtk::Button::with_label("Crear una bóveda nueva…");

    desbloqueo.append(&titulo);
    desbloqueo.append(&sub);
    desbloqueo.append(&fila_ruta);
    desbloqueo.append(&frase);
    desbloqueo.append(&btn_abrir);
    desbloqueo.append(&btn_navegar);
    desbloqueo.append(&error);
    desbloqueo.append(&sep);
    desbloqueo.append(&btn_crear_boveda);

    // ---- página de BÓVEDA (lista + detalle) ----
    let boveda_pag = gtk::Paned::new(gtk::Orientation::Horizontal);
    // 400px: la barra izquierda, igual que chuspa-egui (`exact_width(400.0)`).
    // En GTK es la posición INICIAL del panel (el usuario puede arrastrarla); en
    // egui es fija. Se amplió 300 -> 340 -> 400 para que quepan nombres largos.
    boveda_pag.set_position(400);

    let izq = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let buscar = gtk::SearchEntry::new();
    buscar.set_margin_top(8);
    buscar.set_margin_start(8);
    buscar.set_margin_end(8);
    buscar.set_margin_bottom(8);
    let lista = gtk::ListBox::new();
    lista.set_selection_mode(gtk::SelectionMode::Single);
    lista.add_css_class("navigation-sidebar");
    // Una fila es visible si su nombre contiene la consulta (sin distinguir
    // mayúsculas). El nombre se busca por el índice de la fila en el `Vec`
    // paralelo; una consulta vacía deja pasar todo.
    lista.set_filter_func(glib::clone!(
        #[strong] nombres,
        #[strong] consulta,
        move |fila| {
            let nombres = nombres.borrow();
            let texto = nombres.get(fila.index() as usize);
            // La entrada reservada del volumen del navegador seguro NUNCA se
            // muestra (material de sistema; vive en el .chuspa, no es para el
            // usuario). Se oculta por FILTRO —la fila sigue en la lista, con su
            // índice intacto—, así abrir/editar/eliminar siguen casando 1:1 con la
            // bóveda sin tocar la indexación.
            let nombre = texto.and_then(|t| t.split('\n').next());
            if nombre.is_some_and(chuspa::perfil::es_entrada_de_sistema) {
                return false;
            }
            let q = consulta.borrow();
            if q.is_empty() {
                return true;
            }
            match texto {
                Some(n) => n.to_lowercase().contains(q.as_str()),
                None => true,
            }
        }
    ));
    let lista_scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&lista)
        .build();
    izq.append(&buscar);
    // Fase 2: crear una entrada nueva (mismo backend que la ventana web: `construir`).
    let btn_nueva = gtk::Button::with_label("＋ Nueva entrada…");
    btn_nueva.set_margin_start(8);
    btn_nueva.set_margin_end(8);
    btn_nueva.set_margin_bottom(8);
    izq.append(&btn_nueva);
    izq.append(&lista_scroll);
    // Fase 2: generar contraseña/frase (sobre chuspa::generador, sin tocar la bóveda).
    let btn_generar = gtk::Button::with_label("Generar contraseña…");
    btn_generar.set_margin_start(8);
    btn_generar.set_margin_end(8);
    btn_generar.set_margin_bottom(8);
    btn_generar.connect_clicked(glib::clone!(
        #[weak] ventana,
        move |_| dialogo_generar(&ventana)
    ));
    izq.append(&btn_generar);
    // Fase 2: informe de salud offline (chuspa::salud, sin red).
    let btn_salud = gtk::Button::with_label("Revisar salud…");
    btn_salud.set_margin_start(8);
    btn_salud.set_margin_end(8);
    btn_salud.set_margin_bottom(8);
    btn_salud.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[strong] nucleo,
        move |_| dialogo_salud(&ventana, &nucleo)
    ));
    izq.append(&btn_salud);
    // Fase 2: copia de seguridad cifrada (chuspa::copia).
    let btn_copia = gtk::Button::with_label("Copia de seguridad…");
    btn_copia.set_margin_start(8);
    btn_copia.set_margin_end(8);
    btn_copia.set_margin_bottom(8);
    btn_copia.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[strong] nucleo, #[strong] ruta_abierta,
        move |_| dialogo_copia(&ventana, &nucleo, &ruta_abierta)
    ));
    izq.append(&btn_copia);
    // Fase 5: importar las contraseñas de los navegadores instalados
    // (chuspa::importar::navegadores). Aditivo, no sobrescribe nada.
    let btn_sincronizar = gtk::Button::with_label("Sincronizar desde los navegadores…");
    btn_sincronizar.set_margin_start(8);
    btn_sincronizar.set_margin_end(8);
    btn_sincronizar.set_margin_bottom(8);
    btn_sincronizar.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[strong] nucleo, #[weak] lista, #[strong] nombres,
        move |_| dialogo_sincronizar(&ventana, &nucleo, &lista, &nombres)
    ));
    izq.append(&btn_sincronizar);
    // Importar de un archivo de Bitwarden (.json con passkeys, o .csv solo
    // contraseñas). Para migrar de Bitwarden a chuspa.
    let btn_importar_archivo = gtk::Button::with_label("Importar de un archivo…");
    btn_importar_archivo.set_margin_start(8);
    btn_importar_archivo.set_margin_end(8);
    btn_importar_archivo.set_margin_bottom(8);
    btn_importar_archivo.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[strong] nucleo, #[weak] lista, #[strong] nombres,
        move |_| dialogo_importar_archivo(&ventana, &nucleo, &lista, &nombres)
    ));
    izq.append(&btn_importar_archivo);

    // Cerrar de forma ordenada: `ventana.close()` dispara `connect_close_request`,
    // que cierra el navegador seguro y desmonta su volumen antes de salir. El
    // mismo camino que la X o el menú, pero a la vista.
    let btn_cerrar = gtk::Button::with_label("Cerrar");
    btn_cerrar.set_margin_top(8);
    btn_cerrar.set_margin_start(8);
    btn_cerrar.set_margin_end(8);
    btn_cerrar.set_margin_bottom(8);
    btn_cerrar.connect_clicked(glib::clone!(
        #[weak] ventana,
        move |_| ventana.close()
    ));
    izq.append(&btn_cerrar);

    let detalle = gtk::Box::new(gtk::Orientation::Vertical, 10);
    detalle.set_margin_top(16);
    detalle.set_margin_start(16);
    detalle.set_margin_end(16);
    detalle.set_margin_bottom(16);
    let detalle_scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&detalle)
        .build();
    let placeholder = gtk::Label::new(Some("Elige una entrada"));
    placeholder.add_css_class("dim-label");
    detalle.append(&placeholder);

    boveda_pag.set_start_child(Some(&izq));
    boveda_pag.set_end_child(Some(&detalle_scroll));

    pila.add_named(&desbloqueo, Some("desbloqueo"));
    pila.add_named(&boveda_pag, Some("boveda"));
    ventana.set_child(Some(&pila));

    // ---- elegir bóveda ----
    btn_elegir.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[weak] ruta_lbl,
        #[strong] ruta_abierta,
        move |_| {
            let dialog = gtk::FileDialog::builder().title("Elegir bóveda de chuspa").build();
            dialog.open(Some(&ventana), gtk::gio::Cancellable::NONE, glib::clone!(
                #[weak] ruta_lbl,
                #[strong] ruta_abierta,
                move |res| {
                    if let Ok(archivo) = res
                        && let Some(p) = archivo.path()
                    {
                        ruta_lbl.set_text(&p.display().to_string());
                        *ruta_abierta.borrow_mut() = Some(p);
                    }
                }
            ));
        }
    ));

    // ---- abrir la bóveda ----
    let abrir = glib::clone!(
        #[weak] pila, #[weak] frase, #[weak] error, #[weak] lista,
        #[strong] nucleo, #[strong] ruta_abierta, #[strong] nombres,
        #[upgrade_or_default]
        move || -> bool {
            let ruta = match ruta_abierta.borrow().clone() {
                Some(r) => r,
                None => { error.set_text("Elige primero el archivo de la bóveda."); return false; }
            };
            let clave = frase.text();
            match Boveda::abrir(&ruta, &Acceso::frase(clave.as_str())) {
                Ok(b) => {
                    poblar_lista(&lista, &b, &nombres);
                    *nucleo.boveda.lock().unwrap() = Some(b);
                    nucleo.hay_alguien(); // acabar de teclear la frase es presencia
                    frase.set_text("");
                    error.set_text("");
                    pila.set_visible_child_name("boveda");
                    true
                }
                Err(e) => { error.set_text(&format!("No se pudo abrir: {e:?}")); false }
            }
        }
    );
    btn_abrir.connect_clicked(glib::clone!(#[strong] abrir, move |_| { abrir(); }));
    frase.connect_activate(glib::clone!(#[strong] abrir, move |_| { abrir(); }));
    // «Abrir y navegar»: abre la bóveda y, si tuvo éxito, monta el perfil cifrado
    // y lanza el navegador sobre él.
    btn_navegar.connect_clicked(glib::clone!(
        #[strong] abrir, #[weak] ventana, #[strong] nucleo, #[strong] sesion,
        move |_| {
            if abrir() {
                iniciar_navegador(&ventana, &nucleo, &sesion);
            }
        }
    ));

    // ---- crear una bóveda nueva (para quien aún no tiene) ----
    btn_crear_boveda.connect_clicked(glib::clone!(
        #[weak] ventana, #[weak] pila, #[weak] lista, #[weak] ruta_lbl,
        #[strong] nucleo, #[strong] ruta_abierta, #[strong] nombres,
        move |_| dialogo_crear_boveda(&ventana, &nucleo, &ruta_abierta, &pila, &lista, &nombres, &ruta_lbl)
    ));

    // ---- filtrar la lista ----
    buscar.connect_search_changed(glib::clone!(
        #[weak] lista,
        #[strong] consulta, #[strong] nucleo,
        move |b| {
            nucleo.hay_alguien(); // teclear en el buscador es una persona delante
            *consulta.borrow_mut() = b.text().to_lowercase();
            lista.invalidate_filter();
        }
    ));

    // ---- seleccionar entrada -> detalle ----
    lista.connect_row_selected(glib::clone!(
        #[weak] detalle, #[weak] ventana, #[weak] lista,
        #[strong] nucleo, #[strong] nombres,
        move |_, fila| {
            let Some(fila) = fila else { return; };
            nucleo.hay_alguien(); // mirar una entrada es una persona delante
            let idx = fila.index() as usize;
            let ent = match nucleo.boveda.lock().unwrap().as_ref().map(|b| b.abrir_entrada(idx)) {
                Some(Ok(e)) => e,
                _ => return,
            };
            mostrar_entrada(&detalle, &ent, &ventana, &nucleo, &lista, &nombres, idx);
        }
    ));

    // ---- crear una entrada nueva ----
    btn_nueva.connect_clicked(glib::clone!(
        #[weak] ventana, #[weak] lista,
        #[strong] nucleo, #[strong] nombres,
        move |_| dialogo_entrada(&ventana, &nucleo, &lista, &nombres, None)
    ));

    // ---- agente del navegador (fase 3) ----
    // El enlace con la extensión vive en ESTE proceso (toma `Arc<Aplicacion>` y
    // se comunica por sus Mutex; no depende de tao/wry).
    // 12 horas, no 15 minutos. Ya es SEGURO desde que el agente es solo passkeys:
    // lo único que el enlace atiende es `Autenticar`, y esa firma exige aprobación
    // por uso en la ventana (`decidir_firma`). Se retiraron `Buscar`/`Credencial`/
    // `Generar`/`Proponer`, que entregaban contraseñas sin aprobación — mientras
    // vivían, alargar este plazo abría una ventana de exfiltración silenciosa
    // (concilio 2026-09-15). Durante la navegación normal no se toca la ventana de
    // chuspa, así que 15 min cortaban el login con passkey en silencio; 12 h cubre
    // una jornada. No se pone infinito: la bóveda igual no vence por tiempo (solo
    // al cerrar la ventana), y esto solo es la red del enlace.
    match chuspa::navegador::escuchar_al_navegador(
        Arc::clone(&nucleo),
        std::time::Duration::from_secs(12 * 60 * 60),
    ) {
        Ok(socket) => eprintln!("Atendiendo al navegador en {}", socket.display()),
        Err(e) => eprintln!("AVISO: la extensión no podrá conectarse ({e})"),
    }

    // Cerrar la ventana SUELTA la bóveda (y con ella la clave maestra): cerrar
    // significa cerrar, igual que en la ventana wry.
    ventana.connect_close_request(glib::clone!(
        #[strong] nucleo, #[strong] sesion, #[strong] cerrojo_instancia,
        move |_| {
            // Mantener vivo el cerrojo de instancia hasta aquí (al soltarse, su
            // `Drop` borra el pidfile). Capturarlo ata su vida a la ventana.
            let _ = &cerrojo_instancia;
            // Cierre ordenado: primero el navegador y su volumen cifrado (SIGTERM
            // a Firefox, esperar a que cierre, desmontar), y SOLO luego soltar la
            // bóveda. Así nunca se cierra dejando el volumen montado.
            if let Some(s) = sesion.borrow_mut().take()
                && let Err(e) = s.cerrar()
            {
                eprintln!(
                    "AVISO: el navegador seguro no se cerró limpiamente \
                     (el volumen puede quedar montado hasta apagar): {e}"
                );
            }
            *nucleo.boveda.lock().unwrap() = None;
            glib::Propagation::Proceed
        }
    ));

    // Señales de terminación: cerrar la ventana de forma ORDENADA para que el
    // `connect_close_request` de arriba desmonte el volumen cifrado. Sin esto,
    // `kill` (SIGTERM), Ctrl-C (SIGINT) o cerrar el terminal (SIGHUP) terminaban el
    // proceso dejando el perfil del navegador seguro montado y EN CLARO. (SIGKILL no
    // se puede atrapar; para ese caso está la limpieza de montaje huérfano al arrancar.)
    // Números POSIX estándar en Linux, que es donde corre chuspa-gtk: SIGHUP=1, SIGINT=2, SIGTERM=15.
    for sig in [1i32, 2, 15] {
        glib::unix_signal_add_local(
            sig,
            glib::clone!(
                #[weak] ventana,
                #[upgrade_or] glib::ControlFlow::Break,
                move || {
                    ventana.close();
                    glib::ControlFlow::Break
                }
            ),
        );
    }

    // Sondeo del hilo principal: el agente corre en otro hilo y solo toca los
    // Mutex; DIBUJAR el diálogo de autorización es del hilo principal. Cada
    // ~400 ms se mira si quedó una firma esperando y, si no hay
    // ya un diálogo abierto, se abre. Es el mismo sondeo que hacía la ventana
    // web (`GET /api/firma`), aquí en el reloj de GTK.
    let mostrando = Rc::new(Cell::new(false));
    // La generación de bóveda vista por última vez. Si el AGENTE (el navegador)
    // la sube —registrar una passkey—, este mismo sondeo repuebla la lista: la
    // entrada nació fuera de la ventana y sin esto no aparecía hasta reabrir.
    let ultima_gen = Rc::new(Cell::new(nucleo.generacion_boveda()));
    glib::timeout_add_local(
        std::time::Duration::from_millis(400),
        glib::clone!(
            #[weak] ventana,
            #[weak] lista,
            #[strong] nucleo,
            #[strong] nombres,
            #[strong] mostrando,
            #[strong] ultima_gen,
            #[upgrade_or] glib::ControlFlow::Break,
            move || {
                // OJO: aquí NO se sella la presencia. El sondeo es un
                // temporizador, y sellar por temporizador —o por que la ventana
                // esté enfocada— es la «defensa que solo lo parece» que el núcleo
                // prohíbe (el enlace no vencería nunca con la ventana enfocada y
                // el usuario ausente). La presencia la sella la INTERACCIÓN real
                // (desbloquear, filtrar, seleccionar, guardar, autorizar), no el
                // reloj. Lo señaló el concilio de la fase 3 (opus + fable).
                if mostrando.get() {
                    return glib::ControlFlow::Continue;
                }
                let hay_firma = nucleo
                    .firma
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|f| f.elegida.is_none());
                let hay_registro = nucleo
                    .registro
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|r| r.aprobado.is_none());
                if hay_firma {
                    // Realzar la ventana: cuando una firma espera, la ventana
                    // suele estar DETRÁS del navegador, y un diálogo modal sobre
                    // una ventana escondida no se ve —a los 90 s la firma falla y
                    // el sitio dice «algo salió mal»—. Sacarla al frente es lo que
                    // hacía el aviso de la ventana wry. (Concilio fase 3: fable.)
                    ventana.present();
                    mostrando.set(true);
                    dialogo_firma(&ventana, &nucleo, &mostrando);
                } else if hay_registro {
                    // Mismo motivo que la firma: crear una passkey también espera
                    // detrás del navegador, y sin sacar la ventana al frente el
                    // registro falla a los 90 s sin que nadie vea la pregunta.
                    ventana.present();
                    mostrando.set(true);
                    dialogo_registro(&ventana, &nucleo, &mostrando);
                }
                // Refresco por cambio del AGENTE: si el navegador acaba de
                // registrar una passkey, su entrada ya está en la bóveda pero no
                // en la lista. Repoblar SOLO cuando la generación cambió (las
                // ediciones de la ventana no la tocan), así no se refresca de más
                // ni se pierde la selección por una edición manual.
                let gen_actual = nucleo.generacion_boveda();
                if gen_actual != ultima_gen.get() {
                    ultima_gen.set(gen_actual);
                    if let Some(b) = nucleo.boveda.lock().unwrap().as_ref() {
                        poblar_lista(&lista, b, &nombres);
                    }
                }
                glib::ControlFlow::Continue
            }
        ),
    );

    ventana.present();
}

/// Abre el navegador seguro: lee (o crea la primera vez) la passphrase del
/// volumen en la bóveda ya abierta, monta el perfil cifrado y lanza Firefox.
/// Guarda la sesión para cerrarla de forma ordenada al cerrar la ventana.
fn iniciar_navegador(
    ventana: &ApplicationWindow,
    nucleo: &Nucleo,
    sesion: &Rc<RefCell<Option<chuspa::perfil::Sesion>>>,
) {
    use chuspa::perfil::{self, Rutas};

    if sesion.borrow().is_some() {
        return; // ya hay un navegador seguro abierto
    }
    let rutas = Rutas::por_defecto();

    // La passphrase sale de la bóveda abierta; no la teclea nadie. El guard del
    // Mutex se suelta antes de montar (operación lenta).
    let (frase, recien_creada) = {
        let mut guard = nucleo.boveda.lock().unwrap();
        let Some(boveda) = guard.as_mut() else { return };
        match perfil::passphrase(boveda) {
            Ok(v) => v,
            Err(e) => return avisar(ventana, &format!("No se pudo preparar la llave del navegador: {e}")),
        }
    };

    if !perfil::volumen_iniciado(&rutas.cipher)
        && let Err(e) = perfil::iniciar(&rutas, &frase)
    {
        return avisar(ventana, &format!("No se pudo crear el volumen cifrado: {e}"));
    }

    match perfil::Sesion::abrir(&rutas, &frase) {
        Ok(s) => {
            *sesion.borrow_mut() = Some(s);
            if recien_creada {
                avisar(
                    ventana,
                    "Se creó la llave del navegador cifrado dentro de tu bóveda. \
                     Asegúrate de tener tu respaldo al día (hoja de papel o copia): \
                     sin él, perder la bóveda hace irrecuperable el perfil.",
                );
            }
        }
        Err(e) => avisar(ventana, &format!("No se pudo abrir el navegador seguro: {e}")),
    }
}

/// Un aviso modal simple sobre la ventana.
fn avisar(ventana: &ApplicationWindow, mensaje: &str) {
    gtk::AlertDialog::builder()
        .message(mensaje)
        .modal(true)
        .build()
        .show(Some(ventana));
}

/// Llena la lista con los resúmenes de la bóveda y registra sus nombres en el
/// `Vec` paralelo que usa el filtro (mismo orden que las filas).
///
/// Los nombres se cargan y el `borrow_mut` se SUELTA **antes** de tocar el
/// widget. Al hacer `lista.append`, GTK aplica la `set_filter_func`
/// sincrónicamente sobre la fila insertada, y ese filtro hace `nombres.borrow()`:
/// sostener aquí el `borrow_mut` durante los `append` aborta la app con «already
/// mutably borrowed» en cuanto la búsqueda está activa (guardar tras filtrar).
/// Cuando se inserta la fila i, `nombres` ya está completo, así que el filtro lee
/// `nombres[i]` correctamente y no hay préstamo vivo que choque.
fn poblar_lista(lista: &gtk::ListBox, boveda: &Boveda, nombres: &Rc<RefCell<Vec<String>>>) {
    while let Some(fila) = lista.row_at_index(0) {
        lista.remove(&fila);
    }
    {
        let mut nombres = nombres.borrow_mut();
        nombres.clear();
        for r in boveda.listar() {
            // Texto buscable: nombre Y usuario, para encontrar por cualquiera de
            // los dos (paridad con el filtro de chuspa-egui). El `\n` separador
            // no puede venir de la barra de búsqueda, así que el `contains` del
            // filtro casa cada campo sin cruces falsos entre ellos.
            let usuario = r.usuario.as_deref().unwrap_or("");
            nombres.push(format!("{}\n{usuario}", r.nombre));
        }
    } // el borrow_mut se suelta aquí, antes de cualquier append

    for r in boveda.listar() {
        let fila = gtk::ListBoxRow::new();
        let caja = gtk::Box::new(gtk::Orientation::Vertical, 2);
        caja.set_margin_top(6);
        caja.set_margin_bottom(6);
        caja.set_margin_start(10);
        caja.set_margin_end(10);
        let nombre = gtk::Label::new(Some(&r.nombre));
        nombre.set_xalign(0.0);
        // Subtítulo: usuario -> carpeta -> clase, decidido por el núcleo
        // (`Resumen::subtitulo`, el mismo que usa chuspa-egui). Distingue dos
        // cuentas del mismo sitio sin abrir la entrada.
        let sub = gtk::Label::new(Some(&r.subtitulo()));
        sub.add_css_class("dim-label");
        sub.add_css_class("caption");
        sub.set_xalign(0.0);
        caja.append(&nombre);
        caja.append(&sub);
        fila.set_child(Some(&caja));
        lista.append(&fila);
    }
}

/// Dibuja el detalle de una entrada: sus campos, con revelar y copiar, y un
/// botón para editarla.
fn mostrar_entrada(
    detalle: &gtk::Box,
    ent: &Entrada,
    ventana: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    idx: usize,
) {
    while let Some(hijo) = detalle.first_child() {
        detalle.remove(&hijo);
    }
    // Cabecera: título a la izquierda, botón «Editar…» a la derecha.
    let cabecera = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let titulo = gtk::Label::new(Some(&ent.nombre));
    titulo.add_css_class("title-2");
    titulo.set_xalign(0.0);
    titulo.set_hexpand(true);
    titulo.set_wrap(true);
    let btn_editar = gtk::Button::with_label("Editar…");
    btn_editar.set_valign(gtk::Align::Start);
    btn_editar.connect_clicked(glib::clone!(
        #[weak] ventana, #[weak] lista,
        #[strong] nucleo, #[strong] nombres,
        move |_| dialogo_entrada(&ventana, &nucleo, &lista, &nombres, Some(idx))
    ));
    // Botón «Eliminar…»: borra la ENTRADA entera. Resuelve el residuo de una
    // entrada de solo-passkey cuya llave ya se quitó («Quitar» conserva la entrada
    // a propósito), que si no quedaba sin forma de borrarse desde la ventana.
    let btn_eliminar = gtk::Button::with_label("Eliminar…");
    btn_eliminar.add_css_class("destructive-action");
    btn_eliminar.set_valign(gtk::Align::Start);
    btn_eliminar.connect_clicked(glib::clone!(
        #[weak] ventana, #[weak] lista, #[weak] detalle,
        #[strong] nucleo, #[strong] nombres,
        move |_| confirmar_eliminar_entrada(&ventana, &nucleo, &lista, &nombres, &detalle, idx)
    ));
    cabecera.append(&titulo);
    cabecera.append(&btn_editar);
    cabecera.append(&btn_eliminar);
    detalle.append(&cabecera);

    let clase = gtk::Label::new(Some(ent.clase.etiqueta()));
    clase.add_css_class("dim-label");
    clase.set_xalign(0.0);
    detalle.append(&clase);

    for campo in &ent.campos {
        // El segundo factor no se enseña como un secreto enmascarado: se muestra
        // el CÓDIGO de seis dígitos vivo, con cuenta atrás, como en la web.
        if campo.etiqueta == "acceso.totp" {
            detalle.append(&fila_totp(&campo.valor, ventana));
        } else {
            detalle.append(&fila_campo(&campo.etiqueta, &campo.valor, ventana));
        }
    }

    if let Some(carpeta) = &ent.carpeta {
        detalle.append(&fila_texto("Carpeta", carpeta));
    }
    if !ent.uris.is_empty() {
        let dirs: Vec<&str> = ent.uris.iter().map(|u| u.uri.as_str()).collect();
        detalle.append(&fila_texto("Direcciones", &dirs.join("\n")));
    }
    if let Some(notas) = &ent.notas {
        detalle.append(&fila_texto("Notas", notas.as_str()));
    }

    // Passkeys guardadas en esta entrada: VERLAS y QUITARLAS (paridad con
    // chuspa-egui). El núcleo es el mismo y compartido: `resumen_de_entrada` las
    // lista y `quitar_de_entrada` las borra; aquí va solo la UI GTK.
    let passkeys = chuspa::webauthn::Passkey::resumen_de_entrada(ent);
    if !passkeys.is_empty() {
        let titulo_pk = gtk::Label::new(Some("Passkeys"));
        titulo_pk.add_css_class("heading");
        titulo_pk.set_xalign(0.0);
        titulo_pk.set_margin_top(12);
        detalle.append(&titulo_pk);
        for (n, pk) in passkeys.iter().enumerate() {
            let fila_pk = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let etiqueta = match pk.usuario.as_deref() {
                Some(u) if !u.is_empty() => format!("{}  —  {u}", pk.rp_id),
                _ => pk.rp_id.clone(),
            };
            let lbl = gtk::Label::new(Some(&etiqueta));
            lbl.set_xalign(0.0);
            lbl.set_hexpand(true);
            lbl.set_wrap(true);
            let btn_quitar = gtk::Button::with_label("Quitar");
            btn_quitar.add_css_class("destructive-action");
            btn_quitar.set_valign(gtk::Align::Center);
            btn_quitar.connect_clicked(glib::clone!(
                #[weak] ventana, #[weak] lista, #[weak] detalle,
                #[strong] nucleo, #[strong] nombres,
                move |_| confirmar_quitar_passkey(&ventana, &nucleo, &lista, &nombres, &detalle, idx, n)
            ));
            fila_pk.append(&lbl);
            fila_pk.append(&btn_quitar);
            detalle.append(&fila_pk);
        }
    }
}

/// Pide confirmación y QUITA la passkey `n` de la entrada `idx`. Operación
/// destructiva (borra una llave de acceso), por eso la ventana modal de
/// confirmación —mismo idioma que `ventana_aviso`—. El borrado va por el núcleo
/// compartido con chuspa-egui (`Passkey::quitar_de_entrada`), con el mismo flujo
/// que un editar: `abrir_entrada` -> quitar -> `reemplazar` -> `guardar`, y luego
/// recarga lista y detalle.
fn confirmar_quitar_passkey(
    ventana: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    detalle: &gtk::Box,
    idx: usize,
    n: usize,
) {
    let win = gtk::Window::builder()
        .title("Quitar passkey")
        .transient_for(ventana)
        .modal(true)
        .default_width(420)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 12);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);
    let l = gtk::Label::new(Some(
        "¿Quitar esta passkey? La entrada se conserva; solo se borra esta llave \
         de acceso. No se puede deshacer.",
    ));
    l.set_wrap(true);
    l.set_xalign(0.0);
    caja.append(&l);
    let botones = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    botones.set_halign(gtk::Align::End);
    let cancelar = gtk::Button::with_label("Cancelar");
    cancelar.connect_clicked(glib::clone!(#[weak] win, move |_| win.close()));
    let quitar = gtk::Button::with_label("Quitar");
    quitar.add_css_class("destructive-action");
    quitar.connect_clicked(glib::clone!(
        #[weak] win, #[weak] ventana, #[weak] lista, #[weak] detalle,
        #[strong] nucleo, #[strong] nombres,
        move |_| {
            // Mismo flujo que egui: abrir la entrada, quitar, reemplazar, guardar.
            let resultado = {
                let mut guard = nucleo.boveda.lock().unwrap();
                match guard.as_mut() {
                    None => Err("La bóveda está cerrada.".to_string()),
                    Some(b) => match b.abrir_entrada(idx) {
                        Err(e) => Err(format!("{e}")),
                        Ok(mut entrada) => {
                            if chuspa::webauthn::Passkey::quitar_de_entrada(&mut entrada, n) {
                                b.reemplazar(idx, entrada)
                                    .and_then(|()| b.guardar())
                                    .map_err(|e| format!("{e}"))
                            } else {
                                Err("Esa passkey ya no existe.".to_string())
                            }
                        }
                    },
                }
            };
            win.close();
            match resultado {
                Err(e) => ventana_aviso(&ventana, &e),
                Ok(()) => {
                    // Recargar lista y detalle con la entrada ya sin la passkey.
                    if let Some(b) = nucleo.boveda.lock().unwrap().as_ref() {
                        poblar_lista(&lista, b, &nombres);
                        if let Ok(ent) = b.abrir_entrada(idx) {
                            mostrar_entrada(&detalle, &ent, &ventana, &nucleo, &lista, &nombres, idx);
                        }
                    }
                }
            }
        }
    ));
    botones.append(&cancelar);
    botones.append(&quitar);
    caja.append(&botones);
    win.set_child(Some(&caja));
    win.present();
}

/// Pide confirmación y BORRA la entrada `idx` completa. Operación destructiva e
/// irreversible (se va la entrada y TODO su contenido), por eso la ventana modal.
/// Usa `Boveda::borrar` (el mismo núcleo) + `guardar`, y luego recarga la lista y
/// LIMPIA el detalle (la entrada ya no existe). Es lo que faltaba para borrar las
/// cáscaras que deja «Quitar» una passkey.
fn confirmar_eliminar_entrada(
    ventana: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    detalle: &gtk::Box,
    idx: usize,
) {
    let win = gtk::Window::builder()
        .title("Eliminar entrada")
        .transient_for(ventana)
        .modal(true)
        .default_width(420)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 12);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);
    let l = gtk::Label::new(Some(
        "¿Eliminar esta entrada por completo? Se borra la entrada y TODO su \
         contenido (contraseña, passkeys, segundo factor…). No se puede deshacer.",
    ));
    l.set_wrap(true);
    l.set_xalign(0.0);
    caja.append(&l);
    let botones = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    botones.set_halign(gtk::Align::End);
    let cancelar = gtk::Button::with_label("Cancelar");
    cancelar.connect_clicked(glib::clone!(#[weak] win, move |_| win.close()));
    let eliminar = gtk::Button::with_label("Eliminar");
    eliminar.add_css_class("destructive-action");
    eliminar.connect_clicked(glib::clone!(
        #[weak] win, #[weak] ventana, #[weak] lista, #[weak] detalle,
        #[strong] nucleo, #[strong] nombres,
        move |_| {
            let resultado = {
                let mut guard = nucleo.boveda.lock().unwrap();
                match guard.as_mut() {
                    None => Err("La bóveda está cerrada.".to_string()),
                    Some(b) => b.borrar(idx).and_then(|()| b.guardar()).map_err(|e| format!("{e}")),
                }
            };
            win.close();
            match resultado {
                Err(e) => ventana_aviso(&ventana, &e),
                Ok(()) => {
                    // La entrada ya no existe: recargar la lista y limpiar el detalle.
                    if let Some(b) = nucleo.boveda.lock().unwrap().as_ref() {
                        poblar_lista(&lista, b, &nombres);
                    }
                    while let Some(hijo) = detalle.first_child() {
                        detalle.remove(&hijo);
                    }
                }
            }
        }
    ));
    botones.append(&cancelar);
    botones.append(&eliminar);
    caja.append(&botones);
    win.set_child(Some(&caja));
    win.present();
}

/// Una etiqueta pequeña con su valor de solo lectura (carpeta, direcciones, notas).
fn fila_texto(etiqueta: &str, valor: &str) -> gtk::Box {
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 2);
    caja.set_margin_top(8);
    let l = gtk::Label::new(Some(etiqueta));
    l.add_css_class("dim-label");
    l.add_css_class("caption");
    l.set_xalign(0.0);
    let v = gtk::Label::new(Some(valor));
    v.set_xalign(0.0);
    v.set_wrap(true);
    v.set_selectable(true);
    caja.append(&l);
    caja.append(&v);
    caja
}

/// Da formato a un código TOTP de seis dígitos partiéndolo en dos («123 456»),
/// para que se lea de un vistazo. Otros largos se dejan tal cual.
fn formatear_codigo(c: &str) -> String {
    if c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit()) {
        format!("{} {}", &c[..3], &c[3..])
    } else {
        c.to_string()
    }
}

/// Pone en las etiquetas el código TOTP actual y los segundos que le quedan.
fn refrescar_totp(secreto: &str, codigo: &gtk::Label, cuenta: &gtk::Label) {
    match chuspa::totp::Totp::interpretar(secreto) {
        Ok(t) => {
            codigo.set_text(&formatear_codigo(&t.codigo().unwrap_or_default()));
            cuenta.set_text(&format!("{} s", t.segundos_restantes().unwrap_or(0)));
        }
        Err(_) => {
            codigo.set_text("(segundo factor ilegible)");
            cuenta.set_text("");
        }
    }
}

/// La fila del segundo factor: el CÓDIGO de seis dígitos en vivo, con cuenta
/// atrás y botón de copiar. Se refresca cada segundo hasta que el detalle se
/// redibuja (al cambiar de entrada las etiquetas se sueltan y el temporizador
/// se corta solo).
fn fila_totp(valor: &Valor, ventana: &ApplicationWindow) -> gtk::Box {
    let secreto = match valor {
        Valor::Secreto(s) => s.to_string(),
        Valor::Texto(t) => t.clone(),
        _ => String::new(),
    };

    let caja = gtk::Box::new(gtk::Orientation::Vertical, 2);
    caja.set_margin_top(8);
    let etq = gtk::Label::new(Some("Segundo factor"));
    etq.add_css_class("dim-label");
    etq.add_css_class("caption");
    etq.set_xalign(0.0);
    caja.append(&etq);

    let fila = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let codigo = gtk::Label::new(None);
    codigo.add_css_class("title-3");
    codigo.add_css_class("monospace");
    codigo.set_xalign(0.0);
    codigo.set_selectable(true);
    let cuenta = gtk::Label::new(None);
    cuenta.add_css_class("dim-label");
    cuenta.set_hexpand(true);
    cuenta.set_xalign(0.0);
    let copiar = gtk::Button::from_icon_name("edit-copy-symbolic");
    copiar.set_tooltip_text(Some("Copiar el código"));
    fila.append(&codigo);
    fila.append(&cuenta);
    fila.append(&copiar);
    caja.append(&fila);

    // Copiar toma el código VIGENTE en el momento del clic, no uno viejo.
    copiar.connect_clicked(glib::clone!(
        #[weak] ventana,
        #[strong] secreto,
        move |_| {
            if let Ok(t) = chuspa::totp::Totp::interpretar(&secreto)
                && let Ok(c) = t.codigo()
            {
                ventana.clipboard().set_text(&c);
            }
        }
    ));

    refrescar_totp(&secreto, &codigo, &cuenta);
    // Refresco cada segundo; se corta cuando las etiquetas dejan de existir.
    let codigo_debil = codigo.downgrade();
    let cuenta_debil = cuenta.downgrade();
    glib::timeout_add_local(std::time::Duration::from_secs(1), move || {
        let (Some(c), Some(q)) = (codigo_debil.upgrade(), cuenta_debil.upgrade()) else {
            return glib::ControlFlow::Break;
        };
        refrescar_totp(&secreto, &c, &q);
        glib::ControlFlow::Continue
    });

    caja
}

/// Una fila de campo: etiqueta arriba; valor con botones revelar (si es
/// sensible) y copiar.
fn fila_campo(etiqueta: &str, valor: &Valor, ventana: &ApplicationWindow) -> gtk::Box {
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 2);
    caja.set_margin_top(6);
    let etq = gtk::Label::new(Some(etiqueta));
    etq.add_css_class("dim-label");
    etq.add_css_class("caption");
    etq.set_xalign(0.0);
    caja.append(&etq);

    let texto: String = match valor {
        Valor::Texto(s) => s.clone(),
        Valor::Secreto(s) => s.as_str().to_string(),
        Valor::Booleano(b) => if *b { "sí".into() } else { "no".into() },
        Valor::Referencia(n) => format!("(referencia a #{n})"),
    };
    let sensible = valor.es_sensible();

    let fila = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let vista = gtk::Label::new(None);
    vista.set_xalign(0.0);
    vista.set_hexpand(true);
    vista.set_selectable(!sensible);
    vista.set_wrap(true);
    if sensible {
        vista.set_text("••••••••••");
        vista.add_css_class("monospace");
    } else {
        vista.set_text(&texto);
    }
    fila.append(&vista);

    if sensible {
        let revelar = gtk::ToggleButton::new();
        revelar.set_icon_name("view-reveal-symbolic");
        revelar.set_tooltip_text(Some("Revelar"));
        let texto_rev = texto.clone();
        revelar.connect_toggled(glib::clone!(
            #[weak] vista,
            move |b| {
                if b.is_active() {
                    vista.set_text(&texto_rev);
                    vista.set_selectable(true);
                } else {
                    vista.set_text("••••••••••");
                    vista.set_selectable(false);
                }
            }
        ));
        fila.append(&revelar);
    }

    let copiar = gtk::Button::from_icon_name("edit-copy-symbolic");
    copiar.set_tooltip_text(Some("Copiar"));
    let texto_cp = texto.clone();
    copiar.connect_clicked(glib::clone!(
        #[weak] ventana,
        move |_| {
            ventana.clipboard().set_text(&texto_cp);
        }
    ));
    fila.append(&copiar);
    caja.append(&fila);
    caja
}

/// Fase 2 (migración GTK): diálogo para generar una contraseña o una frase de
/// palabras. Usa `chuspa::generador` y NO toca la bóveda; el resultado se copia al
/// portapapeles a petición.
fn dialogo_generar(padre: &ApplicationWindow) {
    use chuspa::generador::{contrasena, frase, Composicion};

    let win = gtk::Window::builder()
        .title("Generar")
        .transient_for(padre)
        .modal(true)
        .default_width(440)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 12);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let tipo = gtk::DropDown::from_strings(&["Contraseña", "Frase de palabras"]);

    let escala = gtk::SpinButton::with_range(4.0, 128.0, 1.0);
    escala.set_value(20.0);
    let lbl_len = gtk::Label::new(Some("Longitud / n.º de palabras"));
    lbl_len.set_hexpand(true);
    lbl_len.set_xalign(0.0);
    let fila_len = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_len.append(&lbl_len);
    fila_len.append(&escala);

    let salida = gtk::Entry::new();
    salida.set_editable(false);
    salida.set_hexpand(true);
    let copiar = gtk::Button::from_icon_name("edit-copy-symbolic");
    copiar.set_tooltip_text(Some("Copiar al portapapeles"));
    let fila_out = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_out.append(&salida);
    fila_out.append(&copiar);

    let btn_gen = gtk::Button::with_label("Generar");
    btn_gen.add_css_class("suggested-action");
    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_xalign(0.0);
    error.set_wrap(true);

    let generar: std::rc::Rc<dyn Fn()> = std::rc::Rc::new(glib::clone!(
        #[weak] tipo,
        #[weak] escala,
        #[weak] salida,
        #[weak] error,
        move || {
            error.set_text("");
            let n = escala.value() as usize;
            let res = if tipo.selected() == 0 {
                contrasena(n, Composicion::default()).map(|c| c.to_string())
            } else {
                frase(n.max(3), '-').map(|c| c.to_string())
            };
            match res {
                Ok(s) => salida.set_text(&s),
                Err(e) => error.set_text(&format!("{e}")),
            }
        }
    ));
    btn_gen.connect_clicked(glib::clone!(
        #[strong] generar,
        move |_| generar()
    ));
    copiar.connect_clicked(glib::clone!(
        #[weak] salida,
        #[weak] padre,
        move |_| {
            let t = salida.text();
            if !t.is_empty() {
                padre.clipboard().set_text(&t);
            }
        }
    ));

    caja.append(&tipo);
    caja.append(&fila_len);
    caja.append(&btn_gen);
    caja.append(&fila_out);
    caja.append(&error);
    win.set_child(Some(&caja));
    generar(); // uno listo al abrir
    win.present();
}

/// Crea la copia, la escribe y la VERIFICA releyéndola del DISCO —no los bytes
/// en memoria—. Una escritura parcial (disco lleno, USB retirado) dejaría los
/// bytes de RAM válidos sobre un archivo truncado, y verificar la RAM daría un
/// falso «copia buena»: la verdad de una copia es lo que quedó en el disco.
fn crear_copia_verificada(
    boveda: &Boveda,
    frase: &str,
    ruta: &std::path::Path,
) -> Result<chuspa::copia::Ficha, String> {
    let bytes = chuspa::copia::crear(boveda, &Acceso::frase(frase))
        .map_err(|e| format!("No se pudo crear: {e}"))?;
    chuspa::copia::escribir(&bytes, ruta).map_err(|e| format!("No se pudo escribir: {e}"))?;
    let en_disco =
        std::fs::read(ruta).map_err(|e| format!("Se escribió pero no se pudo releer: {e}"))?;
    chuspa::copia::comprobar(&en_disco, &Acceso::frase(frase))
        .map_err(|e| format!("La copia en disco no verifica: {e}"))
}

/// Resumen de una copia, sin un solo dato de su contenido: conteos y tamaños.
fn resumen_copia(f: &chuspa::copia::Ficha, ruta: &str) -> String {
    format!(
        "Copia verificada en «{ruta}»: {} entradas, {} bytes (ahorro {} %).",
        f.entradas,
        f.bytes_archivo,
        f.ahorro().round()
    )
}

/// Fase 2: copia de seguridad cifrada. Dos acciones en un diálogo: CREAR una
/// copia nueva de la bóveda abierta (cifrada con su propia frase, y verificada
/// antes de darla por buena) y COMPROBAR una copia existente (la abre y dice qué
/// trae, sin tocar nada). Como en la web, la copia se hace desde la bóveda
/// ABIERTA —para copiarlo todo hay que descifrarlo todo—, solo cuando se pide.
fn dialogo_copia(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    ruta_abierta: &Rc<RefCell<Option<PathBuf>>>,
) {
    let win = gtk::Window::builder()
        .title("Copia de seguridad")
        .transient_for(padre)
        .modal(true)
        .default_width(520)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let resultado = gtk::Label::new(None);
    resultado.set_wrap(true);
    resultado.set_xalign(0.0);

    // ---- Crear ----
    let cab1 = gtk::Label::new(Some("Crear una copia nueva"));
    cab1.add_css_class("title-4");
    cab1.set_xalign(0.0);
    let destino: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let dest_lbl = gtk::Label::new(Some("(sin destino elegido)"));
    dest_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    dest_lbl.set_xalign(0.0);
    dest_lbl.set_hexpand(true);
    let btn_dest = gtk::Button::with_label("Elegir destino…");
    let fila_dest = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_dest.append(&dest_lbl);
    fila_dest.append(&btn_dest);
    let frase1 = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    frase1.set_placeholder_text(Some("Frase para cifrar la copia"));
    let frase2 = gtk::PasswordEntry::new();
    frase2.set_placeholder_text(Some("Repite la frase"));
    let btn_crear = gtk::Button::with_label("Crear copia");
    btn_crear.add_css_class("suggested-action");

    btn_dest.connect_clicked(glib::clone!(
        #[weak] win, #[weak] dest_lbl, #[strong] destino,
        move |_| {
            let dialog = gtk::FileDialog::builder().title("Guardar la copia de chuspa").build();
            dialog.save(Some(&win), gtk::gio::Cancellable::NONE, glib::clone!(
                #[weak] dest_lbl, #[strong] destino,
                move |res| {
                    if let Ok(archivo) = res
                        && let Some(p) = archivo.path()
                    {
                        dest_lbl.set_text(&p.display().to_string());
                        *destino.borrow_mut() = Some(p);
                    }
                }
            ));
        }
    ));

    btn_crear.connect_clicked(glib::clone!(
        #[weak] resultado, #[weak] frase1, #[weak] frase2, #[strong] destino,
        #[strong] nucleo, #[strong] ruta_abierta,
        move |_| {
            let Some(ruta) = destino.borrow().clone() else {
                resultado.set_text("Elige primero el destino.");
                return;
            };
            let f1 = frase1.text();
            if f1.is_empty() {
                resultado.set_text("La copia necesita una frase.");
                return;
            }
            if f1 != frase2.text() {
                resultado.set_text("Las dos frases no coinciden.");
                return;
            }
            // No dejar que el destino de la copia sea la bóveda ABIERTA: la
            // pisaría con un blob de formato «copia».
            if ruta_abierta.borrow().as_deref() == Some(ruta.as_path()) {
                resultado.set_text("Ese archivo es tu bóveda abierta; elige otro destino para la copia.");
                return;
            }
            let guard = nucleo.boveda.lock().unwrap();
            let Some(b) = guard.as_ref() else {
                resultado.set_text("La bóveda está cerrada.");
                return;
            };
            match crear_copia_verificada(b, f1.as_str(), &ruta) {
                Ok(f) => resultado.set_text(&resumen_copia(&f, &ruta.display().to_string())),
                Err(msg) => resultado.set_text(&msg),
            }
        }
    ));

    // ---- Comprobar ----
    let cab2 = gtk::Label::new(Some("Comprobar una copia"));
    cab2.add_css_class("title-4");
    cab2.set_xalign(0.0);
    cab2.set_margin_top(6);
    let fuente: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let fuente_lbl = gtk::Label::new(Some("(sin archivo elegido)"));
    fuente_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    fuente_lbl.set_xalign(0.0);
    fuente_lbl.set_hexpand(true);
    let btn_fuente = gtk::Button::with_label("Elegir archivo…");
    let fila_fuente = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_fuente.append(&fuente_lbl);
    fila_fuente.append(&btn_fuente);
    let frase3 = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    frase3.set_placeholder_text(Some("Frase de la copia"));
    let btn_comp = gtk::Button::with_label("Comprobar");

    btn_fuente.connect_clicked(glib::clone!(
        #[weak] win, #[weak] fuente_lbl, #[strong] fuente,
        move |_| {
            let dialog = gtk::FileDialog::builder().title("Elegir una copia de chuspa").build();
            dialog.open(Some(&win), gtk::gio::Cancellable::NONE, glib::clone!(
                #[weak] fuente_lbl, #[strong] fuente,
                move |res| {
                    if let Ok(archivo) = res
                        && let Some(p) = archivo.path()
                    {
                        fuente_lbl.set_text(&p.display().to_string());
                        *fuente.borrow_mut() = Some(p);
                    }
                }
            ));
        }
    ));
    btn_comp.connect_clicked(glib::clone!(
        #[weak] resultado, #[weak] frase3, #[strong] fuente,
        move |_| {
            let Some(ruta) = fuente.borrow().clone() else {
                resultado.set_text("Elige primero el archivo.");
                return;
            };
            let bytes = match std::fs::read(&ruta) {
                Ok(b) => b,
                Err(e) => {
                    resultado.set_text(&format!("No se pudo leer: {e}"));
                    return;
                }
            };
            match chuspa::copia::comprobar(&bytes, &Acceso::frase(frase3.text().as_str())) {
                Ok(f) => resultado.set_text(&resumen_copia(&f, &ruta.display().to_string())),
                Err(e) => resultado.set_text(&format!("No se pudo abrir la copia: {e}")),
            }
        }
    ));

    let cerrar = gtk::Button::with_label("Cerrar");
    cerrar.set_halign(gtk::Align::End);
    cerrar.connect_clicked(glib::clone!(
        #[weak] win,
        move |_| win.close()
    ));

    caja.append(&cab1);
    caja.append(&fila_dest);
    caja.append(&frase1);
    caja.append(&frase2);
    caja.append(&btn_crear);
    caja.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    caja.append(&cab2);
    caja.append(&fila_fuente);
    caja.append(&frase3);
    caja.append(&btn_comp);
    caja.append(&resultado);
    caja.append(&cerrar);
    win.set_child(Some(&caja));
    win.present();
}

/// Crear una bóveda NUEVA: elegir DÓNDE guardarla y ponerle una frase (con
/// confirmación). Es la única forma de empezar cuando aún no hay bóveda. Al
/// crearla se abre y se pasa a la página de la bóveda.
#[allow(clippy::too_many_arguments)]
fn dialogo_crear_boveda(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    ruta_abierta: &Rc<RefCell<Option<PathBuf>>>,
    pila: &gtk::Stack,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    ruta_lbl: &gtk::Label,
) {
    let win = gtk::Window::builder()
        .title("Crear bóveda nueva")
        .transient_for(padre)
        .modal(true)
        .default_width(480)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let expl = gtk::Label::new(Some(
        "Elige dónde guardar tu bóveda y ponle una frase. Sin esa frase no se puede \
         abrir, y no hay forma de recuperarla si la olvidas.",
    ));
    expl.set_wrap(true);
    expl.set_xalign(0.0);
    caja.append(&expl);

    let destino: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let dest_lbl = gtk::Label::new(Some("(sin destino elegido)"));
    dest_lbl.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    dest_lbl.set_xalign(0.0);
    dest_lbl.set_hexpand(true);
    let btn_dest = gtk::Button::with_label("Elegir dónde…");
    let fila_dest = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    fila_dest.append(&dest_lbl);
    fila_dest.append(&btn_dest);
    btn_dest.connect_clicked(glib::clone!(
        #[weak] win, #[weak] dest_lbl, #[strong] destino,
        move |_| {
            let dialog = gtk::FileDialog::builder()
                .title("Guardar la bóveda de chuspa")
                .initial_name("boveda.chuspa")
                .build();
            dialog.save(Some(&win), gtk::gio::Cancellable::NONE, glib::clone!(
                #[weak] dest_lbl, #[strong] destino,
                move |res| {
                    if let Ok(archivo) = res
                        && let Some(p) = archivo.path()
                    {
                        dest_lbl.set_text(&p.display().to_string());
                        *destino.borrow_mut() = Some(p);
                    }
                }
            ));
        }
    ));

    let frase1 = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    frase1.set_placeholder_text(Some("Frase para la bóveda"));
    let frase2 = gtk::PasswordEntry::new();
    frase2.set_placeholder_text(Some("Repite la frase"));

    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_xalign(0.0);
    error.set_wrap(true);

    let botones = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    botones.set_halign(gtk::Align::End);
    botones.set_margin_top(6);
    let cancelar = gtk::Button::with_label("Cancelar");
    let btn_crear = gtk::Button::with_label("Crear bóveda");
    btn_crear.add_css_class("suggested-action");
    botones.append(&cancelar);
    botones.append(&btn_crear);

    cancelar.connect_clicked(glib::clone!(
        #[weak] win,
        move |_| win.close()
    ));

    btn_crear.connect_clicked(glib::clone!(
        #[weak] win, #[weak] frase1, #[weak] frase2, #[weak] error, #[weak] pila,
        #[weak] lista, #[weak] ruta_lbl,
        #[strong] destino, #[strong] nucleo, #[strong] ruta_abierta, #[strong] nombres,
        move |_| {
            let Some(ruta) = destino.borrow().clone() else {
                error.set_text("Elige primero dónde guardarla.");
                return;
            };
            let f1 = frase1.text();
            if f1.is_empty() {
                error.set_text("La bóveda necesita una frase.");
                return;
            }
            if f1 != frase2.text() {
                error.set_text("Las dos frases no coinciden.");
                return;
            }
            // Se crea con el coste real de KDF (Argon2id): tarda ~1 s en el hilo
            // principal, igual que abrir una bóveda. Es una acción de una vez.
            match Boveda::crear(&ruta, &Acceso::frase(f1.as_str()), chuspa::cifrado::coste_por_defecto()) {
                Ok(b) => {
                    poblar_lista(&lista, &b, &nombres);
                    *nucleo.boveda.lock().unwrap() = Some(b);
                    *ruta_abierta.borrow_mut() = Some(ruta.clone());
                    ruta_lbl.set_text(&ruta.display().to_string());
                    nucleo.hay_alguien();
                    pila.set_visible_child_name("boveda");
                    win.close();
                }
                Err(e) => error.set_text(&format!("No se pudo crear la bóveda: {e}")),
            }
        }
    ));

    caja.append(&campo_form("Dónde", &fila_dest));
    caja.append(&campo_form("Frase", &frase1));
    caja.append(&frase2);
    caja.append(&error);
    caja.append(&botones);
    win.set_child(Some(&caja));
    win.present();
}

/// Fase 2: informe de salud offline. Abre TODAS las entradas —la decisión de
/// tenerlas en claro en memoria a la vez se toma aquí, a la vista, como en la
/// web— y muestra los hallazgos de `chuspa::salud` ordenados por gravedad.
/// Importa un export de Bitwarden desde un archivo, para MIGRAR a chuspa: `.json`
/// (contraseñas + passkeys) o `.csv` (solo contraseñas). Es aditivo —añade a la
/// bóveda abierta— y enseña los avisos del importador (el CSV pierde passkeys, el
/// archivo va en claro, etc.). Pensado para una bóveda nueva; una segunda pasada
/// duplicaría (el export de Bitwarden no trae identificadores de ítem).
fn dialogo_importar_archivo(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
) {
    if nucleo.boveda.lock().unwrap().is_none() {
        return;
    }
    let dialog = gtk::FileDialog::builder()
        .title("Elegir el export de Bitwarden (.json o .csv)")
        .build();
    dialog.open(
        Some(padre),
        gtk::gio::Cancellable::NONE,
        glib::clone!(
            #[weak] padre,
            #[strong] nucleo,
            #[weak] lista,
            #[strong] nombres,
            move |res| {
                let Ok(archivo) = res else { return };
                let Some(ruta) = archivo.path() else { return };
                importar_archivo_y_reportar(&padre, &nucleo, &lista, &nombres, &ruta);
            }
        ),
    );
}

/// Lee `ruta`, importa según su extensión, añade a la bóveda, persiste y enseña
/// el reporte. Separado para no anidar todo dentro del callback del diálogo.
fn importar_archivo_y_reportar(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    ruta: &std::path::Path,
) {
    // El export de Bitwarden es TODAS las contraseñas en texto plano: se envuelve
    // en `Zeroizing` para borrarlo de memoria al soltarlo, coherente con el resto
    // de chuspa (hallazgo del concilio). El archivo en disco sigue en claro —eso
    // lo avisa el reporte y lo borra el usuario—.
    let texto = match std::fs::read_to_string(ruta) {
        Ok(t) => zeroize::Zeroizing::new(t),
        Err(e) => return ventana_aviso(padre, &format!("No se pudo leer el archivo: {e}")),
    };
    let ext = ruta.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let imp: Result<chuspa::boveda::Importacion, String> = match ext.as_str() {
        // `to_string()` (Display), no `{e:?}`: el importador JSON escribe mensajes
        // de GUÍA para el migrante —p. ej. el export cifrado dice «exporta con
        // formato .json, no .encrypted_json»— y `Debug` los tiraría (concilio, fable).
        "json" => chuspa::importar::bitwarden::importar(&texto).map_err(|e| e.to_string()),
        "csv" => chuspa::importar::bitwarden_csv::importar(&texto).map_err(|e| e.to_string()),
        _ => Err("El archivo debe ser .json (con passkeys) o .csv (solo contraseñas).".into()),
    };
    let imp = match imp {
        Ok(i) => i,
        Err(e) => return ventana_aviso(padre, &format!("No se pudo importar: {e}")),
    };

    // Añadir cada entrada a la bóveda y persistir.
    let (mut ok, mut fallos) = (0usize, 0usize);
    {
        let mut guard = nucleo.boveda.lock().unwrap();
        let Some(b) = guard.as_mut() else {
            return ventana_aviso(padre, "La bóveda está cerrada.");
        };
        for entrada in imp.entradas {
            match b.anadir(entrada) {
                Ok(_) => ok += 1,
                Err(_) => fallos += 1,
            }
        }
        if ok > 0
            && let Err(e) = b.guardar()
        {
            return ventana_aviso(
                padre,
                &format!("Añadí {ok} en memoria pero NO pude guardar en disco: {e}."),
            );
        }
    }
    if ok > 0
        && let Some(b) = nucleo.boveda.lock().unwrap().as_ref()
    {
        poblar_lista(lista, b, nombres);
    }

    let mut msg = format!("Importadas {ok} entradas.");
    if fallos > 0 {
        msg.push_str(&format!(" {fallos} no se pudieron añadir."));
    }
    msg.push_str("\n\n");
    msg.push_str(&imp.avisos.join("\n\n"));
    ventana_aviso(padre, &msg);
}

/// Una ventanita modal con un texto y un botón de cerrar. Para reportes/avisos.
fn ventana_aviso(padre: &ApplicationWindow, texto: &str) {
    let win = gtk::Window::builder()
        .title("Importar de un archivo")
        .transient_for(padre)
        .modal(true)
        .default_width(560)
        .default_height(420)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);
    let l = gtk::Label::new(Some(texto));
    l.set_wrap(true);
    l.set_xalign(0.0);
    l.set_selectable(true);
    let scroll = gtk::ScrolledWindow::builder().vexpand(true).child(&l).build();
    caja.append(&scroll);
    let cerrar = gtk::Button::with_label("Cerrar");
    cerrar.set_halign(gtk::Align::End);
    cerrar.connect_clicked(glib::clone!(#[weak] win, move |_| win.close()));
    caja.append(&cerrar);
    win.set_child(Some(&caja));
    win.present();
}

/// Fase 5: importa las contraseñas guardadas en los navegadores Chromium a la
/// bóveda abierta. Detecta los perfiles instalados, avisa de los navegadores que
/// estén ABIERTOS (leer su `Login Data` a medio escribir da lecturas malas), y al
/// confirmar recorre cada perfil con `importar_de_navegador` —aditivo: nunca pisa
/// una contraseña existente, un conflicto se añade como entrada nueva—. Persiste
/// solo si algo cambió y repuebla la lista.
fn dialogo_sincronizar(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
) {
    use chuspa::importar::navegadores::{deteccion, fusion};

    // Sin bóveda abierta no hay a dónde importar.
    if nucleo.boveda.lock().unwrap().is_none() {
        return;
    }

    let perfiles = deteccion::perfiles_instalados();
    let perfiles_ff = deteccion::perfiles_firefox();

    let win = gtk::Window::builder()
        .title("Sincronizar desde los navegadores")
        .transient_for(padre)
        .modal(true)
        .default_width(560)
        .default_height(480)
        .build();

    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    // Ningún navegador con contraseñas: se dice y no hay más.
    if perfiles.is_empty() && perfiles_ff.is_empty() {
        let vacio = gtk::Label::new(Some(
            "No encontré ningún navegador con contraseñas en tu carpeta de \
             configuración (Brave, Chrome, Chromium, Edge o Firefox).",
        ));
        vacio.set_wrap(true);
        vacio.set_xalign(0.0);
        caja.append(&vacio);
        let cerrar = gtk::Button::with_label("Cerrar");
        cerrar.set_halign(gtk::Align::End);
        cerrar.connect_clicked(glib::clone!(#[weak] win, move |_| win.close()));
        caja.append(&cerrar);
        win.set_child(Some(&caja));
        win.present();
        return;
    }

    let intro = gtk::Label::new(Some(
        "Voy a copiar a la bóveda las contraseñas guardadas en estos perfiles. \
         Es aditivo: no se sobrescribe ninguna entrada que ya tengas; si una \
         contraseña difiere, se añade como entrada nueva para que decidas.",
    ));
    intro.set_wrap(true);
    intro.set_xalign(0.0);
    caja.append(&intro);

    // Lista de perfiles, marcando los que tienen el navegador abierto.
    let alguno_abierto = perfiles.iter().any(deteccion::Perfil::navegador_abierto)
        || perfiles_ff.iter().any(deteccion::PerfilFirefox::navegador_abierto);
    let lista_perfiles = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let fila_perfil = |nombre: &str, perfil: &str, abierto: bool| {
        let txt = if abierto {
            format!("•  {nombre} — {perfil}   ⚠ ábrelo cerrado")
        } else {
            format!("•  {nombre} — {perfil}")
        };
        let l = gtk::Label::new(Some(&txt));
        l.set_xalign(0.0);
        if abierto {
            l.add_css_class("warning");
        }
        lista_perfiles.append(&l);
    };
    for p in &perfiles {
        fila_perfil(p.navegador, &p.perfil, p.navegador_abierto());
    }
    for p in &perfiles_ff {
        fila_perfil("Firefox", &p.perfil, p.navegador_abierto());
    }
    let scroll = gtk::ScrolledWindow::builder().vexpand(true).child(&lista_perfiles).build();
    caja.append(&scroll);

    let aviso = gtk::Label::new(None);
    aviso.set_wrap(true);
    aviso.set_xalign(0.0);
    if alguno_abierto {
        aviso.set_markup(
            "<b>Cierra los navegadores marcados antes de importar.</b> Con el \
             navegador abierto, su archivo de contraseñas puede leerse a medio \
             escribir y algunas no se descifrarán.",
        );
        aviso.add_css_class("warning");
        caja.append(&aviso);
    }

    // Firefox puede tener una CONTRASEÑA PRIMARIA que protege su almacén. La
    // mayoría de perfiles no la usan (se deja vacío); si el tuyo la tiene, va
    // aquí. Solo se enseña si hay algún perfil de Firefox.
    let primaria_ff = gtk::PasswordEntry::new();
    if !perfiles_ff.is_empty() {
        let etq = gtk::Label::new(Some(
            "Contraseña primaria de Firefox (déjala vacía si no usas una):",
        ));
        etq.set_xalign(0.0);
        etq.set_wrap(true);
        primaria_ff.set_show_peek_icon(true);
        caja.append(&etq);
        caja.append(&primaria_ff);
    }

    let resultado = gtk::Label::new(None);
    resultado.set_wrap(true);
    resultado.set_xalign(0.0);
    resultado.set_selectable(true);

    let botones = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    botones.set_halign(gtk::Align::End);
    let cerrar = gtk::Button::with_label("Cerrar");
    cerrar.connect_clicked(glib::clone!(#[weak] win, move |_| win.close()));
    let btn_importar = gtk::Button::with_label("Importar ahora");
    btn_importar.add_css_class("suggested-action");
    botones.append(&cerrar);
    botones.append(&btn_importar);
    caja.append(&resultado);
    caja.append(&botones);

    btn_importar.connect_clicked(glib::clone!(
        #[strong] nucleo,
        #[weak] lista,
        #[strong] nombres,
        #[weak] resultado,
        #[weak] btn_importar,
        // `#[strong]`, NO `#[weak]`: este widget solo se emparenta a la ventana si
        // hay perfiles Firefox; para un usuario sin Firefox (Chromium solo) no
        // tiene padre, y un `#[weak]` se finalizaría al retornar el diálogo,
        // dejando el closure con un weak muerto → `glib::clone!` abortaría el
        // cuerpo entero al pulsar «Importar» y no se importaría NADA, en silencio
        // (regresión cazada por el concilio). Con `#[strong]` el closure lo
        // mantiene vivo; se libera con la ventana, sin ciclo.
        #[strong] primaria_ff,
        move |_| {
            let (mut imp, mut dup, mut conf, mut ileg, mut sd) = (0usize, 0, 0, 0, 0);
            let mut errores: Vec<String> = Vec::new();
            let mut cambio = false;
            let mut fallo_guardar: Option<String> = None;

            {
                let mut guard = nucleo.boveda.lock().unwrap();
                let Some(b) = guard.as_mut() else {
                    resultado.set_text("La bóveda está cerrada.");
                    return;
                };
                for p in &perfiles {
                    let bytes = match std::fs::read(&p.login_data) {
                        Ok(x) => x,
                        Err(e) => {
                            errores.push(format!("{} — {}: no se pudo leer ({e})", p.navegador, p.perfil));
                            continue;
                        }
                    };
                    match fusion::importar_de_navegador(b, &bytes, p.etiqueta_llavero) {
                        Ok(r) => {
                            imp += r.importadas;
                            dup += r.duplicadas;
                            conf += r.conflictos;
                            ileg += r.ilegibles;
                            sd += r.sin_descifrar;
                        }
                        Err(e) => {
                            errores.push(format!("{} — {}: {e:?}", p.navegador, p.perfil));
                        }
                    }
                }
                // Firefox (fase 6): descifra por NSS. La contraseña primaria sale
                // del campo (vacía en el caso común). Se leen los dos archivos.
                let primaria = primaria_ff.text();
                for p in &perfiles_ff {
                    let (Ok(key4), Ok(json)) =
                        (std::fs::read(&p.key4_db), std::fs::read_to_string(&p.logins_json))
                    else {
                        errores.push(format!("Firefox — {}: no se pudieron leer sus archivos", p.perfil));
                        continue;
                    };
                    use chuspa::importar::navegadores::nss::ErrorNss::ContrasenaPrimaria;
                    let mut r = fusion::importar_de_firefox(b, &key4, &json, primaria.as_bytes());
                    // Si el campo va lleno pero ESTE perfil no tiene primaria (otro
                    // sí la tiene), el oráculo la rechaza: se reintenta con la vacía
                    // antes de dar error. Es seguro —`ContrasenaPrimaria` corta ANTES
                    // de importar nada, así que la bóveda no se tocó— y evita un
                    // mensaje que engañaría a ese perfil (concilio, fable obs 1).
                    if matches!(r, Err(fusion::ErrorImportar::Nss(ContrasenaPrimaria))) && !primaria.is_empty()
                    {
                        r = fusion::importar_de_firefox(b, &key4, &json, b"");
                    }
                    match r {
                        Ok(r) => {
                            imp += r.importadas;
                            dup += r.duplicadas;
                            conf += r.conflictos;
                            ileg += r.ilegibles;
                            sd += r.sin_descifrar;
                        }
                        // La primaria equivocada (o ausente cuando el perfil la
                        // tiene) se dice claro, no como un `Debug` cifrado.
                        Err(fusion::ErrorImportar::Nss(ContrasenaPrimaria)) => {
                            errores.push(format!(
                                "Firefox — {}: la contraseña primaria no es correcta (o el perfil tiene una y el campo está vacío)",
                                p.perfil
                            ));
                        }
                        Err(e) => {
                            errores.push(format!("Firefox — {}: {e:?}", p.perfil));
                        }
                    }
                }
                // Persistir SOLO si de verdad entró algo (importadas o conflictos
                // añaden entradas; duplicadas/ilegibles no cambian la bóveda).
                if imp > 0 || conf > 0 {
                    cambio = true;
                    if let Err(e) = b.guardar() {
                        // La verdad: la bóveda EN MEMORIA ya tiene las entradas; lo
                        // que falló es el volcado a disco. Decir «no cambió nada»
                        // sería mentira. Se anota el fallo pero NO se sale aquí: hay
                        // que repoblar la lista igual (que refleje la memoria) antes
                        // de avisar, o la lista mentiría por omisión.
                        fallo_guardar = Some(format!(
                            "Se añadieron {imp} en memoria, pero NO se pudieron guardar en disco: {e}. \
                             Cierra la app sin más cambios para descartarlas, o resuelve el problema \
                             de escritura y reintenta desde cero."
                        ));
                    }
                }
            }

            // Repoblar SIEMPRE que hubo altas, se guardara o no: la lista debe
            // reflejar lo que hay en memoria (D28: la pantalla es el producto).
            if cambio
                && let Some(b) = nucleo.boveda.lock().unwrap().as_ref()
            {
                poblar_lista(&lista, b, &nombres);
            }

            // Un guardado fallido se dice con su verdad y cierra la vía (botón off).
            if let Some(msg) = fallo_guardar {
                resultado.set_text(&msg);
                btn_importar.set_sensitive(false);
                return;
            }

            let mut msg = format!(
                "Añadidas {imp} · ya estaban {dup} · en conflicto {conf} · direcciones ilegibles {ileg} · sin descifrar {sd}."
            );
            if conf > 0 {
                msg.push_str("\nLas «en conflicto» son contraseñas distintas para un sitio que ya tenías: se añadieron como entradas nuevas, revisa cuál conservar.");
            }
            if !errores.is_empty() {
                msg.push_str(&format!("\n\n{} perfil(es) con problema:\n{}", errores.len(), errores.join("\n")));
            }
            resultado.set_text(&msg);
            // Evita una segunda pasada en la misma ventana (los duplicados ya
            // contarían todo como «ya estaban», pero mejor no invitar a ello).
            btn_importar.set_sensitive(false);
        }
    ));

    win.set_child(Some(&caja));
    win.present();
}

fn dialogo_salud(padre: &ApplicationWindow, nucleo: &Nucleo) {
    let informe = {
        let guard = nucleo.boveda.lock().unwrap();
        let Some(b) = guard.as_ref() else {
            return;
        };
        let todas: Vec<Entrada> = (0..b.len()).filter_map(|i| b.abrir_entrada(i).ok()).collect();
        chuspa::salud::revisar(&todas)
    };

    let win = gtk::Window::builder()
        .title("Salud de la bóveda")
        .transient_for(padre)
        .modal(true)
        .default_width(560)
        .default_height(620)
        .build();

    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let resumen = gtk::Label::new(Some(&format!(
        "Revisadas {} · con problemas {} · sin contraseña {}",
        informe.revisadas,
        informe.con_problemas(),
        informe.sin_contrasena,
    )));
    resumen.add_css_class("dim-label");
    resumen.set_xalign(0.0);
    caja.append(&resumen);

    let lista = gtk::Box::new(gtk::Orientation::Vertical, 8);
    if informe.fichas.is_empty() {
        let ok = gtk::Label::new(Some("No se encontraron problemas."));
        ok.add_css_class("title-3");
        ok.set_xalign(0.0);
        ok.set_margin_top(12);
        lista.append(&ok);
    } else {
        let mut fichas = informe.fichas.clone();
        // Lo más urgente primero.
        fichas.sort_by_key(|f| std::cmp::Reverse(f.gravedad()));
        for f in &fichas {
            lista.append(&tarjeta_salud(f));
        }
    }
    let scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&lista)
        .build();
    caja.append(&scroll);

    let cerrar = gtk::Button::with_label("Cerrar");
    cerrar.set_halign(gtk::Align::End);
    cerrar.connect_clicked(glib::clone!(
        #[weak] win,
        move |_| win.close()
    ));
    caja.append(&cerrar);

    win.set_child(Some(&caja));
    win.present();
}

/// La palabra que resume la gravedad de un hallazgo (0–3).
fn palabra_gravedad(g: u8) -> &'static str {
    match g {
        3 => "Urgente",
        2 => "Revisar",
        1 => "Menor",
        _ => "",
    }
}

/// Una tarjeta por entrada con problemas: nombre, gravedad y cada hallazgo.
fn tarjeta_salud(f: &chuspa::salud::Ficha) -> gtk::Frame {
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 4);
    caja.set_margin_top(8);
    caja.set_margin_bottom(8);
    caja.set_margin_start(10);
    caja.set_margin_end(10);

    let cab = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let nombre = gtk::Label::new(Some(&f.nombre));
    nombre.add_css_class("title-4");
    nombre.set_xalign(0.0);
    nombre.set_hexpand(true);
    let grav = gtk::Label::new(Some(palabra_gravedad(f.gravedad())));
    grav.add_css_class(if f.gravedad() >= 3 { "error" } else { "dim-label" });
    cab.append(&nombre);
    cab.append(&grav);
    caja.append(&cab);

    for h in &f.hallazgos {
        let l = gtk::Label::new(Some(&format!("• {}", h.explicacion())));
        l.set_xalign(0.0);
        l.set_wrap(true);
        caja.append(&l);
    }

    let marco = gtk::Frame::new(None);
    marco.set_child(Some(&caja));
    marco
}

/// El texto de un campo de la entrada como cadena (para precargar el formulario).
fn texto_campo(ent: &Entrada, etiqueta: &str) -> String {
    ent.campo(etiqueta)
        .and_then(|c| match &c.valor {
            Valor::Texto(t) => Some(t.clone()),
            Valor::Secreto(s) => Some(s.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Todo el texto de un `TextView` (direcciones, notas).
fn texto_de_vista(tv: &gtk::TextView) -> String {
    let buf = tv.buffer();
    let (ini, fin) = buf.bounds();
    buf.text(&ini, &fin, false).to_string()
}

/// Una fila de formulario: etiqueta pequeña encima del widget.
fn campo_form(etiqueta: &str, w: &impl IsA<gtk::Widget>) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 2);
    let l = gtk::Label::new(Some(etiqueta));
    l.add_css_class("dim-label");
    l.add_css_class("caption");
    l.set_xalign(0.0);
    b.append(&l);
    b.append(w);
    b
}

/// Valores crudos del formulario, ya leídos de los widgets.
#[derive(Default)]
struct Formulario {
    nombre: String,
    usuario: String,
    clave: String,
    quitar_clave: bool,
    totp: String,
    quitar_totp: bool,
    carpeta: String,
    uris: String,
    notas: String,
}

/// Traduce los valores del formulario a `EntradaEntrante`. Separada de los
/// widgets a propósito, para poder probarla sin dibujar la ventana.
///
/// - Los **secretos** (contraseña, segundo factor) pasan por
///   [`chuspa::gui::tres_estados`] —la MISMA regla que la ventana web, no una
///   copia—: vacío o solo-espacios sin «Quitar» → `None` (no tocar); «Quitar» →
///   `Some("")` (borrar); valor real → `Some(v)`; valor real Y «Quitar» a la vez
///   → error. El `trim()` de `tres_estados` es lo que impide que un espacio
///   suelto, invisible en un campo enmascarado, acabe borrando el secreto.
/// - El **resto** (usuario, notas, direcciones, carpeta) se reenvía SIEMPRE como
///   `Some`, porque el formulario sí los precarga; un campo vacío ahí sí
///   significa que se dejó en blanco a propósito.
fn entrada_del_formulario(f: Formulario) -> Result<EntradaEntrante, String> {
    let clave = tres_estados(&f.clave, f.quitar_clave)
        .map_err(|()| "Escribiste una contraseña y marcaste «Quitar» a la vez.".to_string())?;
    let totp = tres_estados(&f.totp, f.quitar_totp)
        .map_err(|()| "Escribiste un segundo factor y marcaste «Quitar» a la vez.".to_string())?;
    Ok(EntradaEntrante {
        nombre: f.nombre,
        usuario: Some(f.usuario),
        clave,
        totp,
        notas: Some(f.notas),
        uris: Some(f.uris),
        carpeta: Some(f.carpeta),
    })
}

/// Valida, fusiona (con `chuspa::gui::construir`) y persiste una entrada. Es el
/// MISMO camino que la ventana web (`gui::guardar_entrada`): la lógica delicada
/// de tres estados vive en `construir`, no aquí, así que sus pruebas guardián la
/// cubren para las dos interfaces.
fn guardar_entrada_gtk(
    boveda: &mut Boveda,
    e: EntradaEntrante,
    indice: Option<usize>,
) -> Result<usize, String> {
    if e.nombre.trim().is_empty() {
        return Err("La entrada necesita un nombre.".to_string());
    }
    // Un secreto TOTP que no se entiende se rechaza AL GUARDAR, no al usarlo.
    if let Some(t) = e.totp.as_deref().filter(|t| !t.trim().is_empty())
        && let Err(err) = chuspa::totp::Totp::interpretar(t)
    {
        return Err(format!("El segundo factor no se pudo interpretar: {err}"));
    }
    // Al editar hay que dar a `construir` la entrada anterior, o pierde lo que la
    // interfaz no maneja (passkeys, campos personalizados, historial, fechas).
    let anterior = indice.and_then(|i| boveda.abrir_entrada(i).ok());
    let entrada = chuspa::gui::construir(e, anterior);
    let idx = match indice {
        Some(i) => boveda.reemplazar(i, entrada).map(|_| i),
        None => boveda.anadir(entrada),
    }
    .map_err(|err| err.to_string())?;
    boveda
        .guardar()
        .map_err(|err| format!("No se pudo guardar en disco: {err}"))?;
    Ok(idx)
}

/// Fase 2: formulario para CREAR (`indice = None`) o EDITAR (`Some(i)`) una
/// entrada. Reproduce la postura de la ventana web:
///
/// - nombre, usuario, notas, direcciones y carpeta se **precargan** y se
///   reenvían tal cual (o corregidos);
/// - los secretos —contraseña y segundo factor— **no se precargan**: dejarlos
///   escritos en un campo de una ventana que se queda abierta es dejarlos a la
///   vista. Un campo de secreto vacío significa «no cambiar» y la casilla
///   «Quitar» significa «borrar» (la regla de tres estados que aplica
///   `construir`).
fn dialogo_entrada(
    padre: &ApplicationWindow,
    nucleo: &Nucleo,
    lista: &gtk::ListBox,
    nombres: &Rc<RefCell<Vec<String>>>,
    indice: Option<usize>,
) {
    let actual: Option<Entrada> = indice
        .and_then(|i| nucleo.boveda.lock().unwrap().as_ref().and_then(|b| b.abrir_entrada(i).ok()));

    let win = gtk::Window::builder()
        .title(if indice.is_some() { "Editar entrada" } else { "Nueva entrada" })
        .transient_for(padre)
        .modal(true)
        .default_width(500)
        .build();

    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let nombre = gtk::Entry::new();
    nombre.set_placeholder_text(Some("Nombre"));
    if let Some(a) = &actual {
        nombre.set_text(&a.nombre);
    }

    let usuario = gtk::Entry::new();
    usuario.set_placeholder_text(Some("Usuario"));
    if let Some(a) = &actual {
        usuario.set_text(&texto_campo(a, "acceso.usuario"));
    }

    // Contraseña: no se precarga. Botón de generar y, en edición, casilla «Quitar».
    let clave = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .hexpand(true)
        .build();
    clave.set_placeholder_text(Some(if indice.is_some() {
        "Contraseña (vacío = no cambiar)"
    } else {
        "Contraseña"
    }));
    let btn_gen = gtk::Button::from_icon_name("dialog-password-symbolic");
    btn_gen.set_tooltip_text(Some("Generar una contraseña"));
    btn_gen.connect_clicked(glib::clone!(
        #[weak] clave,
        move |_| {
            if let Ok(c) = chuspa::generador::contrasena(20, chuspa::generador::Composicion::default()) {
                clave.set_text(c.as_ref());
            }
        }
    ));
    let quitar_clave = gtk::CheckButton::with_label("Quitar");
    let fila_clave = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    fila_clave.append(&clave);
    fila_clave.append(&btn_gen);
    // SIEMPRE en el árbol, aunque solo se VEA al editar. Si solo se añadiera con
    // `indice.is_some()`, al CREAR quedaría huérfano; y como el botón «Guardar» lo
    // captura `#[weak]`, GTK lo suelta al volver de esta función y el `glib::clone!`
    // ya no puede reconstruir ese `#[weak]`, así que OMITE el guardado entero. Era
    // el bug de «una entrada nueva no se guarda» (editar sí, porque ahí estaba en
    // el árbol). Oculto al crear: «Quitar» no significa nada sin nada que quitar.
    fila_clave.append(&quitar_clave);
    quitar_clave.set_visible(indice.is_some());

    // Segundo factor (secreto TOTP): misma regla que la contraseña.
    let totp = gtk::Entry::new();
    totp.set_hexpand(true);
    totp.set_placeholder_text(Some(if indice.is_some() {
        "Secreto del segundo factor (vacío = no cambiar)"
    } else {
        "Secreto del segundo factor (opcional)"
    }));
    let quitar_totp = gtk::CheckButton::with_label("Quitar");
    let fila_totp = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    fila_totp.append(&totp);
    // Siempre en el árbol (ver la nota en `quitar_clave`): un `#[weak]` a un widget
    // huérfano se suelta y el guardado se omite en silencio al crear.
    fila_totp.append(&quitar_totp);
    quitar_totp.set_visible(indice.is_some());

    let carpeta = gtk::Entry::new();
    carpeta.set_placeholder_text(Some("Carpeta (opcional)"));
    if let Some(a) = &actual
        && let Some(c) = &a.carpeta
    {
        carpeta.set_text(c);
    }

    let uris = gtk::TextView::new();
    if let Some(a) = &actual {
        let txt: Vec<&str> = a.uris.iter().map(|u| u.uri.as_str()).collect();
        uris.buffer().set_text(&txt.join("\n"));
    }
    let uris_scroll = gtk::ScrolledWindow::builder()
        .child(&uris)
        .height_request(64)
        .has_frame(true)
        .build();

    let notas = gtk::TextView::new();
    notas.set_wrap_mode(gtk::WrapMode::WordChar);
    if let Some(a) = &actual
        && let Some(n) = &a.notas
    {
        notas.buffer().set_text(n.as_str());
    }
    let notas_scroll = gtk::ScrolledWindow::builder()
        .child(&notas)
        .height_request(64)
        .has_frame(true)
        .build();

    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_xalign(0.0);
    error.set_wrap(true);

    let botones = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    botones.set_halign(gtk::Align::End);
    botones.set_margin_top(6);
    let cancelar = gtk::Button::with_label("Cancelar");
    let guardar = gtk::Button::with_label("Guardar");
    guardar.add_css_class("suggested-action");
    botones.append(&cancelar);
    botones.append(&guardar);

    caja.append(&campo_form("Nombre", &nombre));
    caja.append(&campo_form("Usuario", &usuario));
    caja.append(&campo_form("Contraseña", &fila_clave));
    caja.append(&campo_form("Segundo factor", &fila_totp));
    caja.append(&campo_form("Carpeta", &carpeta));
    caja.append(&campo_form("Direcciones (una por línea)", &uris_scroll));
    caja.append(&campo_form("Notas", &notas_scroll));
    caja.append(&error);
    caja.append(&botones);
    win.set_child(Some(&caja));

    cancelar.connect_clicked(glib::clone!(
        #[weak] win,
        move |_| win.close()
    ));

    guardar.connect_clicked(glib::clone!(
        #[weak] win, #[weak] nombre, #[weak] usuario, #[weak] clave, #[weak] quitar_clave,
        #[weak] totp, #[weak] quitar_totp, #[weak] carpeta, #[weak] error,
        #[weak] lista, #[weak] uris, #[weak] notas,
        #[strong] nucleo, #[strong] nombres,
        move |_| {
            let e = match entrada_del_formulario(Formulario {
                nombre: nombre.text().to_string(),
                usuario: usuario.text().to_string(),
                clave: clave.text().to_string(),
                quitar_clave: quitar_clave.is_active(),
                totp: totp.text().to_string(),
                quitar_totp: quitar_totp.is_active(),
                carpeta: carpeta.text().to_string(),
                uris: texto_de_vista(&uris),
                notas: texto_de_vista(&notas),
            }) {
                Ok(e) => e,
                Err(msg) => {
                    error.set_text(&msg);
                    return;
                }
            };
            let res = {
                let mut guard = nucleo.boveda.lock().unwrap();
                match guard.as_mut() {
                    Some(b) => guardar_entrada_gtk(b, e, indice),
                    None => Err("La bóveda está cerrada.".to_string()),
                }
            };
            match res {
                Ok(idx) => {
                    // Repoblar la lista y reseleccionar: al repoblar se limpia la
                    // selección, así que `select_row` vuelve a emitir
                    // `row-selected` y el detalle se redibuja (también al editar
                    // la fila que ya estaba seleccionada).
                    if let Some(b) = nucleo.boveda.lock().unwrap().as_ref() {
                        poblar_lista(&lista, b, &nombres);
                    }
                    if let Some(fila) = lista.row_at_index(idx as i32) {
                        lista.select_row(Some(&fila));
                    }
                    win.close();
                }
                Err(msg) => error.set_text(&msg),
            }
        }
    ));

    win.present();
}

/// Fase 3: diálogo de autorización de FIRMA (WebAuthn). El agente dejó una
/// petición esperando; aquí se muestran el sitio y el origen que puso el
/// NAVEGADOR (no la página) y las cuentas entre las que elegir. Cerrar sin
/// elegir es un NO: nadie firma sin autorización explícita en la ventana.
fn dialogo_firma(padre: &ApplicationWindow, nucleo: &Nucleo, mostrando: &Rc<Cell<bool>>) {
    // Se leen los datos y se SUELTA el lock antes de dibujar (nada de secretos:
    // la firma pendiente solo lleva el sitio, el origen y los nombres de cuenta).
    let (id, rp_id, origen, candidatas) = {
        let guard = nucleo.firma.lock().unwrap();
        let Some(f) = guard.as_ref().filter(|f| f.elegida.is_none()) else {
            mostrando.set(false);
            return;
        };
        (f.id, f.rp_id.clone(), f.origen.clone(), f.candidatas.clone())
    };

    let win = gtk::Window::builder()
        .title("Autorizar firma")
        .transient_for(padre)
        .modal(true)
        .default_width(460)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let expl = gtk::Label::new(Some(&format!(
        "«{origen}» pide iniciar sesión con una passkey ({rp_id}).\nElige con qué cuenta firmar, o recházalo."
    )));
    expl.set_wrap(true);
    expl.set_xalign(0.0);
    caja.append(&expl);

    // Una decisión ya tomada no debe pisarse con el «rechazar» del cierre.
    let decidido = Rc::new(Cell::new(false));

    for (i, c) in candidatas.iter().enumerate() {
        let etq = match &c.usuario {
            Some(u) if !u.is_empty() => format!("Firmar como {} · {}", c.nombre, u),
            _ => format!("Firmar como {}", c.nombre),
        };
        let btn = gtk::Button::with_label(&etq);
        btn.add_css_class("suggested-action");
        btn.connect_clicked(glib::clone!(
            #[weak] win, #[strong] nucleo, #[strong] decidido,
            move |_| {
                decidido.set(true);
                aplicar_firma(&nucleo, id, Some(i));
                win.close();
            }
        ));
        caja.append(&btn);
    }

    let rechazar = gtk::Button::with_label("Rechazar");
    rechazar.connect_clicked(glib::clone!(
        #[weak] win, #[strong] nucleo, #[strong] decidido,
        move |_| {
            decidido.set(true);
            aplicar_firma(&nucleo, id, None);
            win.close();
        }
    ));
    caja.append(&rechazar);

    // Cerrar la ventana (la X) sin haber decidido es un NO explícito, y suelta
    // el candado del diálogo (`mostrando`).
    win.connect_close_request(glib::clone!(
        #[strong] nucleo, #[strong] mostrando, #[strong] decidido,
        move |_| {
            if !decidido.get() {
                aplicar_firma(&nucleo, id, None);
            }
            mostrando.set(false);
            glib::Propagation::Proceed
        }
    ));

    win.set_child(Some(&caja));
    win.present();
}

/// Aplica la decisión de firma armando el JSON y llamando a la MISMA
/// `chuspa::gui::decidir_firma` que usa la ventana web: la comprobación del `id`
/// (una decisión tardía no vale para la petición siguiente) y la de que la
/// candidata está entre las ofrecidas viven en un solo sitio, no se reimplementan.
fn aplicar_firma(app: &Aplicacion, id: u64, elegida: Option<usize>) {
    app.hay_alguien(); // decidir sobre una firma es una persona delante
    let cuerpo = match elegida {
        Some(i) => format!("{{\"id\":{id},\"elegida\":{i}}}"),
        None => format!("{{\"id\":{id},\"elegida\":null}}"),
    };
    let _ = chuspa::gui::decidir_firma(app, cuerpo.as_bytes());
}

/// El diálogo para autorizar un REGISTRO de passkey. El gemelo de
/// `dialogo_firma`: aquí no se elige cuenta —el sitio pide crear UNA—, así que la
/// decisión es Crear o Rechazar. Cerrar la ventana sin decidir es un NO.
fn dialogo_registro(padre: &ApplicationWindow, nucleo: &Nucleo, mostrando: &Rc<Cell<bool>>) {
    let (id, rp_id, rp_nombre, origen, usuario) = {
        let guard = nucleo.registro.lock().unwrap();
        let Some(r) = guard.as_ref().filter(|r| r.aprobado.is_none()) else {
            mostrando.set(false);
            return;
        };
        (
            r.id,
            r.rp_id.clone(),
            r.rp_nombre.clone(),
            r.origen.clone(),
            r.usuario.clone(),
        )
    };

    let win = gtk::Window::builder()
        .title("Autorizar passkey nueva")
        .transient_for(padre)
        .modal(true)
        .default_width(460)
        .build();
    let caja = gtk::Box::new(gtk::Orientation::Vertical, 10);
    caja.set_margin_top(16);
    caja.set_margin_start(16);
    caja.set_margin_end(16);
    caja.set_margin_bottom(16);

    let sitio = match &rp_nombre {
        Some(n) if !n.is_empty() => format!("{n} ({rp_id})"),
        _ => rp_id.clone(),
    };
    let cuenta = match &usuario {
        Some(u) if !u.is_empty() => format!("\nCuenta: {u}."),
        _ => String::new(),
    };
    let expl = gtk::Label::new(Some(&format!(
        "«{origen}» quiere crear una passkey nueva para {sitio}.{cuenta}\n\
         Se guardará en esta bóveda. Créala solo si eres tú quien está registrándose."
    )));
    expl.set_wrap(true);
    expl.set_xalign(0.0);
    caja.append(&expl);

    let decidido = Rc::new(Cell::new(false));

    let crear = gtk::Button::with_label("Crear la passkey");
    crear.add_css_class("suggested-action");
    crear.connect_clicked(glib::clone!(
        #[weak] win, #[strong] nucleo, #[strong] decidido,
        move |_| {
            decidido.set(true);
            aplicar_registro(&nucleo, id, true);
            win.close();
        }
    ));
    caja.append(&crear);

    let rechazar = gtk::Button::with_label("Rechazar");
    rechazar.connect_clicked(glib::clone!(
        #[weak] win, #[strong] nucleo, #[strong] decidido,
        move |_| {
            decidido.set(true);
            aplicar_registro(&nucleo, id, false);
            win.close();
        }
    ));
    caja.append(&rechazar);

    win.connect_close_request(glib::clone!(
        #[strong] nucleo, #[strong] mostrando, #[strong] decidido,
        move |_| {
            if !decidido.get() {
                aplicar_registro(&nucleo, id, false);
            }
            mostrando.set(false);
            glib::Propagation::Proceed
        }
    ));

    win.set_child(Some(&caja));
    win.present();
}

/// Aplica la decisión de registro por la MISMA `chuspa::gui::decidir_registro`
/// que comprueba el `id`. Autorizar un registro es una persona delante.
fn aplicar_registro(app: &Aplicacion, id: u64, aprobado: bool) {
    app.hay_alguien();
    let cuerpo = format!("{{\"id\":{id},\"aprobado\":{aprobado}}}");
    let _ = chuspa::gui::decidir_registro(app, cuerpo.as_bytes());
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use chuspa::cifrado::{Acceso, Boveda};

    /// Una bóveda de verdad en un archivo temporal, con coste de KDF mínimo.
    fn boveda_temporal(nombre: &str) -> (Boveda, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("chuspa-gtk-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join(format!("{nombre}.chuspa"));
        let _ = std::fs::remove_file(&ruta);
        let params = quipu::kdf::KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 };
        let b = Boveda::crear(&ruta, &Acceso::frase("frase-de-prueba"), params).unwrap();
        (b, ruta)
    }

    fn campo(ent: &Entrada, etq: &str) -> Option<String> {
        ent.campo(etq).and_then(|c| match &c.valor {
            Valor::Texto(t) => Some(t.clone()),
            Valor::Secreto(s) => Some(s.to_string()),
            _ => None,
        })
    }

    /// Fase 3: `aplicar_firma` reusa `decidir_firma`, así que hereda sus
    /// comprobaciones de seguridad. Casos rojos: una decisión con el `id`
    /// equivocado NO firma (una respuesta tardía no vale para la petición
    /// siguiente), y una candidata fuera de rango NO firma con otra cuenta.
    #[test]
    fn aplicar_firma_respeta_id_y_rango() {
        use chuspa::gui::{Candidata, FirmaPendiente};
        let app = Aplicacion::nueva(std::path::PathBuf::from("/tmp/no-existe.chuspa"));
        let poner = || {
            *app.firma.lock().unwrap() = Some(FirmaPendiente {
                id: 7,
                rp_id: "sitio".into(),
                origen: "https://sitio".into(),
                candidatas: vec![Candidata {
                    entrada: 0,
                    passkey: 0,
                    nombre: "cuenta".into(),
                    usuario: None,
                }],
                elegida: None,
            });
        };
        let elegida = || app.firma.lock().unwrap().as_ref().unwrap().elegida;

        // Firmar con la candidata 0.
        poner();
        aplicar_firma(&app, 7, Some(0));
        assert_eq!(elegida(), Some(Some(0)), "firma con la candidata elegida");

        // Rechazar.
        poner();
        aplicar_firma(&app, 7, None);
        assert_eq!(elegida(), Some(None), "rechazo explícito");

        // id equivocado: no decide nada.
        poner();
        aplicar_firma(&app, 999, Some(0));
        assert_eq!(elegida(), None, "una decisión de otra petición no se aplica");

        // Candidata inexistente: no firma con otra cuenta.
        poner();
        aplicar_firma(&app, 7, Some(5));
        assert_eq!(elegida(), None, "una cuenta fuera de rango no se firma");
    }

    #[test]
    fn la_gravedad_tiene_palabra_solo_de_1_a_3() {
        assert_eq!(palabra_gravedad(3), "Urgente");
        assert_eq!(palabra_gravedad(2), "Revisar");
        assert_eq!(palabra_gravedad(1), "Menor");
        assert_eq!(palabra_gravedad(0), "");
    }

    #[test]
    fn el_codigo_totp_se_parte_en_dos_solo_si_son_seis_digitos() {
        assert_eq!(formatear_codigo("123456"), "123 456");
        // Otros largos y lo no numérico se dejan tal cual (nada que partir mal).
        assert_eq!(formatear_codigo("1234567"), "1234567");
        assert_eq!(formatear_codigo("12345"), "12345");
        assert_eq!(formatear_codigo("abcdef"), "abcdef");
        assert_eq!(formatear_codigo(""), "");
    }

    /// La lógica NUEVA de esta pieza: el mapeo del formulario a `EntradaEntrante`.
    /// Casos rojos: un secreto vacío —o de SOLO ESPACIOS— sin «Quitar» tiene que
    /// ser `None` (no tocar), no `""` ni `Some(" ")`, o cada edición que no
    /// reescriba el secreto lo borraría; y valor real + «Quitar» a la vez debe
    /// dar error, no descartar el valor en silencio.
    #[test]
    fn el_formulario_traduce_los_tres_estados() {
        // Todo vacío (como una entrada nueva sin rellenar): los secretos son
        // None (no tocar) y el resto se reenvía como Some(""), nunca None.
        let vacio = entrada_del_formulario(Formulario {
            nombre: "n".into(), ..Default::default()
        }).unwrap();
        assert_eq!(vacio.clave, None, "clave vacía sin quitar = no tocar");
        assert_eq!(vacio.totp, None, "totp vacío sin quitar = no tocar");
        assert_eq!(vacio.usuario, Some(String::new()), "el usuario se reenvía siempre");
        assert_eq!(vacio.carpeta, Some(String::new()), "la carpeta se reenvía siempre");

        // SOLO ESPACIOS sin «Quitar» = no tocar (invisible en un campo enmascarado).
        let espacios = entrada_del_formulario(Formulario {
            nombre: "n".into(), clave: "   ".into(), totp: " ".into(),
            ..Default::default()
        }).unwrap();
        assert_eq!(espacios.clave, None, "clave de solo espacios sin quitar = no tocar");
        assert_eq!(espacios.totp, None, "totp de solo espacios sin quitar = no tocar");

        let con_valor = entrada_del_formulario(Formulario {
            nombre: "n".into(), usuario: "u".into(),
            clave: "secreta".into(), carpeta: "Trabajo".into(),
            ..Default::default()
        }).unwrap();
        assert_eq!(con_valor.clave.as_deref(), Some("secreta"));
        assert_eq!(con_valor.carpeta.as_deref(), Some("Trabajo"));

        let quitando = entrada_del_formulario(Formulario {
            nombre: "n".into(), usuario: "u".into(),
            quitar_clave: true, quitar_totp: true,
            ..Default::default()
        }).unwrap();
        assert_eq!(quitando.clave.as_deref(), Some(""), "quitar = borrar, no no-tocar");
        assert_eq!(quitando.totp.as_deref(), Some(""));

        // Valor real Y «Quitar» a la vez: se rechaza, no se descarta en silencio.
        let contradiccion = entrada_del_formulario(Formulario {
            nombre: "n".into(), clave: "algo".into(), quitar_clave: true,
            ..Default::default()
        });
        assert!(contradiccion.is_err(), "valor + quitar a la vez = error");
    }

    /// Cruza la frontera real (cifrado + disco) por el camino de la app GTK:
    /// crear una entrada con todos sus campos y luego editar SOLO el nombre —los
    /// secretos llegan vacíos porque no se precargan— no puede perder nada.
    #[test]
    fn crear_editar_el_nombre_no_pierde_los_secretos() {
        let (mut b, ruta) = boveda_temporal("ce");
        let totp = "JBSWY3DPEHPK3PXP"; // base32 válido

        let nueva = entrada_del_formulario(Formulario {
            nombre: "Banco".into(), usuario: "juan".into(),
            clave: "clave-secreta".into(), totp: totp.into(),
            carpeta: "Finanzas".into(), uris: "https://banco.example".into(),
            notas: "mi nota".into(), ..Default::default()
        }).unwrap();
        let i = guardar_entrada_gtk(&mut b, nueva, None).expect("crear");

        // Editar SOLO el nombre: secretos vacíos y sin «Quitar» = no tocar.
        let editada = entrada_del_formulario(Formulario {
            nombre: "Banco Nuevo".into(), usuario: "juan".into(),
            carpeta: "Finanzas".into(), uris: "https://banco.example".into(),
            notas: "mi nota".into(), ..Default::default()
        }).unwrap();
        guardar_entrada_gtk(&mut b, editada, Some(i)).expect("editar");

        // Releer del DISCO, no de memoria. Hay que soltar el cerrojo primero: la
        // bóveda no se puede abrir dos veces en el mismo proceso.
        drop(b);
        let b2 = Boveda::abrir(&ruta, &Acceso::frase("frase-de-prueba")).unwrap();
        let ent = b2.abrir_entrada(i).unwrap();
        assert_eq!(ent.nombre, "Banco Nuevo");
        assert_eq!(campo(&ent, "acceso.clave").as_deref(), Some("clave-secreta"), "la contraseña se conservó");
        assert_eq!(campo(&ent, "acceso.totp").as_deref(), Some(totp), "el segundo factor se conservó");
        assert_eq!(ent.carpeta.as_deref(), Some("Finanzas"), "la carpeta se conservó");
        assert_eq!(ent.uris.len(), 1);
        assert_eq!(ent.uris[0].uri, "https://banco.example", "la dirección se conservó");
        assert_eq!(campo(&ent, "acceso.usuario").as_deref(), Some("juan"));
        let _ = std::fs::remove_file(&ruta);
    }

    /// El defecto que cazó el concilio (sonnet + fable, por ejecución): editar
    /// una entrada dejando en el campo del secreto SOLO ESPACIOS —invisible en un
    /// campo enmascarado— no puede borrar el TOTP. Cruza la frontera real; con la
    /// regla vieja (sin `trim`) el TOTP quedaba en `None` sin dejar rastro.
    #[test]
    fn editar_con_secreto_de_solo_espacios_no_lo_borra() {
        let (mut b, ruta) = boveda_temporal("esp");
        let totp = "JBSWY3DPEHPK3PXP";
        let nueva = entrada_del_formulario(Formulario {
            nombre: "Correo".into(), usuario: "u".into(), clave: "c".into(),
            totp: totp.into(), ..Default::default()
        }).unwrap();
        let i = guardar_entrada_gtk(&mut b, nueva, None).unwrap();

        // Editar el nombre dejando un espacio suelto en el campo del segundo factor.
        let editada = entrada_del_formulario(Formulario {
            nombre: "Correo nuevo".into(), usuario: "u".into(), totp: " ".into(),
            ..Default::default()
        }).unwrap();
        guardar_entrada_gtk(&mut b, editada, Some(i)).unwrap();

        drop(b);
        let b2 = Boveda::abrir(&ruta, &Acceso::frase("frase-de-prueba")).unwrap();
        let ent = b2.abrir_entrada(i).unwrap();
        assert_eq!(
            campo(&ent, "acceso.totp").as_deref(),
            Some(totp),
            "un espacio suelto NO borra el segundo factor"
        );
        let _ = std::fs::remove_file(&ruta);
    }

    /// La copia de seguridad cruza la frontera real: se crea, se escribe y se
    /// verifica; y la frase la protege —una frase equivocada NO la abre—.
    #[test]
    fn una_copia_se_crea_verifica_y_la_frase_la_protege() {
        let (mut b, ruta) = boveda_temporal("copia");
        let e = entrada_del_formulario(Formulario {
            nombre: "X".into(), usuario: "u".into(), clave: "c".into(),
            ..Default::default()
        }).unwrap();
        guardar_entrada_gtk(&mut b, e, None).unwrap();

        let dest = ruta.with_extension("copia");
        // crear_copia_verificada verifica releyendo el DISCO: sale Ok con la entrada.
        let f = crear_copia_verificada(&b, "frase-copia", &dest).unwrap();
        assert_eq!(f.entradas, 1, "la copia trae la entrada");

        // La frase protege la copia del disco: otra frase NO la abre.
        let en_disco = std::fs::read(&dest).unwrap();
        assert!(
            chuspa::copia::comprobar(&en_disco, &Acceso::frase("otra")).is_err(),
            "una frase equivocada no abre la copia"
        );
        // Caso rojo del defecto que cazó el concilio: si el archivo del disco se
        // TRUNCA (escritura parcial), la verificación —que lee del disco— falla.
        // Con la versión vieja (verificar los bytes de RAM) esto pasaba por buena.
        std::fs::write(&dest, &en_disco[..en_disco.len() / 2]).unwrap();
        assert!(
            chuspa::copia::comprobar(&std::fs::read(&dest).unwrap(), &Acceso::frase("frase-copia")).is_err(),
            "una copia truncada en disco no verifica (el disco es la fuente de verdad)"
        );

        let _ = std::fs::remove_file(&ruta);
        let _ = std::fs::remove_file(&dest);
    }

    /// Marcar «Quitar» sí borra el secreto —y la contraseña que se retira queda
    /// en el historial, como en la ventana web—.
    #[test]
    fn quitar_la_contrasena_la_borra_y_la_archiva() {
        let (mut b, ruta) = boveda_temporal("q");
        let nueva = entrada_del_formulario(Formulario {
            nombre: "Sitio".into(), usuario: "u".into(), clave: "vieja".into(),
            ..Default::default()
        }).unwrap();
        let i = guardar_entrada_gtk(&mut b, nueva, None).unwrap();

        let quitando = entrada_del_formulario(Formulario {
            nombre: "Sitio".into(), usuario: "u".into(), quitar_clave: true,
            ..Default::default()
        }).unwrap();
        guardar_entrada_gtk(&mut b, quitando, Some(i)).unwrap();

        drop(b); // soltar el cerrojo antes de reabrir
        let b2 = Boveda::abrir(&ruta, &Acceso::frase("frase-de-prueba")).unwrap();
        let ent = b2.abrir_entrada(i).unwrap();
        assert_eq!(campo(&ent, "acceso.clave"), None, "la contraseña se quitó");
        assert!(
            ent.historial.iter().any(|h| h.clave.as_str() == "vieja"),
            "la contraseña quitada quedó en el historial"
        );
        let _ = std::fs::remove_file(&ruta);
    }
}
