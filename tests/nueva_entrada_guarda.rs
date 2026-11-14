// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guardián del bug «una entrada NUEVA no se guarda» (2026-09-23).
//!
//! En `dialogo_entrada` (chuspa-gtk), las casillas «Quitar» de la contraseña y del
//! segundo factor solo tienen sentido al EDITAR. Estaban añadidas al árbol de
//! widgets **solo** cuando `indice.is_some()` (editar). Pero el handler del botón
//! «Guardar» las captura `#[weak]`. Al CREAR (`indice = None`) quedaban huérfanas:
//! al volver de la función nadie las sostenía, GTK las finalizaba, y el
//! `glib::clone!` del guardado —al no poder reconstruir ese `#[weak]`— **omitía el
//! closure entero en silencio**. Resultado: editar guardaba, crear no.
//!
//! Esta prueba reproduce el MECANISMO en GTK real y discrimina (directiva 33): la
//! casilla huérfana omite el guardado; la casilla EN el árbol (el arreglo) lo
//! corre. Necesita un display; si no hay, se salta diciéndolo (no verde falso).
//!
//! Solo compila con la feature `gtk-ui`. Desde que `gtk` pasó a dependencia
//! OPCIONAL (migración a egui, 2026-10-04), el verde por defecto —`egui-ui`, el
//! que compila también en Windows— no trae el crate `gtk`, así que este guardián,
//! que mide la ventana GTK, se excluye del todo salvo cuando se pide esa UI. El
//! mecanismo que vigila es exclusivo de GTK (los `#[weak]` de `glib::clone!`), no
//! tiene equivalente en egui, así que no se pierde cobertura del frontal nuevo.
#![cfg(feature = "gtk-ui")]

use gtk::glib;
use gtk::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

#[test]
fn una_casilla_fuera_del_arbol_no_debe_omitir_el_guardado() {
    if gtk::init().is_err() {
        eprintln!("SALTADA: sin display GTK (esta prueba mide la ventana real)");
        return;
    }

    // ── ANTES (el bug): la casilla NO está en el árbol → se suelta → omite ──
    let corrio_huerfana = Rc::new(Cell::new(false));
    {
        let quitar = gtk::CheckButton::new(); // huérfana, como en modo crear (antes)
        let boton = gtk::Button::new();
        boton.connect_clicked(glib::clone!(
            #[weak]
            quitar,
            #[strong]
            corrio_huerfana,
            move |_| {
                let _ = quitar.is_active();
                corrio_huerfana.set(true);
            }
        ));
        drop(quitar); // como al volver de dialogo_entrada: sin nadie que la sostenga
        boton.emit_clicked();
    }

    // ── DESPUÉS (el arreglo): la casilla SÍ está en el árbol → viva → corre ──
    let corrio_en_arbol = Rc::new(Cell::new(false));
    let fila = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    {
        let quitar = gtk::CheckButton::new();
        fila.append(&quitar); // en el árbol (el arreglo: se añade siempre)
        let boton = gtk::Button::new();
        boton.connect_clicked(glib::clone!(
            #[weak]
            quitar,
            #[strong]
            corrio_en_arbol,
            move |_| {
                let _ = quitar.is_active();
                corrio_en_arbol.set(true);
            }
        ));
        drop(quitar); // la `fila` la mantiene viva
        boton.emit_clicked();
    }

    assert!(
        !corrio_huerfana.get(),
        "CONTROL: una casilla huérfana capturada #[weak] debe hacer que glib omita \
         el closure. Si ESTO corrió, glib ya no suelta huérfanos y el guardián no mide."
    );
    assert!(
        corrio_en_arbol.get(),
        "REGRESIÓN del bug: con la casilla EN el árbol el guardado tiene que ejecutarse. \
         Si falla, alguien volvió a añadir «Quitar» solo al editar."
    );
}
