// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Pruebas de la copia de seguridad cifrada y comprimida.
//!
//! Una copia de seguridad se juzga por dos cosas, y ninguna es «se creó sin
//! error»: que **devuelva exactamente lo que se guardó** —si pierde un campo en
//! silencio, el día que haga falta ya no hay dónde mirar— y que **no se abra
//! sin el secreto**, porque una copia vive precisamente en los sitios que su
//! dueño no controla: un USB, un disco compartido, la nube de alguien.
//!
//! Por eso el viaje de ida y vuelta no compara campos escogidos a mano: compara
//! las entradas ENTERAS, y una prueba aparte cuenta que no se cayó ninguna.

use chuspa::boveda::{Campo, Clase, Entrada, Uri, Valor};
use chuspa::cifrado::{Acceso, Boveda};
use chuspa::copia::{self, CopiaError};
use quipu::kdf::KdfParams;
use std::path::{Path, PathBuf};

/// Coste mínimo: aquí se mide el formato de la copia, no la dureza del KDF.
fn coste() -> KdfParams {
    KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
}

struct Temporal(PathBuf);

impl Temporal {
    fn nuevo(etiqueta: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chuspa-copia-{}-{etiqueta}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn ruta(&self, nombre: &str) -> PathBuf {
        self.0.join(nombre)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entrada(n: usize) -> Entrada {
    Entrada {
        id_origen: Some(format!("origen-{n}")),
        nombre: format!("Sitio {n}"),
        clase: if n.is_multiple_of(4) { Clase::Nota } else { Clase::Acceso },
        carpeta: (n.is_multiple_of(3)).then(|| "Bancos".to_string()),
        favorita: n.is_multiple_of(5),
        archivada: None,
        repreguntar: n.is_multiple_of(7),
        notas: (n.is_multiple_of(6)).then(|| zeroize::Zeroizing::new(format!("nota {n}"))),
        campos: vec![
            Campo::estandar("acceso.usuario", Valor::texto(format!("usuario{n}"))),
            Campo::estandar("acceso.clave", Valor::secreto(format!("clave-secreta-{n}"))),
        ],
        uris: vec![Uri { uri: format!("https://sitio{n}.example"), coincidencia: None }],
        historial: Vec::new(),
        creada: None,
        revisada: None,
    }
}

fn boveda_con(ruta: &Path, n: usize) -> Boveda {
    let mut b = Boveda::crear(ruta, &Acceso::frase("la frase de paso"), coste()).unwrap();
    for i in 0..n {
        b.anadir(entrada(i)).unwrap();
    }
    b.guardar().unwrap();
    b
}

/// Todas las entradas de una bóveda, para comparar de verdad.
fn todas(b: &Boveda) -> Vec<Entrada> {
    (0..b.len()).map(|i| b.abrir_entrada(i).unwrap()).collect()
}

// ---------------------------------------------------------------------------
// Que devuelva lo que se guardó
// ---------------------------------------------------------------------------

#[test]
fn lo_que_entra_es_lo_que_sale() {
    let t = Temporal::nuevo("ida-vuelta");
    let origen = boveda_con(&t.ruta("v.chuspa"), 25);
    let antes = todas(&origen);

    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let destino = t.ruta("restaurada.chuspa");
    copia::restaurar(
        &bytes,
        &Acceso::frase("la frase de paso"),
        &destino,
        &Acceso::frase("otra frase distinta"),
    )
    .unwrap();

    // La bóveda restaurada se abre con la frase NUEVA: restaurar no obliga a
    // conservar la del día que se hizo la copia.
    let vuelta = Boveda::abrir(&destino, &Acceso::frase("otra frase distinta")).unwrap();
    let despues = todas(&vuelta);

    assert_eq!(antes.len(), despues.len(), "se perdieron entradas por el camino");
    for (a, d) in antes.iter().zip(despues.iter()) {
        assert_eq!(a, d, "una entrada volvió distinta de como se guardó");
    }
}

#[test]
fn una_boveda_vacia_tambien_se_copia() {
    // El caso de cero es donde se cuelan los `unwrap` de más.
    let t = Temporal::nuevo("vacia");
    let origen = boveda_con(&t.ruta("v.chuspa"), 0);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let ficha = copia::comprobar(&bytes, &Acceso::frase("la frase de paso")).unwrap();
    assert_eq!(ficha.entradas, 0);
}

#[test]
fn ciento_cincuenta_entradas_van_y_vuelven_enteras() {
    let t = Temporal::nuevo("ciento-cincuenta");
    let origen = boveda_con(&t.ruta("v.chuspa"), 150);
    let antes = todas(&origen);

    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let destino = t.ruta("restaurada.chuspa");
    copia::restaurar(
        &bytes,
        &Acceso::frase("la frase de paso"),
        &destino,
        &Acceso::frase("la frase de paso"),
    )
    .unwrap();
    let vuelta = Boveda::abrir(&destino, &Acceso::frase("la frase de paso")).unwrap();

    assert_eq!(todas(&vuelta), antes, "150 entradas no volvieron idénticas");
}

// ---------------------------------------------------------------------------
// Que comprima de verdad
// ---------------------------------------------------------------------------

#[test]
fn comprimir_ahorra_y_el_archivo_cifrado_no_habria_ahorrado_nada() {
    let t = Temporal::nuevo("comprime");
    let ruta = t.ruta("v.chuspa");
    let origen = boveda_con(&ruta, 150);

    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let ficha = copia::comprobar(&bytes, &Acceso::frase("la frase de paso")).unwrap();

    // Con 150 entradas parecidas hay muchísimo que comprimir; se exige poco
    // —un 40 %— para que la prueba no se vuelva una medida del compresor.
    assert!(
        ficha.ahorro() > 40.0,
        "la copia apenas comprimió: {} bytes de {} en claro ({:.0} %)",
        ficha.bytes_archivo,
        ficha.bytes_en_claro,
        ficha.ahorro()
    );

    // Y la razón por la que esto se hace sobre el contenido y no sobre el
    // archivo: la bóveda cifrada es incompresible, así que copiar el `.chuspa`
    // y comprimirlo no habría ahorrado nada.
    let cifrado = std::fs::read(&ruta).unwrap();
    let apretado = miniz_oxide::deflate::compress_to_vec(&cifrado, 9);
    assert!(
        apretado.len() as f64 > cifrado.len() as f64 * 0.98,
        "el archivo cifrado se comprimió un {:.0} %, cuando no debería comprimirse nada",
        (1.0 - apretado.len() as f64 / cifrado.len() as f64) * 100.0
    );

    // Lo que importa en la práctica: la copia ocupa menos que la bóveda.
    assert!(
        bytes.len() < cifrado.len(),
        "la copia ({}) no es más pequeña que la bóveda ({})",
        bytes.len(),
        cifrado.len()
    );
}

// ---------------------------------------------------------------------------
// Que no se abra sin el secreto
// ---------------------------------------------------------------------------

#[test]
fn con_otra_frase_no_se_abre() {
    let t = Temporal::nuevo("otra-frase");
    let origen = boveda_con(&t.ruta("v.chuspa"), 5);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    let r = copia::comprobar(&bytes, &Acceso::frase("la frase de paso "));
    assert!(matches!(r, Err(CopiaError::NoAbre)), "{r:?}");
}

#[test]
fn ningun_secreto_aparece_en_claro_en_la_copia() {
    // Lo que de verdad se le pide a una copia cifrada. Se buscan los valores
    // reales, no una cadena inventada: si el formato dejara de cifrar el
    // contenido, esto lo caza aunque todo lo demás siga funcionando.
    let t = Temporal::nuevo("sin-claros");
    let origen = boveda_con(&t.ruta("v.chuspa"), 30);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    for i in 0..30 {
        for aguja in [
            format!("clave-secreta-{i}"),
            format!("usuario{i}"),
            format!("Sitio {i}"),
            format!("sitio{i}.example"),
        ] {
            assert!(
                !bytes.windows(aguja.len()).any(|v| v == aguja.as_bytes()),
                "«{aguja}» aparece en claro dentro de la copia"
            );
        }
    }
}

#[test]
fn un_byte_cambiado_en_cualquier_parte_la_invalida() {
    let t = Temporal::nuevo("manipulada");
    let origen = boveda_con(&t.ruta("v.chuspa"), 10);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    // Cada posición representa una parte distinta del archivo: la cabecera —que
    // va como AAD y por tanto ata fecha, contador y procedencia—, la envoltura
    // de la maestra, y el contenido.
    let posiciones = [
        (8, "las banderas"),
        (25, "el salt"),
        (40, "el id de la bóveda de origen"),
        (55, "el contador"),
        (63, "la fecha"),
        (75, "el nonce de la envoltura"),
        (130, "la envoltura de la maestra"),
        (bytes.len() - 1, "el último byte del contenido"),
    ];

    for (pos, que) in posiciones {
        let mut roto = bytes.clone();
        roto[pos] ^= 0x01;
        let r = copia::comprobar(&roto, &Acceso::frase("la frase de paso"));
        assert!(
            r.is_err(),
            "cambiar {que} (byte {pos}) no invalidó la copia: se abrió igual"
        );
    }
}

#[test]
fn la_cabecera_ata_el_contenido_por_si_misma() {
    // La prueba de arriba pasa aunque el CONTENIDO no esté atado a la cabecera:
    // cambiar un byte de la cabecera rompe la envoltura de la maestra, que
    // tiene su propio AAD, y el error llega igual. Es un verde por la razón
    // equivocada — comprobado envenenando el AAD del contenido: la otra prueba
    // seguía verde.
    //
    // Por el camino de la maestra no hay envoltura que abrir, así que lo único
    // que puede detectar una cabecera manipulada es el AAD del contenido. Aquí
    // sí queda aislado.
    let t = Temporal::nuevo("aad-contenido");
    let origen = boveda_con(&t.ruta("v.chuspa"), 8);
    let maestra = origen.exportar_maestra();
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    assert!(copia::comprobar_con_maestra(&bytes, &maestra).is_ok(), "la copia buena no abre");

    for (pos, que) in [
        (40, "el id de la bóveda de origen"),
        (55, "el contador"),
        (63, "la fecha"),
    ] {
        let mut roto = bytes.clone();
        roto[pos] ^= 0x01;
        let r = copia::comprobar_con_maestra(&roto, &maestra);
        assert!(
            matches!(r, Err(CopiaError::NoAbre)),
            "con {que} cambiado (byte {pos}) la copia se abrió igual: el contenido \
             no está atado a su cabecera, así que una copia puede mentir sobre de \
             dónde y de cuándo es"
        );
    }
}

#[test]
fn una_copia_truncada_lo_dice_en_vez_de_entrar_en_panico() {
    let t = Temporal::nuevo("truncada");
    let origen = boveda_con(&t.ruta("v.chuspa"), 3);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    for corte in [0, 1, 10, 60, 100, 130] {
        let r = copia::comprobar(&bytes[..corte.min(bytes.len())], &Acceso::frase("la frase de paso"));
        assert!(r.is_err(), "una copia cortada en {corte} bytes se aceptó");
    }
}

#[test]
fn otro_archivo_cualquiera_no_pasa_por_copia() {
    let r = copia::comprobar(b"esto no es una copia de nada", &Acceso::frase("x"));
    assert!(matches!(r, Err(CopiaError::Truncada { .. }) | Err(CopiaError::NoEsCopia)), "{r:?}");

    // Una bóveda NO es una copia, aunque las dos sean archivos de Chuspa.
    let t = Temporal::nuevo("no-es-copia");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 2);
    let boveda = std::fs::read(&ruta).unwrap();
    let r = copia::comprobar(&boveda, &Acceso::frase("la frase de paso"));
    assert!(matches!(r, Err(CopiaError::NoEsCopia)), "{r:?}");
}

// ---------------------------------------------------------------------------
// Que la hoja de papel siga sirviendo
// ---------------------------------------------------------------------------

#[test]
fn la_clave_maestra_abre_la_copia_sin_la_frase() {
    // Es la promesa del respaldo en papel: si olvidas la frase, la hoja abre la
    // bóveda. Sin esto, la copia sería el único sitio donde esa promesa falla.
    let t = Temporal::nuevo("con-maestra");
    let origen = boveda_con(&t.ruta("v.chuspa"), 12);
    let antes = todas(&origen);
    let maestra = origen.exportar_maestra();
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    let ficha = copia::comprobar_con_maestra(&bytes, &maestra).unwrap();
    assert_eq!(ficha.entradas, 12);

    let destino = t.ruta("desde-el-papel.chuspa");
    copia::restaurar_con_maestra(&bytes, &maestra, &destino, &Acceso::frase("frase nueva")).unwrap();
    let vuelta = Boveda::abrir(&destino, &Acceso::frase("frase nueva")).unwrap();
    assert_eq!(todas(&vuelta), antes);
}

#[test]
fn una_maestra_ajena_no_abre_la_copia() {
    let t = Temporal::nuevo("maestra-ajena");
    let origen = boveda_con(&t.ruta("v.chuspa"), 4);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();

    let otra = boveda_con(&t.ruta("otra.chuspa"), 1);
    let r = copia::comprobar_con_maestra(&bytes, &otra.exportar_maestra());
    assert!(matches!(r, Err(CopiaError::NoAbre)), "{r:?}");
}

// ---------------------------------------------------------------------------
// Que restaurar no destruya nada
// ---------------------------------------------------------------------------

#[test]
fn restaurar_no_escribe_encima_de_una_boveda_existente() {
    let t = Temporal::nuevo("no-pisa");
    let ruta = t.ruta("v.chuspa");
    let origen = boveda_con(&ruta, 6);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let antes = std::fs::read(&ruta).unwrap();

    let r = copia::restaurar(
        &bytes,
        &Acceso::frase("la frase de paso"),
        &ruta,
        &Acceso::frase("la frase de paso"),
    );
    assert!(matches!(r, Err(CopiaError::DestinoOcupado(_))), "{r:?}");
    assert_eq!(std::fs::read(&ruta).unwrap(), antes, "tocó la bóveda que ya estaba");
}

#[test]
fn comprobar_no_toca_ningun_archivo() {
    // Comprobar es lo que se hace por defecto, y tiene que poder hacerse mil
    // veces sobre la copia del cajón sin consecuencias.
    let t = Temporal::nuevo("comprobar-inocuo");
    let ruta = t.ruta("v.chuspa");
    let origen = boveda_con(&ruta, 5);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let antes: Vec<_> = std::fs::read_dir(&t.0).unwrap().map(|e| e.unwrap().path()).collect();
    let boveda_antes = std::fs::read(&ruta).unwrap();

    for _ in 0..5 {
        copia::comprobar(&bytes, &Acceso::frase("la frase de paso")).unwrap();
    }

    let despues: Vec<_> = std::fs::read_dir(&t.0).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(antes.len(), despues.len(), "comprobar creó o borró archivos");
    assert_eq!(std::fs::read(&ruta).unwrap(), boveda_antes, "comprobar tocó la bóveda");
}

#[test]
fn la_copia_recuerda_de_donde_vino_y_cuando() {
    let t = Temporal::nuevo("procedencia");
    let origen = boveda_con(&t.ruta("v.chuspa"), 3);
    let bytes = copia::crear(&origen, &Acceso::frase("la frase de paso")).unwrap();
    let ficha = copia::comprobar(&bytes, &Acceso::frase("la frase de paso")).unwrap();

    assert_eq!(ficha.id_boveda, origen.identidad(), "la copia no dice de qué bóveda salió");
    assert_eq!(ficha.contador, origen.contador(), "la copia no guarda el contador de origen");
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        ficha.creada <= ahora && ahora - ficha.creada < 120,
        "la fecha de la copia no es de ahora: {} vs {ahora}",
        ficha.creada
    );
}

#[test]
fn una_copia_con_frase_propia_no_se_abre_con_la_de_la_boveda() {
    // Se puede hacer una copia con una frase distinta —para dársela a otro
    // custodio— sin que eso cambie la bóveda. Y entonces la frase de la bóveda
    // ya no vale para esa copia.
    let t = Temporal::nuevo("frase-propia");
    let origen = boveda_con(&t.ruta("v.chuspa"), 4);
    let bytes = copia::crear(&origen, &Acceso::frase("frase solo de la copia")).unwrap();

    assert!(copia::comprobar(&bytes, &Acceso::frase("frase solo de la copia")).is_ok());
    let r = copia::comprobar(&bytes, &Acceso::frase("la frase de paso"));
    assert!(matches!(r, Err(CopiaError::NoAbre)), "{r:?}");

    // Y la bóveda sigue abriéndose con la suya: hacer una copia no la tocó.
    // Hay que soltarla antes: el cerrojo entre procesos impide abrirla dos
    // veces, y esa es otra salvaguarda que aquí conviene no confundir con un
    // fallo de la copia.
    drop(origen);
    assert!(Boveda::abrir(t.ruta("v.chuspa"), &Acceso::frase("la frase de paso")).is_ok());
}
