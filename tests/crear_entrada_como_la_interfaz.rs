// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reproduce el flujo de «Nueva entrada» de las dos interfaces (GTK y web): el
//! formulario → `gui::construir(e, None)` → `boveda.anadir` → `boveda.guardar`, y
//! RELEE del disco para comprobar que la entrada quedó de verdad. El reporte de
//! Juan: al crear una entrada nueva no se guarda.

use chuspa::cifrado::{Acceso, Boveda};
use chuspa::gui::{construir, EntradaEntrante};
use quipu::kdf::KdfParams;

fn coste() -> KdfParams {
    // Barato: esto no mide el KDF, mide que la entrada persista.
    KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
}

#[test]
fn crear_una_entrada_nueva_la_persiste_en_disco() {
    let dir = std::env::temp_dir().join(format!("chuspa-crear-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join("boveda.chuspa");

    let entrante = EntradaEntrante {
        nombre: "GitHub".to_string(),
        usuario: Some("juan".to_string()),
        clave: Some("una-clave-secreta".to_string()),
        totp: None,
        notas: Some("mi nota".to_string()),
        uris: Some("github.com".to_string()),
        carpeta: Some("trabajo".to_string()),
    };

    // Como en la vida real: una bóveda que YA existía (con una entrada), se cierra,
    // y en OTRA sesión se ABRE y se le agrega una entrada nueva. Es el camino de
    // `abrir` (no `crear`), que es donde el reporte de Juan ocurre.
    {
        let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase de paso"), coste()).unwrap();
        b.anadir(construir(
            EntradaEntrante {
                nombre: "vieja".to_string(),
                usuario: Some("u".to_string()),
                clave: Some("c".to_string()),
                totp: None,
                notas: None,
                uris: None,
                carpeta: None,
            },
            None,
        ))
        .unwrap();
        b.guardar().unwrap();
    }
    {
        let mut b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).expect("abrir existente");
        let entrada = construir(entrante, None);
        let idx = b.anadir(entrada).expect("anadir");
        b.guardar().expect("guardar tras abrir");
        assert_eq!(idx, 1);
    }

    // RELEER del disco, como haría reabrir la aplicación.
    let b2 = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).expect("reabrir");
    assert_eq!(b2.len(), 2, "la entrada nueva NO quedó en disco (solo está la vieja)");
    let e = b2.abrir_entrada(1).expect("abrir la entrada");
    assert_eq!(e.nombre, "GitHub");
    assert!(
        e.campo("acceso.clave").is_some(),
        "la contraseña de la entrada nueva no se guardó"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
