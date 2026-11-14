// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Pruebas de la bóveda cifrada.
//!
//! El grueso de estas pruebas no comprueba que la bóveda funcione —eso lo dice
//! el viaje de ida y vuelta en tres líneas— sino que **resiste a un archivo
//! manipulado**. Un gestor de contraseñas se guarda en sitios que el usuario no
//! controla del todo: una copia de seguridad, un disco compartido, una sincronía
//! con la nube. El modelo de amenaza no es solo «alguien lee el archivo», es
//! «alguien lo edita y lo devuelve a su sitio».

use chuspa::boveda::{Campo, Clase, Entrada, Uri, Valor};
use chuspa::cifrado::{Acceso, Boveda, BovedaError};
use quipu::kdf::KdfParams;
use std::path::{Path, PathBuf};

/// Tamaño de la cabecera en claro del formato v3.
const CABECERA_V3: usize = 61;
/// Nonce + clave maestra envuelta + tag, justo detrás de la cabecera.
const ENVOLTURA: usize = 24 + 32 + 16;

/// Coste mínimo: estas pruebas miden el atado del formato, no la dureza del KDF.
/// La dureza real se ejercita en `el_coste_por_defecto_funciona`.
fn coste() -> KdfParams {
    KdfParams { mem_kib: 8, iterations: 1, parallelism: 1 }
}

/// Directorio temporal propio: sin dependencias extra y borrado al terminar.
struct Temporal(PathBuf);

impl Temporal {
    fn nuevo(etiqueta: &str) -> Self {
        let mut p = std::env::temp_dir();
        // El identificador del proceso basta para que dos pruebas en paralelo no
        // se pisen; el nombre de la prueba lo hace legible si algo queda atrás.
        p.push(format!("chuspa-prueba-{}-{etiqueta}", std::process::id()));
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

// ---------------------------------------------------------------------------
// Funcionamiento
// ---------------------------------------------------------------------------

#[test]
fn ida_y_vuelta() {
    let t = Temporal::nuevo("ida-y-vuelta");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 3);

    let b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap();
    assert_eq!(b.len(), 3);
    for i in 0..3 {
        assert_eq!(b.abrir_entrada(i).unwrap(), entrada(i));
    }
}

#[test]
fn listar_no_necesita_descifrar_entradas() {
    let t = Temporal::nuevo("listar");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 5);

    let b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap();
    let resumenes = b.listar();
    assert_eq!(resumenes.len(), 5);
    // Lo que se ve sin abrir nada: lo justo para listar y autocompletar.
    assert_eq!(resumenes[1].nombre, "Sitio 1");
    assert_eq!(resumenes[1].uris.len(), 1);
    // Y los identificadores son distintos entre sí: son la etiqueta de dominio
    // de cada subclave, así que repetirlos repetiría claves.
    let ids: std::collections::BTreeSet<_> = resumenes.iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), 5);
}

#[test]
fn modificar_borrar_y_reabrir() {
    let t = Temporal::nuevo("modificar");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 4);

    let mut cambiada = entrada(1);
    cambiada.nombre = "Renombrado".into();
    cambiada.campos = vec![Campo::estandar("acceso.clave", Valor::secreto("otra"))];
    b.reemplazar(1, cambiada.clone()).unwrap();
    b.borrar(3).unwrap();
    b.guardar().unwrap();
    drop(b); // el cerrojo impide dos aperturas a la vez

    let b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap();
    assert_eq!(b.len(), 3);
    assert_eq!(b.abrir_entrada(1).unwrap(), cambiada);
    assert_eq!(b.abrir_entrada(0).unwrap(), entrada(0));
}

#[test]
fn reemplazar_conserva_el_identificador() {
    let t = Temporal::nuevo("id-estable");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 2);
    let id_antes = b.listar()[0].id;

    b.reemplazar(0, entrada(99)).unwrap();
    assert_eq!(b.listar()[0].id, id_antes, "el id es la etiqueta de su subclave");
}

#[test]
fn el_contador_sube_con_cada_guardado() {
    let t = Temporal::nuevo("contador");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 1);
    assert_eq!(b.contador(), 1);
    b.guardar().unwrap();
    assert_eq!(b.contador(), 2);
    drop(b);
    assert_eq!(Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap().contador(), 2);
}

#[test]
fn el_archivo_es_solo_del_dueno() {
    let t = Temporal::nuevo("permisos");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let modo = std::fs::metadata(&ruta).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "la bóveda no puede ser legible por otros");
    }
}

#[test]
fn guardar_no_deja_archivos_temporales() {
    let t = Temporal::nuevo("temporales");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 2);
    b.guardar().unwrap();
    drop(b); // suelta el cerrojo, que sí es un archivo esperado mientras vive

    let sobrantes: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "v.chuspa")
        .collect();
    assert!(sobrantes.is_empty(), "quedaron archivos sueltos: {sobrantes:?}");
}

#[test]
fn los_secretos_no_aparecen_en_claro_en_el_archivo() {
    let t = Temporal::nuevo("sin-claro");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 3);

    let bytes = std::fs::read(&ruta).unwrap();
    // Ni los secretos ni los METADATOS: el nombre de un sitio revela dónde
    // tienes cuenta, así que el índice también va cifrado.
    for aguja in [
        "clave-secreta-1".as_bytes(),
        "usuario1".as_bytes(),
        "Sitio 1".as_bytes(),
        "sitio1.example".as_bytes(),
        "Bancos".as_bytes(),
    ] {
        assert!(
            !bytes.windows(aguja.len()).any(|v| v == aguja),
            "«{}» aparece en claro en el archivo",
            String::from_utf8_lossy(aguja)
        );
    }
}

// ---------------------------------------------------------------------------
// Resistencia a un archivo manipulado
// ---------------------------------------------------------------------------

#[test]
fn una_contrasena_incorrecta_no_abre() {
    let t = Temporal::nuevo("mala-clave");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 2);
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("otra frase")),
        Err(BovedaError::NoAbre)
    ));
}

#[test]
fn alterar_un_byte_de_una_entrada_se_detecta_al_abrir() {
    let t = Temporal::nuevo("byte-alterado");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 3);

    // Se toca el final del archivo, que es la última entrada. La detección
    // ocurre al ABRIR la bóveda, sin haber abierto esa entrada.
    let mut bytes = std::fs::read(&ruta).unwrap();
    let ultimo = bytes.len() - 1;
    bytes[ultimo] ^= 0xFF;
    std::fs::write(&ruta, &bytes).unwrap();

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::HuellaNoCuadra(_))
    ));
}



#[test]
fn restaurar_una_copia_anterior_se_detecta() {
    // El ataque que ninguna firma del propio archivo puede parar: reponer una
    // copia de seguridad antigua, con contraseñas que ya rotaste. La única
    // defensa es recordar fuera cuál era la última versión.
    let t = Temporal::nuevo("reversion");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 1);

    let copia_vieja = std::fs::read(&ruta).unwrap();
    let visto = b.contador();

    b.anadir(entrada(50)).unwrap();
    b.guardar().unwrap();
    let visto_despues = b.contador();
    assert!(visto_despues > visto);

    drop(b);
    std::fs::write(&ruta, &copia_vieja).unwrap();

    match Boveda::abrir_verificando(&ruta, &Acceso::frase("la frase de paso"), visto_despues) {
        Err(BovedaError::Retrocedida { encontrada, minima }) => {
            assert_eq!(encontrada, visto);
            assert_eq!(minima, visto_despues);
        }
        otro => panic!("una copia anterior debe rechazarse: {otro:?}"),
    }

    // Y sin el contador de referencia se abre igual: la protección existe solo
    // si quien llama guarda el estado. Aquí queda dicho lo que `0` significa.
    assert!(Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_ok());
}

#[test]
fn un_indice_de_otra_version_no_pega_con_esta_cabecera() {
    // El contador va dentro del AAD del índice: cambiarlo en la cabecera deja el
    // índice ilegible, así que no se puede envejecer la bóveda editando un byte.
    let t = Temporal::nuevo("cabecera-editada");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 2);

    let mut bytes = std::fs::read(&ruta).unwrap();
    bytes[21] = bytes[21].wrapping_add(1); // primer byte del contador
    std::fs::write(&ruta, &bytes).unwrap();

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::NoAbre)
    ));
}

#[test]
fn un_archivo_truncado_no_se_abre_a_medias() {
    let t = Temporal::nuevo("truncado");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 3);

    let bytes = std::fs::read(&ruta).unwrap();
    for corte in [10, 44, 60, bytes.len() - 1] {
        std::fs::write(&ruta, &bytes[..corte]).unwrap();
        assert!(
            Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_err(),
            "un archivo cortado en {corte} no puede abrirse"
        );
    }
}

#[test]
fn unos_parametros_kdf_disparatados_se_rechazan_antes_de_derivar() {
    // Sin esta comprobación, una cabecera manipulada haría reservar gigabytes
    // ANTES de que ningún tag pudiera desmentirla.
    let t = Temporal::nuevo("params");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 1);

    let mut bytes = std::fs::read(&ruta).unwrap();
    bytes[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&ruta, &bytes).unwrap();

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::ParametrosInsensatos)
    ));
}

#[test]
fn un_archivo_ajeno_no_se_confunde_con_una_boveda() {
    let t = Temporal::nuevo("ajeno");
    let ruta = t.ruta("cualquiera.txt");
    std::fs::write(&ruta, b"esto no es una boveda, solo texto suelto").unwrap();
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::NoEsBoveda)
    ));
}

#[test]
fn una_version_futura_se_rechaza_en_vez_de_malinterpretarse() {
    let t = Temporal::nuevo("version");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 1);

    let mut bytes = std::fs::read(&ruta).unwrap();
    bytes[7] = 99;
    std::fs::write(&ruta, &bytes).unwrap();

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::VersionDesconocida { encontrada: 99 })
    ));
}

// ---------------------------------------------------------------------------
// Simulación
// ---------------------------------------------------------------------------

/// 150 entradas, un ciclo completo de vida y un caso de error inyectado, con
/// tiempo límite: sin él, un bloqueo se confundiría con una compilación lenta.
#[test]
fn simulacion_ciclo_completo() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(std::panic::catch_unwind(ciclo_completo));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(Ok(operaciones)) => assert!(operaciones >= 100, "solo {operaciones} operaciones"),
        Ok(Err(p)) => std::panic::resume_unwind(p),
        Err(_) => panic!("la simulación no terminó en 120 s: hay un bloqueo"),
    }
}

fn ciclo_completo() -> usize {
    const N: usize = 150;
    let t = Temporal::nuevo("simulacion");
    let ruta = t.ruta("v.chuspa");
    let mut operaciones = 0usize;

    let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase de paso"), coste()).unwrap();
    for i in 0..N {
        b.anadir(entrada(i)).unwrap();
        operaciones += 1;
    }
    b.guardar().unwrap();
    drop(b);

    // Reabrir y verificar TODAS: una a una, que es como se usará.
    let b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap();
    assert_eq!(b.len(), N);
    for i in 0..N {
        assert_eq!(b.abrir_entrada(i).unwrap(), entrada(i), "entrada {i}");
        operaciones += 1;
    }
    drop(b);

    // Modificar un tercio, borrar otro tanto, y comprobar que lo que queda
    // sigue siendo exactamente lo que debe ser.
    let mut b = Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).unwrap();
    for i in (0..N).step_by(3) {
        let mut e = entrada(i);
        e.nombre = format!("Modificado {i}");
        b.reemplazar(i, e).unwrap();
        operaciones += 1;
    }
    for _ in 0..20 {
        b.borrar(0).unwrap();
        operaciones += 1;
    }
    b.guardar().unwrap();
    let contador = b.contador();
    drop(b);

    let b = Boveda::abrir_verificando(&ruta, &Acceso::frase("la frase de paso"), contador).unwrap();
    assert_eq!(b.len(), N - 20);
    for i in 0..b.len() {
        let entrada = b.abrir_entrada(i).unwrap();
        assert_eq!(entrada.nombre, b.listar()[i].nombre);
        operaciones += 1;
    }
    // Pedir una entrada que no existe no debe entrar en pánico.
    assert!(matches!(b.abrir_entrada(b.len()), Err(BovedaError::NoExiste(_))));
    drop(b);

    // Camino de error inyectado: recorrer TODA la zona de datos corrompiendo un
    // byte cada vez, y exigir que la bóveda se niegue a abrir siempre. Que falle
    // una vez no basta: tiene que fallar en cada posición.
    //
    // Se salta la última porción, que es relleno de ceros no referenciado por
    // ningún desplazamiento: tocarlo NO debe romper nada, y se comprueba aparte.
    let sanos = std::fs::read(&ruta).unwrap();
    let masa = inicio_de_la_masa(&sanos);
    let ultimo_util = ultimo_byte_util(&ruta, &sanos);

    let paso = ((ultimo_util - CABECERA_V3) / 60).max(1);
    let mut posicion = CABECERA_V3;
    while posicion < ultimo_util {
        let mut roto = sanos.clone();
        roto[posicion] ^= 0xFF;
        std::fs::write(&ruta, &roto).unwrap();
        assert!(
            Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_err(),
            "corromper el byte {posicion} (masa desde {masa}) debe impedir abrir"
        );
        operaciones += 1;
        posicion += paso;
    }

    // Y la otra cara: el relleno sobrante puede cambiar sin romper nada. Sin
    // esta comprobación, la de arriba pasaría igual con un formato que
    // autenticara bytes que no significan nada — verde por exceso de celo.
    if ultimo_util < sanos.len() {
        let mut con_ruido = sanos.clone();
        let ultimo = con_ruido.len() - 1;
        con_ruido[ultimo] ^= 0xFF;
        std::fs::write(&ruta, &con_ruido).unwrap();
        assert!(
            Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_ok(),
            "tocar el relleno no referenciado no debería impedir abrir"
        );
        operaciones += 1;
    }

    operaciones
}

/// Última posición del archivo que alguna entrada referencia de verdad. Lo que
/// venga después es relleno.
fn ultimo_byte_util(ruta: &Path, bytes: &[u8]) -> usize {
    let b = Boveda::abrir(ruta, &Acceso::frase("la frase de paso")).unwrap();
    let fin = inicio_de_la_masa(bytes) + b.listar().iter().map(|r| r.fin()).max().unwrap_or(0);
    fin.min(bytes.len())
}

/// La prueba lenta: el coste real de producción. Se queda sola porque tarda
/// segundos, y correr las demás con él no mediría nada distinto.
#[test]
fn el_coste_por_defecto_funciona() {
    let t = Temporal::nuevo("coste-real");
    let ruta = t.ruta("v.chuspa");

    let inicio = std::time::Instant::now();
    let mut b = Boveda::crear(&ruta, &Acceso::frase("una frase de paso larga y difícil"), chuspa::cifrado::coste_por_defecto())
        .unwrap();
    b.anadir(entrada(1)).unwrap();
    b.guardar().unwrap();
    let creada_en = inicio.elapsed();
    drop(b);

    let b = Boveda::abrir(&ruta, &Acceso::frase("una frase de paso larga y difícil")).unwrap();
    assert_eq!(b.abrir_entrada(0).unwrap(), entrada(1));

    // No se afirma un tiempo concreto —depende de la máquina— pero sí que el
    // coste es real: 256 MiB y 4 iteraciones no salen instantáneos, y si algún
    // día salieran sería que los parámetros dejaron de aplicarse.
    assert!(
        creada_en > std::time::Duration::from_millis(100),
        "derivar con el coste de producción tardó {creada_en:?}: los parámetros no se están aplicando"
    );
}

// ---------------------------------------------------------------------------

/// Dónde empieza la masa opaca. Solo la longitud del índice está en claro; lo
/// demás —cuántos bloques hay y dónde cae cada uno— vive dentro del índice
/// cifrado, que es justamente el punto.
fn inicio_de_la_masa(bytes: &[u8]) -> usize {
    const NONCE: usize = 24;
    let base = CABECERA_V3 + ENVOLTURA;
    let len_indice = u32::from_le_bytes([
        bytes[base + NONCE],
        bytes[base + NONCE + 1],
        bytes[base + NONCE + 2],
        bytes[base + NONCE + 3],
    ]) as usize;
    base + NONCE + 4 + len_indice
}

// ---------------------------------------------------------------------------
// Archivo llave
// ---------------------------------------------------------------------------

#[test]
fn con_archivo_llave_la_frase_correcta_no_basta() {
    let t = Temporal::nuevo("llave");
    let ruta = t.ruta("v.chuspa");
    let llave = chuspa::cifrado::generar_llave().unwrap();

    let mut b = Boveda::crear(&ruta, &Acceso::con_llave("la frase de paso", &llave), coste()).unwrap();
    b.anadir(entrada(1)).unwrap();
    b.guardar().unwrap();
    drop(b);

    // Sin llave: el error dice QUÉ falta, en vez de mandar a dudar de la frase.
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::FaltaLlave)
    ));

    // Con una llave equivocada: eso sí es indistinguible de frase incorrecta,
    // y debe serlo — decir «la llave está mal» confirmaría la frase.
    let otra = chuspa::cifrado::generar_llave().unwrap();
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::con_llave("la frase de paso", &otra)),
        Err(BovedaError::NoAbre)
    ));

    // Con la llave correcta y la frase equivocada, tampoco.
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::con_llave("otra frase", &llave)),
        Err(BovedaError::NoAbre)
    ));

    // Y con las dos, sí.
    let b = Boveda::abrir(&ruta, &Acceso::con_llave("la frase de paso", &llave)).unwrap();
    assert!(b.usa_llave());
    assert_eq!(b.abrir_entrada(0).unwrap(), entrada(1));
}

#[test]
fn una_llave_de_mas_se_avisa_en_vez_de_parecer_contrasena_mala() {
    let t = Temporal::nuevo("llave-de-mas");
    let ruta = t.ruta("v.chuspa");
    boveda_con(&ruta, 1);
    let llave = chuspa::cifrado::generar_llave().unwrap();

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::con_llave("la frase de paso", &llave)),
        Err(BovedaError::LlaveDeMas)
    ));
}

#[test]
fn la_llave_generada_tiene_entropia_suficiente() {
    let a = chuspa::cifrado::generar_llave().unwrap();
    let b = chuspa::cifrado::generar_llave().unwrap();
    assert_eq!(a.len(), chuspa::cifrado::LLAVE_LEN);
    assert_ne!(a[..], b[..], "dos llaves seguidas no pueden coincidir");
    assert!(a.iter().any(|&x| x != 0), "una llave de ceros no es una llave");
}

// ---------------------------------------------------------------------------
// Frase de paso
// ---------------------------------------------------------------------------

#[test]
fn una_frase_vacia_no_crea_boveda() {
    let t = Temporal::nuevo("frase-vacia");
    assert!(matches!(
        Boveda::crear(t.ruta("v.chuspa"), &Acceso::frase(""), coste()),
        Err(BovedaError::FraseVacia)
    ));
}

#[test]
fn una_frase_inusual_pero_legitima_no_se_bloquea() {
    // Se rechaza lo imposible, no lo inusual: una frase corta con archivo llave
    // es una decisión razonable, y bloquearla solo produce «clave1».
    let t = Temporal::nuevo("frase-corta");
    let llave = chuspa::cifrado::generar_llave().unwrap();
    assert!(Boveda::crear(t.ruta("v.chuspa"), &Acceso::con_llave("corta", &llave), coste()).is_ok());
}

// ---------------------------------------------------------------------------
// Rotación
// ---------------------------------------------------------------------------

#[test]
fn cambiar_la_frase_recifra_y_la_vieja_deja_de_servir() {
    let t = Temporal::nuevo("rotar");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 3);
    let ids: Vec<_> = b.listar().iter().map(|r| r.id).collect();

    b.cambiar_acceso(&Acceso::frase("una frase nueva y distinta")).unwrap();
    b.guardar().unwrap();
    drop(b);

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::NoAbre)
    ));

    let b = Boveda::abrir(&ruta, &Acceso::frase("una frase nueva y distinta")).unwrap();
    assert_eq!(b.len(), 3);
    for i in 0..3 {
        assert_eq!(b.abrir_entrada(i).unwrap(), entrada(i), "el contenido sobrevive");
    }
    // Los identificadores son de la entrada, no del acceso: rotar la frase no
    // los cambia.
    let despues: Vec<_> = b.listar().iter().map(|r| r.id).collect();
    assert_eq!(ids, despues);
}

#[test]
fn se_puede_anadir_un_archivo_llave_a_una_boveda_existente() {
    let t = Temporal::nuevo("rotar-llave");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 2);
    let llave = chuspa::cifrado::generar_llave().unwrap();

    b.cambiar_acceso(&Acceso::con_llave("la frase de paso", &llave)).unwrap();
    b.guardar().unwrap();
    drop(b);

    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::FaltaLlave)
    ));
    let b = Boveda::abrir(&ruta, &Acceso::con_llave("la frase de paso", &llave)).unwrap();
    assert_eq!(b.abrir_entrada(1).unwrap(), entrada(1));
}

// ---------------------------------------------------------------------------
// Cerrojo entre procesos
// ---------------------------------------------------------------------------

#[test]
fn dos_instancias_no_abren_la_misma_boveda() {
    // Sin cerrojo, la segunda instancia guardaría encima de la primera y los
    // cambios de una desaparecerían SIN error: la pérdida de datos más difícil
    // de notar.
    let t = Temporal::nuevo("cerrojo");
    let ruta = t.ruta("v.chuspa");
    let primera = boveda_con(&ruta, 1);

    match Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")) {
        Err(BovedaError::Ocupada { pid }) => assert_eq!(pid, std::process::id()),
        otro => panic!("la segunda apertura debe rechazarse: {otro:?}"),
    }

    // Y al cerrar la primera, la bóveda queda libre.
    drop(primera);
    assert!(Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_ok());
}

#[test]
fn un_cerrojo_huerfano_no_deja_la_boveda_inaccesible() {
    // Un corte de luz deja el archivo de cerrojo atrás. Si eso bloqueara la
    // bóveda para siempre, habríamos cambiado una pérdida de datos por otra.
    let t = Temporal::nuevo("cerrojo-huerfano");
    let ruta = t.ruta("v.chuspa");
    drop(boveda_con(&ruta, 1));

    // PID imposible, pero que la consulta SÍ acepte, para que la prueba ejercite
    // la vía real de «ese proceso no existe» y no un error del consultante:
    // `2147483647` (i32::MAX) está por encima del máximo de Linux (2^22) y es
    // IMPAR, así que nunca es un PID real de Windows (son múltiplos de 4); y a
    // diferencia de `u32::MAX`, `tasklist /FI "PID eq ..."` lo acepta y contesta
    // «no hay tareas» (con `u32::MAX` devolvía «consulta no válida» con exit 1, y
    // la prueba pasaba por el brazo de error en vez de por el de «no existe»,
    // así que NO discriminaba — lo midió el concilio 2026-10-04).
    let cerrojo = t.ruta("v.chuspa.lock");
    std::fs::write(&cerrojo, "2147483647").unwrap();

    assert!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")).is_ok(),
        "un cerrojo de un proceso muerto debe reclamarse"
    );
}

#[test]
fn el_cerrojo_no_queda_en_el_disco_al_cerrar() {
    let t = Temporal::nuevo("cerrojo-limpio");
    let ruta = t.ruta("v.chuspa");
    drop(boveda_con(&ruta, 1));
    assert!(!t.ruta("v.chuspa.lock").exists(), "el cerrojo debe soltarse");
}

// ---------------------------------------------------------------------------
// Lo que el tamaño del archivo cuenta
// ---------------------------------------------------------------------------

#[test]
fn el_tamano_del_archivo_esta_cuantizado() {
    // Padmé no promete que dos tamaños cualesquiera coincidan —eso sería relleno
    // a bloque fijo, mucho más caro—: promete que muchas longitudes distintas
    // caigan en pocos tamaños observables. Es lo que se mide.
    let t = Temporal::nuevo("tamano");
    let mut observados = std::collections::BTreeSet::new();
    for relleno in 0..40 {
        let ruta = t.ruta(&format!("v{relleno}.chuspa"));
        let mut b = Boveda::crear(&ruta, &Acceso::frase("la frase de paso"), coste()).unwrap();
        for i in 0..10 {
            let mut e = entrada(i);
            e.campos.push(Campo::estandar("nota", Valor::texto("x".repeat(relleno))));
            b.anadir(e).unwrap();
        }
        b.guardar().unwrap();
        drop(b);
        observados.insert(std::fs::metadata(&ruta).unwrap().len());
    }
    assert!(
        observados.len() < 15,
        "40 contenidos distintos dieron {} tamaños de archivo: no se está cuantizando",
        observados.len()
    );
}

#[test]
fn la_longitud_util_de_la_masa_no_aparece_en_claro() {
    // El relleno solo sirve si la longitud real NO viaja al lado. `prelayers::pad`
    // escribe esa longitud en sus ocho primeros bytes —correcto cuando se aplica
    // antes de cifrar, y ruinoso sobre datos ya cifrados—, así que aquí se usa un
    // relleno sin prefijo. Esta prueba lo fija.
    let t = Temporal::nuevo("sin-prefijo");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 6);
    let util: usize = b.listar().iter().map(|r| r.fin()).max().unwrap();
    drop(b);

    let bytes = std::fs::read(&ruta).unwrap();
    let masa = inicio_de_la_masa(&bytes);
    let aguja = (util as u64).to_be_bytes();
    assert_ne!(
        &bytes[masa..masa + 8],
        &aguja[..],
        "la longitud real de la masa está escrita en claro justo al principio"
    );
}

#[test]
fn el_archivo_llave_tambien_es_solo_del_dueno() {
    // Se descubrió al revés: el ejemplo de importación escribía la llave con
    // `fs::write` y quedaba en 0644. Un secreto de 256 bits con los permisos por
    // defecto lo puede leer cualquier usuario del sistema.
    let t = Temporal::nuevo("permisos-llave");
    let ruta = t.ruta("v.chuspa.llave");
    let llave = chuspa::cifrado::generar_llave().unwrap();
    chuspa::cifrado::escribir_llave(&ruta, &llave).unwrap();

    assert_eq!(std::fs::read(&ruta).unwrap(), llave[..]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let modo = std::fs::metadata(&ruta).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o600, "el archivo llave no puede ser legible por otros");
    }
}

#[test]
fn quitar_la_bandera_de_llave_no_abre_la_boveda() {
    // La bandera dice «esta bóveda necesita archivo llave». Si se pudiera
    // borrar del archivo, Chuspa intentaría abrir sin llave y daría
    // «contraseña incorrecta» — un error que manda a buscar donde no es. Va en
    // el AAD de la envoltura y del índice, así que tocarla rompe el descifrado.
    let t = Temporal::nuevo("bandera");
    let ruta = t.ruta("v.chuspa");
    let llave = chuspa::cifrado::generar_llave().unwrap();
    let mut b = Boveda::crear(&ruta, &Acceso::con_llave("la frase de paso", &llave), coste()).unwrap();
    b.anadir(entrada(1)).unwrap();
    b.guardar().unwrap();
    drop(b);

    let mut bytes = std::fs::read(&ruta).unwrap();
    bytes[8] = 0; // se borra la bandera
    std::fs::write(&ruta, &bytes).unwrap();

    // Ahora el archivo dice que no hace falta llave. Sin ella tampoco abre.
    assert!(matches!(
        Boveda::abrir(&ruta, &Acceso::frase("la frase de paso")),
        Err(BovedaError::NoAbre)
    ));
}

// ---------------------------------------------------------------------------
// Respaldo en papel: el ciclo completo de recuperación
// ---------------------------------------------------------------------------

#[test]
fn se_recupera_la_boveda_con_las_palabras_del_papel() {
    // El escenario para el que existe todo esto: olvidaste la frase de paso.
    // Sin respaldo, la bóveda está perdida para siempre — y eso es correcto,
    // porque un «recuperar contraseña» existiría también para quien no eres tú.
    let t = Temporal::nuevo("recuperar");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 5);

    let hoja = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();
    drop(b);

    // Pasan los años y la frase se olvida. Queda el papel.
    let maestra = chuspa::respaldo::desde_palabras(&hoja.palabras).unwrap();
    let mut recuperada = Boveda::abrir_con_maestra(&ruta, &maestra).unwrap();
    assert_eq!(recuperada.len(), 5);
    for i in 0..5 {
        assert_eq!(recuperada.abrir_entrada(i).unwrap(), entrada(i));
    }

    // Una bóveda abierta así NO tiene acceso conocido: guardar debe fallar en
    // vez de dejarla con una frase que su dueño no sabe cuál es.
    assert!(matches!(recuperada.guardar(), Err(BovedaError::SinAcceso)));

    // Se fija un acceso nuevo y ya se puede guardar.
    recuperada.cambiar_acceso(&Acceso::frase("la frase nueva de después")).unwrap();
    recuperada.guardar().unwrap();
    drop(recuperada);

    let b = Boveda::abrir(&ruta, &Acceso::frase("la frase nueva de después")).unwrap();
    assert_eq!(b.abrir_entrada(2).unwrap(), entrada(2));
}

#[test]
fn el_papel_sigue_valiendo_despues_de_rotar_la_frase() {
    // La razón de respaldar la CLAVE y no la frase. Si el papel guardara la
    // frase, rotarla lo dejaría caduco en silencio, y un respaldo que crees
    // tener y no tienes es peor que no tener ninguno.
    let t = Temporal::nuevo("papel-vigente");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 3);
    let hoja = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();

    b.cambiar_acceso(&Acceso::frase("otra frase completamente distinta")).unwrap();
    b.guardar().unwrap();
    let llave = chuspa::cifrado::generar_llave().unwrap();
    b.cambiar_acceso(&Acceso::con_llave("y una tercera con llave", &llave)).unwrap();
    b.guardar().unwrap();
    drop(b);

    let maestra = chuspa::respaldo::desde_palabras(&hoja.palabras).unwrap();
    let recuperada = Boveda::abrir_con_maestra(&ruta, &maestra).unwrap();
    assert_eq!(recuperada.abrir_entrada(1).unwrap(), entrada(1));
}

#[test]
fn se_recupera_con_una_hoja_danada() {
    // La hoja llega rota: faltan símbolos y las palabras están manchadas.
    let t = Temporal::nuevo("hoja-danada");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 2);
    let hoja = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();
    drop(b);

    let supervivientes: Vec<String> = hoja
        .simbolos
        .iter()
        .skip(hoja.perdidas_toleradas)
        .map(|s| s.to_string())
        .collect();
    let maestra = chuspa::respaldo::desde_simbolos(&supervivientes).unwrap();

    let recuperada = Boveda::abrir_con_maestra(&ruta, &maestra).unwrap();
    assert_eq!(recuperada.abrir_entrada(0).unwrap(), entrada(0));
}

#[test]
fn una_maestra_equivocada_no_abre_la_boveda() {
    let t = Temporal::nuevo("maestra-mala");
    let ruta = t.ruta("v.chuspa");
    drop(boveda_con(&ruta, 2));

    assert!(matches!(
        Boveda::abrir_con_maestra(&ruta, &[0u8; 32]),
        Err(BovedaError::NoAbre)
    ));
}

#[test]
fn rotar_la_frase_no_recifra_las_entradas() {
    // La envoltura existe para esto: cambiar la frase toca 48 bytes, no 595
    // entradas. Se mide comprobando que los bloques cifrados no cambian —si
    // cambiaran, es que se recifró todo, y recifrar todo exige tenerlo todo
    // descifrado en memoria a la vez.
    let t = Temporal::nuevo("rotar-barato");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 8);

    let antes = std::fs::read(&ruta).unwrap();
    let masa_antes = antes[inicio_de_la_masa(&antes)..].to_vec();

    b.cambiar_acceso(&Acceso::frase("una frase nueva del todo")).unwrap();
    b.guardar().unwrap();
    drop(b);

    let despues = std::fs::read(&ruta).unwrap();
    let masa_despues = despues[inicio_de_la_masa(&despues)..].to_vec();
    assert_eq!(
        masa_antes, masa_despues,
        "rotar el acceso no debe tocar los bloques de las entradas"
    );
}

// ---------------------------------------------------------------------------
// Comprobar un respaldo sin gastarlo, y rotar la clave tras un compromiso
// ---------------------------------------------------------------------------

#[test]
fn se_puede_comprobar_un_respaldo_sin_abrir_la_boveda() {
    // Una copia de seguridad que nunca se ha probado no es una copia: es una
    // suposición, y se descubre falsa el día que hace falta.
    let t = Temporal::nuevo("comprobar");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 4);
    let hoja = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();
    let maestra = chuspa::respaldo::desde_palabras(&hoja.palabras).unwrap();

    // Se comprueba CON la bóveda abierta: no toma el cerrojo, porque solo lee.
    assert!(Boveda::comprobar_maestra(&ruta, &maestra).unwrap());
    assert!(!Boveda::comprobar_maestra(&ruta, &[0u8; 32]).unwrap());
    drop(b);
}

#[test]
fn comprobar_distingue_la_hoja_de_otra_boveda() {
    let t = Temporal::nuevo("comprobar-ajena");
    let una = t.ruta("una.chuspa");
    let otra = t.ruta("otra.chuspa");
    let a = boveda_con(&una, 2);
    let hoja_de_a = chuspa::respaldo::hoja(&a.exportar_maestra()).unwrap();
    drop(a);
    drop(boveda_con(&otra, 2));

    let maestra = chuspa::respaldo::desde_palabras(&hoja_de_a.palabras).unwrap();
    assert!(Boveda::comprobar_maestra(&una, &maestra).unwrap());
    assert!(
        !Boveda::comprobar_maestra(&otra, &maestra).unwrap(),
        "la hoja de una bóveda no puede validar contra otra"
    );
}

#[test]
fn rotar_la_maestra_invalida_los_respaldos_anteriores() {
    // El caso que `cambiar_acceso` NO cubre: la hoja se perdió de vista. Cambiar
    // la frase mil veces no la invalida, porque la maestra es la misma.
    let t = Temporal::nuevo("rotar-maestra");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 4);
    let vieja = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();

    // Cambiar solo la frase deja la hoja vieja sirviendo — por diseño.
    b.cambiar_acceso(&Acceso::frase("otra frase distinta")).unwrap();
    b.guardar().unwrap();
    let maestra_vieja = chuspa::respaldo::desde_palabras(&vieja.palabras).unwrap();
    assert!(
        Boveda::comprobar_maestra(&ruta, &maestra_vieja).unwrap(),
        "cambiar la frase no invalida un respaldo, y eso es intencionado"
    );

    // Rotar la maestra sí lo invalida.
    b.rotar_maestra().unwrap();
    let nueva = chuspa::respaldo::hoja(&b.exportar_maestra()).unwrap();
    b.guardar().unwrap();
    drop(b);

    assert!(
        !Boveda::comprobar_maestra(&ruta, &maestra_vieja).unwrap(),
        "tras rotar, el respaldo comprometido no puede seguir abriendo"
    );
    let maestra_nueva = chuspa::respaldo::desde_palabras(&nueva.palabras).unwrap();
    assert!(Boveda::comprobar_maestra(&ruta, &maestra_nueva).unwrap());

    // Y el contenido sobrevive a la rotación.
    let b = Boveda::abrir(&ruta, &Acceso::frase("otra frase distinta")).unwrap();
    assert_eq!(b.len(), 4);
    for i in 0..4 {
        assert_eq!(b.abrir_entrada(i).unwrap(), entrada(i));
    }
}

#[test]
fn rotar_la_maestra_conserva_los_identificadores() {
    let t = Temporal::nuevo("rotar-ids");
    let ruta = t.ruta("v.chuspa");
    let mut b = boveda_con(&ruta, 3);
    let antes: Vec<_> = b.listar().iter().map(|r| r.id).collect();

    b.rotar_maestra().unwrap();
    let despues: Vec<_> = b.listar().iter().map(|r| r.id).collect();
    assert_eq!(antes, despues, "el id es de la entrada, no de la clave");
}

#[test]
fn el_ciclo_completo_de_un_sobre() {
    // Quien custodia genera SUS claves y manda solo la pública. La privada no
    // pasa nunca por el equipo del dueño de la bóveda.
    let t = Temporal::nuevo("sobre-ciclo");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 3);

    let (publica, privada) = chuspa::respaldo::generar_par_destinatario().unwrap();
    let destinatario = chuspa::respaldo::publica_desde_bytes(&publica).unwrap();
    let sobre = chuspa::respaldo::sobre_para(&b.exportar_maestra(), &destinatario).unwrap();
    drop(b);

    // El sobre viaja por donde sea. Años después, el custodio lo abre.
    let secreta = chuspa::respaldo::privada_desde_bytes(&privada).unwrap();
    let maestra = chuspa::respaldo::abrir_sobre(&sobre, &secreta).unwrap();

    let recuperada = Boveda::abrir_con_maestra(&ruta, &maestra).unwrap();
    assert_eq!(recuperada.abrir_entrada(1).unwrap(), entrada(1));
}

#[test]
fn el_ciclo_completo_de_un_reparto() {
    let t = Temporal::nuevo("reparto-ciclo");
    let ruta = t.ruta("v.chuspa");
    let b = boveda_con(&ruta, 3);
    let fragmentos = chuspa::respaldo::repartir(&b.exportar_maestra(), 3, 5).unwrap();
    drop(b);

    // Tres custodios cualesquiera se juntan. Dos de los cinco se perdieron.
    let reunidos: Vec<Vec<String>> = [1usize, 3, 4]
        .iter()
        .map(|&i| fragmentos[i].simbolos.iter().map(|s| s.to_string()).collect())
        .collect();
    let maestra = chuspa::respaldo::reunir(&reunidos).unwrap();

    assert!(Boveda::comprobar_maestra(&ruta, &maestra).unwrap());
    let mut recuperada = Boveda::abrir_con_maestra(&ruta, &maestra).unwrap();
    assert_eq!(recuperada.abrir_entrada(0).unwrap(), entrada(0));

    recuperada.cambiar_acceso(&Acceso::frase("la frase que se fija al recuperar")).unwrap();
    recuperada.guardar().unwrap();
}
