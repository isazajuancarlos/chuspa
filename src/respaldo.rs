// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Respaldo de la clave maestra en **papel**.
//!
//! # Por qué en papel
//!
//! Una bóveda cifrada bien hecha tiene un problema que no tiene una mal hecha:
//! si olvidas la frase de paso, no hay quien la abra. No hay «recuperar
//! contraseña», y eso es lo correcto —el día que exista, existe también para
//! quien no eres tú—. El precio es que un olvido lo borra todo.
//!
//! El papel es la respuesta: sobrevive a un disco muerto, a un cifrado que ya no
//! se puede leer y a quince años en un cajón. No depende de que exista este
//! programa, ni de que arranque tu equipo.
//!
//! # Qué se respalda, y por qué eso y no otra cosa
//!
//! La **clave maestra**, no la frase de paso. Como la maestra es aleatoria y va
//! envuelta por el acceso (ver [`crate::cifrado`]), un respaldo hecho hoy sigue
//! abriendo la bóveda después de cambiar la frase mil veces. Respaldar la frase
//! daría un papel que caduca en silencio la próxima vez que la rotes, y un
//! respaldo que crees tener y no tienes es peor que no tener ninguno.
//!
//! **Estos 32 bytes SON la bóveda.** Quien tenga el papel la abre sin frase y sin
//! archivo llave. Se guarda como se guarda una escritura, no como se guarda una
//! nota.
//!
//! # Dos caminos en la misma hoja
//!
//! Un respaldo con un solo camino de lectura falla entero por una mancha de café.
//! La hoja lleva dos, independientes:
//!
//! 1. **Veinticuatro palabras BIP-39.** Se transcriben a mano, se leen por
//!    teléfono y se entienden dentro de treinta años sin este programa: la lista
//!    es un estándar público. Llevan suma de verificación, así que una palabra
//!    mal copiada se **detecta** — no se corrige, pero avisa en vez de dar una
//!    clave silenciosamente equivocada.
//! 2. **Símbolos con Reed-Solomon.** Los mismos 32 bytes troceados con
//!    corrección de errores: se pueden perder varios símbolos enteros —un roto,
//!    una esquina quemada, una mancha— y la clave sale igual.
//!
//! Si el café cae sobre las palabras, quedan los símbolos. Si la impresora deja
//! media hoja sin tinta, quedan las palabras. Es la razón de llevar los dos y no
//! el mejor de los dos.

use quipu::kdf;
use quipu_nucleo::papel;
use zeroize::Zeroizing;

/// Cuántos bytes útiles lleva cada símbolo. Con la cabecera de `papel` encima,
/// cada símbolo ocupa este valor más nueve bytes.
const UTILES_POR_SIMBOLO: usize = 16;

/// Paridad Reed-Solomon por bloque. Es el máximo que admite `ecc`, y aquí el
/// coste no importa: se protegen 32 bytes, no un archivo. Lo que se compra con
/// ella es cuántos símbolos se pueden perder.
const PARIDAD: u8 = 128;

/// Pone un símbolo en una sola línea.
///
/// `tecleable::escribir` reparte los grupos en varias líneas, que está bien para
/// un secreto largo y es un desastre para un formato que hay que volver a leer:
/// **una línea = un símbolo** es la regla que hace posible pegar la hoja en un
/// archivo y recuperarla. Sin esto, cada símbolo se parte en dos y el lector cree
/// tener el doble de símbolos, todos rotos.
///
/// Se descubrió con el ensayo de punta a punta, con la suite en verde: las
/// pruebas usaban la API y nunca pasaban por el papel.
fn en_una_linea(texto: &str) -> String {
    texto.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, thiserror::Error)]
pub enum RespaldoError {
    #[error("no se pudo preparar la hoja: {0}")]
    Papel(String),

    #[error(
        "las palabras no reconstruyen una clave: {0}. Si la suma de verificación \
         no cuadra hay una palabra mal transcrita — la BIP-39 detecta el error \
         pero no dice cuál es, así que hay que repasarlas."
    )]
    Palabras(String),

    #[error("el reparto falló: {0}")]
    Reparto(String),

    #[error("el sobre no se pudo cerrar o abrir: {0}")]
    Sobre(String),

    #[error(
        "el respaldo reconstruye {encontrados} bytes y una clave maestra tiene \
         {esperados}: el papel no corresponde a una bóveda de Chuspa"
    )]
    TamanoInesperado { encontrados: usize, esperados: usize },
}

/// La hoja imprimible.
#[derive(Debug)]
pub struct Hoja {
    /// Las 24 palabras BIP-39, separadas por espacios.
    pub palabras: Zeroizing<String>,
    /// Los símbolos con corrección de errores, en base32 tecleable.
    pub simbolos: Vec<Zeroizing<String>>,
    /// Cuántos símbolos se pueden perder y aun así recuperar la clave.
    ///
    /// Es una garantía sobre **cualesquiera** símbolos que falten, no sobre los
    /// que falten con suerte: con las pérdidas repartidas se aguanta bastante
    /// más, pero eso no se puede prometer y por eso no se promete.
    pub perdidas_toleradas: usize,
}

/// Prepara la hoja de respaldo a partir de la clave maestra.
pub fn hoja(maestra: &[u8; kdf::KEY_LEN]) -> Result<Hoja, RespaldoError> {
    let palabras = papel::palabras::escribir(maestra)
        .map_err(|e| RespaldoError::Palabras(e.to_string()))?;

    let trozos = papel::empaquetar(maestra, UTILES_POR_SIMBOLO + papel::CABECERA, PARIDAD)
        .map_err(|e| RespaldoError::Papel(format!("{e:?}")))?;

    let perdidas_toleradas = papel::simbolos_perdidos_tolerados(trozos.len(), PARIDAD);

    let simbolos = trozos
        .iter()
        .map(|t| {
            papel::tecleable::escribir(t, papel::tecleable::Marco::Desnudo)
                .map(|t| Zeroizing::new(en_una_linea(&t)))
                .map_err(|e| RespaldoError::Papel(format!("{e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Hoja {
        palabras: Zeroizing::new(palabras),
        simbolos,
        perdidas_toleradas,
    })
}

/// Extrae los símbolos de un texto pegado tal cual desde la hoja impresa.
///
/// Vive aquí y no en cada programa que la necesite por un motivo que ya costó un
/// fallo: si el ejemplo tuviera su parseo y la prueba el suyo, la prueba estaría
/// comprobando un código que nadie ejecuta. Una sola función, usada por los dos.
///
/// Acepta la numeración de la hoja (`[ 3] AEAAA ...`), la sangría y las líneas
/// de adorno. La regla es **una línea, un símbolo**, y lo que va antes de un `]`
/// es numeración: hay que quitarlo entero, porque el número es alfanumérico y
/// se colaría dentro del símbolo —donde un `1` es ambiguo entre `I` y `L`—.
pub fn simbolos_de_texto(texto: &str) -> Vec<String> {
    texto
        .lines()
        .map(|linea| match linea.split_once(']') {
            Some((_, resto)) => resto.trim(),
            None => linea.trim(),
        })
        // Las líneas de adorno y los títulos no llegan a la longitud de un
        // símbolo; filtrarlas por longitud evita tener que reconocerlas.
        .filter(|l| l.len() > 8 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '='))
        .map(String::from)
        .collect()
}

/// Reconstruye la clave maestra desde las palabras BIP-39.
pub fn desde_palabras(texto: &str) -> Result<Zeroizing<[u8; kdf::KEY_LEN]>, RespaldoError> {
    let bytes =
        papel::palabras::leer(texto).map_err(|e| RespaldoError::Palabras(e.to_string()))?;
    a_clave(&bytes)
}

/// Reconstruye la clave maestra desde los símbolos que se hayan podido leer.
///
/// **No hacen falta todos ni en orden**: cada símbolo dice cuál es, y lo que
/// falte lo pone el Reed-Solomon. Es lo que hace útil el respaldo cuando la hoja
/// llega dañada.
pub fn desde_simbolos(simbolos: &[String]) -> Result<Zeroizing<[u8; kdf::KEY_LEN]>, RespaldoError> {
    let trozos = simbolos
        .iter()
        .map(|s| {
            papel::tecleable::leer(s, papel::tecleable::Marco::Desnudo)
                .map_err(|e| RespaldoError::Papel(format!("{e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let bytes =
        papel::reensamblar(&trozos).map_err(|e| RespaldoError::Papel(format!("{e:?}")))?;
    a_clave(&bytes)
}

fn a_clave(bytes: &[u8]) -> Result<Zeroizing<[u8; kdf::KEY_LEN]>, RespaldoError> {
    if bytes.len() != kdf::KEY_LEN {
        return Err(RespaldoError::TamanoInesperado {
            encontrados: bytes.len(),
            esperados: kdf::KEY_LEN,
        });
    }
    let mut clave = Zeroizing::new([0u8; kdf::KEY_LEN]);
    clave.copy_from_slice(bytes);
    Ok(clave)
}

impl Hoja {
    /// La hoja lista para imprimir.
    ///
    /// El texto lleva las advertencias dentro a propósito. Un papel con una clave
    /// y sin explicación acaba en una carpeta cualquiera, y quien lo encuentre
    /// dentro de diez años —o quien lo herede— no tiene forma de saber que eso
    /// abre todas las contraseñas de alguien.
    pub fn imprimible(&self) -> Zeroizing<String> {
        let mut s = String::new();
        s.push_str("RESPALDO DE BÓVEDA CHUSPA\n");
        s.push_str("=========================\n\n");
        s.push_str(
            "ESTE PAPEL ABRE LA BÓVEDA ENTERA. No hace falta la contraseña ni el\n\
             archivo llave: quien tenga esta hoja tiene todas las credenciales.\n\
             Guárdalo donde guardarías una escritura. Si lo pierdes de vista una\n\
             vez, crea una bóveda nueva.\n\n",
        );
        s.push_str(
            "Sigue valiendo aunque cambies la contraseña: respalda la clave de la\n\
             bóveda, no la contraseña.\n\n",
        );

        s.push_str("── 1. VEINTICUATRO PALABRAS ──────────────────────────────\n\n");
        s.push_str(papel::palabras::instruccion());
        s.push_str("\n\n");
        for (i, palabra) in self.palabras.split_whitespace().enumerate() {
            s.push_str(&format!("{:>3}. {:<12}", i + 1, palabra));
            if (i + 1).is_multiple_of(4) {
                s.push('\n');
            }
        }
        if !self.palabras.split_whitespace().count().is_multiple_of(4) {
            s.push('\n');
        }

        s.push_str("\n── 2. SÍMBOLOS CON CORRECCIÓN DE ERRORES ─────────────────\n\n");
        s.push_str(papel::tecleable::instruccion(papel::tecleable::Marco::Desnudo));
        s.push_str(&format!(
            "\n\nSon {} símbolos y se pueden perder hasta {} sin que la clave se\n\
             pierda: si la hoja se rompe o se mancha, teclea los que queden.\n\n",
            self.simbolos.len(),
            self.perdidas_toleradas
        ));
        for (i, simbolo) in self.simbolos.iter().enumerate() {
            s.push_str(&format!("[{:>2}] {}\n", i + 1, simbolo.as_str()));
        }

        s.push_str(
            "\n──────────────────────────────────────────────────────────\n\
             Cualquiera de las dos secciones basta por sí sola.\n",
        );
        Zeroizing::new(s)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn maestra() -> [u8; kdf::KEY_LEN] {
        // Determinista a propósito: una prueba con clave aleatoria que falle una
        // vez de cada mil es una prueba que se acaba ignorando.
        let mut m = [0u8; kdf::KEY_LEN];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        m
    }

    #[test]
    fn las_palabras_dan_la_vuelta() {
        let h = hoja(&maestra()).unwrap();
        assert_eq!(h.palabras.split_whitespace().count(), 24, "32 bytes son 24 palabras");
        assert_eq!(*desde_palabras(&h.palabras).unwrap(), maestra());
    }

    #[test]
    fn los_simbolos_dan_la_vuelta() {
        let h = hoja(&maestra()).unwrap();
        let todos: Vec<String> = h.simbolos.iter().map(|s| s.to_string()).collect();
        assert_eq!(*desde_simbolos(&todos).unwrap(), maestra());
    }

    #[test]
    fn se_recupera_perdiendo_simbolos() {
        let h = hoja(&maestra()).unwrap();
        assert!(h.perdidas_toleradas >= 1, "un respaldo que no tolera nada no es un respaldo");

        // Se quitan tantos como la hoja promete tolerar, y de los primeros, que
        // son los que llevan la cabecera del corrector y por tanto los frágiles.
        let quedan: Vec<String> = h
            .simbolos
            .iter()
            .skip(h.perdidas_toleradas)
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            *desde_simbolos(&quedan).unwrap(),
            maestra(),
            "perdiendo justo lo prometido debe recuperarse"
        );
    }

    #[test]
    fn el_orden_de_los_simbolos_no_importa() {
        // Quien teclea una hoja rota los introduce como puede.
        let h = hoja(&maestra()).unwrap();
        let mut todos: Vec<String> = h.simbolos.iter().map(|s| s.to_string()).collect();
        todos.reverse();
        assert_eq!(*desde_simbolos(&todos).unwrap(), maestra());
    }

    #[test]
    fn una_palabra_mal_copiada_se_detecta() {
        // Lo que justifica la BIP-39 frente a escribir los bytes en hexadecimal:
        // detecta el error en vez de devolver una clave equivocada.
        let h = hoja(&maestra()).unwrap();
        let mut palabras: Vec<&str> = h.palabras.split_whitespace().collect();
        // Se sustituye por otra palabra VÁLIDA de la lista: el fallo realista no
        // es inventarse una palabra, es confundir dos que existen.
        let sustituta = if palabras[5] == "zebra" { "abandon" } else { "zebra" };
        palabras[5] = sustituta;
        assert!(
            desde_palabras(&palabras.join(" ")).is_err(),
            "una palabra cambiada por otra válida tiene que detectarse"
        );
    }

    #[test]
    fn un_simbolo_corrompido_no_da_una_clave_falsa() {
        let h = hoja(&maestra()).unwrap();
        let mut todos: Vec<String> = h.simbolos.iter().map(|s| s.to_string()).collect();
        // Se destroza el contenido de un símbolo por completo.
        let largo = todos[3].len();
        todos[3] = "A".repeat(largo);
        // Rechazarlo es correcto; aceptarlo solo lo es si el corrector lo arregló.
        // Lo que NO puede pasar es devolver una clave distinta sin decir nada.
        if let Ok(clave) = desde_simbolos(&todos) {
            assert_eq!(
                *clave,
                maestra(),
                "aceptó un símbolo destrozado y devolvió una clave que no es la buena"
            );
        }
    }

    #[test]
    fn la_hoja_avisa_de_lo_que_es() {
        let texto = hoja(&maestra()).unwrap().imprimible();
        assert!(texto.contains("ABRE LA BÓVEDA ENTERA"));
        assert!(texto.contains("aunque cambies la contraseña"));
        // Y las dos secciones están.
        assert!(texto.contains("VEINTICUATRO PALABRAS"));
        assert!(texto.contains("CORRECCIÓN DE ERRORES"));
    }

    #[test]
    fn un_texto_que_no_es_un_respaldo_se_rechaza() {
        assert!(desde_palabras("esto no son palabras bip39 ni de lejos").is_err());
        assert!(desde_simbolos(&["basura".to_string()]).is_err());
        assert!(desde_simbolos(&[]).is_err());
    }
}

// ---------------------------------------------------------------------------
// Reparto entre varios custodios (Shamir k-de-n)
// ---------------------------------------------------------------------------

/// Un fragmento del reparto. Por sí solo **no dice nada** de la clave: con menos
/// de `umbral` fragmentos, todas las claves posibles siguen siendo igual de
/// probables. Eso es secreto perfecto, no «difícil de romper».
#[derive(Debug)]
pub struct Fragmento {
    /// Cuál es, de 1 en adelante. Va impreso para poder pedir «el 2 y el 5».
    pub indice: u8,
    /// Cuántos fragmentos hacen falta para recuperar.
    pub umbral: u8,
    /// El fragmento troceado con corrección de errores, listo para teclear.
    pub simbolos: Vec<Zeroizing<String>>,
    /// Cuántos símbolos de ESTE fragmento se pueden perder.
    pub perdidas_toleradas: usize,
}

/// Reparte la clave maestra en `total` fragmentos, de los que bastan `umbral`.
///
/// # Para qué sirve, y qué problema resuelve que el papel no resuelve
///
/// Una hoja de respaldo tiene dos formas de fallar opuestas: que se pierda —y
/// pierdes la bóveda— o que la encuentre quien no debe —y la pierdes también—.
/// Guardarla en un sitio muy seguro empeora lo primero; hacer copias empeora lo
/// segundo. No hay punto bueno.
///
/// El reparto rompe esa disyuntiva: reparte cinco fragmentos entre cinco sitios
/// o personas, y con tres se recupera. Puedes perder dos sin consecuencias, y
/// quien robe dos no obtiene **nada** — ni la mitad de la clave, ni una pista.
///
/// Es también la respuesta seria a la herencia digital: tres de cinco fragmentos
/// en manos de personas distintas no le dan acceso a ninguna por su cuenta, y se
/// lo dan al conjunto cuando haga falta de verdad.
pub fn repartir(
    maestra: &[u8; kdf::KEY_LEN],
    umbral: u8,
    total: u8,
) -> Result<Vec<Fragmento>, RespaldoError> {
    let partes = quipu::shamir::split(maestra, umbral, total)
        .map_err(|e| RespaldoError::Reparto(format!("{e:?}")))?;

    partes
        .iter()
        .map(|parte| {
            let bytes = parte.to_bytes();
            let trozos = papel::empaquetar(&bytes, UTILES_POR_SIMBOLO + papel::CABECERA, PARIDAD)
                .map_err(|e| RespaldoError::Papel(format!("{e:?}")))?;
            let perdidas_toleradas = papel::simbolos_perdidos_tolerados(trozos.len(), PARIDAD);
            let simbolos = trozos
                .iter()
                .map(|t| {
                    papel::tecleable::escribir(t, papel::tecleable::Marco::Desnudo)
                        .map(|s| Zeroizing::new(en_una_linea(&s)))
                        .map_err(|e| RespaldoError::Papel(format!("{e:?}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Fragmento {
                indice: parte.index(),
                umbral: parte.threshold(),
                simbolos,
                perdidas_toleradas,
            })
        })
        .collect()
}

/// Reúne los fragmentos y devuelve la clave maestra.
///
/// Cada entrada de `fragmentos` son los símbolos de UN fragmento. No hacen falta
/// todos los del reparto —ese es el punto— pero sí al menos `umbral`, y si
/// faltan el error lo dice en vez de devolver una clave que no es.
pub fn reunir(fragmentos: &[Vec<String>]) -> Result<Zeroizing<[u8; kdf::KEY_LEN]>, RespaldoError> {
    if fragmentos.is_empty() {
        return Err(RespaldoError::Reparto("no se dio ningún fragmento".into()));
    }
    let partes = fragmentos
        .iter()
        .map(|simbolos| {
            let trozos = simbolos
                .iter()
                .map(|s| {
                    papel::tecleable::leer(s, papel::tecleable::Marco::Desnudo)
                        .map_err(|e| RespaldoError::Papel(format!("{e:?}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let bytes = papel::reensamblar(&trozos)
                .map_err(|e| RespaldoError::Papel(format!("{e:?}")))?;
            quipu::shamir::Share::from_bytes(&bytes)
                .map_err(|e| RespaldoError::Reparto(format!("{e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let secreto = quipu::shamir::combine(&partes)
        .map_err(|e| RespaldoError::Reparto(format!("{e:?}")))?;
    a_clave(&secreto)
}

// ---------------------------------------------------------------------------
// Sobre para un destinatario
// ---------------------------------------------------------------------------

/// Cifra la clave maestra hacia la clave pública de un destinatario.
///
/// # Esta es la única forma sensata de que el correo intervenga
///
/// La tentación es «que el programa me mande la clave por correo si la pierdo».
/// Eso pone la bóveda entera en manos del proveedor de correo, y encima es
/// circular: la contraseña del correo está DENTRO del gestor, así que el día que
/// haga falta la recuperación tampoco se puede entrar al correo. Si además la
/// cuenta se recupera por SMS, quien custodia las 595 credenciales acaba siendo
/// la operadora móvil.
///
/// Un sobre le da la vuelta: el correo transporta algo que **el correo no puede
/// abrir**. Se cifra hacia la clave pública de quien quieras —tu abogado, tu
/// pareja, otro equipo tuyo— y solo su clave privada lo abre. Puede viajar por
/// Gmail, por WhatsApp o impreso, y ninguno de esos canales ve nada.
///
/// El cifrado es híbrido X25519 + ML-KEM-1024: un sobre guardado hoy sigue
/// cerrado cuando existan ordenadores cuánticos, que es exactamente lo que se le
/// pide a un sobre que puede tardar veinte años en abrirse.
pub fn sobre_para(
    maestra: &[u8; kdf::KEY_LEN],
    destinatario: &quipu::pqhybrid::PublicKey,
) -> Result<Zeroizing<String>, RespaldoError> {
    let dict = quipu::dictionaries::ascii94();
    quipu::api::encode_to_recipient(maestra, destinatario, &dict)
        .map(Zeroizing::new)
        .map_err(|_| RespaldoError::Sobre("no hay entropía del sistema".into()))
}

/// Genera el par de claves de un destinatario.
///
/// Lo ejecuta **quien va a custodiar** el sobre, no quien lo envía: la clave
/// privada no debe pasar nunca por el equipo del dueño de la bóveda. El
/// destinatario se queda su privada y devuelve la pública, que no es secreta y
/// puede viajar por cualquier canal.
///
/// Devuelve `(pública, privada)` ya serializadas, listas para guardar.
pub fn generar_par_destinatario()
-> Result<(Vec<u8>, Zeroizing<Vec<u8>>), RespaldoError> {
    let (publica, secreta) = quipu::pqhybrid::generate_keypair()
        .map_err(|_| RespaldoError::Sobre("no hay entropía del sistema".into()))?;
    Ok((publica.to_bytes(), secreta.to_bytes()))
}

/// Lee una clave pública de destinatario desde sus bytes.
pub fn publica_desde_bytes(b: &[u8]) -> Result<quipu::pqhybrid::PublicKey, RespaldoError> {
    quipu::pqhybrid::PublicKey::from_bytes(b)
        .ok_or_else(|| RespaldoError::Sobre("la clave pública no es válida".into()))
}

/// Lee una clave privada de destinatario desde sus bytes.
pub fn privada_desde_bytes(b: &[u8]) -> Result<quipu::pqhybrid::SecretKey, RespaldoError> {
    quipu::pqhybrid::SecretKey::from_bytes(b)
        .ok_or_else(|| RespaldoError::Sobre("la clave privada no es válida".into()))
}

/// Abre un sobre con la clave privada del destinatario.
pub fn abrir_sobre(
    sobre: &str,
    secreta: &quipu::pqhybrid::SecretKey,
) -> Result<Zeroizing<[u8; kdf::KEY_LEN]>, RespaldoError> {
    let dict = quipu::dictionaries::ascii94();
    let bytes = quipu::api::decode_as_recipient(sobre, secreta, &dict)
        .map_err(|e| RespaldoError::Sobre(format!("{e:?}")))?;
    a_clave(&bytes)
}

#[cfg(test)]
mod pruebas_recuperacion {
    use super::*;

    fn maestra() -> [u8; kdf::KEY_LEN] {
        let mut m = [0u8; kdf::KEY_LEN];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(3);
        }
        m
    }

    fn simbolos_de(f: &Fragmento) -> Vec<String> {
        f.simbolos.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tres_de_cinco_recuperan_la_clave() {
        let fragmentos = repartir(&maestra(), 3, 5).unwrap();
        assert_eq!(fragmentos.len(), 5);
        assert!(fragmentos.iter().all(|f| f.umbral == 3));

        // Cualquier combinación de tres sirve, no solo la primera.
        for combinacion in [[0, 1, 2], [0, 2, 4], [2, 3, 4], [1, 3, 4]] {
            let elegidos: Vec<Vec<String>> = combinacion
                .iter()
                .map(|&i| simbolos_de(&fragmentos[i]))
                .collect();
            assert_eq!(
                *reunir(&elegidos).unwrap(),
                maestra(),
                "la combinación {combinacion:?} debería bastar"
            );
        }
    }

    #[test]
    fn dos_de_cinco_no_recuperan_nada() {
        // Lo que distingue el reparto de partir el papel en trozos: con menos
        // del umbral no se obtiene una clave parcial ni una pista, se obtiene
        // un error. Quien robe dos fragmentos no ha avanzado nada.
        let fragmentos = repartir(&maestra(), 3, 5).unwrap();
        let dos: Vec<Vec<String>> = fragmentos[..2].iter().map(simbolos_de).collect();
        match reunir(&dos) {
            Err(_) => {}
            Ok(clave) => assert_ne!(
                *clave,
                maestra(),
                "dos fragmentos de cinco NO pueden reconstruir la clave"
            ),
        }
    }

    #[test]
    fn un_fragmento_solo_no_se_parece_a_la_clave() {
        // Secreto perfecto: los bytes de un fragmento no guardan relación con
        // los de la clave. Si un fragmento contuviera trozos de la clave en
        // claro, esta prueba lo vería.
        let fragmentos = repartir(&maestra(), 3, 5).unwrap();
        let texto: String = simbolos_de(&fragmentos[0]).concat();
        let clave_hex: String = maestra().iter().map(|b| format!("{b:02X}")).collect();
        assert!(
            !texto.contains(&clave_hex[..16]),
            "un fragmento no puede llevar la clave dentro"
        );
    }

    #[test]
    fn un_fragmento_danado_se_recupera_solo() {
        // Cada fragmento lleva su propio Reed-Solomon: se puede perder parte de
        // UN papel sin tener que ir a buscar otro custodio.
        let fragmentos = repartir(&maestra(), 2, 3).unwrap();
        let elegidos: Vec<Vec<String>> = fragmentos[..2]
            .iter()
            .map(|f| simbolos_de(f).into_iter().skip(f.perdidas_toleradas).collect())
            .collect();
        assert_eq!(*reunir(&elegidos).unwrap(), maestra());
    }

    #[test]
    fn el_reparto_rechaza_configuraciones_imposibles() {
        // Un umbral de 1 no reparte nada: cada fragmento sería la clave entera.
        assert!(repartir(&maestra(), 1, 5).is_err());
        // Y un umbral mayor que el total no se puede alcanzar nunca.
        assert!(repartir(&maestra(), 6, 5).is_err());
    }

    #[test]
    fn reunir_sin_fragmentos_no_entra_en_panico() {
        assert!(reunir(&[]).is_err());
        assert!(reunir(&[vec!["basura".to_string()]]).is_err());
    }

    #[test]
    fn el_sobre_solo_lo_abre_su_destinatario() {
        let (publica, secreta) = quipu::pqhybrid::generate_keypair().unwrap();
        let sobre = sobre_para(&maestra(), &publica).unwrap();

        assert_eq!(*abrir_sobre(&sobre, &secreta).unwrap(), maestra());

        // Otro par de claves no lo abre: el correo que lo transporte tampoco.
        let (_, ajena) = quipu::pqhybrid::generate_keypair().unwrap();
        assert!(abrir_sobre(&sobre, &ajena).is_err());
    }

    #[test]
    fn el_sobre_no_lleva_la_clave_en_claro() {
        let (publica, _) = quipu::pqhybrid::generate_keypair().unwrap();
        let sobre = sobre_para(&maestra(), &publica).unwrap();
        let bytes = sobre.as_bytes();
        // Ninguna ventana del sobre puede coincidir con la clave.
        assert!(
            !bytes.windows(kdf::KEY_LEN).any(|v| v == maestra()),
            "el sobre lleva la clave en claro"
        );
    }

    #[test]
    fn dos_sobres_del_mismo_secreto_son_distintos() {
        // Si dos sobres iguales dieran el mismo texto, comparar dos correos
        // revelaría que llevan lo mismo.
        let (publica, _) = quipu::pqhybrid::generate_keypair().unwrap();
        let uno = sobre_para(&maestra(), &publica).unwrap();
        let otro = sobre_para(&maestra(), &publica).unwrap();
        assert_ne!(*uno, *otro);
    }
}

#[cfg(test)]
mod pruebas_formato {
    use super::*;

    fn maestra() -> [u8; kdf::KEY_LEN] {
        [0x5Au8; kdf::KEY_LEN]
    }

    /// La regla del formato de intercambio: **una línea, un símbolo**.
    ///
    /// Sin ella, pegar la hoja en un archivo y leerla de vuelta produce el doble
    /// de símbolos, todos partidos por la mitad. Es lo que pasó en el primer
    /// ensayo de punta a punta, con la suite entera en verde: ninguna prueba
    /// tocaba el papel, todas hablaban con la API.
    #[test]
    fn ningun_simbolo_lleva_saltos_de_linea() {
        let h = hoja(&maestra()).unwrap();
        for (i, s) in h.simbolos.iter().enumerate() {
            assert!(!s.contains('\n'), "el símbolo {i} de la hoja ocupa varias líneas");
        }
        for f in repartir(&maestra(), 2, 3).unwrap() {
            for (i, s) in f.simbolos.iter().enumerate() {
                assert!(
                    !s.contains('\n'),
                    "el símbolo {i} del fragmento {} ocupa varias líneas",
                    f.indice
                );
            }
        }
    }

    /// El viaje que hace el usuario de verdad: imprimir, pegar en un archivo,
    /// leer línea a línea y recuperar. Es el que falló con todo en verde.
    #[test]
    fn el_viaje_por_el_papel_da_la_vuelta() {
        let h = hoja(&maestra()).unwrap();

        // Como lo escribiría una hoja impresa, con su numeración delante.
        let impreso: String = h
            .simbolos
            .iter()
            .enumerate()
            .map(|(i, s)| format!("[{:>2}] {}\n", i + 1, s.as_str()))
            .collect();

        // Y como lo leería quien recupera: una línea, un símbolo, sin el número.
        let releidos = simbolos_de_texto(&impreso);

        assert_eq!(releidos.len(), h.simbolos.len(), "el número de símbolos cambió al pasar por el papel");
        assert_eq!(*desde_simbolos(&releidos).unwrap(), maestra());
    }

    #[test]
    fn el_viaje_por_el_papel_de_un_reparto_da_la_vuelta() {
        let fragmentos = repartir(&maestra(), 3, 5).unwrap();
        let releer = |f: &Fragmento| -> Vec<String> {
            let impreso: String = f
                .simbolos
                .iter()
                .enumerate()
                .map(|(i, s)| format!("   [{:>2}] {}\n", i + 1, s.as_str()))
                .collect();
            simbolos_de_texto(&impreso)
        };
        let reunidos: Vec<Vec<String>> = fragmentos[1..4].iter().map(releer).collect();
        assert_eq!(*reunir(&reunidos).unwrap(), maestra());
    }
}
