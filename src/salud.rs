// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Qué está mal en la bóveda, sin salir a internet.
//!
//! # Por qué no se consulta a nadie
//!
//! Los gestores comerciales comprueban si tus contraseñas aparecen en
//! filtraciones preguntando a un servicio (Have I Been Pwned y similares). Se
//! hace con *k-anonimato* —solo se envían los cinco primeros caracteres del hash—
//! y es un diseño razonable, pero sigue siendo enviar algo derivado de tus
//! contraseñas a un tercero cada vez que abres el informe.
//!
//! Chuspa es offline y no lo hace. Todo lo que hay aquí sale de comparar la
//! bóveda **consigo misma** y de medir lo que se puede medir sin ayuda. Se pierde
//! la detección de filtraciones concretas; se gana no tener que confiar en nadie.
//!
//! # Cómo se evita que el informe sea ruido
//!
//! Una alarma que resulta falsa dos veces es una alarma que a la tercera nadie
//! mira, así que aquí **no hay ninguna categoría abierta**. Cada hallazgo es una
//! afirmación concreta que se puede comprobar:
//!
//! - «esta contraseña está en otras cuatro entradas» — se comprueba contando;
//! - «aunque fuera aleatoria tendría 47 bits» — es aritmética sobre la longitud
//!   y el alfabeto;
//! - «es una secuencia de teclado» — se comprueba mirando el teclado.
//!
//! Lo que **no** se dice nunca es «esta contraseña es fuerte». La medida de
//! entropía es una **cota superior**: supone que la contraseña se eligió al azar.
//! Si la cota ya es baja, es débil con seguridad. Si es alta, solo significa que
//! desde aquí no se puede saber — `contraseñacontraseña` tiene 20 caracteres y no
//! vale nada. Decir «fuerte» sería la mentira más cara que puede contar un
//! gestor.

use crate::boveda::{Entrada, Valor};
use std::collections::HashMap;

/// Un problema concreto de una entrada.
#[derive(Debug, Clone, PartialEq)]
pub enum Hallazgo {
    /// La misma contraseña está en varias entradas. Es el hallazgo más
    /// accionable de todos: si filtran una, caen todas.
    Repetida {
        /// En cuántas entradas aparece, contando esta.
        veces: usize,
    },
    /// La contraseña actual de esta entrada fue la contraseña vieja de otra.
    /// Rotar y volver a lo mismo en otro sitio deja el mismo agujero.
    RecicladaDeOtroHistorial,
    /// Corta incluso suponiendo que se eligió al azar.
    Corta {
        /// Cota SUPERIOR de entropía, en bits.
        bits_maximos: u32,
    },
    /// Sigue un patrón que un atacante prueba primero.
    Patron(Patron),
    /// La entrada tiene una URI `http://`: la contraseña viaja en claro.
    ViajaEnClaro {
        /// El host, para poder buscarlo.
        host: String,
    },
    /// Guarda un secreto TOTP que no se puede interpretar, así que el segundo
    /// factor no funcionará cuando haga falta.
    TotpIlegible,
}

/// Patrones que se comprueban mirando, no adivinando.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Patron {
    /// `qwerty`, `123456`, `asdfgh`: teclas seguidas.
    SecuenciaDeTeclado,
    /// `aaaaaa`, `abcabcabc`: un trozo repetido.
    Repeticion,
    /// `verano2024`, `medellin99`: letras y luego dígitos al final. Es el patrón
    /// que produce una política que exige «al menos un número».
    PalabraConNumerosAlFinal,
}

impl Hallazgo {
    /// De 0 a 3: cuánto urge. Sirve para ordenar el informe, no para asustar.
    pub fn gravedad(&self) -> u8 {
        match self {
            Hallazgo::Repetida { veces } if *veces >= 5 => 3,
            Hallazgo::Repetida { .. } => 2,
            Hallazgo::RecicladaDeOtroHistorial => 2,
            Hallazgo::Corta { bits_maximos } if *bits_maximos < 40 => 3,
            Hallazgo::Corta { .. } => 2,
            Hallazgo::Patron(_) => 3,
            Hallazgo::ViajaEnClaro { .. } => 2,
            Hallazgo::TotpIlegible => 1,
        }
    }

    pub fn explicacion(&self) -> String {
        match self {
            Hallazgo::Repetida { veces } => format!(
                "la misma contraseña está en {veces} entradas; si filtran una, caen todas"
            ),
            Hallazgo::RecicladaDeOtroHistorial => {
                "esta contraseña fue la contraseña ANTERIOR de otra entrada".into()
            }
            Hallazgo::Corta { bits_maximos } => format!(
                "aunque se hubiera elegido al azar tendría como mucho {bits_maximos} bits; \
                 es poco para resistir un ataque con la lista filtrada delante"
            ),
            Hallazgo::Patron(Patron::SecuenciaDeTeclado) => {
                "es una secuencia de teclas seguidas; está en las primeras líneas de \
                 cualquier lista de prueba".into()
            }
            Hallazgo::Patron(Patron::Repeticion) => {
                "es un trozo corto repetido; su entropía real es la del trozo".into()
            }
            Hallazgo::Patron(Patron::PalabraConNumerosAlFinal) => {
                "es una palabra con números al final, que es exactamente lo que produce \
                 una política de «añada un número» y lo primero que se prueba".into()
            }
            Hallazgo::ViajaEnClaro { host } => format!(
                "«{host}» usa http: la contraseña viaja en claro por la red"
            ),
            Hallazgo::TotpIlegible => {
                "el segundo factor guardado no se puede interpretar, así que no dará \
                 código cuando haga falta".into()
            }
        }
    }
}

/// Lo que se ha encontrado en una entrada. **No lleva la contraseña.**
#[derive(Debug, Clone)]
pub struct Ficha {
    /// Posición en la bóveda, para poder abrirla.
    pub indice: usize,
    pub nombre: String,
    pub hallazgos: Vec<Hallazgo>,
}

impl Ficha {
    /// La gravedad de su peor hallazgo.
    pub fn gravedad(&self) -> u8 {
        self.hallazgos.iter().map(|h| h.gravedad()).max().unwrap_or(0)
    }
}

/// El informe completo.
#[derive(Debug, Default)]
pub struct Informe {
    pub fichas: Vec<Ficha>,
    /// Cuántas entradas se revisaron.
    pub revisadas: usize,
    /// Cuántas no tenían contraseña que revisar (notas, tarjetas…).
    pub sin_contrasena: usize,
}

impl Informe {
    pub fn con_problemas(&self) -> usize {
        self.fichas.len()
    }

    /// Cuenta de hallazgos de un tipo, para el resumen.
    pub fn cuantas<F: Fn(&Hallazgo) -> bool>(&self, filtro: F) -> usize {
        self.fichas
            .iter()
            .filter(|f| f.hallazgos.iter().any(&filtro))
            .count()
    }
}

/// Revisa las entradas ya descifradas.
///
/// Recibe las entradas y no la bóveda porque revisarlas exige abrirlas todas, y
/// esa decisión —tener las 595 en claro en memoria a la vez— la toma quien
/// llama, a la vista. Esconderla dentro de una función que «solo hace un
/// informe» sería justo el tipo de cosa que este proyecto evita.
pub fn revisar(entradas: &[Entrada]) -> Informe {
    let mut informe = Informe { revisadas: entradas.len(), ..Default::default() };

    // Índice de contraseñas actuales → cuántas veces aparece.
    let mut cuentas: HashMap<&str, usize> = HashMap::new();
    for e in entradas {
        if let Some(c) = clave_de(e) {
            *cuentas.entry(c).or_insert(0) += 1;
        }
    }
    // Índice de contraseñas ANTIGUAS de cada entrada.
    let mut historicas: HashMap<&str, usize> = HashMap::new();
    for (i, e) in entradas.iter().enumerate() {
        for vieja in &e.historial {
            historicas.entry(vieja.clave.as_str()).or_insert(i);
        }
    }

    for (indice, entrada) in entradas.iter().enumerate() {
        let mut hallazgos = Vec::new();

        // Las URI en claro se miran aunque no haya contraseña: una nota con
        // credenciales en un sitio http también expone algo.
        for uri in &entrada.uris {
            if let Some(host) = host_http(&uri.uri) {
                hallazgos.push(Hallazgo::ViajaEnClaro { host });
                break; // una vez por entrada; repetirlo por URI sería ruido
            }
        }
        if let Some(t) = texto(entrada, "acceso.totp")
            && crate::totp::Totp::interpretar(t).is_err()
        {
            hallazgos.push(Hallazgo::TotpIlegible);
        }

        match clave_de(entrada) {
            None => {
                informe.sin_contrasena += 1;
            }
            Some(clave) => {
                if let Some(&veces) = cuentas.get(clave)
                    && veces > 1
                {
                    hallazgos.push(Hallazgo::Repetida { veces });
                }
                // Que la clave actual esté en el historial de OTRA entrada.
                if let Some(&duena) = historicas.get(clave)
                    && duena != indice
                {
                    hallazgos.push(Hallazgo::RecicladaDeOtroHistorial);
                }
                let bits = cota_de_entropia(clave);
                if bits < 60 {
                    hallazgos.push(Hallazgo::Corta { bits_maximos: bits });
                }
                if let Some(p) = patron_de(clave) {
                    hallazgos.push(Hallazgo::Patron(p));
                }
            }
        }

        if !hallazgos.is_empty() {
            hallazgos.sort_by_key(|h| std::cmp::Reverse(h.gravedad()));
            informe.fichas.push(Ficha {
                indice,
                nombre: entrada.nombre.clone(),
                hallazgos,
            });
        }
    }

    informe.fichas.sort_by_key(|f| std::cmp::Reverse(f.gravedad()));
    informe
}

fn texto<'a>(entrada: &'a Entrada, etiqueta: &str) -> Option<&'a str> {
    entrada.campo(etiqueta).and_then(|c| match &c.valor {
        Valor::Texto(t) => Some(t.as_str()),
        Valor::Secreto(s) => Some(s.as_str()),
        _ => None,
    })
}

fn clave_de(entrada: &Entrada) -> Option<&str> {
    texto(entrada, "acceso.clave").filter(|c| !c.is_empty())
}

fn host_http(uri: &str) -> Option<String> {
    let d = crate::navegador::coincidencia::Direccion::analizar(uri)?;
    // Solo `http`. Un `ftp` o un esquema de aplicación no dicen nada sobre si
    // la contraseña viaja en claro, y marcarlos sería inventar una categoría.
    (d.esquema == "http").then_some(d.host)
}

/// Cota **superior** de entropía en bits: `longitud × log2(alfabeto)`.
///
/// Supone que cada carácter se eligió al azar dentro del alfabeto observado, que
/// es lo mejor que le puede pasar a una contraseña. Por eso solo sirve para
/// decir «esto es poco»: nunca para decir que algo es suficiente.
pub fn cota_de_entropia(clave: &str) -> u32 {
    let (mut min, mut may, mut dig, mut otros) = (false, false, false, false);
    for c in clave.chars() {
        if c.is_ascii_lowercase() {
            min = true;
        } else if c.is_ascii_uppercase() {
            may = true;
        } else if c.is_ascii_digit() {
            dig = true;
        } else {
            otros = true;
        }
    }
    let alfabeto = (if min { 26 } else { 0 })
        + (if may { 26 } else { 0 })
        + (if dig { 10 } else { 0 })
        // Los símbolos imprimibles de ASCII son 33; para el resto de Unicode se
        // usa el mismo número en vez de una cifra enorme, porque quien mete un
        // emoji no está eligiendo entre un millón de puntos de código al azar.
        + (if otros { 33 } else { 0 });

    if alfabeto == 0 {
        return 0;
    }
    let bits_por_caracter = (alfabeto as f64).log2();
    (clave.chars().count() as f64 * bits_por_caracter) as u32
}

/// Patrones comprobables. Ninguno es «parece débil»: cada uno se verifica.
fn patron_de(clave: &str) -> Option<Patron> {
    let minusculas = clave.to_lowercase();

    // 1. Secuencia de teclado o de dígitos, en cualquier sentido.
    //
    // La secuencia tiene que DOMINAR la contraseña, no solo aparecer en ella.
    // La primera versión marcaba cualquier coincidencia de cuatro caracteres, y
    // eso convertía en «débil» a una frase BIP-39 perfectamente sólida: las
    // palabras `liberty`, `poverty` y `property` contienen «erty», de `qwerty`.
    //
    // El arreglo va en la REGLA y no en una lista de excepciones para esas tres
    // palabras: lo que hace débil a `qwerty` es que la secuencia ES la
    // contraseña entera, no que la contenga. Con un umbral de la mitad,
    // `qwerty123` sigue cayendo y `poverty-caballo-grapa` no.
    const FILAS: &[&str] = &[
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz",
    ];
    let largo_clave = minusculas.chars().count();
    if largo_clave >= 4 {
        let mut mayor = 0;
        for fila in FILAS {
            let invertida: String = fila.chars().rev().collect();
            for ventana in [*fila, invertida.as_str()] {
                mayor = mayor.max(secuencia_mas_larga(ventana, &minusculas));
            }
        }
        if mayor >= 4 && mayor * 2 >= largo_clave {
            return Some(Patron::SecuenciaDeTeclado);
        }
    }

    // 2. Un trozo repetido que ocupa toda la contraseña.
    let n = clave.chars().count();
    if n >= 4 {
        let caracteres: Vec<char> = clave.chars().collect();
        for largo in 1..=n / 2 {
            if n.is_multiple_of(largo) && caracteres.chunks(largo).all(|t| t == &caracteres[..largo]) {
                return Some(Patron::Repeticion);
            }
        }
    }

    // 3. Letras y después dígitos, y nada más. `verano2024`, no `a1b2c3`.
    let letras: String = minusculas.chars().take_while(|c| c.is_alphabetic()).collect();
    let resto: String = minusculas.chars().skip(letras.chars().count()).collect();
    if letras.chars().count() >= 3
        && !resto.is_empty()
        && resto.chars().all(|c| c.is_ascii_digit())
    {
        return Some(Patron::PalabraConNumerosAlFinal);
    }

    None
}

/// La subcadena más larga de `fuente` que aparece en `clave`, en caracteres.
fn secuencia_mas_larga(fuente: &str, clave: &str) -> usize {
    let f: Vec<char> = fuente.chars().collect();
    let mut mayor = 0;
    for inicio in 0..f.len() {
        for largo in (1..=f.len() - inicio).rev() {
            if largo <= mayor {
                break;
            }
            let trozo: String = f[inicio..inicio + largo].iter().collect();
            if clave.contains(&trozo) {
                mayor = largo;
                break;
            }
        }
    }
    mayor
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::boveda::{Campo, Clase, ClaveAnterior, Uri};
    use zeroize::Zeroizing;

    fn entrada(nombre: &str, clave: &str) -> Entrada {
        Entrada {
            id_origen: None,
            nombre: nombre.into(),
            clase: Clase::Acceso,
            carpeta: None,
            favorita: false,
            archivada: None,
            repreguntar: false,
            notas: None,
            campos: vec![Campo::estandar("acceso.clave", Valor::secreto(clave))],
            uris: Vec::new(),
            historial: Vec::new(),
            creada: None,
            revisada: None,
        }
    }

    #[test]
    fn las_repetidas_se_cuentan_y_se_marcan_todas() {
        let e = vec![
            entrada("A", "Tr0ub4dor&3xyzQ!p"),
            entrada("B", "Tr0ub4dor&3xyzQ!p"),
            entrada("C", "otra-distinta-larga-y-rara#9Z"),
        ];
        let i = revisar(&e);
        let repetidas: Vec<_> = i
            .fichas
            .iter()
            .filter(|f| f.hallazgos.contains(&Hallazgo::Repetida { veces: 2 }))
            .map(|f| f.nombre.clone())
            .collect();
        assert_eq!(repetidas.len(), 2, "las DOS entradas se marcan, no solo la segunda");
        assert!(repetidas.contains(&"A".to_string()) && repetidas.contains(&"B".to_string()));
    }

    #[test]
    fn el_informe_no_lleva_ninguna_contrasena() {
        // Un informe que imprima las contraseñas para «ayudar» es una filtración
        // con buenas intenciones.
        let e = vec![entrada("A", "secreto-inconfundible-123"), entrada("B", "qwerty")];
        let i = revisar(&e);
        let texto = format!("{i:?}")
            + &i.fichas.iter().flat_map(|f| f.hallazgos.iter().map(|h| h.explicacion())).collect::<String>();
        assert!(!texto.contains("secreto-inconfundible"));
        assert!(!texto.contains("qwerty"));
    }

    #[test]
    fn la_entropia_es_una_cota_superior_no_una_promesa() {
        // Una contraseña larga y pésima NO se marca como corta, y eso es
        // correcto: la medida no sabe que es una palabra repetida. Lo que sí la
        // caza es el patrón.
        let bits = cota_de_entropia("contrasenacontrasena");
        assert!(bits >= 60, "20 caracteres en minúsculas superan la cota de corta");
        assert_eq!(patron_de("contrasenacontrasena"), Some(Patron::Repeticion));

        // Y una corta se marca aunque tenga de todo.
        assert!(cota_de_entropia("aA1!") < 40);
    }

    #[test]
    fn los_patrones_se_comprueban_y_no_se_adivinan() {
        assert_eq!(patron_de("qwerty"), Some(Patron::SecuenciaDeTeclado));
        assert_eq!(patron_de("123456"), Some(Patron::SecuenciaDeTeclado));
        assert_eq!(patron_de("ytrewq"), Some(Patron::SecuenciaDeTeclado));
        assert_eq!(patron_de("abcdef"), Some(Patron::SecuenciaDeTeclado));
        assert_eq!(patron_de("abcabcabc"), Some(Patron::Repeticion));
        assert_eq!(patron_de("aaaaaa"), Some(Patron::Repeticion));
        assert_eq!(patron_de("medellin2024"), Some(Patron::PalabraConNumerosAlFinal));

        // Y lo que NO es un patrón no se marca: aquí es donde un informe se
        // llena de ruido y deja de mirarse.
        for buena in ["xK9#mQ2$vL7@pR4", "correcto-caballo-batería-grapa", "j4T!zW8&nB1"] {
            assert_eq!(patron_de(buena), None, "«{buena}» no tiene patrón");
        }

        // El falso positivo que encontró la prueba cruzada con el generador:
        // tres palabras de la lista BIP-39 llevan «erty» dentro. Una frase que
        // las use es fuerte y no puede marcarse.
        for palabra in ["liberty", "poverty", "property"] {
            let frase = format!("{palabra}-caballo-grapa-correcto-nueve");
            assert_eq!(patron_de(&frase), None, "«{frase}» es una frase sólida");
        }
        // Pero la secuencia que SÍ domina sigue cayendo.
        assert_eq!(patron_de("qwerty123"), Some(Patron::SecuenciaDeTeclado));
    }

    #[test]
    fn una_clave_reciclada_del_historial_ajeno_se_detecta() {
        let mut a = entrada("A", "clave-nueva-de-A-larga#7");
        a.historial = vec![ClaveAnterior {
            clave: Zeroizing::new("la-vieja-de-A-que-alguien-reuso".into()),
            usada_hasta: None,
        }];
        let b = entrada("B", "la-vieja-de-A-que-alguien-reuso");

        let i = revisar(&[a, b]);
        let ficha_b = i.fichas.iter().find(|f| f.nombre == "B").unwrap();
        assert!(ficha_b.hallazgos.contains(&Hallazgo::RecicladaDeOtroHistorial));
    }

    #[test]
    fn el_http_se_marca_y_el_https_no() {
        let mut con_http = entrada("Http", "una-clave-larga-y-decente#42");
        con_http.uris = vec![Uri { uri: "http://viejo.example/entrar".into(), coincidencia: None }];
        let mut con_https = entrada("Https", "otra-clave-larga-y-decente#43");
        con_https.uris = vec![Uri { uri: "https://nuevo.example/".into(), coincidencia: None }];

        let i = revisar(&[con_http, con_https]);
        assert!(
            i.fichas.iter().any(|f| f.nombre == "Http"
                && f.hallazgos.iter().any(|h| matches!(h, Hallazgo::ViajaEnClaro { .. })))
        );
        assert!(
            !i.fichas.iter().any(|f| f.nombre == "Https"),
            "una entrada sin problemas no aparece en el informe"
        );
    }

    #[test]
    fn un_totp_ilegible_se_marca_y_uno_bueno_no() {
        let mut malo = entrada("Malo", "clave-larga-y-decente#111");
        malo.campos.push(Campo::estandar("acceso.totp", Valor::secreto("no-base32-!!")));
        let mut bueno = entrada("Bueno", "clave-larga-y-decente#222");
        bueno.campos.push(Campo::estandar(
            "acceso.totp",
            Valor::secreto("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ));

        let i = revisar(&[malo, bueno]);
        assert!(i.fichas.iter().any(|f| f.nombre == "Malo"
            && f.hallazgos.contains(&Hallazgo::TotpIlegible)));
        assert!(!i.fichas.iter().any(|f| f.nombre == "Bueno"));
    }

    #[test]
    fn una_boveda_sana_da_un_informe_vacio() {
        // Si un informe marca algo en TODAS las entradas, deja de informar. Se
        // comprueba con contraseñas que de verdad están bien.
        let e = vec![
            entrada("A", "xK9#mQ2$vL7@pR4tZ"),
            entrada("B", "correcto-caballo-bateria-grapa-9"),
            entrada("C", "7hG!kW3&nB8*qE5^rT"),
        ];
        let i = revisar(&e);
        assert_eq!(i.con_problemas(), 0, "no puede haber falsos positivos aquí: {:?}", i.fichas);
        assert_eq!(i.revisadas, 3);
    }

    #[test]
    fn las_entradas_sin_contrasena_se_cuentan_aparte() {
        let mut nota = entrada("Nota", "");
        nota.campos.clear();
        nota.clase = Clase::Nota;
        let i = revisar(&[nota]);
        assert_eq!(i.sin_contrasena, 1);
        assert_eq!(i.con_problemas(), 0, "una nota sin contraseña no es un problema");
    }

    #[test]
    fn lo_mas_grave_sale_primero() {
        let e = vec![
            entrada("Leve", "clave-larga-pero-toda-minusculas-si"),
            entrada("Grave", "qwerty"),
        ];
        let i = revisar(&e);
        assert_eq!(i.fichas[0].nombre, "Grave", "el informe se lee de arriba abajo");
    }
}
