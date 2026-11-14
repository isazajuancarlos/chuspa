// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Cómo se lee el nombre de una entrada para pintarla en la lista.
//!
//! Nada de esto codifica una propiedad de seguridad: es lo que ayuda a encontrar
//! una entrada entre seiscientas, y ya.
//!
//! # Por qué está en Rust
//!
//! Nació en TypeScript (`interfaz/src/app/nombre.ts`) con su banco en
//! `node --test`, y se trajo tal cual al retirar Angular. **La regla no se
//! reinventó**: es la misma, con los mismos casos de prueba, sacados de una
//! bóveda real de 595 entradas. Traducirla en vez de rehacerla es lo que impide
//! que una migración pierda por el camino una decisión que costó medir.

/// Los prefijos que no dicen nada del sitio.
///
/// Enumerados uno a uno, no descritos. Una regla del tipo «la primera etiqueta
/// si es corta» acabaría comiéndose nombres reales, y el fallo se vería como dos
/// entradas distintas pintadas igual sin que nadie entienda por qué.
const PREFIJOS: &[&str] = &[
    "www", "www2", "ww2", "account", "accounts", "cuenta", "cuentas", "login", "signin", "auth",
    "my", "mi", "secure", "portal", "id", "app", "web", "mail", "correo", "user", "users", "admin",
    "panel", "dashboard", "home",
];

/// La parte del nombre que de verdad identifica al sitio.
///
/// `account.foxit.com` es Foxit, no «account» — y en la bóveda real hay 174
/// entradas que empiezan por `www.`, así que la inicial cruda pintaba a casi un
/// tercio de la lista con la misma letra. Eso es exactamente no distinguir nada.
///
/// El prefijo solo se quita si después quedan **dos etiquetas o más**: sin esa
/// condición, un sitio llamado `my.com` quedaría reducido a «com».
pub fn nucleo(nombre: &str) -> &str {
    let n = nombre.trim();
    let partes: Vec<&str> = n.split('.').collect();
    if partes.len() >= 3 {
        let primera = partes[0].to_lowercase();
        if PREFIJOS.contains(&primera.as_str()) {
            // Se devuelve una rodaja del original, no una cadena nueva: así
            // conserva las mayúsculas que tuviera.
            return &n[partes[0].len() + 1..];
        }
    }
    n
}

/// La letra que se pinta en el círculo de la lista, ya en mayúscula.
///
/// La mayúscula la pone esta función y no un `text-transform` del CSS: si la
/// forma de la letra la decidiera la hoja de estilos, lo que devuelve esto y lo
/// que se ve en pantalla serían dos cosas distintas, y la prueba dejaría de
/// medir el producto.
pub fn inicial(nombre: &str) -> String {
    // El primer carácter ALFANUMÉRICO: los nombres importados empiezan a menudo
    // por `[`, `(` o un espacio, y un círculo lleno de paréntesis no distingue
    // nada de nada.
    match nucleo(nombre).chars().find(|c| c.is_alphanumeric()) {
        Some(c) => c.to_uppercase().to_string(),
        // No se inventa una letra: «no se puede saber» tiene su propio símbolo.
        None => "·".to_string(),
    }
}

/// Color del círculo, derivado del nombre.
///
/// Determinista a propósito: una entrada tiene siempre el mismo color, así que
/// se aprende dónde está sin leerla. Si dependiera de la posición en la lista,
/// cambiaría al filtrar y no serviría de ancla para nada.
///
/// Sale del mismo núcleo que la inicial, así que `account.foxit.com` y
/// `foxit.com` se pintan igual: son el mismo sitio y se leen como tal.
pub fn tono(nombre: &str) -> String {
    let mut h: u32 = 0;
    for ch in nucleo(nombre).chars() {
        h = (h.wrapping_mul(31).wrapping_add(ch as u32)) % 360;
    }
    // Saturación y luminosidad fijas y medias: el mismo círculo tiene que
    // contrastar con el texto blanco en el tema claro y en el oscuro.
    format!("hsl({h} 45% 42%)")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Los casos vienen del banco que tenía en TypeScript, y salen de una bóveda
    /// REAL de 595 entradas: no son ejemplos inventados.
    #[test]
    fn el_prefijo_administrativo_no_decide_la_letra() {
        // Los siete `account.*` de la bóveda real daban todos «A».
        let nombres = [
            "account.battle.net",
            "account.foxit.com",
            "account.humanapharmacy.com",
            "account.live.com",
            "account.magicjack.com",
            "account.msi.com",
            "account.proton.me",
        ];
        let letras: Vec<String> = nombres.iter().map(|n| inicial(n)).collect();
        assert_eq!(letras, ["B", "F", "H", "L", "M", "M", "P"]);
    }

    #[test]
    fn el_mismo_sitio_se_pinta_igual_aunque_cambie_el_subdominio() {
        // Es la razón de que el color salga del núcleo y no del nombre entero.
        assert_eq!(tono("account.foxit.com"), tono("foxit.com"));
        assert_eq!(tono("www.github.com"), tono("github.com"));
    }

    /// La pareja del caso anterior: quitar el prefijo NO puede dejar el nombre
    /// en la extensión.
    #[test]
    fn un_dominio_de_dos_etiquetas_se_queda_entero() {
        assert_eq!(nucleo("my.com"), "my.com");
        assert_eq!(inicial("my.com"), "M");
        assert_eq!(nucleo("id.es"), "id.es");
    }

    #[test]
    fn un_nombre_que_no_es_un_dominio_se_deja_en_paz() {
        assert_eq!(inicial("Banco de Bogotá"), "B");
        assert_eq!(nucleo("Banco de Bogotá"), "Banco de Bogotá");
    }

    /// Lo que empieza por puntuación no pinta un círculo con un corchete.
    #[test]
    fn se_busca_el_primer_caracter_que_signifique_algo() {
        assert_eq!(inicial("[archivada] netflix.com"), "A");
        assert_eq!(inicial("  (vieja) gmail"), "V");
        // Y cuando no hay ninguno, se dice que no se sabe en vez de inventarlo.
        assert_eq!(inicial("---"), "·");
        assert_eq!(inicial(""), "·");
    }

    #[test]
    fn la_letra_va_en_mayuscula_y_con_acentos() {
        assert_eq!(inicial("ñandú.example"), "Ñ");
        assert_eq!(inicial("ávila.com"), "Á");
    }

    /// El color es determinista y está dentro del círculo cromático.
    #[test]
    fn el_color_no_depende_de_donde_este_en_la_lista() {
        let a = tono("banco.example");
        assert_eq!(a, tono("banco.example"), "el mismo nombre dio dos colores");
        assert_ne!(a, tono("correo.example"), "dos sitios distintos, el mismo color");
        let grado: u32 = a
            .trim_start_matches("hsl(")
            .split(' ')
            .next()
            .and_then(|g| g.parse().ok())
            .expect("el tono es un número");
        assert!(grado < 360);
    }
}
