// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! ¿Le corresponde esta credencial a la página que la pide?
//!
//! # Por qué este archivo es el más delicado del proyecto
//!
//! Un gestor de contraseñas hace una cosa peligrosa: entregar credenciales a
//! quien las pide. Toda su seguridad se apoya en decidir bien a **quién**. El
//! cifrado puede ser perfecto y la bóveda inexpugnable, y si la extensión
//! rellena la contraseña del banco en `banco.com.phishing.example`, no ha
//! servido de nada.
//!
//! Los fallos históricos de los gestores están casi todos aquí, y casi todos son
//! la misma clase de error: comparar dominios **como cadenas**. `contains`,
//! `starts_with`, `ends_with` — cualquiera de los tres se rompe con un dominio
//! elegido a propósito:
//!
//! | Regla ingenua | Dominio que la engaña |
//! |---|---|
//! | `url.contains("banco.com")` | `phishing.example/banco.com` |
//! | `host.ends_with("banco.com")` | `evilbanco.com` |
//! | `host.starts_with("banco.com")` | `banco.com.evil.example` |
//!
//! Aquí la comparación es **por etiquetas de dominio**, nunca por texto. Y ante
//! la duda no se entrega: un falso negativo obliga a copiar y pegar, un falso
//! positivo entrega la contraseña del banco a un desconocido.
//!
//! # Por defecto estricto, laxo solo si se marca
//!
//! Bitwarden usa «dominio base» por defecto, y eso hace que una credencial de
//! `google.com` se ofrezca en cualquier `*.google.com`. Aquí el defecto es el
//! **host**, con una sola concesión: `www.` se ignora, porque `www.banco.com` y
//! `banco.com` son el mismo sitio para cualquiera menos para un comparador de
//! cadenas, y no reconocerlo obliga a guardar la credencial dos veces.
//!
//! Lo demás —compartir credencial entre subdominios— existe, se usa y es
//! legítimo, pero se pide por entrada con [`Regla::DominioBase`]. Se rechaza lo
//! imposible, no lo inusual; simplemente lo inusual hay que declararlo.

/// Cómo decide una URI guardada si le corresponde una página.
///
/// Los números son los de Bitwarden, para que una bóveda importada conserve el
/// comportamiento que tenía. Lo que cambia es el **defecto** cuando la entrada no
/// trae ninguno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regla {
    /// Mismo dominio registrable: `mail.ejemplo.com` vale para `ejemplo.com`.
    DominioBase,
    /// Mismo host, ignorando un `www.` inicial. **Es el defecto.**
    Host,
    /// La URL empieza por la URI guardada. Comparación de texto, y por eso
    /// se limita a la parte de ruta: el host se sigue comparando por etiquetas.
    ComienzaPor,
    /// La URL es idéntica a la guardada.
    Exacta,
    /// Nunca ofrecer esta credencial automáticamente.
    Nunca,
}

impl Regla {
    /// Traduce el número que viene de un export de Bitwarden.
    ///
    /// El 4 de Bitwarden es «expresión regular». **No se admite**: una expresión
    /// regular escrita a mano decidiendo a quién se le da la contraseña es una
    /// forma muy cómoda de escribir `.*` sin darse cuenta. Se convierte en
    /// [`Regla::Nunca`] para que la credencial siga existiendo pero no se ofrezca
    /// sola, que es el lado seguro de equivocarse.
    pub fn desde_bitwarden(n: Option<u8>) -> Self {
        match n {
            None | Some(1) => Regla::Host,
            Some(0) => Regla::DominioBase,
            Some(2) => Regla::ComienzaPor,
            Some(3) => Regla::Exacta,
            // 4 = regex, 5 = never, y cualquier valor futuro desconocido.
            _ => Regla::Nunca,
        }
    }

    /// Cómo se llama esta regla para una persona.
    ///
    /// Existe porque una regla que no se ve no se puede conservar a propósito:
    /// la ventana enseñaba las direcciones de una entrada como texto pelado, así
    /// que una credencial marcada para **no ofrecerse sola** tenía exactamente
    /// el mismo aspecto que cualquier otra. Quien no puede ver una regla la
    /// borra sin enterarse.
    pub fn nombre(self) -> &'static str {
        match self {
            Regla::DominioBase => "dominio base",
            Regla::Host => "host",
            Regla::ComienzaPor => "empieza por",
            Regla::Exacta => "exacta",
            Regla::Nunca => "nunca sola",
        }
    }
}

/// Una URL descompuesta en lo que hace falta para decidir.
///
/// No se usa un analizador de URL completo a propósito: hace falta muy poco, y
/// ese poco tiene que ser evidente de leer. Un analizador general trae consigo
/// normalizaciones —de `%2E`, de mayúsculas, de IDN— que son justamente donde se
/// esconden las sorpresas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Direccion {
    /// `https`, `http`, … en minúsculas.
    pub esquema: String,
    /// El host en minúsculas, sin puerto ni credenciales.
    pub host: String,
    /// Lo que sigue al host, empezando por `/`.
    pub ruta: String,
}

impl Direccion {
    /// Descompone una URL. Devuelve `None` si no se puede entender **sin
    /// adivinar**: una URL que no se sabe leer no puede recibir una contraseña.
    pub fn analizar(url: &str) -> Option<Self> {
        let url = url.trim();
        let (esquema, resto) = url.split_once("://")?;
        let esquema = esquema.to_ascii_lowercase();
        if esquema.is_empty() || !esquema.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return None;
        }

        // La ruta empieza en la primera `/`; antes puede haber `?` o `#` si no
        // hay ruta ninguna.
        let corte = resto.find(['/', '?', '#']).unwrap_or(resto.len());
        let (autoridad, cola) = resto.split_at(corte);

        // `usuario:clave@host` — se descarta la parte de credenciales. Es el
        // truco clásico: `https://banco.com@evil.example` tiene host
        // `evil.example`, y quien lo lee deprisa ve el banco.
        let sin_credenciales = autoridad.rsplit_once('@').map_or(autoridad, |(_, h)| h);

        // El puerto no participa: una credencial no cambia porque el sitio
        // escuche en otro puerto. Un host entre corchetes es IPv6.
        let host = if let Some(fin) = sin_credenciales.strip_prefix('[') {
            let (dentro, _) = fin.split_once(']')?;
            format!("[{dentro}]")
        } else {
            sin_credenciales.split(':').next()?.to_string()
        };

        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.contains(' ') {
            return None;
        }

        let ruta = if cola.is_empty() { "/".to_string() } else { cola.to_string() };
        Some(Direccion { esquema, host, ruta })
    }

    /// Las etiquetas del host, de derecha a izquierda: `a.b.com` → `["com","b","a"]`.
    fn etiquetas(&self) -> Vec<&str> {
        self.host.rsplit('.').collect()
    }

    /// El host sin un `www.` inicial.
    fn sin_www(&self) -> &str {
        self.host.strip_prefix("www.").unwrap_or(&self.host)
    }

    /// El dominio registrable: `mail.ejemplo.com` → `ejemplo.com`.
    ///
    /// Se apoya en una lista corta de sufijos de dos niveles. **No es la Public
    /// Suffix List**, y por eso `DominioBase` no es el defecto: con un sufijo que
    /// no esté en la lista, esto devolvería un dominio demasiado ancho. La lista
    /// lleva los que importan aquí —`com.co` el primero— y la limitación está
    /// escrita en vez de disimulada.
    fn dominio_registrable(&self) -> Option<String> {
        const SUFIJOS_COMPUESTOS: &[&str] = &[
            "com.co", "net.co", "org.co", "gov.co", "edu.co", "mil.co", "nom.co",
            "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
            "com.ar", "com.br", "com.mx", "com.pe", "com.ve", "com.ec", "com.py",
            "com.uy", "com.bo", "com.es", "com.au", "net.au", "org.au",
            "co.jp", "or.jp", "ne.jp", "co.nz", "co.za", "co.in", "com.tr",
        ];
        // Una dirección IP no tiene dominio registrable: comparar «los dos
        // últimos números» de una IP no significa nada.
        if self.es_ip() {
            return None;
        }
        let et = self.etiquetas();
        if et.len() < 2 {
            return None;
        }
        let ultimos_dos = format!("{}.{}", et[1], et[0]);
        if SUFIJOS_COMPUESTOS.contains(&ultimos_dos.as_str()) {
            // Hace falta una etiqueta más: `banco.com.co`.
            if et.len() < 3 {
                return None;
            }
            Some(format!("{}.{}", et[2], ultimos_dos))
        } else {
            Some(ultimos_dos)
        }
    }

    fn es_ip(&self) -> bool {
        self.host.starts_with('[')
            || (self.host.split('.').count() == 4
                && self.host.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
    }
}

/// Por qué no se ofreció una credencial. Sirve para poder explicárselo al
/// usuario en vez de dejarlo mirando una lista vacía.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rechazo {
    /// Una de las dos direcciones no se pudo entender.
    NoSeEntiende,
    /// Los hosts no corresponden.
    OtroSitio,
    /// La credencial es de `https` y la página es `http`: entregarla la expondría
    /// en claro, y además es el aspecto que tiene un ataque de degradación.
    DegradaLaConexion,
    /// La entrada está marcada para no ofrecerse sola.
    MarcadaComoNunca,
    /// El host coincide pero la ruta no cumple la regla pedida.
    OtraRuta,
}

/// ¿Corresponde `guardada` a la página `actual`?
pub fn corresponde(guardada: &str, actual: &str, regla: Regla) -> Result<(), Rechazo> {
    if regla == Regla::Nunca {
        return Err(Rechazo::MarcadaComoNunca);
    }
    let (g, a) = match (Direccion::analizar(guardada), Direccion::analizar(actual)) {
        (Some(g), Some(a)) => (g, a),
        _ => return Err(Rechazo::NoSeEntiende),
    };

    // Antes que nada: nunca entregar por http una credencial guardada para
    // https. Es el caso del atacante que degrada la conexión, y también el del
    // portal cautivo que suplanta el sitio.
    if g.esquema == "https" && a.esquema != "https" {
        return Err(Rechazo::DegradaLaConexion);
    }

    match regla {
        Regla::Nunca => Err(Rechazo::MarcadaComoNunca),
        Regla::Host => {
            if g.sin_www() == a.sin_www() {
                Ok(())
            } else {
                Err(Rechazo::OtroSitio)
            }
        }
        Regla::DominioBase => match (g.dominio_registrable(), a.dominio_registrable()) {
            (Some(x), Some(y)) if x == y => Ok(()),
            // Sin dominio registrable (una IP, un host de una sola etiqueta) se
            // exige el host completo en vez de dejarlo pasar.
            (None, None) if g.host == a.host => Ok(()),
            _ => Err(Rechazo::OtroSitio),
        },
        Regla::Exacta => {
            if g.host == a.host && g.ruta == a.ruta && g.esquema == a.esquema {
                Ok(())
            } else if g.host != a.host {
                Err(Rechazo::OtroSitio)
            } else {
                Err(Rechazo::OtraRuta)
            }
        }
        Regla::ComienzaPor => {
            // El host SIEMPRE por etiquetas; solo la ruta se compara como texto.
            // Comparar el host como texto es el fallo que este módulo existe para
            // no cometer.
            if g.sin_www() != a.sin_www() {
                Err(Rechazo::OtroSitio)
            } else if a.ruta.starts_with(&g.ruta) {
                Ok(())
            } else {
                Err(Rechazo::OtraRuta)
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_host_se_compara_por_etiquetas_no_por_texto() {
        // La tabla del encabezado del módulo, convertida en prueba. Cada uno de
        // estos engaña a una comparación de cadenas distinta.
        for impostor in [
            "https://banco.com.evil.example/",   // starts_with
            "https://evilbanco.com/",            // ends_with
            "https://phishing.example/banco.com", // contains
            "https://banco.com.co.evil.example/",
            "https://xn--banco-8va.com/",        // homógrafo
        ] {
            assert_eq!(
                corresponde("https://banco.com", impostor, Regla::Host),
                Err(Rechazo::OtroSitio),
                "«{impostor}» no puede recibir la credencial de banco.com"
            );
        }
    }

    #[test]
    fn las_credenciales_de_usuario_en_la_url_no_confunden() {
        // `https://banco.com@evil.example` tiene host evil.example. Es el truco
        // más viejo del correo de phishing, y un analizador ingenuo lo lee al
        // revés.
        assert_eq!(
            corresponde("https://banco.com", "https://banco.com@evil.example/", Regla::Host),
            Err(Rechazo::OtroSitio)
        );
        let d = Direccion::analizar("https://usuario:clave@banco.com/x").unwrap();
        assert_eq!(d.host, "banco.com");
    }

    #[test]
    fn www_es_el_mismo_sitio() {
        // Y no reconocerlo obliga a guardar la credencial dos veces, que es lo
        // que lleva a la gente a desactivar el gestor.
        assert!(corresponde("https://banco.com", "https://www.banco.com/", Regla::Host).is_ok());
        assert!(corresponde("https://www.banco.com", "https://banco.com/entrar", Regla::Host).is_ok());
    }

    #[test]
    fn un_subdominio_no_vale_por_defecto() {
        assert_eq!(
            corresponde("https://banco.com", "https://oficina.banco.com/", Regla::Host),
            Err(Rechazo::OtroSitio),
            "compartir entre subdominios se pide con DominioBase, no se regala"
        );
        assert!(
            corresponde("https://banco.com", "https://oficina.banco.com/", Regla::DominioBase).is_ok()
        );
    }

    #[test]
    fn el_dominio_base_respeta_los_sufijos_compuestos() {
        // Sin esto, `banco.com.co` y `otro.com.co` compartirían «dominio base»
        // com.co y se ofrecerían credenciales entre bancos colombianos distintos.
        assert_eq!(
            corresponde("https://banco.com.co", "https://otrobanco.com.co/", Regla::DominioBase),
            Err(Rechazo::OtroSitio)
        );
        assert!(
            corresponde("https://banco.com.co", "https://pagos.banco.com.co/", Regla::DominioBase)
                .is_ok()
        );
        assert_eq!(
            corresponde("https://algo.co.uk", "https://otro.co.uk/", Regla::DominioBase),
            Err(Rechazo::OtroSitio)
        );
    }

    #[test]
    fn no_se_entrega_una_credencial_https_por_http() {
        assert_eq!(
            corresponde("https://banco.com", "http://banco.com/", Regla::Host),
            Err(Rechazo::DegradaLaConexion)
        );
        // Al revés sí: si se guardó en http, el sitio no prometía nada.
        assert!(corresponde("http://interno.local", "https://interno.local/", Regla::Host).is_ok());
    }

    #[test]
    fn la_regla_regex_de_bitwarden_se_convierte_en_nunca() {
        // Una expresión regular decidiendo a quién se le da la contraseña es una
        // forma cómoda de escribir `.*` sin querer.
        assert_eq!(Regla::desde_bitwarden(Some(4)), Regla::Nunca);
        assert_eq!(Regla::desde_bitwarden(Some(5)), Regla::Nunca);
        // Y un valor futuro que no conocemos también.
        assert_eq!(Regla::desde_bitwarden(Some(99)), Regla::Nunca);
        // El defecto es el estricto.
        assert_eq!(Regla::desde_bitwarden(None), Regla::Host);
    }

    #[test]
    fn comienza_por_no_afloja_el_host() {
        // El error clásico: implementar «empieza por» sobre la URL entera.
        // `https://banco.com` es prefijo de `https://banco.com.evil.example`.
        assert_eq!(
            corresponde("https://banco.com/", "https://banco.com.evil.example/x", Regla::ComienzaPor),
            Err(Rechazo::OtroSitio)
        );
        assert!(
            corresponde("https://banco.com/app", "https://banco.com/app/entrar", Regla::ComienzaPor)
                .is_ok()
        );
        assert_eq!(
            corresponde("https://banco.com/app", "https://banco.com/otro", Regla::ComienzaPor),
            Err(Rechazo::OtraRuta)
        );
    }

    #[test]
    fn una_url_que_no_se_entiende_no_recibe_nada() {
        for basura in ["", "banco.com", "https://", "https:// espacio.com", "://x"] {
            assert_eq!(
                corresponde("https://banco.com", basura, Regla::Host),
                Err(Rechazo::NoSeEntiende),
                "«{basura}» no se puede entender y no puede recibir credenciales"
            );
        }
    }

    #[test]
    fn el_puerto_y_el_punto_final_no_cambian_el_sitio() {
        assert!(corresponde("https://banco.com", "https://banco.com:8443/", Regla::Host).is_ok());
        // El punto final del FQDN: `banco.com.` es el mismo sitio.
        assert!(corresponde("https://banco.com", "https://banco.com./", Regla::Host).is_ok());
    }

    #[test]
    fn las_mayusculas_del_host_no_importan_y_las_de_la_ruta_si() {
        assert!(corresponde("https://Banco.COM", "https://banco.com/", Regla::Host).is_ok());
        // La ruta sí distingue mayúsculas: en un servidor Unix son rutas
        // distintas, y aflojarlo sería decidir por el servidor.
        assert_eq!(
            corresponde("https://banco.com/App", "https://banco.com/app", Regla::Exacta),
            Err(Rechazo::OtraRuta)
        );
    }

    #[test]
    fn una_ip_no_tiene_dominio_base() {
        // Comparar «los dos últimos números» de dos IP distintas no significa
        // nada, y con la regla ingenua 10.0.0.1 y 20.0.0.1 compartirían base.
        assert_eq!(
            corresponde("https://192.168.1.10", "https://10.0.1.10/", Regla::DominioBase),
            Err(Rechazo::OtroSitio)
        );
        assert!(
            corresponde("https://192.168.1.10", "https://192.168.1.10/x", Regla::DominioBase).is_ok()
        );
    }

    #[test]
    fn ipv6_se_entiende_entera() {
        let d = Direccion::analizar("https://[2001:db8::1]:8443/x").unwrap();
        assert_eq!(d.host, "[2001:db8::1]");
        assert!(corresponde("https://[2001:db8::1]", "https://[2001:db8::1]/y", Regla::Host).is_ok());
    }
}
