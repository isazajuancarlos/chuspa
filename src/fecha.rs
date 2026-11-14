// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! La fecha de hoy, en el mismo formato en que llegan las importadas.
//!
//! # Por qué hay que escribirlo a mano
//!
//! Hasta ahora ninguna fecha nacía aquí: `creada`, `revisada` y `usada_hasta`
//! venían del export de Bitwarden y se conservaban tal cual. En cuanto la
//! aplicación **crea** una entrada —desde la ventana o desde el navegador— hace
//! falta poder decir cuándo, y una entrada sin fecha de creación es un dato que
//! ya no se puede reconstruir nunca.
//!
//! No se añade una dependencia de calendario por veinte líneas de aritmética
//! que no cambia desde 1582. El algoritmo es el de Howard Hinnant
//! (*chrono-Compatible Low-Level Date Algorithms*), que aquí se simplifica
//! porque el reloj del sistema en segundos Unix no da negativos en ningún
//! escenario que este programa vaya a ver.
//!
//! **Siempre UTC.** Guardar la hora local metería la zona horaria en un archivo
//! que viaja entre máquinas —la copia de seguridad, el sobre a un
//! destinatario—, y una fecha que significa una cosa distinta según dónde se
//! abra es peor que no tenerla.

/// La fecha y hora de ahora, como `2026-08-02T04:13:00Z`.
pub fn ahora_utc() -> String {
    let segundos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        // Un reloj anterior a 1970 no es un motivo para no guardar la entrada:
        // se ancla en la época y la fecha queda visiblemente absurda, que es
        // justo lo que hay que ver si el reloj de la máquina está mal.
        .unwrap_or(0);
    iso_utc(segundos)
}

/// Convierte segundos Unix a `AAAA-MM-DDTHH:MM:SSZ`.
///
/// Separada de [`ahora_utc`] porque una función que lee el reloj no se puede
/// probar: esta sí, contra fechas conocidas.
pub fn iso_utc(segundos: u64) -> String {
    let dias = segundos / 86_400;
    let resto = segundos % 86_400;
    let (hora, minuto, segundo) = (resto / 3_600, (resto % 3_600) / 60, resto % 60);

    // Se traslada la era para que el año empiece el 1 de marzo: así el día
    // bisiesto cae AL FINAL y desaparece el caso especial de febrero.
    let z = dias + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // día dentro de la era, [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // día del año desplazado
    let mp = (5 * doy + 2) / 153; // mes desplazado, [0, 11] con 0 = marzo
    let dia = doy - (153 * mp + 2) / 5 + 1;
    let mes = if mp < 10 { mp + 3 } else { mp - 9 };
    let ano = yoe + era * 400 + u64::from(mes <= 2);

    format!("{ano:04}-{mes:02}-{dia:02}T{hora:02}:{minuto:02}:{segundo:02}Z")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Fechas comprobadas contra `date -u -d @N`, no contra lo que devuelve
    /// esta misma función: una prueba que compara el código consigo mismo
    /// confirma que es determinista, no que es correcto.
    #[test]
    fn las_fechas_conocidas_salen_bien() {
        let casos = [
            (0u64, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (1_000_000_000, "2001-09-09T01:46:40Z"),
            // 29 de febrero: el caso que rompe las conversiones ingenuas.
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            // 1900 NO fue bisiesto y 2000 SÍ: la regla de los siglos.
            (951_782_400, "2000-02-29T00:00:00Z"),
            // Fin de año, que es donde se equivoca el desplazamiento de marzo.
            (1_767_225_599, "2025-12-31T23:59:59Z"),
            (1_767_225_600, "2026-01-01T00:00:00Z"),
            (1_754_092_800, "2025-08-02T00:00:00Z"),
        ];
        for (segundos, esperada) in casos {
            assert_eq!(iso_utc(segundos), esperada, "para {segundos} segundos");
        }
    }

    #[test]
    fn cada_dia_del_ano_sale_una_sola_vez() {
        // Recorre cuatro años completos —incluido uno bisiesto— y comprueba que
        // no hay ni un día repetido ni un salto. Un error de un día en el
        // desplazamiento de marzo pasa desapercibido en una fecha suelta y aquí
        // no: duplicaría un 28 de febrero o se saltaría un 1 de marzo.
        let mut vistas = std::collections::BTreeSet::new();
        let inicio = 1_704_067_200; // 2024-01-01
        let dias = 366 + 365 + 365 + 365;
        for d in 0..dias {
            assert!(
                vistas.insert(iso_utc(inicio + d * 86_400)[..10].to_string()),
                "el día {d} repite una fecha ya vista"
            );
        }
        assert_eq!(vistas.len(), dias as usize);
        assert_eq!(vistas.iter().next().unwrap(), "2024-01-01");
        assert_eq!(vistas.iter().next_back().unwrap(), "2027-12-31");
    }

    #[test]
    fn el_formato_es_el_que_lee_el_importador() {
        // Las fechas de Bitwarden llegan en ISO 8601 con Z. Si esta función
        // escribiera otra cosa, una bóveda tendría dos formatos de fecha según
        // de dónde viniera cada entrada.
        let f = ahora_utc();
        assert_eq!(f.len(), 20, "«{f}» no tiene la forma AAAA-MM-DDTHH:MM:SSZ");
        assert!(f.ends_with('Z'));
        assert_eq!(f.as_bytes()[10], b'T');
        // Y que de verdad lee el reloj: una constante pasaría todo lo anterior.
        assert!(f.as_str() > "2026-01-01T00:00:00Z", "el reloj da «{f}»");
    }
}
