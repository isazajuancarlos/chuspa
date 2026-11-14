// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Genera contraseñas y frases de paso.
//!
//! # El detalle que casi todo el mundo hace mal
//!
//! Lo natural es escribir `alfabeto[byte % alfabeto.len()]`. Y está **sesgado**:
//! si el alfabeto tiene 62 caracteres, los bytes 0..=255 se reparten en cuatro
//! vueltas incompletas, así que los primeros 8 caracteres del alfabeto salen 5
//! veces cada 256 bytes y el resto solo 4. Un 25 % más probables.
//!
//! No es catastrófico, pero es entropía regalada sin motivo, y en un generador de
//! contraseñas es exactamente la clase de detalle que no se puede permitir: es la
//! única función del programa cuyo trabajo *entero* es producir azar. Aquí se usa
//! **muestreo por rechazo**: se descarta el byte que caería en la vuelta
//! incompleta y se pide otro. Cuesta un puñado de bytes más y quita el sesgo del
//! todo.
//!
//! # Las frases de paso salen de la lista BIP-39
//!
//! Cuatro palabras corrientes aguantan más que ocho caracteres con símbolos, y
//! además se recuerdan. Se usa la lista BIP-39 que ya viaja en el binario para el
//! respaldo en papel: 2 048 palabras, así que **cada palabra aporta 11 bits
//! exactos** y la cuenta de entropía es una multiplicación, no una estimación.

use quipu_nucleo::papel::palabras;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum GeneradorError {
    #[error("no hay entropía del sistema")]
    SinEntropia,

    #[error("un alfabeto vacío no puede producir nada: activa al menos un tipo de carácter")]
    AlfabetoVacio,

    #[error("una contraseña de {0} caracteres no protege nada; el mínimo es 8")]
    DemasiadoCorta(usize),

    #[error("la lista de palabras del binario está corrupta")]
    ListaCorrupta,
}

/// Qué caracteres puede usar.
#[derive(Debug, Clone, Copy)]
pub struct Composicion {
    pub minusculas: bool,
    pub mayusculas: bool,
    pub digitos: bool,
    pub simbolos: bool,
    /// Quitar `0 O o l 1 I` y similares.
    ///
    /// Es para contraseñas que alguien va a **teclear mirando un papel**. Cuesta
    /// entropía —el alfabeto encoge— así que no está activo por defecto: solo
    /// paga la pena cuando de verdad hay que copiarla a mano.
    pub sin_ambiguos: bool,
}

impl Default for Composicion {
    fn default() -> Self {
        Self {
            minusculas: true,
            mayusculas: true,
            digitos: true,
            simbolos: true,
            sin_ambiguos: false,
        }
    }
}

impl Composicion {
    fn alfabeto(&self) -> Vec<char> {
        const SIMBOLOS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
        const AMBIGUOS: &str = "0OolI1|";

        let mut v = Vec::new();
        if self.minusculas {
            v.extend('a'..='z');
        }
        if self.mayusculas {
            v.extend('A'..='Z');
        }
        if self.digitos {
            v.extend('0'..='9');
        }
        if self.simbolos {
            v.extend(SIMBOLOS.chars());
        }
        if self.sin_ambiguos {
            v.retain(|c| !AMBIGUOS.contains(*c));
        }
        v
    }
}

/// Una contraseña aleatoria de `largo` caracteres.
pub fn contrasena(largo: usize, composicion: Composicion) -> Result<Zeroizing<String>, GeneradorError> {
    if largo < 8 {
        return Err(GeneradorError::DemasiadoCorta(largo));
    }
    let alfabeto = composicion.alfabeto();
    if alfabeto.is_empty() {
        return Err(GeneradorError::AlfabetoVacio);
    }

    let mut salida = Zeroizing::new(String::with_capacity(largo));
    for _ in 0..largo {
        salida.push(alfabeto[indice_sin_sesgo(alfabeto.len())?]);
    }
    Ok(salida)
}

/// Una frase de `palabras` palabras de la lista BIP-39, separadas por guiones.
///
/// Cada palabra aporta exactamente 11 bits: cuatro son 44, seis son 66. Con
/// cinco ya se supera lo que se le puede pedir a una contraseña tecleada a mano.
pub fn frase(cuantas: usize, separador: char) -> Result<Zeroizing<String>, GeneradorError> {
    let lista: Vec<&str> = palabras::LISTA_CRUDA
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lista.len() != palabras::PALABRAS_EN_LA_LISTA {
        return Err(GeneradorError::ListaCorrupta);
    }

    let mut partes = Vec::with_capacity(cuantas);
    for _ in 0..cuantas {
        partes.push(lista[indice_sin_sesgo(lista.len())?]);
    }
    Ok(Zeroizing::new(partes.join(&separador.to_string())))
}

/// Bits de entropía de una frase de `cuantas` palabras. Es exacto, no estimado.
pub fn bits_de_frase(cuantas: usize) -> u32 {
    // 2048 = 2^11.
    (cuantas * 11) as u32
}

/// Un índice uniforme en `0..n`, **sin sesgo modular**.
///
/// El límite es el mayor múltiplo de `n` que cabe en 256: todo byte por encima
/// se descarta. Así cada valor de `0..n` sale de exactamente el mismo número de
/// bytes posibles.
fn indice_sin_sesgo(n: usize) -> Result<usize, GeneradorError> {
    if n <= 256 {
        let limite = (256 / n) * n;
        loop {
            let mut b = [0u8; 1];
            quipu::aleatorio::llenar(&mut b).map_err(|_| GeneradorError::SinEntropia)?;
            if (b[0] as usize) < limite {
                return Ok(b[0] as usize % n);
            }
        }
    } else {
        // Para alfabetos grandes (la lista de 2 048 palabras) se usan dos bytes.
        let limite = (65536 / n) * n;
        loop {
            let mut b = [0u8; 2];
            quipu::aleatorio::llenar(&mut b).map_err(|_| GeneradorError::SinEntropia)?;
            let v = u16::from_le_bytes(b) as usize;
            if v < limite {
                return Ok(v % n);
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_se_repiten_ni_son_predecibles() {
        let mut vistas = HashSet::new();
        for _ in 0..500 {
            let c = contrasena(16, Composicion::default()).unwrap();
            assert_eq!(c.chars().count(), 16);
            assert!(vistas.insert(c.to_string()), "salió dos veces la misma en 500");
        }
    }

    /// La prueba que justifica el muestreo por rechazo.
    ///
    /// La primera versión comparaba el carácter más frecuente con el menos, y
    /// estaba mal calibrada: con 400 muestras por carácter, una diferencia de
    /// ±3σ es puro azar y ya da una razón de 1,29. El máximo y el mínimo de 62
    /// variables son justo los estadísticos más ruidosos que se pueden elegir.
    ///
    /// Lo correcto es chi-cuadrado sobre el reparto entero, y **validado contra
    /// el caso rojo**: se mide también un generador con `% n`, que es el error
    /// que se quiere evitar, y se exige que ese sí lo detecte. Un medidor que
    /// nunca ha visto un positivo es un generador de ceros.
    #[test]
    fn el_muestreo_no_tiene_sesgo_modular() {
        const N: usize = 62;
        const MUESTRAS: usize = N * 1000;
        // Chi-cuadrado con 61 grados de libertad: el valor crítico al 99,9 % es
        // ~112. Con 130 no hay falsos positivos ni con mala suerte.
        const UMBRAL: f64 = 130.0;

        let composicion = Composicion {
            minusculas: true,
            mayusculas: true,
            digitos: true,
            simbolos: false,
            sin_ambiguos: false,
        };
        assert_eq!(composicion.alfabeto().len(), N, "62 no divide a 256: es el caso que sesga");

        let chi2 = |cuentas: &[usize]| -> f64 {
            let esperado = MUESTRAS as f64 / N as f64;
            cuentas
                .iter()
                .map(|&o| {
                    let d = o as f64 - esperado;
                    d * d / esperado
                })
                .sum()
        };

        // 1. El generador de verdad.
        let mut cuentas = vec![0usize; N];
        let alfabeto = composicion.alfabeto();
        let texto = contrasena(MUESTRAS, composicion).unwrap();
        for c in texto.chars() {
            cuentas[alfabeto.iter().position(|&a| a == c).unwrap()] += 1;
        }
        let bueno = chi2(&cuentas);

        // 2. El error que se quiere evitar: `byte % n` sin rechazo.
        let mut sesgadas = vec![0usize; N];
        for _ in 0..MUESTRAS {
            let mut b = [0u8; 1];
            quipu::aleatorio::llenar(&mut b).unwrap();
            sesgadas[b[0] as usize % N] += 1;
        }
        let malo = chi2(&sesgadas);

        assert!(
            bueno < UMBRAL,
            "el reparto del generador no es uniforme: chi2 = {bueno:.1} (umbral {UMBRAL})"
        );
        assert!(
            malo > UMBRAL,
            "la prueba no DISCRIMINA: `% n` debería detectarse y dio chi2 = {malo:.1}"
        );
    }

    #[test]
    fn la_composicion_se_respeta() {
        let solo_digitos = Composicion {
            minusculas: false,
            mayusculas: false,
            digitos: true,
            simbolos: false,
            sin_ambiguos: false,
        };
        let c = contrasena(30, solo_digitos).unwrap();
        assert!(c.chars().all(|x| x.is_ascii_digit()));

        let sin_ambiguos = Composicion { sin_ambiguos: true, ..Default::default() };
        let c = contrasena(200, sin_ambiguos).unwrap();
        for malo in ['0', 'O', 'o', 'l', 'I', '1', '|'] {
            assert!(!c.contains(malo), "salió «{malo}», que se pidió excluir");
        }
    }

    #[test]
    fn lo_imposible_se_rechaza() {
        assert!(matches!(
            contrasena(4, Composicion::default()),
            Err(GeneradorError::DemasiadoCorta(4))
        ));
        let vacia = Composicion {
            minusculas: false,
            mayusculas: false,
            digitos: false,
            simbolos: false,
            sin_ambiguos: false,
        };
        assert!(matches!(contrasena(16, vacia), Err(GeneradorError::AlfabetoVacio)));
    }

    #[test]
    fn las_frases_salen_de_la_lista_y_no_se_repiten() {
        let lista: HashSet<&str> = palabras::LISTA_CRUDA.lines().map(str::trim).collect();
        let mut vistas = HashSet::new();
        for _ in 0..200 {
            let f = frase(5, '-').unwrap();
            assert_eq!(f.split('-').count(), 5);
            for p in f.split('-') {
                assert!(lista.contains(p), "«{p}» no está en la lista BIP-39");
            }
            assert!(vistas.insert(f.to_string()));
        }
        assert_eq!(bits_de_frase(5), 55, "2048 palabras son 11 bits exactos cada una");
    }

    /// Lo que genera el generador no puede caer en lo que denuncia el informe de
    /// salud. Si lo hiciera, una de las dos piezas estaría mal.
    #[test]
    fn lo_generado_pasa_el_informe_de_salud() {
        use crate::salud::{cota_de_entropia, revisar};
        use crate::boveda::{Campo, Clase, Entrada, Valor};

        let mut entradas = Vec::new();
        for i in 0..60 {
            let clave = if i % 2 == 0 {
                contrasena(16, Composicion::default()).unwrap().to_string()
            } else {
                frase(5, '-').unwrap().to_string()
            };
            assert!(cota_de_entropia(&clave) >= 60, "«{i}» no llega a 60 bits");
            entradas.push(Entrada {
                id_origen: None,
                nombre: format!("Sitio {i}"),
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
            });
        }
        let informe = revisar(&entradas);
        assert_eq!(
            informe.con_problemas(),
            0,
            "el generador produjo algo que el informe marca: {:?}",
            informe.fichas
        );
    }
}
