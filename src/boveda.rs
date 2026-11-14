// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Modelo interno de la bóveda.
//!
//! Un gestor de contraseñas importa de fuentes con esquemas muy distintos
//! (Bitwarden, KeePass, 1Password, CSV). Si el modelo interno tuviera una rama
//! por cada tipo de cada fuente, cada fuente nueva tocaría todo el programa.
//!
//! Aquí hay UNA representación: una entrada es una lista de campos etiquetados.
//! La `Clase` dice qué es la entrada —para agrupar y para presentarla—, pero no
//! decide qué campos existen. Un número de tarjeta y un TOTP son ambos
//! `Campo` con `Valor::Secreto`; el resto del programa no necesita saber más.
//!
//! La consecuencia que importa: **un campo que el importador no supo clasificar
//! sigue siendo un campo**. No hay ningún sitio donde un dato se caiga por no
//! encajar en una estructura.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Qué representa la entrada. Sirve para agrupar y presentar, NUNCA para
/// decidir qué campos puede tener: los campos son libres.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Clase {
    /// Credencial de acceso (usuario/contraseña, TOTP, passkey).
    Acceso,
    /// Nota segura sin credencial asociada.
    Nota,
    /// Medio de pago.
    Tarjeta,
    /// Documento de identidad / datos personales.
    Identidad,
}

impl Clase {
    pub fn etiqueta(self) -> &'static str {
        match self {
            Clase::Acceso => "acceso",
            Clase::Nota => "nota",
            Clase::Tarjeta => "tarjeta",
            Clase::Identidad => "identidad",
        }
    }
}

/// Valor de un campo. `Secreto` se distingue de `Texto` por dos motivos: se
/// borra de memoria al soltarlo, y la interfaz no lo muestra sin pedirlo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Valor {
    Texto(String),
    Secreto(Zeroizing<String>),
    Booleano(bool),
    /// Campo que la fuente define por referencia a otro campo en vez de por
    /// valor (los *linked fields* de Bitwarden). Se conserva la referencia
    /// cruda: perderla convertiría el campo en uno vacío, que es peor que uno
    /// raro, porque parece un dato ausente y no lo es.
    Referencia(u32),
}

impl Valor {
    /// `true` si el valor no debe mostrarse ni registrarse en claro.
    pub fn es_sensible(&self) -> bool {
        matches!(self, Valor::Secreto(_))
    }

    pub fn secreto(s: impl Into<String>) -> Self {
        Valor::Secreto(Zeroizing::new(s.into()))
    }

    pub fn texto(s: impl Into<String>) -> Self {
        Valor::Texto(s.into())
    }
}

/// De dónde salió el campo. Se conserva porque al exportar de vuelta hay que
/// saber si el campo era del esquema de la fuente o lo puso el usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origen {
    /// Campo del esquema de la fuente (p. ej. `login.username`).
    Estandar,
    /// Campo que el usuario añadió a mano.
    Personalizado,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campo {
    /// Etiqueta canónica del campo. Para los campos estándar se usa una ruta
    /// con puntos que reproduce el esquema de origen (`login.totp`,
    /// `tarjeta.numero`), de modo que la importación sea reversible.
    pub etiqueta: String,
    pub valor: Valor,
    pub origen: Origen,
}

impl Campo {
    pub fn estandar(etiqueta: impl Into<String>, valor: Valor) -> Self {
        Self { etiqueta: etiqueta.into(), valor, origen: Origen::Estandar }
    }

    pub fn personalizado(etiqueta: impl Into<String>, valor: Valor) -> Self {
        Self { etiqueta: etiqueta.into(), valor, origen: Origen::Personalizado }
    }
}

/// Una URI asociada a la entrada, con su regla de coincidencia tal como la
/// definió la fuente. La regla se guarda cruda: es la que decide si la
/// extensión ofrece autocompletar en un dominio, y traducirla a ciegas
/// cambiaría el comportamiento sin avisar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uri {
    pub uri: String,
    /// Regla de coincidencia de la fuente. `None` = usar la de por defecto.
    pub coincidencia: Option<u8>,
}

/// Una contraseña anterior, con la fecha hasta la que estuvo en uso.
///
/// La fecha no es adorno: es lo que permite saber, ante una filtración fechada,
/// si la contraseña comprometida era esta. Guardar la clave vieja y tirar su
/// fecha deja el dato a medias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaveAnterior {
    pub clave: Zeroizing<String>,
    pub usada_hasta: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entrada {
    /// Identificador de la fuente. Se conserva para poder reimportar sin
    /// duplicar.
    pub id_origen: Option<String>,
    pub nombre: String,
    pub clase: Clase,
    pub carpeta: Option<String>,
    pub favorita: bool,
    /// Fecha en que se archivó, si se archivó. Archivar no es borrar: el ítem
    /// sigue existiendo, solo sale de la vista principal. Se conserva la fecha
    /// entera y no un booleano porque el dato que da Bitwarden es la fecha, y
    /// reducirlo a «sí/no» pierde información que no se puede reconstruir.
    pub archivada: Option<String>,
    /// Exigir la contraseña maestra otra vez para revelar esta entrada.
    pub repreguntar: bool,
    pub notas: Option<Zeroizing<String>>,
    pub campos: Vec<Campo>,
    pub uris: Vec<Uri>,
    /// Contraseñas anteriores. Son material sensible real: se importan.
    pub historial: Vec<ClaveAnterior>,
    pub creada: Option<String>,
    pub revisada: Option<String>,
}

impl Entrada {
    pub fn campo(&self, etiqueta: &str) -> Option<&Campo> {
        self.campos.iter().find(|c| c.etiqueta == etiqueta)
    }
}

/// Resultado de una importación.
///
/// Lleva los avisos explícitamente porque una importación de contraseñas que
/// "sale bien" pero deja cosas fuera es exactamente el fallo que este diseño
/// quiere hacer imposible. Un aviso NO es un error —la importación sigue— pero
/// tiene que llegar al usuario en la salida, no al registro.
#[derive(Debug, Default)]
pub struct Importacion {
    pub entradas: Vec<Entrada>,
    pub avisos: Vec<String>,
}
