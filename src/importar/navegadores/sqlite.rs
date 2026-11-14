// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza

//! Lector SQLite MÍNIMO, en Rust puro, para leer la tabla `logins` del archivo
//! `Login Data` de Chromium (Chrome/Brave/Edge). Fase 2 del importador.
//!
//! # Por qué a mano y no `rusqlite`
//!
//! `rusqlite` enlaza la biblioteca C de SQLite, y el árbol de chuspa es Rust
//! exclusivo (deny.toml). Leer una tabla de un archivo SQLite en reposo es un
//! recorrido de b-tree acotado: no hace falta un motor entero. Este lector NO
//! escribe, NO interpreta SQL (salvo leer los nombres de columna del
//! `CREATE TABLE`), y NO abre journals/WAL — se llama con los NAVEGADORES
//! CERRADOS, así que el archivo no está bloqueado ni a medias.
//!
//! # Alcance deliberado
//!
//! Solo lo que el importador necesita: recorrer una tabla por su b-tree y sacar
//! tres columnas por nombre (`origin_url`, `username_value`, `password_value`).
//! Cubre páginas hoja e interiores de tabla y el desbordamiento (overflow). NO
//! cubre índices, ni `WITHOUT ROWID`, ni `freelist` — nada de eso hace falta
//! para `logins`, y ante algo que no entiende **falla ruidosamente** (D20), no
//! devuelve datos a medias.

/// Una fila de `logins`. La contraseña sigue CIFRADA (la descifra [`super::oscrypt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub origin_url: String,
    pub username: String,
    pub password: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSqlite {
    /// No empieza por la cabecera mágica de SQLite.
    NoEsSqlite,
    /// Un número de página fuera del archivo, o un tamaño de página imposible.
    PaginaInvalida,
    /// No hay ninguna tabla `logins` en el esquema.
    TablaNoEncontrada,
    /// El `CREATE TABLE` no declara alguna de las tres columnas que se piden.
    ColumnaNoEncontrada(&'static str),
    /// Algo del formato que este lector acotado no maneja: se dice, no se adivina.
    NoSoportado(&'static str),
    /// Estructura inconsistente (un offset que se sale, un varint sin fin…).
    Corrupto(&'static str),
}

const CABECERA: &[u8; 16] = b"SQLite format 3\0";

/// Prepara el contexto de lectura desde la cabecera del archivo (medidas de
/// página, tope de visitas). Compartido por todos los lectores.
fn preparar(db: &[u8]) -> Result<Ctx<'_>, ErrorSqlite> {
    if db.get(..16) != Some(CABECERA.as_slice()) {
        return Err(ErrorSqlite::NoEsSqlite);
    }
    // Tamaño de página: u16 big-endian en el offset 16; el valor 1 significa 65536.
    let ps = u16::from_be_bytes([db[16], db[17]]) as usize;
    let page_size = if ps == 1 { 65536 } else { ps };
    if page_size < 512 || !page_size.is_power_of_two() || page_size > db.len() {
        return Err(ErrorSqlite::PaginaInvalida);
    }
    // Bytes reservados al final de cada página (casi siempre 0).
    let reservados = db[20] as usize;
    let usable = page_size
        .checked_sub(reservados)
        .filter(|u| *u >= 480)
        .ok_or(ErrorSqlite::PaginaInvalida)?;
    // Cota de trabajo: un b-tree válido visita cada página del archivo A LO SUMO
    // una vez, así que el número total de páginas es el techo. Sin esto, un DAG
    // de páginas interiores (cada celda apuntando a la siguiente) con profundidad
    // ≤ 64 explota en (fan+1)^prof visitas —un archivo de pocos KB cuelga el
    // proceso— sin ser un ciclo que la guarda de profundidad detecte. Cazado por
    // la revisión del 2026-09-15.
    let max_visitas = db.len() / page_size + 1;
    Ok(Ctx { db, page_size, usable, visitadas: std::cell::Cell::new(0), max_visitas })
}

/// Busca en la tabla de esquema (b-tree de la página 1) una tabla por nombre y
/// devuelve su `rootpage` y su `CREATE TABLE`.
fn buscar_raiz(ctx: &Ctx, tabla: &str) -> Result<(usize, String), ErrorSqlite> {
    let mut rootpage = None;
    let mut sql = None;
    ctx.recorrer(1, &mut |registro| {
        let v = decodificar(registro)?;
        // columnas de sqlite_master: 0=type 1=name 2=tbl_name 3=rootpage 4=sql
        let tipo = v.first().and_then(Valor::texto);
        let nombre = v.get(1).and_then(Valor::texto);
        if tipo.as_deref() == Some("table") && nombre.as_deref() == Some(tabla) {
            rootpage = v.get(3).and_then(Valor::entero);
            sql = v.get(4).and_then(Valor::texto);
        }
        Ok(())
    })?;
    Ok((
        rootpage.ok_or(ErrorSqlite::TablaNoEncontrada)? as usize,
        sql.ok_or(ErrorSqlite::TablaNoEncontrada)?,
    ))
}

/// Lee una tabla por nombre y devuelve (nombres de columna, filas), donde cada
/// celda es sus BYTES: un BLOB tal cual, un TEXT como su UTF-8, y NULL o entero
/// como `None`. Es lo que necesita el lector de `key4.db` (fase 6), cuyas
/// columnas de interés son BLOB.
#[allow(clippy::type_complexity)]
pub fn leer_tabla_bytes(
    db: &[u8],
    tabla: &str,
) -> Result<(Vec<String>, Vec<Vec<Option<Vec<u8>>>>), ErrorSqlite> {
    let ctx = preparar(db)?;
    let (rootpage, sql) = buscar_raiz(&ctx, tabla)?;
    let columnas = columnas_de(&sql);
    let ancho = columnas.len();
    let mut filas = Vec::new();
    ctx.recorrer(rootpage, &mut |registro| {
        let v = decodificar(registro)?;
        let mut fila = Vec::with_capacity(ancho);
        for i in 0..ancho {
            fila.push(v.get(i).and_then(Valor::bytes));
        }
        filas.push(fila);
        Ok(())
    })?;
    Ok((columnas, filas))
}

pub fn leer_logins(db: &[u8]) -> Result<Vec<Login>, ErrorSqlite> {
    let ctx = preparar(db)?;
    let (rootpage, sql) = buscar_raiz(&ctx, "logins")?;

    // 2) Del `CREATE TABLE` se sacan los índices de las tres columnas por nombre:
    //    el orden de columnas cambia entre versiones de Chromium, así que no se
    //    puede cablear una posición.
    let columnas = columnas_de(&sql);
    let idx = |n: &'static str| {
        columnas.iter().position(|c| c == n).ok_or(ErrorSqlite::ColumnaNoEncontrada(n))
    };
    let i_origin = idx("origin_url")?;
    let i_user = idx("username_value")?;
    let i_pass = idx("password_value")?;

    // 3) Se recorre el b-tree de `logins` y se saca cada fila.
    let mut salida = Vec::new();
    ctx.recorrer(rootpage, &mut |registro| {
        let v = decodificar(registro)?;
        let origin_url = v.get(i_origin).and_then(Valor::texto).unwrap_or_default();
        let username = v.get(i_user).and_then(Valor::texto).unwrap_or_default();
        // La contraseña es un BLOB; si viniera como texto (raro) también se acepta.
        let password = match v.get(i_pass) {
            Some(Valor::Blob(b)) => b.clone(),
            Some(Valor::Texto(t)) => t.clone().into_bytes(),
            _ => Vec::new(),
        };
        salida.push(Login { origin_url, username, password });
        Ok(())
    })?;

    Ok(salida)
}

/// El contexto de lectura: el archivo entero y las medidas de página.
struct Ctx<'a> {
    db: &'a [u8],
    page_size: usize,
    usable: usize,
    /// Cuántas páginas se han visitado ya en el recorrido en curso.
    visitadas: std::cell::Cell<usize>,
    /// Techo de visitas: el nº de páginas del archivo. Pasarlo significa que una
    /// página se visita más de una vez (DAG o ciclo) → archivo malformado.
    max_visitas: usize,
}

impl Ctx<'_> {
    /// Los bytes de la página `n` (1-based).
    fn pagina(&self, n: usize) -> Result<&[u8], ErrorSqlite> {
        if n == 0 {
            return Err(ErrorSqlite::PaginaInvalida);
        }
        let ini = (n - 1) * self.page_size;
        self.db
            .get(ini..ini + self.page_size)
            .ok_or(ErrorSqlite::PaginaInvalida)
    }

    /// Recorre el b-tree de TABLA con raíz en `pagina_n` y llama a `cb` con el
    /// payload de cada celda de hoja (el registro), ya reunido si desbordaba.
    fn recorrer(
        &self,
        pagina_n: usize,
        cb: &mut dyn FnMut(&[u8]) -> Result<(), ErrorSqlite>,
    ) -> Result<(), ErrorSqlite> {
        // Recursión acotada por la profundidad del árbol; un tope evita que un
        // archivo corrupto con un ciclo se lleve la pila.
        self.recorrer_hondo(pagina_n, cb, 0)
    }

    fn recorrer_hondo(
        &self,
        pagina_n: usize,
        cb: &mut dyn FnMut(&[u8]) -> Result<(), ErrorSqlite>,
        prof: usize,
    ) -> Result<(), ErrorSqlite> {
        if prof > 64 {
            return Err(ErrorSqlite::Corrupto("b-tree demasiado hondo (¿ciclo?)"));
        }
        // Presupuesto GLOBAL: la profundidad sola no acota el TRABAJO —un DAG
        // ancho explota exponencialmente sin superar 64 de hondo—. Cada página
        // válida se visita una vez; pasar del total de páginas del archivo es un
        // DAG/ciclo, y se corta.
        let v = self.visitadas.get() + 1;
        if v > self.max_visitas {
            return Err(ErrorSqlite::Corrupto("se visita una página más de una vez (¿DAG/ciclo?)"));
        }
        self.visitadas.set(v);
        let pagina = self.pagina(pagina_n)?;
        // La página 1 lleva delante los 100 bytes de la cabecera del archivo.
        let base = if pagina_n == 1 { 100 } else { 0 };
        let tipo = *pagina.get(base).ok_or(ErrorSqlite::Corrupto("página sin tipo"))?;
        let n_celdas = u16_en(pagina, base + 3)?;
        // Interior de tabla: cabecera de 12 bytes (incluye el puntero derecho).
        // Hoja de tabla: cabecera de 8 bytes.
        let (cab, interior) = match tipo {
            0x05 => (12, true),
            0x0d => (8, false),
            0x02 | 0x0a => return Err(ErrorSqlite::NoSoportado("b-tree de índice")),
            _ => return Err(ErrorSqlite::Corrupto("tipo de página desconocido")),
        };
        let punteros = base + cab;

        for i in 0..n_celdas {
            let off = u16_en(pagina, punteros + i * 2)?;
            if interior {
                // 4 bytes: página hija izquierda; luego varint rowid (se ignora).
                let hijo = u32_en(pagina, off)?;
                self.recorrer_hondo(hijo, cb, prof + 1)?;
            } else {
                let payload = self.payload_de_hoja(pagina, off)?;
                cb(&payload)?;
            }
        }

        // El puntero derecho del interior: la última rama.
        if interior {
            let der = u32_en(pagina, base + 8)?;
            self.recorrer_hondo(der, cb, prof + 1)?;
        }
        Ok(())
    }

    /// Reúne el payload de una celda de HOJA de tabla, siguiendo las páginas de
    /// desbordamiento si el registro no cabía en la página.
    fn payload_de_hoja(&self, pagina: &[u8], off: usize) -> Result<Vec<u8>, ErrorSqlite> {
        // Celda de hoja de tabla: varint(len del payload), varint(rowid), payload.
        let (len_payload, n1) = varint(pagina.get(off..).ok_or(cor("celda fuera"))?)?;
        let (_rowid, n2) = varint(pagina.get(off + n1..).ok_or(cor("celda sin rowid"))?)?;
        // El payload NUNCA puede ser mayor que el archivo entero. Se comprueba
        // ANTES de `Vec::with_capacity`: sin esto, un varint de longitud gigante
        // (hasta `u64::MAX` con 9 bytes 0xFF) hace `capacity overflow` —pánico,
        // también en release— o reserva gigabytes elegidos por el atacante antes
        // de fallar por límites. Cazado por la revisión del 2026-09-15.
        if len_payload > self.db.len() as u64 {
            return Err(cor("un payload declara ser más grande que el archivo"));
        }
        let len_payload = len_payload as usize;
        let inicio = off + n1 + n2;

        // Cuánto payload va LOCAL en esta página (fórmula del formato SQLite para
        // hoja de tabla).
        let u = self.usable;
        let x = u - 35;
        let local = if len_payload <= x {
            len_payload
        } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + (len_payload - m) % (u - 4);
            if k <= x { k } else { m }
        };

        let mut datos = Vec::with_capacity(len_payload);
        datos.extend_from_slice(
            pagina.get(inicio..inicio + local).ok_or(cor("payload local fuera"))?,
        );

        if local < len_payload {
            // Detrás del trozo local hay 4 bytes: la primera página de overflow.
            let mut sig = u32_en(pagina, inicio + local)?;
            let mut guardia = 0;
            while sig != 0 && datos.len() < len_payload {
                guardia += 1;
                if guardia > self.db.len() / 4 + 8 {
                    return Err(cor("cadena de overflow sin fin (¿ciclo?)"));
                }
                let ov = self.pagina(sig)?;
                sig = u32_en(ov, 0)?;
                let falta = len_payload - datos.len();
                let cabe = (u - 4).min(falta);
                datos.extend_from_slice(ov.get(4..4 + cabe).ok_or(cor("overflow corto"))?);
            }
            if datos.len() != len_payload {
                return Err(cor("el payload reunido no mide lo declarado"));
            }
        }
        Ok(datos)
    }
}

fn cor(m: &'static str) -> ErrorSqlite {
    ErrorSqlite::Corrupto(m)
}

/// Lee un u16 big-endian en `off`, o error si se sale. Los offsets vienen del
/// archivo (punteros de celda, número de celdas): un `Login Data` manipulado no
/// puede provocar un pánico por indexar fuera.
fn u16_en(bytes: &[u8], off: usize) -> Result<usize, ErrorSqlite> {
    let b = bytes.get(off..off + 2).ok_or(cor("u16 fuera de la página"))?;
    Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
}

/// Lee un u32 big-endian en `off`, o error si se sale.
fn u32_en(bytes: &[u8], off: usize) -> Result<usize, ErrorSqlite> {
    let b = bytes.get(off..off + 4).ok_or(cor("u32 fuera de la página"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

/// Un valor de una columna, en los tipos que este lector necesita distinguir.
#[derive(Debug, Clone, PartialEq)]
enum Valor {
    Nulo,
    Entero(i64),
    Real(f64),
    Texto(String),
    Blob(Vec<u8>),
}

impl Valor {
    fn texto(&self) -> Option<String> {
        match self {
            Valor::Texto(t) => Some(t.clone()),
            _ => None,
        }
    }
    fn entero(&self) -> Option<i64> {
        match self {
            Valor::Entero(n) => Some(*n),
            _ => None,
        }
    }
    /// Los bytes de la celda: un BLOB tal cual, un TEXT como su UTF-8; el resto
    /// (NULL, entero, real) no tiene una representación de bytes útil aquí.
    fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Valor::Blob(b) => Some(b.clone()),
            Valor::Texto(t) => Some(t.clone().into_bytes()),
            _ => None,
        }
    }
}

/// Decodifica un registro SQLite (cabecera de tipos seriales + cuerpo) en sus
/// columnas.
fn decodificar(registro: &[u8]) -> Result<Vec<Valor>, ErrorSqlite> {
    let (len_cab, n) = varint(registro)?;
    let len_cab = len_cab as usize;
    if len_cab > registro.len() {
        return Err(cor("cabecera de registro más larga que el registro"));
    }
    let mut tipos = Vec::new();
    let mut p = n;
    while p < len_cab {
        let (t, k) = varint(&registro[p..])?;
        tipos.push(t);
        p += k;
    }
    let mut cuerpo = len_cab;
    let mut valores = Vec::with_capacity(tipos.len());
    for t in tipos {
        let (valor, avanza) = leer_valor(t, registro.get(cuerpo..).ok_or(cor("cuerpo corto"))?)?;
        cuerpo += avanza;
        valores.push(valor);
    }
    Ok(valores)
}

/// Lee un valor dado su tipo serial. Devuelve (valor, cuántos bytes ocupó).
fn leer_valor(tipo: u64, resto: &[u8]) -> Result<(Valor, usize), ErrorSqlite> {
    let entero_be = |n: usize| -> Result<i64, ErrorSqlite> {
        let bytes = resto.get(..n).ok_or(cor("entero corto"))?;
        let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 }; // extensión de signo
        for b in bytes {
            v = (v << 8) | i64::from(*b);
        }
        Ok(v)
    };
    Ok(match tipo {
        0 => (Valor::Nulo, 0),
        1 => (Valor::Entero(entero_be(1)?), 1),
        2 => (Valor::Entero(entero_be(2)?), 2),
        3 => (Valor::Entero(entero_be(3)?), 3),
        4 => (Valor::Entero(entero_be(4)?), 4),
        5 => (Valor::Entero(entero_be(6)?), 6),
        6 => (Valor::Entero(entero_be(8)?), 8),
        7 => {
            let bytes = resto.get(..8).ok_or(cor("real corto"))?;
            (Valor::Real(f64::from_be_bytes(bytes.try_into().unwrap())), 8)
        }
        8 => (Valor::Entero(0), 0),
        9 => (Valor::Entero(1), 0),
        10 | 11 => return Err(cor("tipo serial reservado")),
        n if n % 2 == 0 => {
            // BLOB de (n-12)/2 bytes.
            let largo = ((n - 12) / 2) as usize;
            let b = resto.get(..largo).ok_or(cor("blob corto"))?.to_vec();
            (Valor::Blob(b), largo)
        }
        n => {
            // TEXT de (n-13)/2 bytes (se asume UTF-8; Chromium lo guarda así).
            let largo = ((n - 13) / 2) as usize;
            let b = resto.get(..largo).ok_or(cor("texto corto"))?;
            let s = String::from_utf8_lossy(b).into_owned();
            (Valor::Texto(s), largo)
        }
    })
}

/// Un varint de SQLite: hasta 9 bytes, 7 bits por byte (big-endian), el bit alto
/// marca continuación; el 9º byte aporta sus 8 bits. Devuelve (valor, longitud).
fn varint(bytes: &[u8]) -> Result<(u64, usize), ErrorSqlite> {
    let mut v: u64 = 0;
    for i in 0..8 {
        let b = *bytes.get(i).ok_or(cor("varint sin fin"))?;
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    // 9º byte: los 8 bits.
    let b9 = *bytes.get(8).ok_or(cor("varint sin 9º byte"))?;
    v = (v << 8) | u64::from(b9);
    Ok((v, 9))
}

/// Saca los nombres de columna, en orden, del `CREATE TABLE`. No es un parser de
/// SQL: localiza el paréntesis de apertura, parte por comas de primer nivel, y de
/// cada trozo toma el primer identificador; descarta las restricciones de tabla
/// (`PRIMARY KEY(...)`, `UNIQUE(...)`, `CONSTRAINT…`, `FOREIGN KEY…`, `CHECK…`).
fn columnas_de(sql: &str) -> Vec<String> {
    let Some(ini) = sql.find('(') else { return Vec::new() };
    // El cuerpo va hasta el paréntesis de cierre que EQUILIBRA al de apertura.
    let cuerpo: &str = {
        let tras = &sql[ini + 1..];
        let mut prof = 1;
        let mut fin = tras.len();
        for (i, c) in tras.char_indices() {
            match c {
                '(' => prof += 1,
                ')' => {
                    prof -= 1;
                    if prof == 0 {
                        fin = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        &tras[..fin]
    };

    let mut cols = Vec::new();
    for trozo in partir_por_comas_de_primer_nivel(cuerpo) {
        let t = trozo.trim();
        if t.is_empty() {
            continue;
        }
        let primera = t.split_whitespace().next().unwrap_or("");
        let mayus = primera.to_ascii_uppercase();
        if matches!(
            mayus.as_str(),
            "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT" | "KEY"
        ) {
            continue;
        }
        cols.push(desentrecomillar(primera));
    }
    cols
}

fn partir_por_comas_de_primer_nivel(s: &str) -> Vec<String> {
    let mut partes = Vec::new();
    let mut prof = 0i32;
    let mut actual = String::new();
    let mut comilla: Option<char> = None;
    for c in s.chars() {
        if let Some(q) = comilla {
            actual.push(c);
            if c == q {
                comilla = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                comilla = Some(c);
                actual.push(c);
            }
            '[' => {
                comilla = Some(']');
                actual.push(c);
            }
            '(' => {
                prof += 1;
                actual.push(c);
            }
            ')' => {
                prof -= 1;
                actual.push(c);
            }
            ',' if prof == 0 => {
                partes.push(std::mem::take(&mut actual));
            }
            _ => actual.push(c),
        }
    }
    partes.push(actual);
    partes
}

/// Quita comillas de un identificador (`"x"`, `` `x` ``, `[x]`).
fn desentrecomillar(id: &str) -> String {
    let id = id.trim();
    let pares = [('"', '"'), ('`', '`'), ('[', ']'), ('\'', '\'')];
    for (a, b) in pares {
        if id.len() >= 2 && id.starts_with(a) && id.ends_with(b) {
            return id[1..id.len() - 1].to_string();
        }
    }
    id.to_string()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Fixture SQLite `Login Data` generado con python3 `sqlite3` (el oráculo
    // independiente, D33): 41 filas, page_size 512 → varias páginas, con un b-tree
    // que tiene interiores, no una sola hoja. La columna `password_value` no es ni
    // la primera ni la última, así que el mapeo por nombre importa de verdad. La
    // última fila lleva el blob v10 REAL del KAT de oscrypt.
    const FIXTURE: &[u8] = include_bytes!("login_data_fixture.db");

    #[test]
    fn lee_las_41_filas_con_las_columnas_correctas() {
        let logins = leer_logins(FIXTURE).unwrap();
        assert_eq!(logins.len(), 41, "el b-tree multipágina se recorre entero");
        // Primera, una del medio y la penúltima (las arbitrarias).
        assert_eq!(logins[0].origin_url, "https://sitio0.example/entrar");
        assert_eq!(logins[0].username, "usuario0@correo.test");
        assert_eq!(logins[0].password, b"v10".iter().chain([3u8; 16].iter()).copied().collect::<Vec<_>>());
        assert_eq!(logins[20].origin_url, "https://sitio20.example/entrar");
        assert_eq!(logins[20].username, "usuario20@correo.test");
    }

    #[test]
    fn el_pipeline_lee_y_descifra_una_contrasena_v10() {
        // Fase 2 + fase 1 juntas: leer el blob de la fila del KAT y descifrarlo.
        let logins = leer_logins(FIXTURE).unwrap();
        let kat = logins.iter().find(|l| l.origin_url.contains("kat.example")).unwrap();
        let claro = super::super::oscrypt::descifrar_con_secreto(&kat.password, super::super::oscrypt::SECRETO_V10).unwrap();
        assert_eq!(claro, "hunter2-contraseña".as_bytes());
    }

    #[test]
    fn los_nombres_de_columna_salen_del_create_table() {
        let cols = columnas_de(
            "CREATE TABLE logins (origin_url TEXT NOT NULL, username_value TEXT, \
             password_value BLOB, PRIMARY KEY (origin_url, username_value))",
        );
        assert_eq!(cols, ["origin_url", "username_value", "password_value"]);
        // La restricción de tabla PRIMARY KEY(...) no cuenta como columna.
    }

    #[test]
    fn rechaza_lo_que_no_es_sqlite() {
        assert_eq!(leer_logins(b"no soy una base de datos"), Err(ErrorSqlite::NoEsSqlite));
    }

    #[test]
    fn una_base_manipulada_da_error_nunca_panico() {
        // El archivo lo controla quien tenga el disco; un `Login Data` corrupto o
        // manipulado tiene que fallar RUIDOSAMENTE, no tumbar el proceso (D20).
        // Cada mutación se prueba: ninguna puede provocar un `panic` por indexar
        // fuera, un bucle sin fin, ni un `unwrap` reventado.

        // 1) Número de celdas imposible en la página 1 (base 100, offset +3..+5).
        let mut m = FIXTURE.to_vec();
        m[103] = 0xff;
        m[104] = 0xff;
        assert!(leer_logins(&m).is_err(), "n_celdas gigante debe fallar acotado");

        // 2) Tamaño de página imposible (no potencia de 2).
        let mut m = FIXTURE.to_vec();
        m[16] = 0x01;
        m[17] = 0x23;
        assert!(leer_logins(&m).is_err());

        // 3) Truncado a la mitad de una página.
        assert!(leer_logins(&FIXTURE[..300]).is_err());

        // 4) Byte a byte, truncando en cada frontera de página: nunca panic.
        for corte in (512..FIXTURE.len()).step_by(512) {
            let _ = leer_logins(&FIXTURE[..corte]); // Ok o Err, pero jamás panic.
        }

        // 5) Ruido en el cuerpo (deja la cabecera válida): Ok o Err, sin panic.
        let mut m = FIXTURE.to_vec();
        for (i, b) in m.iter_mut().enumerate().skip(200) {
            *b = (i as u8).wrapping_mul(31);
        }
        let _ = leer_logins(&m);
    }

    #[test]
    fn una_bomba_de_payload_da_error_no_panico() {
        // Página 1 = hoja con una celda cuyo varint de longitud de payload es
        // 9×0xFF (u64::MAX). Sin el clamp, `Vec::with_capacity` hace `capacity
        // overflow` (pánico, también en release). Con él, error acotado.
        // (Cazado por la revisión del 2026-09-15.)
        const BOMBA: &[u8] = include_bytes!("login_data_payloadbomb.db");
        assert!(
            matches!(leer_logins(BOMBA), Err(ErrorSqlite::Corrupto(_))),
            "un payload gigante tiene que dar Err, no panic"
        );
    }

    #[test]
    fn una_bomba_de_fanout_se_corta_no_cuelga() {
        // DAG de páginas interiores (cada celda → la siguiente): sin ciclo, con
        // profundidad ≤ 64, pero (fan+1)^prof recorridos. Sin el presupuesto de
        // visitas NO termina. Con él, corta con Corrupto. El tope de tiempo hace
        // que una regresión FALLE en vez de colgar la suite. (Revisión 2026-09-15.)
        const BOMBA: &[u8] = include_bytes!("login_data_fanout.db");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(leer_logins(BOMBA).is_err());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => panic!("la bomba de fan-out debía dar Err"),
            Err(_) => panic!("la bomba de fan-out NO terminó en 5 s: el presupuesto no corta"),
        }
    }

    #[test]
    fn el_varint_de_una_y_de_dos_partes() {
        assert_eq!(varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(varint(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(varint(&[0x81, 0x00]).unwrap(), (128, 2));
        // Sin byte de fin: error, no un valor a medias.
        assert!(varint(&[0x81]).is_err());
    }
}
