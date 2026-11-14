// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza
//
// Vive en el mundo aislado del content script: ve los mensajes de la página pero
// no su JavaScript, y puede hablar con el resto de la extensión.
//
// Su único trabajo es pasar el mensaje. No añade el origen —eso lo hace el
// script de fondo con el dato que pone el navegador— porque aquí todavía
// estamos del lado de la pestaña.
//
// POR QUÉ `postMessage` Y NO UN `CustomEvent`
//
// Firefox aísla los dos mundos con visión X-ray: un objeto creado aquí NO es
// legible desde la página. Con `CustomEvent`, la página recibía el evento y su
// `detail` le llegaba inaccesible, así que la promesa del otro lado no resolvía
// nunca: se agotaba el plazo y la llamada caía al camino del navegador. El
// síntoma era Firefox pidiendo una llave de seguridad FÍSICA, con la passkey
// correcta guardada y la aplicación firmando perfectamente por su cuenta.
//
// La receta de Mozilla para eso es `cloneInto`, pero `postMessage` **clona
// estructuralmente por definición** y funciona igual en los dos navegadores sin
// una sola línea por plataforma. Quitar la causa antes que añadir la envoltura.
//
// QUE LA PÁGINA VEA ESTOS MENSAJES NO ROMPE NADA
//
// Van por el `window` de la pestaña, así que el JavaScript del sitio puede
// leerlos y falsificarlos. Ninguna de las dos cosas le sirve de nada:
//
// - Falsificar una RESPUESTA es fabricarse una credencial a sí misma, que es
//   algo que ya podía hacer sin nosotros.
// - Falsificar una PETICIÓN no le da más alcance, porque el origen lo pone el
//   script de fondo desde `sender.url` y no viaja en el mensaje. Solo puede
//   pedir firmas para su propio origen — exactamente lo que consigue llamando a
//   `navigator.credentials.get`.
//
// Aquí no pasa ningún secreto: el reto y los identificadores los publica el
// propio sitio, y la aserción va a acabar en sus manos de todos modos.

// Firefox expone `browser`; Chrome y Brave solo `chrome`. Las llamadas que se
// usan aquí devuelven promesas en Manifest V3 en los dos navegadores, así que
// con esta línea el MISMO archivo vale para ambos: una copia por navegador se
// desincroniza en cuanto se toca una sola.
const navegador = globalThis.browser ?? globalThis.chrome;

const FUENTE_PAGINA = "chuspa-peticion";
const FUENTE_PUENTE = "chuspa-respuesta";

// El destino del mensaje. En una página de origen opaco —un iframe con
// `sandbox`— `location.origin` es la cadena "null", que `postMessage` rechaza.
function destino() {
  const o = location.origin;
  return o && o !== "null" ? o : "*";
}

window.addEventListener("message", async (e) => {
  // Solo mensajes de esta misma ventana: un iframe de otro origen no tiene por
  // qué poder pedir firmas a través de nosotros.
  if (e.source !== window) return;
  const datos = e.data;
  if (!datos || datos.fuente !== FUENTE_PAGINA) return;

  const { id, peticion } = datos;
  if (!id) return;

  let respuesta = null;
  try {
    respuesta = await navegador.runtime.sendMessage(peticion);
  } catch {
    respuesta = null;
  }

  // Se contesta SIEMPRE, incluso con `null`. Callar dejaría a la página
  // esperando a que venza el plazo, que es justo el fallo que se está
  // arreglando: nadie tiene por qué mirar diez segundos una pantalla parada
  // para acabar en el camino del navegador de todas formas.
  window.postMessage({ fuente: FUENTE_PUENTE, id, respuesta }, destino());
});
