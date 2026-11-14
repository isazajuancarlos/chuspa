// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza
//
// El script de fondo. Aquí es donde se pone el ORIGEN, y esa es la pieza de la
// que depende que las passkeys no sirvan para el phishing.
//
// `sender.url` lo rellena el NAVEGADOR con la dirección real de la pestaña que
// envió el mensaje. La página no puede tocarlo. Si el origen viniera de la
// página, un sitio falso pediría una firma para el banco y la conseguiría — que
// es exactamente lo que las passkeys existen para impedir.

// Firefox expone `browser`; Chrome y Brave solo `chrome`. Las llamadas que se
// usan aquí devuelven promesas en Manifest V3 en los dos, así que con esta línea
// el MISMO archivo vale para ambos. Una copia por navegador se desincroniza en
// cuanto se toca una: el origen se pondría bien en un sitio y mal en el otro.
const navegador = globalThis.browser ?? globalThis.chrome;

const HOST = "com.xiliux.chuspa";

// `sendResponse` + `return true`, y NO un escuchador `async` que devuelva una
// promesa.
//
// MEDIDO, no supuesto (2026-08-03, Brave 151 / Chromium 151, banco de pruebas):
// la forma `async` que devuelve la promesa **también funciona ahí**. Se creyó lo
// contrario y era falso. Lo que sostiene esta forma es otra cosa: el manifiesto
// declara `minimum_chrome_version: 111`, y en el Chromium de esa época devolver
// la promesa NO se atendía. `sendResponse` + `return true` funciona en los dos
// navegadores y en todas las versiones que este manifiesto admite; la otra
// forma funciona hoy, aquí, en la versión que este portátil tiene instalada.
//
// Que el fallo sería mudo sigue siendo cierto y es lo que lo hace peligroso: la
// página recibe `undefined`, la passkey no llega y el sitio acaba pidiendo una
// llave física, sin un solo error por ninguna parte.
navegador.runtime.onMessage.addListener((mensaje, sender, responder) => {
  const tipo = mensaje?.tipo;
  if (tipo !== "autenticar" && tipo !== "registrar") return false;

  // El origen lo determina el navegador, NUNCA la página. Vale para las dos
  // operaciones: es lo que impide que un sitio de phishing firme —o registre—
  // «para el banco» desde su propio dominio.
  let origen;
  try {
    origen = new URL(sender.url).origin;
  } catch {
    return false;
  }

  // Se arma el mensaje nativo campo a campo —no se reenvía el de la página tal
  // cual— para que el `origen` que pone el navegador no lo pueda pisar un campo
  // homónimo venido de la pestaña, y para no pasar al agente nada que no se
  // espere.
  const nativo =
    tipo === "autenticar"
      ? {
          tipo: "autenticar",
          rp_id: mensaje.rp_id,
          reto: mensaje.reto,
          permitidas: mensaje.permitidas ?? [],
          origen,
        }
      : {
          tipo: "registrar",
          rp_id: mensaje.rp_id,
          rp_nombre: mensaje.rp_nombre ?? null,
          usuario_handle: mensaje.usuario_handle,
          usuario: mensaje.usuario ?? null,
          usuario_mostrado: mensaje.usuario_mostrado ?? null,
          reto: mensaje.reto,
          algoritmos: mensaje.algoritmos ?? [],
          excluidas: mensaje.excluidas ?? [],
          origen,
        };

  navegador.runtime
    .sendNativeMessage(HOST, nativo)
    // Sin aplicación abierta no se firma ni se registra; la página sigue con el
    // camino normal del navegador.
    .then((r) => responder(r ?? null))
    .catch(() => responder(null));

  // La respuesta llega después: sin esto el canal se cierra al volver.
  return true;
});
