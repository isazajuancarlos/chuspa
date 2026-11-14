// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza
//
// El popup, reducido a SOLO llaves de acceso (passkeys). Ya no toca contraseñas:
// no lee ni rellena formularios, y por eso la extensión ya no pide `activeTab`
// ni `scripting`. Su único trabajo es:
//
//   1. ACTIVAR las llaves — conceder el permiso de host que en Firefox es
//      OPCIONAL y sin el cual el content script de passkeys no llega a correr.
//   2. DECIR si la aplicación está conectada y la bóveda abierta, para que un
//      fallo de passkey —que si no sería mudo— tenga dónde verse.
//
// Las contraseñas las maneja el gestor nativo del navegador, sincronizado con
// chuspa desde la aplicación y con los navegadores cerrados. Aquí no hay nada
// que rellenar, buscar ni guardar: ese código se retiró con esta versión.
//
// NOTAS PARA QUIEN REVISE ESTE COMPLEMENTO
//
// - No hay código remoto ni dinámico: ni `eval`, ni `new Function`, ni
//   `executeScript`. Ya no se inyecta nada en ninguna página.
// - No hay `innerHTML`: todo lo que viene de fuera se pone con `textContent`.
// - No se envía nada a ninguna red. La única comunicación es `nativeMessaging`
//   con una aplicación local del propio usuario.
// - No se almacena nada: ni `storage`, ni cookies, ni estado que sobreviva al
//   cierre del popup.

// Firefox expone `browser`; Chrome y Brave solo `chrome`. Las llamadas que se
// usan aquí devuelven promesas en Manifest V3 en los dos navegadores, así que
// con esta línea el MISMO archivo vale para ambos: una copia por navegador se
// desincroniza en cuanto se toca una sola.
const navegador = globalThis.browser ?? globalThis.chrome;

const HOST = "com.xiliux.chuspa";

// Los orígenes cuyo permiso de host necesita el content script de passkeys. Deben
// coincidir con los `content_scripts.matches` / `optional_host_permissions` del
// manifiesto: `https://*/*` para la web y `http://localhost/*` para el desarrollo
// local (WebAuthn admite http SOLO en localhost, y una IP no vale como rpId). Si
// aquí faltara localhost, el popup diría «activado» con https concedido mientras el
// script NO se inyecta en localhost, y el fallo sería invisible.
const ORIGENES_DE_LLAVES = ["https://*/*", "http://localhost/*"];

const $estado = document.getElementById("estado");
const $aviso = document.getElementById("aviso");
const $permiso = document.getElementById("permiso");

function avisar(texto) {
  $aviso.textContent = texto;
}

// Los permisos de host de un complemento de Manifest V3 son OPCIONALES en
// Firefox: aunque el manifiesto los declare para los content scripts, el
// usuario tiene que concederlos. Sin ellos el script que atiende las llaves de
// acceso no llega a ejecutarse — y el fallo es invisible: parece que el sitio no
// detecta la llave. Por eso se comprueba y se ofrece activarlo, en vez de fallar
// callando.
async function comprobarPermisoDeLlaves() {
  let concedido = false;
  try {
    // `contains` con los dos orígenes es `true` solo si AMBOS están concedidos: así,
    // tener https pero no localhost (o al revés) ofrece el botón en vez de callar.
    concedido = await navegador.permissions.contains({ origins: ORIGENES_DE_LLAVES });
  } catch {
    return;
  }
  if (concedido) return;

  $permiso.hidden = false;
  document.getElementById("pedir-permiso").addEventListener("click", async () => {
    try {
      const ok = await navegador.permissions.request({ origins: ORIGENES_DE_LLAVES });
      if (ok) {
        $permiso.hidden = true;
        avisar("Listo. Recarga la página donde quieras usar la llave.");
      }
    } catch (e) {
      avisar("Firefox no permitió activarlo desde aquí: hazlo en about:addons.");
    }
  });
}

// El estado de la aplicación. `estado` no revela nada del contenido de la
// bóveda: solo si está abierta y, si no, por qué. No se pide ni se enseña el
// número de entradas —al popup de passkeys no le hace falta—.
async function mostrarEstado() {
  let estado;
  try {
    estado = await navegador.runtime.sendNativeMessage(HOST, { tipo: "estado" });
  } catch (e) {
    $estado.className = "estado cerrada";
    $estado.textContent = "No se pudo hablar con la aplicación.";
    avisar(
      "Abre Chuspa y desbloquea la bóveda. Si ya está abierta, puede que el " +
        "navegador no encuentre el puente: revisa que el manifiesto esté en " +
        "~/.mozilla/native-messaging-hosts/",
    );
    return;
  }

  if (!estado.abierta) {
    $estado.className = "estado cerrada";
    // Las dos causas piden cosas distintas: inactividad se recupera solo volviendo
    // a la ventana; bóveda cerrada exige teclear la frase.
    if (estado.razon === "inactividad") {
      $estado.textContent = "El enlace con el navegador caducó por inactividad.";
      avisar(
        "La bóveda sigue abierta. Vuelve a la ventana de Chuspa y usa el programa " +
          "—basta con mirar la lista— y el enlace se restablece solo.",
      );
    } else {
      $estado.textContent = "La bóveda está cerrada.";
      avisar("Ábrela desde la aplicación. Por seguridad, no se puede abrir desde aquí.");
    }
    return;
  }

  $estado.textContent = "Bóveda abierta · llaves de acceso listas";
}

mostrarEstado();
comprobarPermisoDeLlaves();
