// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Juan Carlos Isaza
//
// Se ejecuta DENTRO de la página (mundo principal) para poder sustituir
// `navigator.credentials.get`. Es el único sitio desde donde se puede.
//
// NOTAS PARA QUIEN REVISE ESTE COMPLEMENTO
//
// - Este archivo NO decide nada y no ve ninguna clave. Recoge lo que el sitio
//   pide y lo manda al resto de la extensión por un evento; la firma la hace la
//   aplicación del usuario, en otro proceso.
// - En particular NO manda el origen. El origen lo pone el navegador más
//   adelante en la cadena, precisamente porque este código vive en territorio
//   hostil: la página podría redefinir `location`.
// - Si el usuario no tiene passkey para el sitio, se llama a la implementación
//   original del navegador. Nunca se deja al usuario sin poder entrar.

(() => {
  const original = navigator.credentials.get.bind(navigator.credentials);

  const aBase64url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const deBase64url = (texto) => {
    const s = atob(texto.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes.buffer;
  };

  const FUENTE_PAGINA = "chuspa-peticion";
  const FUENTE_PUENTE = "chuspa-respuesta";

  // El destino del mensaje. En una página de origen opaco —un iframe con
  // `sandbox`— `location.origin` es la cadena "null", que `postMessage` rechaza.
  const destino = () => {
    const o = location.origin;
    return o && o !== "null" ? o : "*";
  };

  // Se habla con el resto de la extensión por `postMessage` y no por un
  // `CustomEvent`: Firefox aísla los dos mundos con visión X-ray, y el `detail`
  // de un evento creado por el content script llega INACCESIBLE a la página.
  // Con eso, esta promesa no resolvía nunca, se agotaba el plazo, y la llamada
  // caía al navegador — que pedía una llave física con la passkey correcta
  // guardada. `postMessage` clona estructuralmente por definición.
  const preguntar = (peticion, signal) =>
    new Promise((resolve) => {
      const id = crypto.randomUUID();
      let plazo;
      const limpiar = () => {
        window.removeEventListener("message", alRecibir);
        clearTimeout(plazo);
        if (signal) signal.removeEventListener("abort", alAbortar);
      };
      const alRecibir = (e) => {
        if (e.source !== window) return;
        const d = e.data;
        if (!d || d.fuente !== FUENTE_PUENTE || d.id !== id) return;
        limpiar();
        resolve(d.respuesta);
      };
      // Si el sitio ABORTA la llamada (`AbortController`, muy común en los flujos
      // de passkey para cancelar un intento y empezar otro), se deja de esperar y
      // se sigue por el camino del navegador. Sin honrar la señal, un `create`/
      // `get` ya cancelado se quedaba con nuestro diálogo abierto pese a que el
      // sitio lo dio por muerto — y, peor, la diferencia entre «responde al
      // instante» y «sale el diálogo» era medible (concilio 2026-09-16, fable).
      const alAbortar = () => {
        limpiar();
        resolve(null);
      };
      window.addEventListener("message", alRecibir);
      if (signal) signal.addEventListener("abort", alAbortar);
      window.postMessage({ fuente: FUENTE_PAGINA, id, peticion }, destino());
      // Si nadie contesta, se sigue por el camino del navegador en vez de dejar
      // la promesa colgada: una pantalla de acceso que no responde es peor que
      // una que pide la llave física.
      //
      // Son dos minutos porque al otro lado hay una PERSONA decidiendo con qué
      // cuenta entrar. El puente contesta siempre —incluso que no—, así que
      // este plazo no es el camino normal sino la red de debajo; medirlo con la
      // paciencia de una máquina cortaría al usuario a mitad de la elección.
      plazo = setTimeout(() => {
        limpiar();
        resolve(null);
      }, 120000);
    });

  navigator.credentials.get = async function (opciones) {
    const pk = opciones?.publicKey;
    if (!pk) return original(opciones);

    // Las peticiones CONDICIONALES no se tocan.
    //
    // Con `mediation: "conditional"` el sitio no está pidiendo entrar: está
    // preparando el autocompletado, y lo hace nada más cargar la página. La
    // especificación dice que el autenticador no debe interrumpir con ningún
    // diálogo — y contestarlas era justo lo que hacía que Gmail entrara SOLO,
    // con la primera cuenta, sin que nadie hubiera pedido nada.
    //
    // Ofrecerlas bien exige integrarse con el autocompletado del navegador, que
    // una extensión no puede hacer. Así que se devuelven al navegador enteras,
    // en vez de atenderlas a medias.
    if (opciones.mediation === "conditional") return original(opciones);

    // Si la llamada ya viene abortada, la atiende el navegador (que rechaza con
    // `AbortError`): no se muestra nuestro diálogo por algo que el sitio canceló.
    if (opciones.signal?.aborted) return original(opciones);

    // En un marco de OTRO origen no se interviene.
    //
    // El script corre en todos los marcos —hace falta: el sitio puede pedir la
    // llave desde un iframe suyo, y ahí es donde no había nadie—. Pero un
    // iframe de un tercero solo puede usar WebAuthn si la página que lo aloja se
    // lo permite con `Permissions-Policy: publickey-credentials-get`, y esa
    // comprobación la hace el navegador. Interceptar aquí se la saltaría: un
    // anuncio incrustado pediría firmas que el navegador le habría negado.
    //
    // Leer el origen del marco de arriba lanza justo cuando es de otro origen,
    // y eso es lo que se usa para distinguirlos. Ante la duda, el navegador:
    // devolverle la llamada aplica la política de verdad en vez de imitarla.
    try {
      if (window.top !== window) void window.top.location.origin;
    } catch {
      return original(opciones);
    }

    const respuesta = await preguntar(
      {
        tipo: "autenticar",
        rp_id: pk.rpId ?? location.hostname,
        reto: aBase64url(pk.challenge),
        permitidas: (pk.allowCredentials ?? []).map((c) => aBase64url(c.id)),
      },
      opciones.signal,
    );

    // Sin passkey nuestra para este sitio, manda el navegador. El usuario puede
    // tener una llave física o una del sistema.
    if (!respuesta || respuesta.tipo !== "asercion") return original(opciones);

    const codificador = new TextEncoder();
    const credencial = {
      id: respuesta.credential_id,
      rawId: deBase64url(respuesta.credential_id),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: codificador.encode(respuesta.client_data).buffer,
        authenticatorData: deBase64url(respuesta.authenticator_data),
        signature: deBase64url(respuesta.signature),
        userHandle: respuesta.user_handle ? deBase64url(respuesta.user_handle) : null,
      },
      getClientExtensionResults: () => ({}),
    };
    return credencial;
  };

  const original_create = navigator.credentials.create.bind(navigator.credentials);

  navigator.credentials.create = async function (opciones) {
    const pk = opciones?.publicKey;
    // Sin `publicKey` no es una passkey (puede ser una credencial federada);
    // que lo atienda el navegador.
    if (!pk || !pk.user || !pk.challenge) return original_create(opciones);

    // Igual que en `get`: una llamada ya abortada la atiende el navegador.
    if (opciones.signal?.aborted) return original_create(opciones);

    // Solo registramos ES256 (−7). Si el sitio no lo ofrece, se devuelve al
    // navegador, que puede tener otro autenticador (una llave física, el del
    // sistema) capaz de dar el algoritmo pedido. Mismo criterio que en el agente.
    const algoritmos = (pk.pubKeyCredParams ?? []).map((p) => p.alg);
    if (!algoritmos.includes(-7)) return original_create(opciones);

    // Igual que en `get`: en un marco de OTRO origen no se interviene, para no
    // saltarse la política de permisos que aplica el navegador.
    try {
      if (window.top !== window) void window.top.location.origin;
    } catch {
      return original_create(opciones);
    }

    const respuesta = await preguntar(
      {
        tipo: "registrar",
        rp_id: pk.rp?.id ?? location.hostname,
        rp_nombre: pk.rp?.name ?? null,
        usuario_handle: aBase64url(pk.user.id),
        usuario: pk.user.name ?? null,
        usuario_mostrado: pk.user.displayName ?? null,
        reto: aBase64url(pk.challenge),
        algoritmos,
        excluidas: (pk.excludeCredentials ?? []).map((c) => aBase64url(c.id)),
      },
      opciones.signal,
    );

    // Sin credencial nuestra (rechazo, plazo, o algoritmo que no damos), manda
    // el navegador.
    if (!respuesta || respuesta.tipo !== "credencial") return original_create(opciones);

    const codificador = new TextEncoder();
    return {
      id: respuesta.credential_id,
      rawId: deBase64url(respuesta.credential_id),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: codificador.encode(respuesta.client_data).buffer,
        attestationObject: deBase64url(respuesta.attestation_object),
        // `authenticatorData` va DENTRO del attestationObject; el servidor lo
        // saca de ahí. No se ofrece `getAuthenticatorData` porque devolver el
        // objeto entero en su lugar sería darle un dato falso (es opcional, y los
        // navegadores viejos tampoco lo traían).
        // Transporte desconocido: `[]` en vez de un valor concreto, porque
        // anunciar «internal» contradiría el `authenticatorAttachment` de abajo
        // y sería una pista falsa. El único algoritmo que registramos es ES256.
        getTransports: () => [],
        getPublicKeyAlgorithm: () => -7,
      },
      getClientExtensionResults: () => ({}),
    };
  };
})();
