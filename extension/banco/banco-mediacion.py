"""Banco de la mediacion condicional.

Con `mediation: "conditional"` el sitio no esta pidiendo entrar: prepara el
autocompletado, y lo hace nada mas cargar la pagina. Atender esas peticiones era
lo que hacia que Gmail entrara SOLO, con la primera cuenta, sin que nadie hubiera
pedido nada.

Se llama a la API de las dos formas y se cuenta cuantas veces la extension
pregunta al agente, observando los `postMessage` que cruzan la pagina.
"""
import http.server, socketserver, json, sys

PAGINA = """<!doctype html><meta charset=utf-8><title>banco mediacion</title>
<body><pre id=s>corriendo...</pre><script>
const veredicto = { sustituida: null, consultas_condicional: 0, consultas_normal: 0 };
let contando = null;

try {
  veredicto.sustituida = !navigator.credentials.get.toString().includes("[native code]");
} catch (e) { veredicto.sustituida = "error: " + e.message; }

window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  if (e.data && e.data.fuente === "chuspa-peticion" && contando) veredicto[contando]++;
});

const opciones = () => ({ publicKey: {
  challenge: new Uint8Array(32),
  rpId: location.hostname,
  allowCredentials: [],
  timeout: 3000,
}});

(async () => {
  // Con plazo: sin autenticador, la promesa de WebAuthn puede no volver nunca,
  // y entonces el banco no reporta y el silencio se lee como "no se pudo medir".
  const conPlazo = (p, ms) => Promise.race([
    p.catch(() => null), new Promise((r) => setTimeout(r, ms)),
  ]);

  contando = "consultas_condicional";
  await conPlazo(navigator.credentials.get({ ...opciones(), mediation: "conditional" }), 4000);

  contando = "consultas_normal";
  await conPlazo(navigator.credentials.get(opciones()), 4000);

  contando = null;
  document.getElementById("s").textContent = JSON.stringify(veredicto, null, 2);
  fetch("/veredicto", { method: "POST", body: JSON.stringify(veredicto) });
})();
</script></body>""".encode("utf-8")


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGINA)))
        self.end_headers()
        self.wfile.write(PAGINA)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(n).decode()
        self.send_response(204)
        self.end_headers()
        print("VEREDICTO " + cuerpo.replace("\n", " "), flush=True)
        sys.stdout.flush()


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8934), H) as s:
    s.serve_forever()
