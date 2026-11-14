"""Banco de pruebas del puente de passkeys. Sirve una página que ejercita la
cadena página → puente → fondo y recoge el veredicto por HTTP."""
import http.server, socketserver, json, sys

PAGINA = """<!doctype html><meta charset=utf-8><title>banco</title>
<body><pre id=s>corriendo...</pre><script>
const veredicto = { sustituida: null, respondio: null, detalle: null };

// 1. ¿Alguien sustituyo navigator.credentials.get?
try {
  veredicto.sustituida = !navigator.credentials.get.toString().includes("[native code]");
} catch (e) { veredicto.sustituida = "error: " + e.message; }

// 2. ¿Contesta el puente? Se habla el mismo protocolo que passkeys.js.
const id = crypto.randomUUID();
const plazo = setTimeout(() => terminar(false, "sin respuesta en 6s"), 6000);
window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  const d = e.data;
  if (!d || d.fuente !== "chuspa-respuesta" || d.id !== id) return;
  clearTimeout(plazo);
  terminar(true, JSON.stringify(d.respuesta));
});
window.postMessage({ fuente: "chuspa-peticion", id, peticion: {
  tipo: "autenticar", rp_id: "localhost",
  reto: "cmV0by1kZS1iYW5jby0zMi1ieXRlcy1kZS1sYXJnbw", permitidas: []
}}, location.origin);

function terminar(ok, detalle) {
  veredicto.respondio = ok; veredicto.detalle = detalle;
  document.getElementById("s").textContent = JSON.stringify(veredicto, null, 2);
  fetch("/veredicto", { method: "POST", body: JSON.stringify(veredicto) });
}
</script></body>""".encode("utf-8")

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGINA))); self.end_headers()
        self.wfile.write(PAGINA)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(n).decode()
        self.send_response(204); self.end_headers()
        print("VEREDICTO " + cuerpo, flush=True)
        sys.stdout.flush()

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8932), H) as s:
    s.serve_forever()
