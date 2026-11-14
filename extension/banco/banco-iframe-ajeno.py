"""Banco del marco anidado.

`all_frames` es false por defecto: los content scripts solo corren en el marco
principal. Si el sitio hace la llamada a WebAuthn desde un iframe -como hace
Google en su flujo de llaves-, ahi no hay nadie que la intercepte.

La pagina crea un iframe del mismo origen que llama a la API, y se cuenta si la
extension pregunta al agente desde dentro.
"""
import http.server, socketserver, json, sys

PADRE = """<!doctype html><meta charset=utf-8><title>banco iframe ajeno</title>
<body><pre id=s>corriendo...</pre>
<iframe src="http://127.0.0.1:8936/dentro" style="width:300px;height:80px"></iframe>
<script>
const veredicto = { principal_sustituida: null, iframe_sustituida: null, iframe_consultas: 0 };
try {
  veredicto.principal_sustituida = !navigator.credentials.get.toString().includes("[native code]");
} catch (e) { veredicto.principal_sustituida = "error"; }

window.addEventListener("message", (e) => {
  const d = e.data;
  if (d && d.banco === "iframe") {
    veredicto.iframe_sustituida = d.sustituida;
    veredicto.iframe_consultas = d.consultas;
    document.getElementById("s").textContent = JSON.stringify(veredicto, null, 2);
    fetch("/veredicto", { method: "POST", body: JSON.stringify(veredicto) });
  }
});
</script></body>""".encode("utf-8")

DENTRO = """<!doctype html><meta charset=utf-8>
<body>iframe<script>
let consultas = 0;
let sustituida = null;
try {
  sustituida = !navigator.credentials.get.toString().includes("[native code]");
} catch (e) { sustituida = "error"; }

window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  if (e.data && e.data.fuente === "chuspa-peticion") consultas++;
});

(async () => {
  const conPlazo = (p, ms) => Promise.race([
    p.catch(() => null), new Promise((r) => setTimeout(r, ms)),
  ]);
  await conPlazo(navigator.credentials.get({ publicKey: {
    challenge: new Uint8Array(32), rpId: location.hostname,
    allowCredentials: [], timeout: 3000,
  }}), 4000);
  parent.postMessage({ banco: "iframe", sustituida, consultas }, "*");
})();
</script></body>""".encode("utf-8")


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cuerpo = DENTRO if self.path == "/dentro" else PADRE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(n).decode()
        self.send_response(204)
        self.end_headers()
        print("VEREDICTO " + cuerpo.replace("\n", " "), flush=True)
        sys.stdout.flush()


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", 8936), H) as s:
    s.serve_forever()
