"""Petite application d'exemple (sert de cible de build pour l'image durcie)."""

from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080


class Handler(BaseHTTPRequestHandler):
    """Repond a /health et affiche un message minimal."""

    def do_GET(self) -> None:  # noqa: N802 (nom impose par BaseHTTPRequestHandler)
        body = b"ok" if self.path == "/health" else b"docker-security-scanner demo"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silence les logs du serveur d'exemple."""


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
