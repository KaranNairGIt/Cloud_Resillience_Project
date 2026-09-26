"""Synthetic HTTP target for the isolated Kubernetes resilience lab."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock


ATTACK_STATE = {"active": False}
ATTACK_LOCK = Lock()


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        with ATTACK_LOCK:
            attacked = ATTACK_STATE["active"]
        responses = {
            "/healthz": {"status": "healthy", "service": "synthetic-records-demo"},
            "/behavior": {"status": "anomalous" if attacked else "normal",
                           "records": "synthetic-only"},
        }
        value = responses.get(self.path)
        if value is None:
            self.send_error(404)
            return
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        if self.path != "/simulate/attack":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 1024:
                self.send_error(413)
                return
            self.rfile.read(size)
        except ValueError:
            self.send_error(400)
            return
        with ATTACK_LOCK:
            ATTACK_STATE["active"] = True
        payload = json.dumps({"status": "anomalous", "effect": "in-memory demo flag only"}).encode()
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:
        pass


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 8080), DemoHandler).serve_forever()


if __name__ == "__main__":
    main()
