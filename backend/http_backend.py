#!/usr/bin/env python3
"""Tiny HTTP telemetry backend (stands in for a cloud API behind the gateway)."""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send(200, {"status": "ok", "ts": time.time()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        self._send(200, {"received": data, "bytes": n})

    def log_message(self, *_):  # keep benchmark output quiet
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
