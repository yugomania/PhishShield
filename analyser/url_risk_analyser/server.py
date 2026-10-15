"""Minimal local JSON API so the Chrome extension can request an analysis.

    POST /analyse   {"url": "..."}   -> report (same shape as `url-risk --json`)
    GET  /health                     -> {"status": "ok", "sources": [...]}

Binds to 127.0.0.1 only. Standard library only, no framework needed.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .analyser import analyse
from .threat_intel import IntelSource, default_sources

MAX_BODY = 16 * 1024


class _Handler(BaseHTTPRequestHandler):
    server_version = "URLRiskAnalyser/1.0"
    sources: list[IntelSource] = []

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # CORS preflight
        self._send(204, {})

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok", "sources": [s.name for s in self.sources]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path not in ("/analyse", "/analyze"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"error": "request body missing or too large"})
            return
        try:
            data = json.loads(self.rfile.read(length))
            url = data["url"]
            if not isinstance(url, str):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": 'expected JSON body {"url": "<string>"}'})
            return
        try:
            self._send(200, analyse(url, self.sources))
        except ValueError as exc:
            self._send(422, {"error": f"not a valid URL: {exc}"})


def serve(host: str = "127.0.0.1", port: int = 8765, sources: list[IntelSource] | None = None) -> None:
    _Handler.sources = sources if sources is not None else default_sources()
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"URL risk analyser API on http://{host}:{port}  (POST /analyse, GET /health)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
