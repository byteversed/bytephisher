# pytest bootstrap: make the project importable and share helpers.
import os
import sys
import socket
import threading

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

TEMPLATES = os.path.join(HERE, "templates")
FIXTURES = os.path.join(HERE, "tests", "fixtures")


def free_port():
    """Ask the OS for a free TCP port (avoids hardcoded-port collisions)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class StubHTTP:
    """Tiny local HTTP server that records every request body it receives.
    Used to verify Telegram/webhook alerting without touching the internet."""

    def __init__(self, status=200, body=b'{"ok":true}'):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        self.received = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.received.append({
                    "path": self.path,
                    "ct": self.headers.get("Content-Type", ""),
                    "body": self.rfile.read(n),
                })
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.do_POST()

        self.port = free_port()
        self.httpd = HTTPServer(("127.0.0.1", self.port), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
