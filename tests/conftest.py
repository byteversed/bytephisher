# pytest bootstrap: make the project importable and share helpers.
import contextlib
import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# The suite runs against the repository. An exported BYTEPHISHER_HOME in the
# developer's shell would otherwise point the in-process module constants (and
# every CLI subprocess) at an unrelated data home.
os.environ["BYTEPHISHER_HOME"] = HERE

TEMPLATES = os.path.join(HERE, "templates")
FIXTURES = os.path.join(HERE, "tests", "fixtures")


def ensure_templates():
    """Generate templates/ when a fresh clone has none.

    They are a build artifact (1209 files), so they are not committed; the tool
    generates them on first run and the suite does the same, which is what makes
    the repository work on a clean checkout and in CI.
    """
    man = os.path.join(HERE, "templates", "templates.json")
    if os.path.isfile(man):
        return False
    import subprocess
    import sys as _sys
    subprocess.run([_sys.executable, os.path.join(HERE, "tools", "gen_templates.py")],
                   cwd=HERE, check=True, capture_output=True, timeout=600)
    return True


def pytest_sessionstart(session):
    """Run before collection so module-level manifest reads see the files."""
    if ensure_templates():
        print("\n[conftest] generated templates/ (first run on this checkout)")


def repo_env(**over):
    """Environment for CLI subprocess tests, pinned to the repository.

    Without this an exported BYTEPHISHER_HOME in the developer's shell silently
    changes what the CLI tests exercise (they ran against a two-template temp
    home and failed on missing templates).
    """
    env = dict(os.environ, BYTEPHISHER_HOME=HERE)
    env.update(over)
    return env


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
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
