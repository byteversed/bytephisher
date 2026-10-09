"""Cross-platform portability regression tests (Termux/Android, Windows, macOS, Linux).

The owner runs this tool from a phone (Termux) and a Windows laptop as well as Linux
servers, so a Linux-only assumption is a real defect, not a cosmetic one. This suite
proves the shipped code is portable by *executing* it, and locks in the platform guards
that make the Unix-only calls safe so a future change cannot silently break them.

Two kinds of assertion live here:

* behaviour -- call the function for real and check the cross-platform result
  (a path builder creates its parent dir, a tunneler with no binary returns None
  instead of raising FileNotFoundError, an export into a missing dir never dumps a
  traceback at the operator);
* guard existence -- for code that can only run on one OS (os.chmod with unix bits),
  parse the AST and assert the platform check is still present in front of the call,
  because that line cannot be exercised on Linux.

Run:  ./.venv/bin/python -m pytest tests/test_cross_platform.py -q -p no:cacheprovider
"""

import ast
import os
import re
import sys
import urllib.request

import pytest

# integration: these invariants are checked by running the CLI and the tools
pytestmark = pytest.mark.integration

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Directories that are not shipped code (runtime output, vendored env, docs, tests).
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "data", "logs",
             "docs", "templates", ".ruff_cache", "build", "dist"}
SHIP_DIRS = ("core", "tools", "mailer", "tunnels", "dashboard")

# tools/gen_templates.py emits real template markup (accented language-switcher labels)
# that is written to disk as UTF-8; it is the one documented non-ASCII data file, and
# tests/test_portability.py already exempts it for the same reason.
ASCII_DATA_ALLOWLIST = {"tools/gen_templates.py"}


def shipped_files():
    """Every shipped .py file (the CLI module + the packages), tests excluded."""
    out = [os.path.join(ROOT, "bytephisher.py")]
    for d in SHIP_DIRS:
        base = os.path.join(ROOT, d)
        for root, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in files:
                if f.endswith(".py"):
                    out.append(os.path.join(root, f))
    return sorted(out)


def rel(p):
    return os.path.relpath(p, ROOT)


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def _tree(p):
    return ast.parse(_read(p), filename=p)


def _parent_map(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _ancestor_ifs(node, parents):
    n = node
    while n in parents:
        n = parents[n]
        if isinstance(n, ast.If):
            yield n


# ===========================================================================
# 1. Unix-only modules, fork and euid -- none may appear in shipped code
# ===========================================================================
UNIX_ONLY_IMPORTS = ("pwd", "grp", "fcntl", "termios", "resource", "pty", "posix", "tty")
UNIX_ONLY_CALLS = ("os.fork", "os.geteuid", "os.getuid", "os.setsid", "os.setuid",
                   "os.getgid", "os.killpg", "os.wait4")


class TestNoUnixOnlyPrimitives:
    def test_no_unix_only_module_imports(self):
        """pwd/grp/fcntl/termios/resource/pty do not exist on Windows at all."""
        rx = re.compile(
            r"^\s*(?:import|from)\s+(?:" + "|".join(UNIX_ONLY_IMPORTS) + r")\b")
        offenders = []
        for p in shipped_files():
            for i, line in enumerate(_read(p).splitlines(), 1):
                if rx.search(line):
                    offenders.append(f"{rel(p)}:{i}: {line.strip()}")
        assert not offenders, "unix-only imports in shipped code: " + "; ".join(offenders)

    def test_no_fork_euid_or_session_calls(self):
        """os.fork / os.geteuid / os.setsid are absent on Windows (AttributeError)."""
        offenders = []
        for p in shipped_files():
            for i, line in enumerate(_read(p).splitlines(), 1):
                for call in UNIX_ONLY_CALLS:
                    if re.search(r"\b" + re.escape(call) + r"\b", line):
                        offenders.append(f"{rel(p)}:{i}: {line.strip()}")
        assert not offenders, "unix-only calls in shipped code: " + "; ".join(offenders)


# ===========================================================================
# 2. os.chmod with unix bits -- must stay behind a platform check
# ===========================================================================
class TestChmodGuard:
    def test_every_os_chmod_is_behind_a_nt_check(self):
        """os.chmod(0o755) is a no-op on Windows but the call itself is fine there;
        the real risk is that a future edit drops the `if os.name != \"nt\"` guard and
        chmod starts raising on the auto-download path. Assert the guard is present."""
        offenders = []
        checked = 0
        for p in shipped_files():
            tree = _tree(p)
            parents = _parent_map(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "chmod"):
                    continue
                if not (isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"):
                    continue
                checked += 1
                guarded = any(
                    "os.name" in ast.unparse(ifnode.test)
                    and ("nt" in ast.unparse(ifnode.test)
                         or "posix" in ast.unparse(ifnode.test))
                    for ifnode in _ancestor_ifs(node, parents))
                if not guarded:
                    offenders.append(f"{rel(p)}:{node.lineno}")
        assert checked > 0, "expected at least one os.chmod in the auto-download path"
        assert not offenders, f"os.chmod not guarded by a platform check: {offenders}"

    def test_console_hardening_is_windows_guarded(self):
        """The ctypes windll SetConsoleOutputCP call only exists on Windows and must
        stay inside the os.name == \"nt\" branch."""
        tree = _tree(os.path.join(ROOT, "bytephisher.py"))
        parents = _parent_map(tree)
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "SetConsoleOutputCP"]
        assert calls, "expected the Windows console-codepage call to be present"
        for c in calls:
            assert any("nt" in ast.unparse(i.test)
                       for i in _ancestor_ifs(c, parents)), \
                "SetConsoleOutputCP is no longer behind an os.name == 'nt' guard"


# ===========================================================================
# 3. Signals -- Windows has no SIGKILL and no fork; the shutdown must not need them
# ===========================================================================
# signal() on Windows accepts only SIGABRT/SIGFPE/SIGILL/SIGINT/SIGSEGV/SIGTERM/SIGBREAK.
WINDOWS_OK_SIGNALS = {"SIGINT", "SIGTERM", "SIGBREAK", "SIGABRT", "SIGFPE",
                      "SIGILL", "SIGSEGV"}


class TestSignals:
    def test_no_sigkill_reference(self):
        """signal.SIGKILL does not exist on Windows -> AttributeError at import/run."""
        offenders = []
        for p in shipped_files():
            for i, line in enumerate(_read(p).splitlines(), 1):
                if re.search(r"\bsignal\.SIGKILL\b", line):
                    offenders.append(f"{rel(p)}:{i}")
        assert not offenders, f"signal.SIGKILL used in shipped code: {offenders}"

    def test_signal_handlers_use_windows_portable_constants(self):
        offenders = []
        for p in shipped_files():
            tree = _tree(p)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "signal"):
                    continue
                if not (isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "signal"):
                    continue
                if not node.args:
                    continue
                sig = node.args[0]
                name = sig.attr if isinstance(sig, ast.Attribute) else None
                if name is None or name not in WINDOWS_OK_SIGNALS:
                    offenders.append(f"{rel(p)}:{node.lineno}: {ast.unparse(sig)}")
        assert not offenders, f"non-portable signal handler(s): {offenders}"

    def test_shutdown_does_not_require_a_posix_signal(self):
        """On Windows SIGTERM is never delivered by Ctrl+C; the live loop must also
        exit on the in-process stop flag and on KeyboardInterrupt, so shutdown is
        reachable there."""
        src = _read(os.path.join(ROOT, "bytephisher.py"))
        assert "stop[\"flag\"]" in src, "the stop flag the live loop polls is gone"
        assert "except KeyboardInterrupt" in src, \
            "Ctrl+C on Windows raises KeyboardInterrupt and must be handled"
        # SIGINT is the one signal Windows does deliver for Ctrl+C.
        assert "signal.SIGINT" in src


# ===========================================================================
# 4. External binaries -- every tunneler must fail cleanly when it is absent
# ===========================================================================
class TestExternalBinaries:
    @pytest.fixture()
    def no_binaries(self, monkeypatch, tmp_path):
        """Make every external binary unreachable AND every auto-download fail, the
        way a fresh Termux/Windows box looks before anything is installed."""
        import tunnels
        monkeypatch.chdir(tmp_path)                       # keep logs/ out of the repo
        monkeypatch.setattr(tunnels.shutil, "which", lambda name: None)

        def _no_net(*a, **k):
            raise OSError("network disabled for the test")
        monkeypatch.setattr(urllib.request, "urlretrieve", _no_net)
        monkeypatch.setattr(urllib.request, "urlopen", _no_net)
        return tunnels

    def test_every_tunneler_returns_none_without_its_binary(self, no_binaries):
        """A missing binary must yield None + a reason string, never a traceback."""
        for name, cls in no_binaries.REGISTRY.items():
            t = cls(8080)
            result = t.start()          # must not raise
            assert result is None, f"{name}.start() returned {result!r} with no binary"
            assert isinstance(t.reason, str)

    def test_run_all_degrades_cleanly_when_start_raises(self, no_binaries, monkeypatch):
        """`-t all` must survive a tunneler that blows up mid-launch: the operator
        still gets the others. (run_one, the single-tunnel path, is NOT wrapped --
        reported as a defect; this test pins the safe path.)"""
        def _boom(self):
            raise RuntimeError(f"{self.name} exploded")

        for cls in no_binaries.REGISTRY.values():
            monkeypatch.setattr(cls, "start", _boom)
        results = no_binaries.run_all(8080)     # must not raise
        assert set(results) == set(no_binaries.REGISTRY)
        assert all(v is None for v in results.values())

    def test_playwright_absence_is_handled(self, tmp_path):
        """The browser takeover path imports playwright lazily and must return a
        result dict with a hint, not raise ImportError at the operator."""
        from core import session
        src = _read(os.path.join(ROOT, "core", "session.py"))
        assert "playwright not installed" in src, \
            "the guarded playwright import / friendly error is gone"
        # dry_run returns before the browser is touched -- prove no browser is needed.
        rec = {"sid": "x", "cookies": []}
        result = session.run_task(rec, "probe", outdir=str(tmp_path / "takeover"),
                                  dry_run=True)
        assert isinstance(result, dict) and result.get("dry_run") is True


# ===========================================================================
# 5. Path handling -- writers create their parent directory; exports degrade cleanly
# ===========================================================================
class TestPathHandling:
    def test_capture_db_creates_its_parent_directory(self, tmp_path):
        from core import capture
        target = tmp_path / "deep" / "nested" / "store.sqlite"
        capture.CaptureDB(str(target))
        assert target.is_file()

    def test_keepalive_state_creates_its_parent_directory(self, tmp_path):
        from core import keepalive
        target = tmp_path / "a" / "b" / "state.json"
        ka = keepalive.KeepAlive("tok", client_id="cid", state_path=str(target))
        ka.save()
        assert target.is_file()

    def test_takeover_outdir_is_created(self, tmp_path):
        from core import session
        outdir = tmp_path / "x" / "y"
        session.run_task({"sid": "s1", "cookies": []}, "probe",
                         outdir=str(outdir), dry_run=True)
        assert outdir.is_dir()

    def test_export_to_a_missing_directory_never_traces_back(self, tmp_path):
        """DEFECT (reported): CaptureDB.export_json/export_csv do not create their
        parent dir, so `--export nested/out.json` raises FileNotFoundError in the
        library. The CLI wraps the call in _clean_error, so the operator sees one
        line and exit 2, not a traceback -- that contract is what this test pins.
        If the writers start creating the parent, the export succeeds and the test
        still passes."""
        import bytephisher
        from core import capture
        db = capture.CaptureDB(str(tmp_path / "store.sqlite"))
        for name, ext in (("export_json", "json"), ("export_csv", "csv")):
            target = str(tmp_path / "missing" / "dir" / f"out.{ext}")
            result = bytephisher._clean_error(getattr(db, name), target)
            assert result is None or os.path.isfile(target), \
                f"{name} neither created {target} nor was reported cleanly"


# ===========================================================================
# 6. Encoding -- explicit encodings on every text open; ASCII-only sources
# ===========================================================================
class TestEncoding:
    def test_no_builtin_open_in_text_mode_without_encoding(self):
        """Every text-mode file open must pass encoding= (a bare open() uses the
        locale default, which is cp1252 on Windows and mangles captured UTF-8)."""
        offenders = []
        for p in shipped_files():
            try:
                tree = _tree(p)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "open"):
                    continue
                has_enc = any(k.arg == "encoding" for k in node.keywords)
                mode = "r"
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for k in node.keywords:
                    if k.arg == "mode" and isinstance(k.value, ast.Constant):
                        mode = str(k.value.value)
                if not has_enc and "b" not in mode:
                    offenders.append(f"{rel(p)}:{node.lineno} (mode={mode!r})")
        assert not offenders, f"text-mode open() without encoding=: {offenders}"

    def test_shipped_sources_are_ascii(self):
        """A non-ASCII literal in shipped code crashes a cp437 Windows console; the
        one documented data file is allowlisted (see tests/test_portability.py)."""
        offenders = {}
        for p in shipped_files():
            if rel(p) in ASCII_DATA_ALLOWLIST:
                continue
            with open(p, "rb") as fh:
                raw = fh.read()
            bad = sorted({b for b in raw if b > 127})
            if bad:
                offenders[rel(p)] = bytes(bad[:20])
        assert not offenders, f"non-ASCII bytes in shipped code: {offenders}"

    def test_export_csv_is_written_as_utf8_with_bom(self, tmp_path):
        """The CSV export is opened utf-8-sig so Excel on Windows detects UTF-8
        instead of mis-decoding captured names as cp1252."""
        from core import capture
        db = capture.CaptureDB(str(tmp_path / "store.sqlite"))
        out = tmp_path / "out.csv"
        db.export_csv(str(out))
        with open(out, "rb") as fh:
            head = fh.read(3)
        assert head == b"\xef\xbb\xbf", "CSV export lost its UTF-8 BOM"


# ===========================================================================
# 7. Hardcoded Unix filesystem paths in shipped code
# ===========================================================================
class TestNoHardcodedUnixPaths:
    def test_no_hardcoded_tmp_root_dev_or_proc_paths(self):
        """'/' is the Windows separator and /tmp, /root, /dev, /proc, /home do not
        exist on Windows. None may be a literal in shipped code.
        (core/exploits.py carries /etc/passwd and /usr/bin/id, but those are exploit
        *payload* strings sent to a target -- verified as data, not local I/O.)"""
        rx = re.compile(r"['\"]/(?:tmp|root|dev|proc|home)(?:/[^'\"]*)?['\"]")
        offenders = []
        for p in shipped_files():
            for i, line in enumerate(_read(p).splitlines(), 1):
                if rx.search(line):
                    offenders.append(f"{rel(p)}:{i}: {line.strip()}")
        assert not offenders, f"hardcoded unix paths: {offenders}"


# ===========================================================================
# 8. The auto-download maps must cover the owner's targets (Termux + Apple Silicon)
# ===========================================================================
class TestDownloadMaps:
    def test_cloudflared_map_covers_termux_and_apple_silicon(self):
        """Termux/Android reports sys.platform='linux', machine='aarch64'; Apple
        Silicon reports 'darwin'/'arm64'. Both must be in the download map or the
        auto-download path returns False on the owner's own devices."""
        from tunnels import Cloudflared
        assert "linux-arm64" in Cloudflared.DOWNLOADS       # Termux / ARM Linux
        assert "darwin-arm64" in Cloudflared.DOWNLOADS      # Apple Silicon
        assert "linux-amd64" in Cloudflared.DOWNLOADS

    def test_cloudflared_key_resolves_on_this_host(self):
        """_key() must produce a key the map knows on whatever OS this runs on --
        a mismatch means silent auto-download failure."""
        from tunnels import Cloudflared
        key = Cloudflared(8080)._key()
        if key.startswith("linux") or key.startswith("darwin"):
            assert key in Cloudflared.DOWNLOADS, f"unmapped key {key!r}"
        else:
            # Windows: no prebuilt in the map, and ensure_binary must then just
            # return False (clean), which TestExternalBinaries already pins.
            assert Cloudflared.DOWNLOADS.get(key) is None

    def test_resolve_home_returns_an_absolute_directory(self):
        """HOME resolution must not assume a Unix layout: it returns an absolute,
        existing directory and falls back to CWD rather than a hardcoded path."""
        import bytephisher
        home = bytephisher.resolve_home()
        assert os.path.isabs(home)
        assert os.path.isdir(home)

