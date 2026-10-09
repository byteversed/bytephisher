"""Cross-platform invariants, enforced statically.

The toolkit claims Linux/macOS/Windows/Termux support. These tests check the
properties that actually break on Windows, by inspecting the shipped code with
the AST rather than by trusting a README:

  * every text-mode open() names an encoding (the platform default is cp1252 on
    Windows, so a non-ASCII captured value would raise on write),
  * no POSIX-only module is imported,
  * no POSIX absolute path is hardcoded,
  * os.chmod (a no-op on Windows) is guarded by an os.name check,
  * no shell=True subprocess call,
  * every shipped module imports on this interpreter.

Run:  ./.venv/bin/python -m pytest tests/test_crossplatform.py -v
"""
import ast
import os
import subprocess
import sys

import pytest

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.unit


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable

POSIX_MODULES = {"fcntl", "termios", "pty", "pwd", "grp", "resource", "tty",
                 "posix", "crypt", "syslog", "nis"}
POSIX_PATHS = ("/tmp/", "/etc/", "/usr/", "/var/", "/bin/sh", "/dev/null",
               "/proc/", "/sys/", "/opt/")
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "data", "logs",
             "docs", "templates"}


def shipped_files():
    out = []
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, ROOT)
            if rel.startswith("tests" + os.sep) or os.path.basename(p).startswith("test_"):
                continue
            out.append(p)
    return sorted(out)


def trees():
    return [(p, ast.parse(open(p, encoding="utf-8").read(), filename=p))
            for p in shipped_files()]


class TestFileEncodings:
    def test_text_open_calls_name_an_encoding(self):
        """A write without encoding= uses cp1252 on Windows and raises on any
        non-ASCII value that came from a victim."""
        offenders = []
        for path, tree in trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                # builtin open() only: tarfile.open/gzip.open take their own
                # modes and are not text file handles
                if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
                    continue
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                if "b" in mode:                      # binary needs no encoding
                    continue
                has_enc = any(kw.arg == "encoding" for kw in node.keywords)
                if not has_enc:
                    offenders.append(f"{os.path.relpath(path, ROOT)}:{node.lineno}")
        assert not offenders, f"open() without encoding: {offenders}"

    def test_file_writes_are_utf8(self):
        """CSV export must survive a non-ASCII value; utf-8-sig also keeps Excel
        happy on Windows."""
        src = open(os.path.join(ROOT, "core", "capture.py"), encoding="utf-8").read()
        # 'utf-8-sig' already implies 'utf-8': the second assertion proved nothing
        assert 'encoding="utf-8-sig"' in src


class TestPosixOnlyCode:
    def test_no_posix_only_imports(self):
        offenders = []
        for path, tree in trees():
            rel = os.path.relpath(path, ROOT)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    offenders += [f"{rel}:{node.lineno} {a.name}" for a in node.names
                                  if a.name.split(".")[0] in POSIX_MODULES]
                elif (isinstance(node, ast.ImportFrom) and node.module
                      and node.module.split(".")[0] in POSIX_MODULES):
                    offenders.append(f"{rel}:{node.lineno} {node.module}")
        assert not offenders, f"POSIX-only imports: {offenders}"

    def test_no_hardcoded_posix_paths(self):
        """A path this tool opens or runs must not be hardcoded.

        The rule is about the tool's OWN file and process handling: a POSIX path
        inside a payload the tool sends to a target (the exploit library reads
        /etc/shadow on the victim, not here) is data, not a portability problem.
        So only strings that reach a file/process API are checked - as an
        argument, a default, or an assignment that is later used as one.
        """
        file_apis = {"open", "join", "exists", "isfile", "isdir", "listdir", "makedirs",
                     "remove", "unlink", "rmtree", "copy", "copy2", "move", "walk",
                     "run", "Popen", "check_output", "check_call", "abspath", "dirname",
                     "basename", "realpath", "chmod", "glob", "splitext"}
        offenders = []
        for path, tree in trees():
            rel = os.path.relpath(path, ROOT)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name not in file_apis:
                    continue
                for arg in list(node.args) + [k.value for k in node.keywords
                                              if k.arg is not None]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        v = arg.value
                        if any(v.startswith(p) or f" {p}" in v for p in POSIX_PATHS):
                            offenders.append(f"{rel}:{node.lineno} {name}('{v[:50]}')")
        assert not offenders, f"hardcoded POSIX paths: {offenders}"

    def test_chmod_is_guarded(self):
        src = open(os.path.join(ROOT, "tunnels", "__init__.py"), encoding="utf-8").read()
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if "os.chmod(" not in line:
                continue
            # The guard must come BEFORE the call: a mention after it (a comment, a
            # later branch) must not satisfy this check.
            before = "\n".join(lines[max(0, i - 6):i])
            assert 'os.name != "nt"' in before, \
                f"os.chmod without a Windows guard before line {i + 1}"

    def test_no_shell_true(self):
        offenders = []
        for path, tree in trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True for kw in node.keywords):
                    offenders.append(f"{os.path.relpath(path, ROOT)}:{node.lineno}")
        assert not offenders, f"shell=True subprocess calls: {offenders}"


class TestImportsCleanly:
    @pytest.mark.parametrize("module", [
        "core.capture", "core.classify", "core.gate", "core.risk", "core.intel",
        "core.net", "core.templates", "core.alerts", "core.lures",
        "core.phishlet", "core.tls_fp", "core.session", "core.ops", "core.forge",
        "core.server", "core.proxy", "dashboard", "mailer", "tunnels",
    ])
    def test_module_imports(self, module):
        p = subprocess.run([PY, "-c", f"import {module}"], cwd=ROOT,
                           capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, f"{module}: {p.stderr[-400:]}"

    def test_tools_import(self):
        for tool in ("doctor", "import_site", "gen_templates", "probe_tunnels",
                     "stress"):
            p = subprocess.run([PY, "-c", f"import tools.{tool}"], cwd=ROOT,
                               capture_output=True, text=True, timeout=120)
            assert p.returncode == 0, f"tools.{tool}: {p.stderr[-400:]}"


class TestCliOnAForeignConsole:
    @pytest.mark.parametrize("codepage", ["cp1252", "cp437", "ascii"])
    def test_cli_survives_a_legacy_console(self, codepage):
        env = dict(os.environ, PYTHONIOENCODING=codepage)
        for args in (["--help"], ["--version"], ["--list"], ["--tasks"],
                     ["--lures"], ["--sessions"], ["--scanners"]):
            p = subprocess.run([PY, "bytephisher.py"] + args, cwd=ROOT, env=env,
                               capture_output=True, timeout=180)
            assert p.returncode == 0, (f"{args} under {codepage}: "
                                       f"{p.stderr.decode('utf-8', 'replace')[-300:]}")

    def test_paths_are_built_with_os_path(self):
        """No module should join paths with a literal separator."""
        offenders = []
        for path, tree in trees():
            src = open(path, encoding="utf-8").read().split("\n")
            for node in ast.walk(tree):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    line = src[node.lineno - 1]
                    if re_add_path(line):
                        offenders.append(f"{os.path.relpath(path, ROOT)}:{node.lineno} {line.strip()[:70]}")
        assert not offenders, f"string-built paths: {offenders}"


def re_add_path(line):
    """Heuristic: a line adding a quoted '/' to something in a path context."""
    import re
    if re.search(r"os\.path|Path\(|open\(|makedirs|isfile|isdir|exists", line):
        return bool(re.search(r"\+\s*['\"][^'\"]*/[^'\"]*['\"]", line))
    return False
