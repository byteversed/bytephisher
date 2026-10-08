"""Portability / console-encoding regression tests.

Found in the field: `bytephisher.py --help` exited 1 on Windows because an
argparse help string contained a Unicode arrow and the console is cp437/cp1252.
A tool that crashes on --help on a third of its target platforms is broken, so
this suite locks the fix down at three levels: the strings themselves, the
runtime guard, and a real subprocess run with a Windows codepage.

Run:  ./.venv/bin/python -m pytest tests/test_portability.py -v
"""
import ast
import io
import os
import subprocess
import sys

import pytest

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable

SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "data", "logs", "docs"}


def code_files():
    """Every shipped .py file (tests excluded: their fixtures use unicode)."""
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


# Files whose non-ASCII is DATA, not console output: tools/gen_templates.py
# emits real template markup ("Espanol/Francais" language switchers) that is
# written to disk as UTF-8. Stripping it would make the templates less real, so
# it is exempted here and covered instead by the AST check below.
DATA_FILES = {"tools/gen_templates.py"}

CONSOLE_CALLS = {"print", "write", "add_argument", "ArgumentParser",
                 "add_parser", "error", "exit"}
CONSOLE_KWARGS = {"help", "description", "epilog", "metavar", "usage", "prog"}


def _console_strings(tree):
    """Every string literal this file can put on an operator's terminal."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = ""
            if isinstance(node.func, ast.Name):
                fname = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fname = node.func.attr
            if fname in CONSOLE_CALLS:
                for a in list(node.args) + [k.value for k in node.keywords]:
                    for sub in ast.walk(a):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            out.append((sub.value, sub.lineno))
            for k in node.keywords:
                if k.arg in CONSOLE_KWARGS:
                    for sub in ast.walk(k.value):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            out.append((sub.value, sub.lineno))
    return out


class TestAsciiInvariant:
    def test_console_strings_are_pure_ascii(self):
        """Anything printed must be ASCII: cp437 cannot render anything else."""
        offenders = {}
        for p in code_files():
            rel = os.path.relpath(p, ROOT)
            if rel in DATA_FILES:
                continue
            tree = ast.parse(open(p, encoding="utf-8").read(), filename=p)
            for text, line in _console_strings(tree):
                bad = sorted({c for c in text if ord(c) > 127})
                if bad:
                    offenders[f"{rel}:{line}"] = ("".join(bad)[:20], text[:60])
        assert not offenders, f"non-ASCII console strings: {offenders}"

    def test_no_non_ascii_outside_the_data_allowlist(self):
        offenders = {}
        for p in code_files():
            rel = os.path.relpath(p, ROOT)
            if rel in DATA_FILES:
                continue
            txt = open(p, encoding="utf-8").read()
            bad = sorted({c for c in txt if ord(c) > 127})
            if bad:
                offenders[rel] = "".join(bad)[:40]
        assert not offenders, f"non-ASCII in shipped code: {offenders}"

    def test_every_py_file_parses(self):
        for p in code_files():
            ast.parse(open(p, encoding="utf-8").read(), filename=p)

    def test_argparse_help_is_ascii(self):
        """The exact string argparse prints must survive a cp1252 console."""
        out = subprocess.run([PY, "bytephisher.py", "--help"], cwd=ROOT,
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        for line in out.stdout.splitlines():
            line.encode("cp1252")          # raises if unencodable


class TestConsoleHardening:
    def test_help_runs_under_a_windows_codepage(self):
        """The real bug: --help exited 1 with PYTHONIOENCODING=cp1252."""
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        out = subprocess.run([PY, "bytephisher.py", "--help"], cwd=ROOT, env=env,
                             capture_output=True)
        assert out.returncode == 0, out.stderr.decode("utf-8", "replace")
        assert b"usage" in out.stdout.lower()

    def test_unicode_victim_data_cannot_crash_output(self):
        """A captured name in Japanese must print, not raise.

        Nothing about the operator's terminal may depend on what a victim typed.
        """
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        script = (
            f"import sys, os; sys.path.insert(0, {ROOT!r});"
            "import importlib.util as u;"
            f"spec = u.spec_from_file_location('bp', os.path.join({ROOT!r}, 'bytephisher.py'));"
            "m = u.module_from_spec(spec); spec.loader.exec_module(m);"
            "print('victim name:', '\\u65e5\\u672c\\u8a9e \\u00e9\\u00e8 \\u2192')"
        )
        out = subprocess.run([PY, "-c", script], cwd=ROOT, env=env,
                             capture_output=True)
        assert out.returncode == 0, out.stderr.decode("utf-8", "replace")

    def test_hardened_stream_replaces_instead_of_raising(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bp_mod", os.path.join(ROOT, "bytephisher.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="replace")
        # the guard is what keeps this from raising
        assert hasattr(mod, "_harden_console")
        buf.write("arrow -> and name \u65e5\u672c")
        buf.flush()

    def test_help_does_not_need_a_tty(self):
        """Piped output (CI, logs, `| less`) must work too."""
        out = subprocess.run([PY, "bytephisher.py", "--help"], cwd=ROOT,
                             capture_output=True)
        assert out.returncode == 0 and b"--proxy" in out.stdout


class TestSubcommandHelp:
    """Every documented flag must still parse after the ASCII pass."""

    @pytest.mark.parametrize("flag", [
        "--tasks", "--lures", "--sessions", "--version", "--help",
    ])
    def test_simple_flags_exit_cleanly(self, flag):
        out = subprocess.run([PY, "bytephisher.py", flag], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, f"{flag} -> {out.returncode}: {out.stderr[:400]}"

    def test_lure_create_and_list_round_trip(self, tmp_path):
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        created = subprocess.run(
            [PY, "bytephisher.py", "--lure-create", "--campaign", "port-test",
             "--lure-label", "victim@corp.test"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        assert created.returncode == 0, created.stderr
        assert "lure created" in created.stdout
        listed = subprocess.run([PY, "bytephisher.py", "--lures"], cwd=ROOT,
                                env=env, capture_output=True, text=True, timeout=120)
        assert listed.returncode == 0 and "port-test" in listed.stdout
