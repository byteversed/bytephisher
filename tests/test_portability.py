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
        files = code_files()
        assert len(files) >= 50, f"only {len(files)} files were parsed"
        for p in files:
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


class TestTheScanCoversTheWholeShippedTree:
    """The ASCII invariant must cover the shipped code, not a hand-picked list.

    The scan used to be able to hide a file two ways - a directory in SKIP_DIRS that
    later grew shipped code, or the ``basename.startswith("test_")`` filter dropping a
    shipped module that happens to be named like a test. These guards fail the moment a
    shipped ``.py`` stops being scanned, instead of passing quietly.
    """

    def _shipped_py(self):
        """Every ``.py`` outside the test tree, found independently of code_files()."""
        out = set()
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "__pycache__",
                                                     "node_modules"}]
            for f in files:
                if not f.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(root, f), ROOT)
                if rel.startswith("tests" + os.sep):
                    continue
                out.add(rel)
        return out

    def test_every_shipped_python_file_is_scanned(self):
        shipped = self._shipped_py()
        covered = {os.path.relpath(p, ROOT) for p in code_files()}
        missing = sorted(shipped - covered)
        assert not missing, (
            f"shipped .py the ASCII invariant never opens: {missing} "
            f"(add it to code_files() or to DATA_FILES with a reason)")

    def test_the_entry_point_and_every_core_module_are_scanned(self):
        covered = {os.path.relpath(p, ROOT) for p in code_files()}
        assert "bytephisher.py" in covered, "the CLI entry point must be scanned"
        core = {f"core/{f}" for f in os.listdir(os.path.join(ROOT, "core"))
                if f.endswith(".py")}
        assert core <= covered, f"core modules not scanned: {sorted(core - covered)}"


DOCS_ROOT = os.path.join(ROOT, "docs")
ROOT_DOCS = ("README.md", "CHANGELOG.md")


def doc_files():
    """Every shipped document: the two at the root plus every .md under docs/."""
    out = [os.path.join(ROOT, name) for name in ROOT_DOCS
           if os.path.isfile(os.path.join(ROOT, name))]
    for root, dirs, files in os.walk(DOCS_ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        out.extend(os.path.join(root, f) for f in files if f.endswith(".md"))
    return sorted(out)


class TestTheDocumentsAreAscii:
    """A document is read in an editor, a terminal and a diff on three platforms, and a
    box-drawing character or a smart quote survives none of them intact."""

    def test_the_scan_finds_the_documents(self):
        """Guards the check below against passing because it opened nothing."""
        found = doc_files()
        names = {os.path.basename(p) for p in found}
        assert "README.md" in names and "ARCHITECTURE.md" in names
        assert len(found) >= 8, f"the document scan found only {len(found)} files"

    def test_every_document_is_pure_ascii(self):
        offenders = {}
        for path in doc_files():
            bad = sorted({c for c in open(path, encoding="utf-8").read() if ord(c) > 127})
            if bad:
                offenders[os.path.relpath(path, ROOT)] = [f"U+{ord(c):04X}" for c in bad]
        assert not offenders, f"non-ASCII in shipped documents: {offenders}"


class TestTheSuiteRunnerClassifiesItsFiles:
    """run_all.py runs every tests/test_*.py. A standalone self-test defines no pytest
    tests and carries a __main__ block, and it also imports pytest to declare its tier:
    keying on `import pytest` alone sent it through pytest, which collected nothing and
    reported the module as a failure."""

    @staticmethod
    def _runner():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bp_run_all_under_test", os.path.join(ROOT, "tests", "run_all.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_self_test_is_a_script_and_a_module_is_a_module(self):
        runner = self._runner()
        assert runner._kind(os.path.join(ROOT, "tests", "test_e2e.py")) == "script"
        assert runner._kind(os.path.join(ROOT, "tests", "test_totp.py")) == "pytest"

    def test_the_rule_agrees_with_what_each_file_actually_contains(self):
        """Every test file that defines no test function and no Test class must be a
        script, and every file that defines one must be a module."""
        import re
        runner = self._runner()
        for name in sorted(os.listdir(os.path.join(ROOT, "tests"))):
            if not (name.startswith("test_") and name.endswith(".py")):
                continue
            path = os.path.join(ROOT, "tests", name)
            body = open(path, encoding="utf-8").read()
            defines_tests = bool(re.search(r"^def test_|^class Test", body, re.M))
            kind = runner._kind(path)
            assert kind == ("pytest" if defines_tests else "script"), f"{name} -> {kind}"
