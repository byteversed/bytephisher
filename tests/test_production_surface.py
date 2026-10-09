"""The production surface: the edge cases an operator actually hits.

Everything here drives the REAL CLI (`bytephisher.py`) as a subprocess, because the
failures that hurt in the field are the ones at the process boundary - a flag given
without its companion, a path that is a directory, a port already taken, a value out of
range, a URL with no scheme. Each case asserts the operator-facing contract: a non-zero
exit and one ``[bytephisher] ...`` line, never a raw traceback, and never a hang.

The one rule the assertions follow: assert on the exit code and the message, never on a
traceback being present. A serve flag given alone must refuse - it must not fall into the
interactive template picker, which calls ``input()`` and blocks forever on a phone or an
SSH TTY while the operator believes the command ran.

Run:  ./.venv/bin/python -m pytest tests/test_production_surface.py -q
"""
import os
import re
import select
import socket
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = HERE
PY = sys.executable
CLI = os.path.join(ROOT, "bytephisher.py")
TIMEOUT = 20

# tier marker: the Makefile and pyproject document `pytest -m integration`
pytestmark = pytest.mark.integration


# --------------------------------------------------------------------- helpers
def _env(home=None):
    """The environment for a CLI subprocess, pinned to a home (default: the repo).

    A test that can write seeds a temporary home so the developer's
    ``data/bytephisher.db`` is never touched.
    """
    env = dict(os.environ)
    env["BYTEPHISHER_HOME"] = str(home or ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_cli(*args, home=None, timeout=TIMEOUT):
    """Run the CLI with stdin closed (EOF), capture everything, hard timeout."""
    return subprocess.run([PY, CLI, *args], cwd=ROOT, env=_env(home),
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)


def text_of(p):
    return ((p.stdout or b"").decode("utf-8", "replace")
            + (p.stderr or b"").decode("utf-8", "replace"))


def assert_refusal(p, *needles):
    """The contract for every case below: non-zero exit, one clean line, no traceback."""
    t = text_of(p)
    assert p.returncode != 0, (
        f"expected a non-zero exit, got {p.returncode}:\n{t[-600:]}")
    assert "Traceback" not in t, (
        f"a raw traceback reached the operator:\n{t[-1800:]}")
    assert "[bytephisher]" in t, (
        f"no operator-facing '[bytephisher] ...' line:\n{t[-600:]}")
    for n in needles:
        assert n.lower() in t.lower(), (
            f"expected {n!r} in the message:\n{t[-600:]}")


def temp_home(tmp_path):
    """A writable BYTEPHISHER_HOME whose templates/ are the repo's (via a symlink)."""
    home = tmp_path / "home"
    (home / "data").mkdir(parents=True)
    os.symlink(os.path.join(ROOT, "templates"), str(home / "templates"))
    cfg = os.path.join(ROOT, "config")
    if os.path.isdir(cfg):
        os.symlink(cfg, str(home / "config"))
    return home


def hold_a_port():
    """Bind a real port and keep it held so the CLI cannot take it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


# ==================================================== missing companion flags ==
class TestAMissingCompanionFlagIsRefused:
    """A flag whose companion is absent must say so, not fall into the picker."""

    def test_inbox_without_a_host_and_user(self):
        assert_refusal(run_cli("--inbox"), "IMAP")

    def test_tls_without_a_certificate(self):
        assert_refusal(run_cli("--tls"), "cert")

    def test_tls_with_a_missing_certificate_file(self):
        assert_refusal(run_cli("--tls", "--cert", "/nonexistent-bp-xyz.pem"), "cert")

    def test_proxy_without_a_phishlet_or_upstream(self):
        assert_refusal(run_cli("--proxy", "--phishlet", "/nonexistent-bp-xyz.yaml"),
                       "phishlet")

    def test_golden_forge_without_its_inputs(self):
        assert_refusal(run_cli("--golden-forge"), "needs")

    def test_saml_assert_without_issuer_and_audience(self):
        assert_refusal(run_cli("--saml-assert", "a@b.test"), "saml")

    def test_heartbeat_check_without_a_file(self):
        assert_refusal(run_cli("--heartbeat-check"), "heartbeat")

    def test_ldap_filter_without_a_host(self):
        assert_refusal(run_cli("--ldap-filter", "(cn=*)"), "--ldap")

    def test_roast_spn_without_a_user(self):
        assert_refusal(run_cli("--roast-spn", "HTTP/web"), "--roast")

    def test_shadow_write_without_ldap(self):
        assert_refusal(run_cli("--shadow-write", "attr"), "--ldap")

    def test_pool_command_without_a_pool_file(self):
        assert_refusal(run_cli("--pool-status"), "--pool")

    def test_adcs_esc_ldap_without_a_host(self):
        assert_refusal(run_cli("--adcs-esc", "ldap"), "--ldap")

    def test_devicecode_without_a_client_id(self):
        assert_refusal(run_cli("--devicecode", "azure"), "--dc-client-id")


# ================================================= a path that is a directory ==
class TestADirectoryWhereAFileIsExpected:
    def test_export_to_a_directory(self, tmp_path):
        assert_refusal(run_cli("--export", str(tmp_path)), "directory")

    def test_intel_export_to_a_directory(self, tmp_path):
        assert_refusal(run_cli("--intel-export", str(tmp_path)), "directory")

    def test_session_export_to_a_directory(self, tmp_path):
        home = temp_home(tmp_path)
        ck = tmp_path / "cookies.json"
        ck.write_text('[{"name": "a", "value": "b", "domain": ".x.test", "path": "/"}]')
        imp = run_cli("--session-import", str(ck), home=home)
        assert imp.returncode == 0, text_of(imp)
        m = re.search(r"imported session (\S+)", text_of(imp))
        assert m, text_of(imp)
        assert_refusal(run_cli("--session-export", m.group(1), str(tmp_path), home=home),
                       "directory")

    def test_pool_add_to_a_directory(self, tmp_path):
        assert_refusal(run_cli("--pool", str(tmp_path), "--pool-add", "x"), "pool")

    def test_pool_status_is_read_only(self, tmp_path):
        """--pool-status must not rewrite the pool file it only reads."""
        home = temp_home(tmp_path)
        pool = tmp_path / "pool.json"
        add = run_cli("--pool", str(pool), "--pool-add", "a.example,b.example", home=home)
        assert add.returncode == 0, text_of(add)
        before = pool.read_bytes()
        st = run_cli("--pool", str(pool), "--pool-status", home=home)
        assert st.returncode == 0, text_of(st)
        assert pool.read_bytes() == before, "reading the pool rewrote it"

    def test_pool_status_on_a_directory_is_not_a_silent_success(self, tmp_path):
        """A directory is not a pool file: reading it must refuse, not print an empty pool."""
        assert_refusal(run_cli("--pool", str(tmp_path), "--pool-status"), "pool")


# ====================================================== a nonexistent file =====
class TestANonexistentFileIsReported:
    def test_a_missing_input_file(self):
        assert_refusal(run_cli("--cohorts", "/nonexistent-bp-xyz/a.json"), "no such file")


# ====================================================== a port already in use ==
class TestAPortAlreadyInUse:
    def test_the_campaign_listener_reports_the_bind_failure(self, tmp_path):
        home = temp_home(tmp_path)
        s, port = hold_a_port()
        try:
            assert_refusal(
                run_cli("-o", "google", "-m", "test", "-p", str(port), home=home),
                "in use")
        finally:
            s.close()

    def test_the_web_dashboard_does_not_claim_success_on_a_dead_port(self, tmp_path):
        """The bind happens in a daemon thread: a dead port must not be printed as success.

        The port is held bound but with nothing listening, so the dashboard's bind fails
        and its own readiness probe finds no server: the CLI must report the failure, not
        print a URL for a dashboard that is not there.
        """
        home = temp_home(tmp_path)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        try:
            p = subprocess.Popen(
                [PY, CLI, "-o", "google", "--web-dashboard", "--web-port", str(port)],
                cwd=ROOT, env=_env(home), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            buf = _drain_until(p, (b"web dashboard",), timeout=15)
            if p.poll() is None:
                p.kill()
            p.wait()
        finally:
            s.close()
        t = buf.decode("utf-8", "replace")
        assert "web dashboard: http://" not in t, (
            f"claimed the dashboard was up on a dead port:\n{t[-800:]}")
        assert "Traceback" not in t, f"a raw traceback reached the operator:\n{t[-800:]}"
        assert ("in use" in t.lower() or "failed" in t.lower()), (
            f"the dashboard bind failure was not reported:\n{t[-800:]}")


def _drain_until(p, markers, timeout):
    """Read the child's stdout until a marker line appears or the deadline passes."""
    buf = b""
    deadline = time.time() + timeout
    fd = p.stdout.fileno()
    while time.time() < deadline:
        rl, _, _ = select.select([fd], [], [], 0.5)
        if rl:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buf += chunk
            if any(m in buf for m in markers):
                # the verdict line is in; give the process a beat to flush the rest
                time.sleep(0.4)
                rl, _, _ = select.select([fd], [], [], 0.3)
                if rl:
                    buf += os.read(fd, 4096)
                break
        if p.poll() is not None:
            break
    return buf


# ======================================================= a value out of range ==
class TestAValueOutOfRange:
    def test_a_port_above_the_range(self):
        assert_refusal(run_cli("-p", "99999"), "65535")

    def test_a_negative_port(self):
        assert_refusal(run_cli("-p", "-1"), "65535")

    def test_a_negative_web_port(self):
        assert_refusal(run_cli("--web-port", "-1"), "65535")


# =========================================================== URL with no scheme ==
class TestABareHostIsNormalizedNotReportedUnreachable:
    """`unknown url type` is not a reachability verdict: a bare host must be normalized."""

    def test_adcs_probe_assumes_http(self):
        p = run_cli("--adcs-probe", "127.0.0.1")
        t = text_of(p)
        assert "unknown url type" not in t, t[-800:]
        assert "http://127.0.0.1" in t, t[-800:]

    def test_verify_chain_assumes_http(self):
        p = run_cli("--verify-chain", "127.0.0.1:1")
        t = text_of(p)
        assert "unknown url type" not in t, t[-800:]
        assert "redirect chain" in t, t[-800:]


# ============================================================= --help/--version ==
class TestHelpAndVersion:
    def test_help_exits_zero_and_prints_usage(self):
        p = run_cli("--help")
        assert p.returncode == 0, text_of(p)
        assert b"usage" in (p.stdout or b"").lower()

    def test_version_exits_zero_and_names_the_version(self):
        p = run_cli("--version")
        assert p.returncode == 0, text_of(p)
        assert b"bytephisher" in (p.stdout or b"").lower()


# ======================================================= a flag alone must not hang
class TestAFlagGivenAloneNeverBlocksOnInput:
    """stdin is a pipe held OPEN with no data: a read() from input() would block forever."""

    def _run_with_open_stdin(self, *args):
        r, w = os.pipe()
        try:
            p = subprocess.Popen([PY, CLI, *args], cwd=ROOT, env=_env(),
                                 stdin=r, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            os.close(r)
            try:
                out, _ = p.communicate(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()
                pytest.fail(
                    f"the CLI blocked on input() for {args!r}: a flag given alone must "
                    f"refuse, not wait for a menu choice")
            return p.returncode, out.decode("utf-8", "replace")
        finally:
            os.close(w)

    def test_a_serve_modifier_alone_refuses(self):
        rc, t = self._run_with_open_stdin("--bot-gate", "5")
        assert rc != 0, t[-600:]
        assert "[bytephisher]" in t, t[-600:]
        assert "Traceback" not in t, t[-1800:]

    def test_a_hit_cap_alone_refuses(self):
        rc, t = self._run_with_open_stdin("--max-hits", "5")
        assert rc != 0, t[-600:]
        assert "[bytephisher]" in t, t[-600:]
