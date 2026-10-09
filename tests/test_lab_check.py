"""The real-world preflight: what it must say, and what it must not claim.

The value of `tools/lab_check.py` is that it refuses to pretend: a required check that
fails must produce BLOCKED, an optional one must not, and every failure must carry the
fix. These tests drive the verdict logic with injected results (so they are deterministic
and offline) and exercise the local checks for real.
"""
import json
import os
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from tools import lab_check as L  # noqa: E402

pytestmark = pytest.mark.unit


def _r(name, status, required=True):
    return {"name": name, "status": status, "detail": "d", "fix": "f",
            "required": required}


# ============================================================== the verdict ====
class TestTheVerdict:

    def test_all_pass_is_ready(self):
        rep = L.run(results=[_r("a", L.PASS), _r("b", L.PASS)])
        assert rep["verdict"] == "READY" and rep["blocking"] == []

    def test_a_required_failure_blocks(self):
        rep = L.run(results=[_r("a", L.PASS), _r("browser", L.FAIL)])
        assert rep["verdict"] == "BLOCKED"
        assert rep["blocking"] == ["browser"]

    def test_an_optional_failure_does_not_block(self):
        rep = L.run(results=[_r("a", L.PASS),
                             _r("egress", L.FAIL, required=False)])
        assert rep["verdict"] == "READY" and rep["blocking"] == []

    def test_a_skip_never_blocks(self):
        rep = L.run(results=[_r("clock", L.SKIP, required=False),
                             _r("domain", L.SKIP, required=False)])
        assert rep["verdict"] == "READY"

    def test_warn_only_downgrades_a_named_check(self):
        """The browser is not needed to serve a page: a campaign that never runs a
        takeover or a live view must not be blocked by it."""
        rep = L.run(results=[_r("a", L.PASS), _r("browser", L.FAIL)], warn_only=["browser"])
        assert rep["verdict"] == "READY" and rep["blocking"] == []
        # and the failure is still visible in the report
        assert [c for c in rep["checks"] if c["name"] == "browser"][0]["status"] == L.FAIL

    def test_warn_only_does_not_downgrade_anything_else(self):
        rep = L.run(results=[_r("database", L.FAIL), _r("browser", L.FAIL)],
                    warn_only=["browser"])
        assert rep["verdict"] == "BLOCKED" and rep["blocking"] == ["database"]

    def test_only_filters_the_checks(self):
        rep = L.run(results=[_r("a", L.PASS), _r("b", L.FAIL)], only=["a"])
        assert [c["name"] for c in rep["checks"]] == ["a"]
        assert rep["verdict"] == "READY"


# ================================================================ rendering ====
class TestTheReport:

    def test_a_failure_shows_its_fix_and_the_verdict(self):
        text = L.render(L.run(results=[_r("browser", L.FAIL)]))
        assert "FAIL" in text and "browser" in text
        assert "-> f" in text, "the fix must be shown"
        assert "BLOCKED" in text

    def test_a_ready_report_says_so(self):
        text = L.render(L.run(results=[_r("a", L.PASS)]))
        assert "READY" in text and "BLOCKED" not in text


# ========================================================== the real checks ====
class TestTheLocalChecks:

    def test_python_is_supported_here(self):
        r = L.check_python()
        assert r["status"] == L.PASS, r

    def test_the_database_check_passes_on_a_writable_dir(self):
        d = tempfile.mkdtemp()
        r = L.check_db(os.path.join(d, "sub", "x.db"))
        assert r["status"] == L.PASS, r

    def test_the_database_check_fails_when_the_path_is_not_a_directory(self):
        # /dev/null is a file, so /dev/null/sub cannot be created
        r = L.check_db("/dev/null/sub/x.db")
        assert r["status"] == L.FAIL
        assert r["fix"], "a failure without a fix is useless to the operator"

    def test_dns_tls_without_a_domain_is_a_skip_not_a_failure(self):
        assert L.check_dns_tls("")["status"] == L.SKIP

    def test_tunnel_and_tenant_are_skipped_without_arguments(self):
        assert L.check_tunnel("")["status"] == L.SKIP
        assert L.check_tenant("microsoft", "")["status"] == L.SKIP

    def test_dependencies_reports_what_is_missing(self):
        r = L.check_deps()
        assert r["name"] == "dependencies"
        if r["status"] == L.FAIL:
            assert "pip install" in r["fix"], r
            assert r["detail"], "a dependency failure must name what is missing"
        else:
            assert r["status"] == L.PASS and not r["fix"], r

    @pytest.mark.live  # the probe renders a page in a real browser
    def test_the_browser_check_answers_the_decisive_question(self):
        """Either it can reach a live host (PASS) or it must say exactly why not.

        Three failure modes, and CI hits the first one (playwright is not
        installed there): playwright missing, cannot render, cannot reach a live host.
        """
        r = L.check_browser()
        assert r["name"] == "browser" and r["status"] in (L.PASS, L.FAIL)
        if r["status"] == L.FAIL:
            assert r["fix"], "a browser failure must say what to do about it"
            assert any(k in r["detail"] for k in
                       ("playwright missing", "data: URL", "live host")), r
        else:
            assert "live host" in r["detail"], r

    def test_dependencies_never_block_a_campaign(self):
        """playwright gates the browser layer, not the ability to serve a page: marking
        it required made the launcher refuse to start on a host without it."""
        r = L.check_deps()
        assert r["required"] is False
        if r["status"] == L.FAIL:
            assert "playwright" in r["fix"] and r["fix"].startswith("pip install")

    def test_a_missing_playwright_does_not_block_the_verdict(self):
        rep = L.run(results=[_r("python", L.PASS),
                             L.check_deps(),
                             _r("browser", L.FAIL)], warn_only=["browser"])
        assert rep["verdict"] == "READY", rep["blocking"]


# ================================================================== the cli ====
class TestTheCli:

    def test_json_output_and_exit_code(self, capsys):
        code = L.main(["--only", "python", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert code == 0 and out["verdict"] == "READY"
        assert out["checks"][0]["name"] == "python"

    def test_a_blocking_check_returns_a_nonzero_code(self, capsys, monkeypatch):
        # a plain report, not a call back into run() (that recursed)
        monkeypatch.setattr(L, "run", lambda **kw: {"verdict": "BLOCKED", "checks": [],
                                                   "blocking": ["browser"]})
        assert L.main([]) == 1
