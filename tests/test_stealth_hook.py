"""The hook must survive the check that actually catches wrapped built-ins.

`window.fetch.toString()` on a plain JS wrapper returns the wrapper's source instead
of "[native code]", and PerimeterX / HUMAN / bank integrity scripts call exactly that
(and `Function.prototype.toString.call(builtin)`). These tests execute the REAL hook -
the same string the proxy serves - inside a fake page under Node, and read the
properties such a script would read.

The stealth-off case is asserted too: a test that cannot fail proves nothing, so the
suite shows the difference between the two modes on the same artifact.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.proxy import ProxyEngine  # noqa: E402

pytestmark = pytest.mark.integration

NODE = shutil.which("node")
HARNESS = os.path.join(HERE, "tests", "hook_harness.js")

NATIVE_FETCH = re.compile(r"^function fetch\(\) \{ \[native code\] \}$")
NATIVE_SEND = re.compile(r"^function send\(\) \{ \[native code\] \}$")


def hook_js(stealth=True, sid="a" * 32):
    engine = ProxyEngine.__new__(ProxyEngine)
    engine.hook_stealth = stealth
    return ProxyEngine.hook_js(engine, sid)


def run_hook(source, timeout=60):
    """Execute the hook in the harness and return its observation report."""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(source)
        path = f.name
    try:
        p = subprocess.run([NODE, HARNESS, path], capture_output=True, text=True,
                           timeout=timeout, cwd=HERE)
    finally:
        os.unlink(path)
    line = (p.stdout or "").strip().splitlines()
    assert line, f"the harness printed nothing (stderr={p.stderr[:400]})"
    out = json.loads(line[-1])
    assert out.get("ok") is True, out
    return out


@pytest.fixture(scope="module")
def on():
    """The hook with stealth enabled, rendered once for the module.

    Module scope because the node harness is the slow part and these assertions only read
    its report. A class-scoped fixture defined as an instance method is deprecated in
    pytest 8.4 (it warns on every run), and this one does not need the class.
    """
    return run_hook(hook_js(stealth=True))


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestTheStealthHook:

    def test_fetch_reports_itself_as_a_native(self, on):
        assert NATIVE_FETCH.match(on["fetch_to_string"]), on["fetch_to_string"]
        assert NATIVE_FETCH.match(on["proto_to_string_call"]), on["proto_to_string_call"]
        assert NATIVE_FETCH.match(on["string_coercion"]), on["string_coercion"]

    def test_the_hook_source_is_not_reachable_through_the_wrapper(self, on):
        for key in ("fetch_to_string", "proto_to_string_call", "string_coercion"):
            assert "origFetch" not in on[key]
            assert "sendBeacon" not in on[key]
            assert "return " not in on[key]

    def test_the_shim_hides_itself(self, on):
        """`Function.prototype.toString.toString()` is one call away from catching a
        naive spoof."""
        assert on["shim_is_native"] is True
        assert on["toString_replaced"] is True, "no shim was installed"

    def test_the_surface_matches_the_native_it_replaced(self, on):
        assert on["fetch_name"] == "fetch"
        assert on["fetch_length"] == 1
        assert on["xhr_send_name"] == "send"
        # enumerability is copied from what was there, not invented: a window global is
        # enumerable, a DOM prototype method is not
        assert on["fetch_desc"] == {"enumerable": True, "writable": True,
                                    "configurable": True}
        assert on["xhr_send_desc"] == {"enumerable": False, "writable": True,
                                       "configurable": True}
        assert on["xhr_open_desc"] == {"enumerable": False, "writable": True,
                                       "configurable": True}

    def test_xhr_methods_report_native_too(self, on):
        assert NATIVE_SEND.match(on["xhr_send_to_string"]), on["xhr_send_to_string"]

    def test_the_wrapper_still_does_its_job(self, on):
        assert on["native_still_reachable"] is True, "the real fetch was never called"
        assert on["beacon_on_login_body"] is True, "the fetch body was not reported"

    def test_an_xhr_body_is_still_reported(self, on):
        """The wrapper is a named function expression; naming the inner function `send`
        bound that name in its own scope and the inner call went to the wrapper instead
        of the collector, silently dropping every XHR credential."""
        assert on["beacon_on_form_submit"] is True, on.get("beacon_urls")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestTheDifferenceStealthMakes:
    """Without this, the suite above could pass on a hook that never patched anything."""

    def test_without_stealth_the_wrapper_exposes_itself(self):
        off = run_hook(hook_js(stealth=False))
        assert "[native code]" not in off["fetch_to_string"], off["fetch_to_string"]
        assert "input" in off["fetch_to_string"] or "function" in off["fetch_to_string"]
        # the untouched native toString is naturally "native", so the reliable signal is
        # that no shim was installed at all
        assert off["toString_replaced"] is False
        # and it still captures, so the comparison is about stealth alone
        assert off["beacon_on_login_body"] is True

    def test_the_two_modes_differ_only_in_stealth(self):
        off = run_hook(hook_js(stealth=False))
        on = run_hook(hook_js(stealth=True))
        # fetch.length is deliberately NOT compared: correcting the wrapper's arity to
        # the native 1 is part of the stealth, so the two modes must differ there
        for key in ("native_still_reachable", "beacon_on_login_body",
                    "beacon_on_form_submit", "fetch_name",
                    "xhr_send_name", "xhr_send_desc"):
            assert (off[key] if not isinstance(off[key], dict)
                    else off[key].get("enumerable")) == \
                   (on[key] if not isinstance(on[key], dict)
                    else on[key].get("enumerable")), key
            assert off[key] == on[key], key
        assert off["fetch_to_string"] != on["fetch_to_string"]
        assert off["fetch_length"] == 2 and on["fetch_length"] == 1, (
            "the arity correction is part of the stealth")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestTheHookContent:

    def test_the_stealth_layer_is_in_the_served_hook_by_default(self):
        js = hook_js(stealth=True)
        assert "__STEALTH__" not in js
        assert "var stealth = " in js and "native code" in js

    def test_it_can_be_turned_off(self):
        js = hook_js(stealth=False)
        assert "var stealth = null;" in js

    def test_the_sid_is_still_substituted(self):
        sid = "b" * 32
        assert sid in hook_js(stealth=True, sid=sid)
