"""The deeper-harvest modules, verified by executing the collector.

Each module must land in the beacon the collector sends. A module that throws is
invisible in a browser but obvious here, which is the point: the harvest is the
product.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import asset_path  # noqa: E402
from core import intel as I  # noqa: E402

pytestmark = pytest.mark.integration

ASSETS = os.path.dirname(asset_path("intel.js"))
HARNESS = os.path.join(HERE, "tests", "js_harness.js")
NODE = shutil.which("node")

NEW_MODULES = ("voices", "keyboardLayout", "gamepadDevices", "perfMemory",
               "idbNames", "opfs", "xr", "sensors", "chromeInternals", "pwa")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestDeepHarvest:

    @staticmethod
    def _blob(out):
        """Every payload the collector sent, whichever transport it used:
        sendBeacon is preferred, fetch is the fallback."""
        return "\n".join(list(out.get("beacon_bodies") or [])
                         + list(out.get("call_bodies") or []))

    @staticmethod
    def _run(wait_ms=None):
        js = I.render_js(os.path.join(ASSETS, "intel.js"), "d" * 32, randomize=False)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
            path = f.name
        try:
            env = dict(os.environ)
            if wait_ms:
                env["BH_WAIT_MS"] = str(wait_ms)
            p = subprocess.run([NODE, HARNESS, path], capture_output=True, text=True,
                               timeout=180, cwd=HERE, env=env)
        finally:
            os.unlink(path)
        assert p.stdout.strip(), f"harness printed nothing (stderr={p.stderr[:400]})"
        return json.loads(p.stdout.strip().splitlines()[-1])

    def test_every_new_module_reports(self):
        out = self._run()
        assert out["ok"] is True, out.get("error")
        blob = self._blob(out)
        assert blob, "the collector sent no beacon"
        missing = [m for m in NEW_MODULES if f'"{m}"' not in blob]
        assert missing == [], f"these modules never reported: {missing}"

    def test_the_parsed_values_are_real(self):
        out = self._run()
        blob = self._blob(out)
        # the stub values must survive the collector's parsing, not just the keys
        for needle in ("Microsoft David Desktop", "Xbox Wireless Controller",
                       "ghostery", "keyA=a", "illuminance"):
            assert needle in blob, f"{needle} missing from the harvest"

    def test_the_module_count_grew(self):
        """Count the module keys the collector actually reported."""
        out = self._run(wait_ms=7000)      # let the deep2 wave land
        keys = set()
        for body in (out.get("beacon_bodies") or []) + (out.get("call_bodies") or []):
            try:
                mods = json.loads(body).get("mods") or {}
            except Exception:
                continue
            keys |= set(mods)
        # the harness stubs fewer APIs than a real browser, so a module that has
        # nothing to report is simply absent: 34 is what this DOM can produce, and
        # all ten new modules must be among them
        assert len(keys) >= 30, (len(keys), sorted(keys))
        for name in NEW_MODULES:
            assert name in keys, (name, sorted(keys))
