"""Post-exploitation chains: the runner, the keyword hunt and the reporting.

The browser half of a chain is exercised through a stubbed task runner (a real
Chrome is sandbox-blocked on this host), which is what lets the chain's own logic
be verified: ordering, per-task outcomes, error isolation, and turning an
extracted mailbox into findings.

Run:  ./.venv/bin/python -m pytest tests/test_chains.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import chains as C
from core import session as S

# tier marker: the Makefile and pyproject document `pytest -m unit` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.unit



# =================================================================== hunt ====
class TestHunt:
    def test_high_value_lines_are_found(self):
        text = ("Inbox (12)\n"
                "Your invoice INV-20431 from Acme is due\n"
                "Statement for account ending 4412\n"
                "Your one-time code is 918273\n"
                "Team lunch on Friday\n")
        hits = C.hunt(text)
        kws = {h["keyword"] for h in hits}
        assert "invoice" in kws and "statement" in kws and "one-time" in kws
        assert all(h["line"] for h in hits)
        assert not any("Team lunch" in h["line"] for h in hits)

    def test_the_line_is_reported_not_a_boolean(self):
        hits = C.hunt("Reset your password now")
        assert hits and hits[0]["line"] == "Reset your password now"

    def test_duplicate_lines_are_reported_once(self):
        hits = C.hunt("invoice 1\ninvoice 1\ninvoice 2")
        assert len([h for h in hits if h["keyword"] == "invoice"]) == 2

    def test_the_limit_is_respected(self):
        text = "\n".join(f"invoice number {i}" for i in range(100))
        assert len(C.hunt(text, limit=5)) == 5

    def test_empty_and_junk_input(self):
        assert C.hunt("") == []
        assert C.hunt(None) == []
        assert C.hunt("x" * 400) == []          # a wall of text is not a line

    def test_custom_keywords(self):
        assert C.hunt("only alpha here", keywords=("alpha",))[0]["keyword"] == "alpha"


# ================================================================== chains ===
class TestChainCatalogue:
    def test_every_chain_runs_real_tasks(self):
        for c in C.list_chains():
            assert c["tasks"], c["name"]
            for t in c["tasks"]:
                assert t in S.BUILTIN_TASKS, f"{c['name']} references unknown task {t}"

    def test_the_documented_names_exist(self):
        names = {c["name"] for c in C.list_chains()}
        assert {"recon", "inbox", "takeover", "full", "lockout"} <= names

    def test_an_unknown_chain_raises_with_the_options(self):
        with pytest.raises(ValueError) as e:
            C.run_chain({}, "nope")
        assert "unknown chain" in str(e.value) and "recon" in str(e.value)


class TestRunChain:
    def _stub(self, monkeypatch, behaviour):
        """Replace the task runner; `behaviour` maps task name -> result or raises."""
        calls = []

        def fake_run(rec, task, home="", outdir=None, headless=True, timeout=45000,
                     replay=None):
            calls.append(task)
            out = behaviour(task)
            if isinstance(out, Exception):
                raise out
            return out
        monkeypatch.setattr(S, "run_task", fake_run)
        return calls

    def test_tasks_run_in_order(self, monkeypatch):
        calls = self._stub(monkeypatch, lambda t: {"task": t, "steps": [], "extracted": {},
                                                   "errors": [], "duration": 0})
        res = C.run_chain({}, "recon")
        assert calls == ["probe", "profile", "links"]
        assert [t["task"] for t in res["tasks"]] == calls
        assert res["ok"] is True

    def test_a_task_error_makes_the_chain_incomplete(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [{"step": 1, "ok": False}],
                                           "extracted": {}, "errors": ["selector not found"],
                                           "duration": 0})
        res = C.run_chain({}, "recon")
        assert res["ok"] is False
        assert res["errors"] and "selector not found" in res["errors"][0]
        assert all(t["ok"] is False for t in res["tasks"])

    def test_an_exception_in_one_task_does_not_kill_the_chain(self, monkeypatch):
        def behaviour(task):
            if task == "profile":
                raise RuntimeError("browser died")
            return {"task": task, "steps": [], "extracted": {}, "errors": [], "duration": 0}
        calls = self._stub(monkeypatch, behaviour)
        res = C.run_chain({}, "recon")
        assert calls == ["probe", "profile", "links"]     # it kept going
        bad = [t for t in res["tasks"] if t["task"] == "profile"][0]
        assert bad["ok"] is False and "browser died" in bad["errors"][0]
        assert res["ok"] is False

    def test_the_mail_hunt_turns_the_page_into_findings(self, monkeypatch):
        def behaviour(task):
            extracted = {}
            if task == "mail-hunt":
                extracted = {"mail_page": "Your invoice INV-7 is due\nOTP 918273\n"}
            return {"task": task, "steps": [], "extracted": extracted, "errors": [],
                    "duration": 0}
        self._stub(monkeypatch, behaviour)
        res = C.run_chain({}, "inbox")
        kws = {f["keyword"] for f in res["findings"]}
        assert "invoice" in kws and "otp" in kws
        hunt_task = [t for t in res["tasks"] if t["task"] == "mail-hunt"][0]
        assert hunt_task["findings"], "the per-task findings must be kept"

    def test_the_takeover_surfaces_produce_findings(self, monkeypatch):
        def behaviour(task):
            key = {"mail-forward": "settings_page", "app-password": "security_page",
                   "mfa-add": "mfa_page"}.get(task, "")
            return {"task": task, "steps": [], "extracted": {key: "Forwarding rules\n"
                                                            "App passwords\n"
                                                            "Two-factor devices\n"},
                    "errors": [], "duration": 0}
        self._stub(monkeypatch, behaviour)
        res = C.run_chain({}, "takeover")
        kws = {f["keyword"] for f in res["findings"]}
        assert "forward" in kws and "app password" in kws and "device" in kws

    def test_a_task_with_no_extract_yields_no_findings(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [], "extracted": {},
                                           "errors": [], "duration": 0})
        assert C.run_chain({}, "inbox")["findings"] == []

    def test_on_task_reports_each_task_as_it_finishes(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [], "extracted": {},
                                           "errors": [], "duration": 0})
        seen = []
        C.run_chain({}, "recon", on_task=seen.append)
        assert [t["task"] for t in seen] == ["probe", "profile", "links"]

    def test_the_result_carries_what_the_operator_needs(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [1, 2], "extracted": {},
                                           "errors": [], "duration": 0})
        res = C.run_chain({}, "recon")
        assert res["chain"] == "recon" and res["description"]
        assert isinstance(res["duration"], (int, float))
        assert res["tasks"][0]["steps"] == 2

    def test_extracted_lists_are_bounded_in_the_result(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [],
                                           "extracted": {"rows": list(range(1000))},
                                           "errors": [], "duration": 0})
        res = C.run_chain({}, "recon")
        assert len(res["tasks"][0]["extracted"]["rows"]) == 5

    def test_a_chain_name_is_case_insensitive(self, monkeypatch):
        self._stub(monkeypatch, lambda t: {"task": t, "steps": [], "extracted": {},
                                           "errors": [], "duration": 0})
        assert C.run_chain({}, "RECON")["chain"] == "recon"


class TestReport:
    def test_the_report_shows_tasks_findings_and_errors(self, monkeypatch):
        def behaviour(task):
            extracted = {"mail_page": "invoice INV-9 due\n"} if task == "mail-hunt" else {}
            errs = ["click failed"] if task == "inbox-subjects" else []
            return {"task": task, "steps": [1], "extracted": extracted, "errors": errs,
                    "duration": 0}
        monkeypatch.setattr(S, "run_task", lambda *a, **k: behaviour(k.get("task") or a[1]))
        res = C.run_chain({}, "inbox")
        text = C.report(res)
        assert "CHAIN inbox" in text
        assert "mail-hunt" in text and "ERR" in text
        assert "FINDINGS (1)" in text and "invoice" in text
        assert "error(s); the chain is not complete" in text

    def test_a_clean_chain_says_nothing_about_errors(self, monkeypatch):
        monkeypatch.setattr(S, "run_task",
                            lambda *a, **k: {"task": "x", "steps": [], "extracted": {},
                                             "errors": [], "duration": 0})
        text = C.report(C.run_chain({}, "recon"))
        assert "error(s)" not in text


# ======================================================== acting steps =======
class FakeEl:
    def __init__(self, visible=True, disabled=False):
        self.visible, self.disabled, self.filled, self.clicked = visible, disabled, None, False

    def is_visible(self):
        return self.visible

    def get_attribute(self, name):
        return "disabled" if (name == "disabled" and self.disabled) else None

    def fill(self, value, timeout=None):
        self.filled = value

    def click(self, timeout=None):
        self.clicked = True


class FakePage:
    """Just enough page for the step dispatcher: selector -> elements."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.goto_calls = []

    def query_selector_all(self, sel):
        return list(self.mapping.get(sel, []))

    def query_selector(self, sel):
        els = self.mapping.get(sel) or []
        return els[0] if els else None

    def goto(self, url, timeout=None, wait_until=None):
        self.goto_calls.append(url)


class TestActingSteps:
    def _step(self, spec, vars_=None, mapping=None):
        page = FakePage(mapping or {})
        out = S._run_step(page, spec, "https://x.test/", None, {}, vars_=vars_ or {})
        return page, out

    def test_fill_first_fills_every_match(self):
        a, b = FakeEl(), FakeEl()
        page, out = self._step({"fill_first": {"selectors": ["input[type=password]"],
                                               "value": "N3w!pass"}},
                               mapping={"input[type=password]": [a, b]})
        assert a.filled == "N3w!pass" and b.filled == "N3w!pass"
        assert out["filled"] == 2

    def test_fill_first_skips_hidden_and_disabled_fields(self):
        hidden, disabled, ok = FakeEl(visible=False), FakeEl(disabled=True), FakeEl()
        page, out = self._step({"fill_first": {"selectors": ["input"], "value": "v"}},
                               mapping={"input": [hidden, disabled, ok]})
        assert out["filled"] == 1 and ok.filled == "v"

    def test_fill_first_refuses_to_lie_when_nothing_matches(self):
        with pytest.raises(ValueError) as e:
            self._step({"fill_first": {"selectors": ["input[type=password]"], "value": "v"}})
        assert "matched nothing" in str(e.value)

    def test_fill_first_without_a_value_is_an_error(self):
        with pytest.raises(ValueError) as e:
            self._step({"fill_first": {"selectors": ["input"], "value": "{operator}"}},
                       vars_={"operator": ""})
        assert "no value" in str(e.value)

    def test_the_operator_and_password_variables_are_substituted(self):
        el = FakeEl()
        page, out = self._step({"fill_first": {"selectors": ["input"], "value": "{operator}"}},
                               vars_={"operator": "op@example.test"},
                               mapping={"input": [el]})
        assert el.filled == "op@example.test"

    def test_click_first_clicks_the_first_visible_match(self):
        page, out = self._step({"click_first": {"selectors": ["button[type=submit]"]}},
                               mapping={"button[type=submit]": [FakeEl()]})
        assert out["clicked"] == "button[type=submit]"

    def test_click_first_tries_the_next_selector(self):
        el = FakeEl()
        page, out = self._step({"click_first": {"selectors": ["a.missing", "button.save"]}},
                               mapping={"button.save": [el]})
        assert el.clicked and out["clicked"] == "button.save"

    def test_click_first_refuses_to_lie_when_nothing_matches(self):
        with pytest.raises(ValueError) as e:
            self._step({"click_first": {"selectors": ["nope"]}})
        assert "matched nothing" in str(e.value)


class TestActingTasksAreWired:
    def test_the_acting_tasks_exist_and_use_the_new_steps(self):
        for name in ("forward-submit", "password-change", "mfa-enroll"):
            task = S.BUILTIN_TASKS[name]
            kinds = {k for st in task["steps"] for k in st}
            assert kinds & {"fill_first", "click_first"}, name

    def test_the_own_chain_submits_rather_than_only_opening(self):
        assert C.CHAINS["own"]["tasks"] == ["probe", "forward-submit",
                                            "password-change", "sessions-kill"]

    def test_full_covers_the_acting_tasks(self):
        assert {"forward-submit", "password-change", "mfa-enroll"} <= set(
            C.CHAINS["full"]["tasks"])


# ===================================================== auto-chain notifier ===
class TestAutoChain:
    def _db(self):
        import tempfile

        from core import capture as cap
        d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_auto_"), "a.db"))
        d.session_save(S.new_record("a" * 32, campaign="auto"))
        return d

    def test_a_session_capture_triggers_the_chain(self, monkeypatch):
        db = self._db()
        calls = []
        monkeypatch.setattr(C, "run_chain",
                            lambda rec, name, **k: calls.append((name, k)) or
                            {"chain": name, "ok": True, "tasks": [], "findings": [],
                             "errors": [], "duration": 0})
        alerts = []
        # a session alert only has a chain to run if the session was stored: a bare
        # page view is no longer persisted, so give it the cookies a real capture has
        from core import session as S
        rec = S.new_record("a" * 32, campaign="auto")
        S.add_cookies(rec, [{"name": "sess", "value": "v", "domain": "x.test"}])
        db.session_save(rec)
        n = C.make_auto_notifier(alerts.append, db, "recon", spawn=lambda fn: fn())
        n({"type": "session", "sid": "a" * 32, "campaign": "auto"})
        assert calls and calls[0][0] == "recon"
        assert any(a.get("type") == "chain" for a in alerts)
        assert alerts[-1]["chain"] == "recon"
        db.close()

    def test_one_run_per_session_however_many_alerts(self, monkeypatch):
        db = self._db()
        calls = []
        monkeypatch.setattr(C, "run_chain",
                            lambda rec, name, **k: calls.append(name) or
                            {"chain": name, "ok": True, "tasks": [], "findings": [],
                             "errors": [], "duration": 0})
        n = C.make_auto_notifier(lambda c: None, db, "recon", spawn=lambda fn: fn())
        for _ in range(4):
            n({"type": "session", "sid": "a" * 32})
        assert calls == ["recon"]
        db.close()

    def test_only_a_session_capture_triggers_it(self, monkeypatch):
        db = self._db()
        calls = []
        monkeypatch.setattr(C, "run_chain",
                            lambda rec, name, **k: calls.append(name) or
                            {"chain": name, "ok": True, "tasks": [], "findings": [],
                             "errors": [], "duration": 0})
        n = C.make_auto_notifier(lambda c: None, db, "recon", spawn=lambda fn: fn())
        for kind in ("creds", "otp", "live", "intel", "fields"):
            n({"type": kind, "sid": "a" * 32})
        assert calls == []
        db.close()

    def test_the_base_notifier_still_receives_everything(self):
        db = self._db()
        seen = []
        n = C.make_auto_notifier(seen.append, db, "recon", spawn=lambda fn: None)
        n({"type": "creds", "sid": "a" * 32})
        n({"type": "session", "sid": "b" * 32})
        assert [c["type"] for c in seen] == ["creds", "session"]
        db.close()

    def test_an_unknown_chain_is_rejected_up_front(self):
        with pytest.raises(ValueError):
            C.make_auto_notifier(lambda c: None, None, "nope")

    def test_a_failing_chain_is_reported_not_swallowed(self, monkeypatch):
        db = self._db()
        monkeypatch.setattr(C, "run_chain",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no browser")))
        alerts = []
        n = C.make_auto_notifier(alerts.append, db, "recon", spawn=lambda fn: fn())
        n({"type": "session", "sid": "a" * 32})
        assert any("no browser" in str(e) for a in alerts for e in a.get("errors") or [])
        db.close()

    def test_an_unknown_session_is_not_an_error(self):
        db = self._db()
        alerts = []
        n = C.make_auto_notifier(alerts.append, db, "recon", spawn=lambda fn: fn())
        n({"type": "session", "sid": "f" * 32})          # never captured
        assert not any(a.get("type") == "chain" for a in alerts)
        db.close()


class TestChainAlertRendering:
    def test_the_chain_message_shows_tasks_findings_and_errors(self):
        from core import alerts
        text = alerts.format_capture({
            "type": "chain", "sid": "abc", "chain": "own", "ok": False, "campaign": "c",
            "tasks": [{"task": "probe", "ok": True, "steps": 3},
                      {"task": "password-change", "ok": False, "steps": 4}],
            "findings": [{"keyword": "success", "line": "Password updated"}],
            "errors": ["password-change: selector matched nothing"]})
        assert "CHAIN own INCOMPLETE" in text
        assert "ok  probe" in text and "ERR password-change" in text
        assert "Password updated" in text
        assert "/chain abc own" in text

    def test_a_chain_alert_offers_the_follow_ups(self):
        from core import alerts
        rows = alerts._buttons_for({"type": "chain", "sid": "abc"})
        flat = [d for row in rows for _, d in row]
        assert "/live abc" in flat and "/session abc" in flat and "/chain abc" in flat


# ========================================================= task variables ====
class TestTaskVariables:
    def test_defaults_derive_from_the_home_page(self):
        rec = S.new_record("a" * 32)
        rec["meta"] = {"home": "https://mail.example.test/"}
        v = S._task_vars(rec, "https://mail.example.test/")
        assert v["home"] == "https://mail.example.test/"
        assert v["mail"] == "https://mail.example.test/mail"
        assert v["security"] == "https://mail.example.test/settings/security"

    def test_meta_overrides_every_path(self):
        rec = S.new_record("a" * 32)
        rec["meta"] = {"home": "https://s.example/", "mail": "{home}/u/0/inbox",
                       "security": "https://sec.example/apps",
                       "operator": "op@example.test"}
        v = S._task_vars(rec, "https://s.example/")
        assert v["mail"] == "https://s.example/u/0/inbox"
        assert v["security"] == "https://sec.example/apps"
        assert v["operator"] == "op@example.test"

    def test_no_meta_does_not_crash(self):
        v = S._task_vars(S.new_record("b" * 32), "https://x.test")
        assert v["home"] == "https://x.test"        # verbatim, never re-slash-ed

    def test_a_path_url_is_not_rewritten(self):
        """Appending a slash turned /account into a different resource, and the
        replay/browser then fetched something the site never served."""
        v = S._task_vars({"meta": {"home": "https://s.test/account"}},
                         "https://s.test/account")
        assert v["home"] == "https://s.test/account"


# ====================================================== browser integration ==
@pytest.mark.skipif(not os.path.isdir(os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "templates")),
    reason="templates are generated on first run")
class TestChainInABrowser:
    def test_a_chain_reports_instead_of_crashing_without_a_browser(self, tmp_path):
        """Whatever the host allows, the chain must return a result, not raise."""
        rec = S.new_record("c" * 32)
        rec["meta"] = {"home": "https://example.test/"}
        res = C.run_chain(rec, "recon", outdir=str(tmp_path), timeout=8000)
        assert res["chain"] == "recon"
        # the contract, not the type: complete exactly when nothing errored
        assert res["ok"] == (not res["errors"]), res
        assert res["tasks"], "the chain must report its tasks either way"


# ======================================================= the CLI wiring =======
class TestChainCli:
    """`--chains`, `--run-chain SID:CHAIN --chain-json`, and the exit codes.

    test_chains covered core.chains directly; nothing exercised the CLI glue, so a
    regression in the SID:CHAIN parsing or the return-code contract would have
    passed the whole suite.
    """

    @staticmethod
    def _cli(home, *args):
        import os
        import subprocess
        import sys
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, BYTEPHISHER_HOME=home)
        return subprocess.run([sys.executable, os.path.join(root, "bytephisher.py"),
                               *args], cwd=root, capture_output=True, text=True,
                              timeout=120, env=env)

    @pytest.mark.integration  # runs the CLI in a subprocess
    def test_chains_lists_the_registry(self):
        import tempfile
        home = tempfile.mkdtemp(prefix="bh_chain_cli_")
        p = self._cli(home, "--chains")
        assert p.returncode == 0, p.stderr
        for name in ("recon", "inbox", "takeover", "lockout", "full"):
            assert name in p.stdout, name
        assert "own" in p.stdout

    @staticmethod
    def _home_with_session():
        """A temp home holding one real session row (the CLI resolves the session
        first, so an unknown chain can only be reached with a live sid)."""
        import os
        import tempfile

        from core import capture as cap
        from core import session as sess
        home = tempfile.mkdtemp(prefix="bh_chain_cli_")
        os.makedirs(os.path.join(home, "data"), exist_ok=True)
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        sid = "a1" * 16
        db.session_save(sess.new_record(sid))
        db.close()
        return home, sid

    @pytest.mark.integration  # runs the CLI in a subprocess
    def test_a_missing_session_exits_one(self):
        import tempfile
        home = tempfile.mkdtemp(prefix="bh_chain_cli_")
        p = self._cli(home, "--run-chain", "no-colon-here")
        assert p.returncode == 1, (p.returncode, p.stdout[-300:])
        assert "no session" in p.stdout

    @pytest.mark.integration  # runs the CLI in a subprocess
    def test_an_unknown_chain_exits_two(self):
        home, sid = self._home_with_session()
        p = self._cli(home, "--run-chain", f"{sid}:nope")
        assert p.returncode == 2, (p.returncode, p.stdout[-400:], p.stderr[-400:])
        assert "unknown chain" in (p.stdout + p.stderr).lower()

    @pytest.mark.integration  # runs the CLI in a subprocess
    def test_chain_json_writes_a_report_for_a_real_session(self):
        """A session with a placeholder home produces task errors, and those must
        still be reported in the JSON - the file is the contract."""
        import json
        import os
        home, sid = self._home_with_session()
        out = os.path.join(home, "chain.json")
        p = self._cli(home, "--run-chain", f"{sid}:recon", "--chain-json", out)
        assert os.path.isfile(out), (p.returncode, p.stdout[-400:], p.stderr[-400:])
        rep = json.load(open(out))
        assert rep["chain"] == "recon"
        assert rep["sid"] == sid
        assert isinstance(rep["tasks"], list) and rep["tasks"]
        assert "ok" in rep
