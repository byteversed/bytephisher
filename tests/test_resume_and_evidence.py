"""P1.5/P1.6: evidence an action produced, and sessions that survive a restart.

Two production gaps, one file each:

* **evidence** - a task that ran and returned nothing was indistinguishable from one
  that worked, which is how a report ends up claiming something that never happened.
* **resume** - the durable state is in SQLite, but the engine's live session objects are
  not, so after a restart a victim's cookie resolved to a brand-new session and the
  campaign looked like it had lost its targets.
"""
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap  # noqa: E402
from core import session as S  # noqa: E402
from core.proxy import Phishlet, ProxyEngine  # noqa: E402

pytestmark = pytest.mark.unit


# ================================================================== evidence ====
class TestEvidence:

    def test_a_new_record_has_an_empty_evidence_block(self):
        assert S.new_record("s")["evidence"] == []

    def test_an_artefact_is_recorded_as_proven(self):
        rec = S.new_record("s")
        e = S.add_evidence(rec, "extract", "subject=Invoice 4471", source="inbox")
        assert e["proven"] is True and e["kind"] == "extract"
        assert e["source"] == "inbox" and e["ts"]
        assert rec["timeline"][-1]["event"] == "evidence"
        assert "proven" in rec["timeline"][-1]["detail"]

    def test_the_summary_counts_proven_and_unproven(self):
        rec = S.new_record("s")
        S.add_evidence(rec, "extract", "a=1")
        S.add_evidence(rec, "task", "password-change", proven=False)
        summ = S.evidence_summary(rec)
        assert summ == {"total": 2, "proven": 1, "unproven": 1,
                        "kinds": {"extract": 1, "task": 1}}
        assert S.evidence_summary(S.new_record("x"))["total"] == 0
        assert S.evidence_summary(None)["total"] == 0

    def test_a_task_that_returned_nothing_is_unproven_never_success(self):
        rec = S.new_record("s")
        result = {"task": "password-change", "extracted": {}, "files": [],
                  "errors": ["click failed", "no selector"]}
        assert S.evidence_from_task(rec, result) == 0
        entry = rec["evidence"][-1]
        assert entry["proven"] is False and entry["kind"] == "task"
        assert "2 step errors" in entry["detail"]
        assert S.evidence_summary(rec)["unproven"] == 1

    def test_extracted_values_and_files_become_artefacts(self, tmp_path):
        rec = S.new_record("s")
        f = tmp_path / "shot.png"
        f.write_bytes(b"x" * 64)
        result = {"task": "probe", "extracted": {"name": "Victim", "empty": "  "},
                  "files": [str(f)], "asserted": {"logged_in": True}, "errors": []}
        n = S.evidence_from_task(rec, result, outdir=str(tmp_path))
        kinds = S.evidence_summary(rec)["kinds"]
        assert kinds.get("extract") == 1, "a blank extracted value is not evidence"
        assert kinds.get("file") == 1 and kinds.get("assert") == 1
        assert kinds.get("log") == 1 and n == 3
        file_entry = [e for e in rec["evidence"] if e["kind"] == "file"][0]
        assert "64 bytes" in file_entry["detail"]

    def test_a_failed_assertion_is_unproven(self):
        rec = S.new_record("s")
        S.evidence_from_task(rec, {"task": "t", "asserted": {"logged_in": False}})
        assert [e for e in rec["evidence"] if e["kind"] == "assert"][0]["proven"] is False

    @pytest.mark.parametrize("junk", [None, "nope", [], 5])
    def test_junk_results_do_not_raise(self, junk):
        rec = S.new_record("s")
        assert S.evidence_from_task(rec, junk) == 0
        assert rec["evidence"][-1]["proven"] is False

    def test_add_evidence_tolerates_no_record(self):
        assert S.add_evidence(None, "x", "y") is None

    def test_it_survives_the_database(self, tmp_path):
        path = os.path.join(str(tmp_path), "e.db")
        db = cap.CaptureDB(path)
        rec = S.new_record("sid-e")
        S.evidence_from_task(rec, {"task": "probe", "extracted": {"name": "V"},
                                   "files": [], "errors": []})
        db.session_save(rec)
        db.close()
        db2 = cap.CaptureDB(path)
        back = db2.session_get("sid-e")
        db2.close()
        assert S.evidence_summary(back)["proven"] == 1
        assert back["evidence"][0]["value"] == "name=V"


# =================================================================== resume =====
class TestResume:

    @staticmethod
    def _engine(db):
        ph = Phishlet(name="t", upstream="up.test", scheme="http")
        return ProxyEngine(ph, db=db, geo_provider="off", logger=lambda *a: None)

    def test_a_session_active_before_the_restart_comes_back(self, tmp_path):
        path = os.path.join(str(tmp_path), "r.db")
        db = cap.CaptureDB(path)
        rec = S.new_record("sid-r", phishlet="t", campaign="c", ip="9.9.9.9")
        S.add_cookies(rec, [{"name": "auth", "value": "TOK", "domain": "up.test",
                             "path": "/", "secure": True}])
        db.session_save(rec)
        db.close()

        db2 = cap.CaptureDB(path)
        engine = self._engine(db2)
        assert engine.sessions == {}
        assert engine.restore_sessions(hours=12) == 1
        sess = engine.sessions["sid-r"]
        assert sess.sid == "sid-r" and sess.ip == "9.9.9.9"
        assert sess.vault["sid"] == "sid-r"
        # the cookie jar is the part that makes the victim's next request land right
        assert [(c.name, c.domain) for c in sess.cookies] == [("auth", "up.test")]
        db2.close()

    def test_a_stale_session_is_not_restored(self, tmp_path):
        """Age the row for real: a cutoff of 0.36 s would not prove anything."""
        import sqlite3
        path = os.path.join(str(tmp_path), "r2.db")
        db = cap.CaptureDB(path)
        db.session_save(S.new_record("sid-old", phishlet="t"))
        old = time.time() - 3600 * 3
        con = sqlite3.connect(path)
        con.execute("UPDATE sessions SET updated=? WHERE sid=?", (old, "sid-old"))
        con.commit()                    # same connection, or the update is never applied
        con.close()
        engine = self._engine(db)
        assert engine.restore_sessions(hours=1) == 0, "a 3-hour-old session came back"
        assert engine.sessions == {}
        # ...and it does come back when the window covers it
        assert engine.restore_sessions(hours=6) == 1
        db.close()

    def test_restoring_twice_does_not_duplicate(self, tmp_path):
        path = os.path.join(str(tmp_path), "r3.db")
        db = cap.CaptureDB(path)
        db.session_save(S.new_record("sid-x", phishlet="t"))
        engine = self._engine(db)
        assert engine.restore_sessions(hours=12) == 1
        assert engine.restore_sessions(hours=12) == 0
        assert list(engine.sessions) == ["sid-x"]
        db.close()

    def test_it_can_restore_only_one_campaign(self, tmp_path):
        path = os.path.join(str(tmp_path), "r4.db")
        db = cap.CaptureDB(path)
        db.session_save(S.new_record("s-a", phishlet="t", campaign="alpha"))
        db.session_save(S.new_record("s-b", phishlet="t", campaign="beta"))
        rows = db.sessions_since(time.time() - 3600, campaign="alpha")
        assert [r["sid"] for r in rows] == ["s-a"]
        db.close()

    def test_an_engine_without_a_database_says_zero(self):
        ph = Phishlet(name="t", upstream="up.test", scheme="http")
        engine = ProxyEngine(ph, db=None, geo_provider="off", logger=lambda *a: None)
        assert engine.restore_sessions() == 0

    def test_a_broken_database_does_not_crash_startup(self, tmp_path):
        class Broken:
            def sessions_since(self, *a, **kw):
                raise RuntimeError("db is gone")

        ph = Phishlet(name="t", upstream="up.test", scheme="http")
        engine = ProxyEngine(ph, db=Broken(), geo_provider="off",
                             logger=lambda *a: None)
        assert engine.restore_sessions() == 0      # a startup must never die here

    def test_the_stored_record_is_not_mutated_by_the_restore(self, tmp_path):
        """The vault dict is handed to the session; the row keeps its own copy."""
        path = os.path.join(str(tmp_path), "r5.db")
        db = cap.CaptureDB(path)
        db.session_save(S.new_record("sid-z", phishlet="t"))
        engine = self._engine(db)
        engine.restore_sessions(hours=12)
        engine.sessions["sid-z"].vault["state"] = "session"
        fresh = cap.CaptureDB(path).session_get("sid-z")
        assert fresh["state"] == "opened", "an in-memory change leaked into the row"
        db.close()
        assert json.dumps(fresh)                       # still serialisable
