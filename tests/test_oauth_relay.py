"""OAuth authorization-code relay: PKCE, the state binding, and the exchange.

A fake provider drives the whole flow, so the assertions are about what a real provider
would have received: the PKCE challenge on the authorize request, the verifier on the token
exchange, and no exchange at all when the state does not match.
"""
import base64
import hashlib
import http.client
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import time
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import free_port  # noqa: E402

from core import oauth as O  # noqa: E402
from core import session as S  # noqa: E402

pytestmark = pytest.mark.integration


class IdP:
    """A fake OAuth provider. `answers` steers the token endpoint."""

    def __init__(self, token_answer=None, token_status=200, authorize_error=""):
        self.port = free_port()
        self.requests = []                  # (path, query dict, form dict)
        self.token_answer = token_answer or {
            "access_token": "AT-1", "refresh_token": "RT-1", "token_type": "Bearer",
            "expires_in": 3600, "scope": "openid offline_access Mail.Read"}
        self.token_status = token_status
        self.authorize_error = authorize_error
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, payload, status=200):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
                outer.requests.append((parsed.path, q, {}))
                if parsed.path == "/authorize":
                    if outer.authorize_error:
                        loc = (f"{q.get('redirect_uri', '')}?error={outer.authorize_error}"
                               f"&state={q.get('state', '')}")
                    else:
                        loc = (f"{q.get('redirect_uri', '')}?code=CODE-1"
                               f"&state={q.get('state', '')}")
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._json({"ok": True})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode("utf-8", "replace")
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                outer.requests.append((self.path, {}, form))
                if self.path == "/token":
                    self._json(outer.token_answer, status=outer.token_status)
                    return
                self._json({"error": "not_found"}, status=404)

        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), H)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def spec(self, **over):
        kwargs = {"provider": "custom", "client_id": "test-client", "tenant": self.base,
                  "redirect_uri": "http://127.0.0.1:9/cb"}
        kwargs.update(over)
        return O.OauthSpec(**kwargs)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestPkce:

    def test_the_verifier_and_challenge_follow_the_spec(self):
        verifier, challenge = O.pkce_pair()
        assert 43 <= len(verifier) <= 128
        expect = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
        assert challenge == expect
        assert "=" not in challenge, "the challenge must be unpadded base64url"

    def test_two_pairs_differ(self):
        a = O.pkce_pair()
        b = O.pkce_pair()
        assert a[0] != b[0] and a[1] != b[1]


class TestTheAuthorizeUrl:

    def test_it_carries_the_pkce_challenge_and_the_state(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(), "sid-1")
            url = flow.authorize_url()
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            assert q["client_id"] == "test-client"
            assert q["response_type"] == "code"
            assert q["code_challenge_method"] == "S256"
            assert q["code_challenge"] == flow.challenge
            assert q["state"] == flow.state
            assert q["redirect_uri"] == "http://127.0.0.1:9/cb"
            assert "openid" in q.get("scope", "") or q.get("scope", "") == ""

    def test_empty_parameters_are_left_out(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(scope=""), "sid-1")
            url = flow.authorize_url()
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            assert "scope" not in q


class TestTheFlowEndToEnd:

    def test_a_complete_flow_vaults_the_tokens(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(), "sid-1")
            # the victim's browser goes to the provider; follow it by hand rather than with
            # urlopen, which would chase the 302 into our own (unlistened) callback port
            import urllib.request
            req = urllib.request.Request(flow.authorize_url(),
                                         headers={"User-Agent": "Mozilla/5.0"})
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                opener.open(req, timeout=10)
                landed = ""
            except urllib.error.HTTPError as e:
                landed = e.headers.get("Location", "")
            assert landed.startswith(idp.spec().redirect_uri), landed
            auth_req = [q for path, q, _f in idp.requests if path == "/authorize"][0]
            assert auth_req["code_challenge"] == flow.challenge
            code, state, error, _desc = O.parse_redirect(f"code=CODE-1&state={flow.state}")
            assert (code, state, error) == ("CODE-1", flow.state, "")
            tokens = flow.exchange(code)
            assert tokens["refresh_token"] == "RT-1"
            assert flow.status == "token"
            # the exchange must have carried the PKCE verifier
            token_form = [f for path, _q, f in idp.requests if path == "/token"][0]
            assert token_form["code_verifier"] == flow.verifier
            assert token_form["grant_type"] == "authorization_code"
            assert token_form["code"] == "CODE-1"
            assert token_form["redirect_uri"] == flow.redirect_uri
            assert landed is not None

    def test_the_tokens_reach_the_vault(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(), "sid-2")
            tokens = flow.exchange("CODE-1")
            rec = S.new_record("a" * 32)
            kept = S.add_oauth(rec, tokens, provider=idp.spec().provider,
                               client_id="test-client", source="oauth")
            assert kept >= 1
            summary = S.oauth_summary(rec)
            assert summary["has_refresh"] is True and summary["has_access"] is True
            assert S.oauth_valid(rec) is True

    def test_a_mismatched_state_is_refused_without_an_exchange(self):
        with IdP() as idp:
            manager = O.OauthManager()
            flow = manager.start(idp.spec(), "sid-3")
            with pytest.raises(O.OauthError) as ei:
                manager.finish("not-the-state", "CODE-1")
            assert "state" in str(ei.value)
            assert not [p for p, _q, _f in idp.requests if p == "/token"], \
                "the code was exchanged despite the state mismatch"
            assert flow.status == "started"

    def test_an_unknown_state_is_refused(self):
        with IdP() as idp:
            manager = O.OauthManager()
            manager.start(idp.spec(), "sid-4")
            with pytest.raises(O.OauthError):
                manager.finish("ghost-state", "CODE-1")

    def test_a_provider_refusal_is_reported_verbatim(self):
        with IdP(token_answer={"error": "invalid_grant",
                               "error_description": "the code has expired"},
                 token_status=400) as idp:
            flow = O.OauthFlow(idp.spec(), "sid-5")
            with pytest.raises(O.OauthError) as ei:
                flow.exchange("CODE-1")
            assert "code has expired" in str(ei.value)
            assert flow.status == "refused"

    def test_a_missing_code_is_refused(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(), "sid-6")
            with pytest.raises(O.OauthError):
                flow.exchange("")

    def test_a_token_answer_without_a_token_is_refused(self):
        with IdP(token_answer={"token_type": "Bearer"}) as idp:
            flow = O.OauthFlow(idp.spec(), "sid-7")
            with pytest.raises(O.OauthError) as ei:
                flow.exchange("CODE-1")
            assert "no token" in str(ei.value)

    def test_an_unreachable_provider_is_a_refusal_not_a_traceback(self):
        spec = O.OauthSpec(provider="custom", client_id="c",
                           tenant=f"http://127.0.0.1:{free_port()}")
        flow = O.OauthFlow(spec, "sid-8")
        with pytest.raises(O.OauthError) as ei:
            flow.exchange("CODE-1")
        assert "unreachable" in str(ei.value)

    def test_an_error_redirect_is_parsed_not_exchanged(self):
        code, state, error, desc = O.parse_redirect(
            "error=access_denied&error_description=the+user+refused&state=abc")
        assert code == "" and error == "access_denied" and state == "abc"
        assert "refused" in desc

    def test_the_authorize_error_path(self):
        with IdP(authorize_error="access_denied") as idp:
            flow = O.OauthFlow(idp.spec(), "sid-9")
            url = flow.authorize_url()
            assert "redirect_uri" in url
            # the provider answers with an error redirect instead of a code
            _code, _state, error, _d = O.parse_redirect("error=access_denied&state=x")
            assert error == "access_denied"


class TestRefresh:

    def test_a_refresh_keeps_the_scope_and_the_old_refresh_token(self):
        with IdP(token_answer={"access_token": "AT-2", "expires_in": 3600}) as idp:
            flow = O.OauthFlow(idp.spec(), "sid-10")
            flow.tokens = {"access_token": "AT-1", "refresh_token": "RT-OLD",
                           "scope": "openid Mail.Read", "token_type": "Bearer"}
            out = flow.refresh()
            assert out["access_token"] == "AT-2"
            assert out["refresh_token"] == "RT-OLD", "a provider that omits the refresh token"
            assert out["scope"] == "openid Mail.Read"
            form = [f for p, _q, f in idp.requests if p == "/token"][0]
            assert form["grant_type"] == "refresh_token"
            assert form["refresh_token"] == "RT-OLD"

    def test_refresh_without_a_token_is_refused(self):
        with IdP() as idp:
            flow = O.OauthFlow(idp.spec(), "sid-11")
            with pytest.raises(O.OauthError):
                flow.refresh()


class TestTheManager:

    def test_a_second_flow_for_the_same_session_replaces_the_first(self):
        with IdP() as idp:
            m = O.OauthManager()
            first = m.start(idp.spec(), "sid-x")
            second = m.start(idp.spec(), "sid-x")
            assert m.get("sid-x") is second
            assert m.by_state_lookup(first.state) is None, "the old state must stop working"
            assert m.by_state_lookup(second.state) is second

    def test_the_flow_map_is_bounded(self):
        with IdP() as idp:
            m = O.OauthManager(max_flows=3)
            flows = [m.start(idp.spec(), f"sid-{i}") for i in range(6)]
            assert len(m.summary()) == 3
            assert m.by_state_lookup(flows[0].state) is None
            assert m.by_state_lookup(flows[-1].state) is not None

    def test_the_summary_hides_tokens_by_default(self):
        with IdP() as idp:
            m = O.OauthManager()
            flow = m.start(idp.spec(), "sid-y")
            flow.exchange("CODE-1")
            row = m.summary()[0]
            assert row["status"] == "token" and "tokens" not in row
            assert m.flows["sid-y"].to_dict(with_tokens=True)["tokens"]["access_token"] == "AT-1"


class TestSpecValidation:

    def test_a_client_id_is_required(self):
        with pytest.raises(O.OauthError) as ei:
            O.OauthSpec(provider="microsoft", client_id="")
        assert "--oauth-client-id" in str(ei.value)

    def test_an_unknown_provider_lists_the_known_ones(self):
        with pytest.raises(O.OauthError) as ei:
            O.OauthSpec(provider="nope", client_id="c")
        assert "microsoft" in str(ei.value)

    def test_a_custom_provider_needs_an_issuer(self):
        with pytest.raises(O.OauthError):
            O.OauthSpec(provider="custom", client_id="c", tenant="")

    def test_the_known_providers_build_urls(self):
        for name in ("microsoft", "google", "okta", "github"):
            spec = O.OauthSpec(provider=name, client_id="c", tenant="acme")
            assert spec.issuer.startswith("http") and spec.authorize_path
            assert "://" not in spec.authorize_path


class TestTheProxyRelay:
    """The relay through the real proxy: a scanner that reads the first response sees a 302
    to the provider and nothing of ours, and the tokens land in the vault."""

    def _proxy(self, db, idp, **over):
        from test_phishlet import two_host_phishlet

        from core.proxy import ProxyEngine, serve_proxy
        phishlet = two_host_phishlet(self._up_port, **over)
        phishlet.oauth = idp.spec(redirect_uri=f"http://127.0.0.1:{0}/__bh/oauth/cb")
        phishlet.oauth.redirect_uri = ""          # the proxy fills in its own origin
        engine = ProxyEngine(phishlet, db=db, geo_provider="off", logger=lambda *a: None)
        self.alerts = []
        engine.on_capture = self.alerts.append
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="oauth-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return engine, httpd, port

    def _get(self, port, path, follow=False):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", path, headers={"Host": "127.0.0.1",
                                          "User-Agent": "Mozilla/5.0 (Windows NT 10.0) "
                                                        "AppleWebKit/537.36 Chrome/126",
                                          "Accept": "text/html,*/*;q=0.8"})
        r = conn.getresponse()
        out = (r.status, r.getheader("Location"), r.read().decode("utf-8", "replace"))
        conn.close()
        return out

    def test_the_first_navigation_is_a_redirect_to_the_real_provider(self):
        from test_phishlet import UpstreamServer
        with UpstreamServer() as up, IdP() as idp:
            self._up_port = up.port
            from core import capture as cap
            db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "o.db"))
            engine, httpd, port = self._proxy(db, idp)
            try:
                st, loc, body = self._get(port, "/login")
                assert st == 302, (st, body[:120])
                assert loc.startswith(idp.base + "/authorize"), loc
                assert "code_challenge=" in loc and "state=" in loc
                # actually hit the provider (without following its redirect back to us)
                import urllib.request
                class _NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *a, **kw):
                        return None
                import contextlib
                with contextlib.suppress(urllib.error.HTTPError):
                    urllib.request.build_opener(_NoRedirect).open(
                        urllib.request.Request(loc, headers={"User-Agent": "Mozilla/5.0"}),
                        timeout=10)
                auth = [q for p, q, _f in idp.requests if p == "/authorize"][0]
                assert auth["client_id"] == "test-client"
                assert auth["code_challenge_method"] == "S256"
            finally:
                httpd.shutdown()
                db.close()

    def test_the_callback_vaults_the_tokens_and_sends_the_victim_on(self):
        from test_phishlet import UpstreamServer
        with UpstreamServer() as up, IdP() as idp:
            self._up_port = up.port
            from core import capture as cap
            db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "o2.db"))
            engine, httpd, port = self._proxy(db, idp)
            try:
                _st, loc, _b = self._get(port, "/login")
                state = dict(urllib.parse.parse_qsl(
                    urllib.parse.urlparse(loc).query))["state"]
                st, loc2, _body = self._get(port, f"/__bh/oauth/cb?code=CODE-1&state={state}")
                assert st == 302, (st, loc2)
                token_form = [f for p, _q, f in idp.requests if p == "/token"]
                assert token_form and token_form[0]["code_verifier"], "no PKCE verifier sent"
                rec = list(db.session_list(limit=5))
                assert rec, "no session stored"
                vaulted = db.session_get(rec[0]["sid"])
                assert (vaulted.get("oauth") or {}).get("refresh_token") == "RT-1"
                assert S.oauth_valid(vaulted) is True
                assert any(a.get("type") == "oauth" for a in self.alerts), self.alerts
            finally:
                httpd.shutdown()
                db.close()

    def test_a_wrong_state_is_refused_and_nothing_is_exchanged(self):
        from test_phishlet import UpstreamServer
        with UpstreamServer() as up, IdP() as idp:
            self._up_port = up.port
            from core import capture as cap
            db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "o3.db"))
            engine, httpd, port = self._proxy(db, idp)
            try:
                self._get(port, "/login")
                st, _loc, body = self._get(port, "/__bh/oauth/cb?code=CODE-1&state=wrong")
                assert st == 200 and "could not be completed" in body.lower(), body[:200]
                assert not [p for p, _q, _f in idp.requests if p == "/token"], \
                    "a code was exchanged with a mismatched state"
            finally:
                httpd.shutdown()
                db.close()

    def test_a_provider_refusal_shows_a_neutral_page(self):
        from test_phishlet import UpstreamServer
        with UpstreamServer() as up, IdP() as idp:
            self._up_port = up.port
            from core import capture as cap
            db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "o4.db"))
            engine, httpd, port = self._proxy(db, idp)
            try:
                self._get(port, "/login")
                st, _loc, body = self._get(
                    port, "/__bh/oauth/cb?error=access_denied&state=x")
                assert st == 200 and "not completed" in body.lower(), body[:200]
                assert not [p for p, _q, _f in idp.requests if p == "/token"]
            finally:
                httpd.shutdown()
                db.close()
