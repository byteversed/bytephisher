"""Identity-tier hardening: each fix from the hostile-input / protocol audit, pinned.

Every test here drives an INJECTED transport, so nothing touches a tenant. The point of each
assertion is a defect that was found by reading the module against the real protocol and then
reproduced: a hostile token that crashed the tier, an injected answer whose refusal was ignored,
markup that escaped into an XML envelope, a fabricated client id, a tenant that injected a URL
path, and a state file that was neither durable nor refused when corrupt.
"""
import base64
import json
import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import appconsent as AC  # noqa: E402
from core import (
    dbsc,  # noqa: E402
    foci,  # noqa: E402
    prt,  # noqa: E402
)
from core import federation as F  # noqa: E402
from core import keepalive as K  # noqa: E402
from core import oauth as O  # noqa: E402
from core import samlforge as SF  # noqa: E402
from core import spray as S  # noqa: E402

pytestmark = pytest.mark.unit

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def jwt(payload):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return seg({"alg": "RS256"}) + "." + seg(payload) + ".sig"


def tokens(**claims):
    claims.setdefault("exp", time.time() + 600)
    return {"access_token": jwt(claims), "refresh_token": "RT-1"}


# =============================================================== dbsc: hostile exp ====
class TestReplayabilitySurvivesAHostileToken:

    def test_a_non_numeric_exp_does_not_crash_the_tier(self):
        # DEFECT: float(claims.get("exp")) raised on a token whose exp was a string, taking the
        # whole identity tier down with an uncaught ValueError.
        report = dbsc.replayability({"access_token": jwt({"exp": "not-a-number"}),
                                     "refresh_token": "RT-1"})
        assert report["verdict"] == "replayable" and report["expired"] is False
        assert any("not a number" in r for r in report["reasons"])

    def test_a_structured_exp_does_not_crash_either(self):
        # a list/dict exp raised TypeError, the sibling of the ValueError above
        report = dbsc.replayability({"access_token": jwt({"exp": [1, 2]}),
                                     "refresh_token": "RT-1"})
        assert report["verdict"] == "replayable"
        assert any("not a number" in r for r in report["reasons"])

    def test_an_absent_exp_is_not_expired(self):
        report = dbsc.replayability({"access_token": jwt({"sub": "a"}),
                                     "refresh_token": "RT-1"})
        assert report["expired"] is False

    def test_a_token_exactly_at_its_expiry_is_expired(self):
        # DEFECT (off-by-one): `exp < now` called a token at its exact expiry still valid, which
        # disagreed with core.session.oauth_valid (`now >= exp`). RFC 7519: valid only while
        # now < exp.
        report = dbsc.replayability({"access_token": jwt({"exp": 1000}),
                                     "refresh_token": "RT-1"}, now=1000)
        assert report["expired"] is True
        report = dbsc.replayability({"access_token": jwt({"exp": 1000}),
                                     "refresh_token": "RT-1"}, now=999.5)
        assert report["expired"] is False


# =============================================================== prt: injected transport ====
class TestPrtRefusalAndLeak:

    def test_an_injected_tenant_refusal_is_a_refusal_not_a_success(self):
        # DEFECT: the injected transport returned the Graph answer unchecked, so an error body
        # became a "successful" registration with empty ids and the refusal surfaced only as a
        # misleading "no device id" message.
        def post(url, payload, timeout, token):
            return {"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges"}}

        with pytest.raises(prt.PrtError) as ei:
            prt.register_device("AT", post=post)
        assert "refused" in str(ei.value) and "Insufficient privileges" in str(ei.value)
        assert "no device id" not in str(ei.value)

    def test_a_missing_device_id_reports_the_shape_not_the_values(self):
        # DEFECT: the error message interpolated the whole answer, which for a registration can
        # carry the transport key - a secret in an exception message.
        def post(url, payload, timeout, token):
            return {"transportKey": "SECRET-TOKEN-VALUE", "hint": "no device here"}

        with pytest.raises(prt.PrtError) as ei:
            prt.register_device("AT", post=post)
        message = str(ei.value)
        assert "SECRET-TOKEN-VALUE" not in message
        assert "keys:" in message and "transportKey" in message

    def test_a_good_injected_registration_still_works(self):
        def post(url, payload, timeout, token):
            return {"id": "obj-9", "deviceId": "dev-9", "transportKey": "tk-9"}

        reg = prt.register_device("AT", post=post)
        assert reg.device_id == "dev-9" and reg.transport_key == "tk-9"


# =============================================================== samlforge: XML escaping ====
class TestSamlResponseEscaping:

    def test_a_hostile_issuer_cannot_inject_markup(self):
        # DEFECT: response() interpolated issuer/destination/InResponseTo/ID raw while
        # assertion() escaped - markup in any of them broke or extended the envelope.
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        resp = SF.response(xml, '<script>alert(1)</script>',
                           destination='https://sp.test/"onload="x',
                           in_response_to='"><evil', response_id='"><x')
        assert "<script>alert(1)</script>" not in resp
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in resp
        assert 'https://sp.test/&quot;onload=&quot;x' in resp
        assert "&quot;&gt;&lt;evil" in resp

    def test_a_clean_response_is_byte_for_byte_the_same(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        resp = SF.response(xml, "https://i.test", destination="https://a.test/saml")
        assert 'Destination="https://a.test/saml"' in resp
        assert "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" \
               "https://i.test</saml:Issuer>" in resp


# =============================================================== spray: index + leak ====
class TestSprayAccounting:

    def test_a_repeated_password_reports_the_right_index(self):
        # DEFECT: passwords.index(password) returned the first occurrence, so a repeated
        # password reported the wrong index (and cost O(n) per attempt).
        rows = S.spray(["u1"], ["pw", "pw"], submit=lambda u, p: {"valid": False},
                       sleep=lambda s: None)["rows"]
        assert [r["password_index"] for r in rows] == [0, 1]

    def test_the_result_does_not_leak_the_callback_return(self):
        # DEFECT: row["_cb"] = on_result(row) stored the callback's return in the returned row.
        seen = []
        out = S.spray(["u1"], ["pw"], submit=lambda u, p: {"valid": False},
                      on_result=lambda r: (seen.append(r["user"]), "CB")[1],
                      sleep=lambda s: None)
        assert seen == ["u1"], "the callback still fires"
        assert all("_cb" not in r for r in out["rows"]), "the callback's return leaked into a row"


# =============================================================== tenant URL injection ====
class TestTenantInjection:

    def test_a_tenant_with_a_path_separator_is_refused(self):
        # DEFECT: the tenant was interpolated straight into the issuer URL, so "../../evil"
        # pointed the authorize/token calls at a different path on the provider.
        with pytest.raises(O.OauthError) as ei:
            O.OauthSpec(provider="microsoft", client_id="c", tenant="../../evil")
        assert "host segment" in str(ei.value)

    def test_other_breakout_characters_are_refused(self):
        for bad in ("a/b", "a\\b", "a@b.com", "a?x", "a#x", "a b", "..", "x/../y"):
            with pytest.raises(O.OauthError):
                O.OauthSpec(provider="microsoft", client_id="c", tenant=bad)

    def test_a_real_tenant_shape_is_accepted(self):
        for good in ("common", "organizations", "consumers", "contoso.onmicrosoft.com",
                     "contoso.test", "62e90394-69f5-4237-9190-012177145e10"):
            assert O.tenant_is_safe(good)
            spec = O.OauthSpec(provider="microsoft", client_id="c", tenant=good)
            assert good in spec.issuer

    def test_the_custom_provider_is_exempt(self):
        # for `custom` the tenant IS the base URL, so it must not be rejected
        spec = O.OauthSpec(provider="custom", client_id="c", tenant="http://127.0.0.1:9")
        assert spec.issuer == "http://127.0.0.1:9"

    def test_the_token_exchanges_refuse_a_hostile_tenant(self):
        with pytest.raises(AC.AppConsentError):
            AC.app_token("c", "s", tenant="../../evil")
        with pytest.raises(AC.AppConsentError):
            AC.consent_url("c", "https://x/cb", tenant="../../evil")
        with pytest.raises(foci.FociError):
            foci.swap("RT", "client", tenant="../../evil")

    def test_an_explicit_issuer_still_overrides_the_tenant(self):
        # the issuer argument is used as-is; the tenant is not embedded, so it is not validated
        seen = {}

        def post(url, data, timeout):
            seen["url"] = url
            return {"access_token": "AT"}

        foci.swap("RT", "client", tenant="../../evil", issuer="http://fake.test/token",
                  post=post)
        assert seen["url"] == "http://fake.test/token"


# =============================================================== keepalive state ====
class TestKeepAliveState:

    def test_a_corrupt_state_file_is_refused_not_silently_ignored(self):
        # DEFECT: a corrupt state file was swallowed and the daemon resumed from the
        # constructor's token - usually the original, already-consumed one.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ka.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ this is not json")
            with pytest.raises(K.KeepAliveError) as ei:
                K.KeepAlive("RT-old", client_id="c", state_path=path).load()
            assert "unreadable" in str(ei.value)

    def test_a_state_file_that_is_not_an_object_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ka.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[1, 2, 3]")
            with pytest.raises(K.KeepAliveError):
                K.KeepAlive("RT-old", client_id="c", state_path=path).load()

    def test_a_missing_state_file_is_not_an_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ka = K.KeepAlive("RT-old", client_id="c",
                             state_path=os.path.join(d, "absent.json")).load()
            assert ka.refresh_token == "RT-old"

    def test_a_rotation_is_written_atomically_and_durably(self, tmp_path, monkeypatch):
        # DEFECT: the write was atomic but not durable - no fsync, so a crash after the rename
        # could leave the file zero-length and the session lost.
        path = os.path.join(str(tmp_path), "ka.json")
        fsynced = []
        real_fsync = os.fsync

        def fake_fsync(fd):
            fsynced.append(fd)
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", fake_fsync)
        ka = K.KeepAlive("RT-0", client_id="c", state_path=path,
                         post=lambda u, d, t: {"access_token": "AT", "refresh_token": "RT-9"})
        ka.tick()
        assert fsynced, "the state file was not fsynced"
        assert not os.path.exists(path + ".tmp"), "the write is atomic"
        again = K.KeepAlive("RT-old", client_id="c", state_path=path).load()
        assert again.refresh_token == "RT-9" and again.rotations == 1


# =============================================================== federation domain ====
class TestFederationDomainValidation:

    def test_add_domain_refuses_a_non_hostname(self):
        # DEFECT: add_domain skipped the hostname check the other three calls apply.
        with pytest.raises(F.FederationError):
            F.add_domain("AT", "../../applications/abc")
        with pytest.raises(F.FederationError):
            F.add_domain("AT", "not a domain")

    def test_a_valid_domain_still_posts_the_id(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "contoso.test"}

        F.add_domain("AT-1", "contoso.test", post=post)
        assert seen["payload"] == {"id": "contoso.test"}


# =============================================================== foci client table ====
class TestFociClientTable:

    def test_the_fabricated_excel_id_is_gone(self):
        # DEFECT: an "excel" entry carried a made-up GUID (c7f0e3d6-...-1b1a1e1a1e1a) that is
        # not in the published FOCI research set; a wrong id exchanges against the wrong app.
        assert "excel" not in foci.CLIENTS
        assert "c7f0e3d6-1a1e-4d3f-8a7e-1b1a1e1a1e1a" not in foci.CLIENTS.values()

    def test_every_kept_client_id_is_a_real_uuid(self):
        for name, client in foci.CLIENTS.items():
            assert UUID.match(client), (name, client)
