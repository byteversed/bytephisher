"""The last three rungs: PKINIT, shadow credentials, and the Golden Ticket.

What can be verified without a domain is verified here: the structures round-trip, the RC4-HMAC
cipher round-trips (and refuses a wrong key), the refusals fire with a reason, and the blobs
carry the tags a DC or a tool expects. What cannot be verified here - a real KDC accepting a
forged ticket, a DC accepting a shadow credential - is stated as such and not pretended.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import goldenticket as GT  # noqa: E402
from core import kerberos as K  # noqa: E402
from core import pkinit as P  # noqa: E402
from core import shadowcred as SC  # noqa: E402

pytestmark = pytest.mark.unit

KEY = bytes(range(16))
SID = "S-1-5-21-1-2-3"


class TestRc4Hmac:

    @pytest.mark.parametrize("size", [0, 1, 12, 64, 200])
    def test_it_round_trips(self, size):
        payload = bytes(range(256))[:size]
        blob = GT.rc4_hmac_encrypt(KEY, payload, usage=2)
        assert GT.rc4_hmac_decrypt(KEY, blob, usage=2) == payload
        assert len(blob) == size + 32, "checksum 16 + plaintext 16 + payload"

    def test_the_checksum_sits_outside_the_cipher(self):
        """The wire form is `checksum || RC4(K3, checksum || plain)`; running the cipher over the
        whole blob shifts the keystream by 16 bytes and nothing ever verifies."""
        payload = b"A" * 32
        blob = GT.rc4_hmac_encrypt(KEY, payload, usage=2)
        assert GT.rc4_hmac_decrypt(KEY, blob, usage=2) == payload

    def test_a_wrong_key_is_refused_not_ignored(self):
        blob = GT.rc4_hmac_encrypt(KEY, b"x" * 20, usage=2)
        with pytest.raises(GT.GoldenTicketError):
            GT.rc4_hmac_decrypt(bytes(16), blob, usage=2)

    def test_a_wrong_usage_is_refused(self):
        blob = GT.rc4_hmac_encrypt(KEY, b"x" * 20, usage=2)
        with pytest.raises(GT.GoldenTicketError):
            GT.rc4_hmac_decrypt(KEY, blob, usage=3)

    def test_a_short_blob_is_refused(self):
        with pytest.raises(GT.GoldenTicketError):
            GT.rc4_hmac_decrypt(KEY, b"short", usage=2)

    def test_the_rc4_core_matches_the_published_keystream(self):
        # RFC 6229: key 0x0102030405 -> b2 39 63 05 f0 3d c0 27 ...
        assert GT._rc4(bytes([1, 2, 3, 4, 5]), bytes(8)).hex() == "b2396305f03dc027"


class TestTheGoldenTicket:

    def test_a_forged_ticket_carries_the_application_tag_and_the_pac(self):
        out = GT.forge("CONTOSO.TEST", user="Administrator", krbtgt_hash=KEY,
                       domain_sid=SID, user_rid=500, groups=[SID + "-512"])
        assert out["ticket"][0] == 0x61, "a Ticket is [APPLICATION 1]"
        assert b"krbtgt/CONTOSO.TEST" in out["ticket"]
        assert b"Administrator" not in out["ticket"], \
            "the account name is inside the ENCRYPTED part: a ticket with it in the clear is " \
            "not a ticket a DC accepts"

    def test_the_kirbi_is_a_krb_cred_and_the_ccache_has_its_magic(self):
        out = GT.forge("CONTOSO.TEST", krbtgt_hash=KEY, domain_sid=SID)
        raw_kirbi = base64.b64decode(out["kirbi"])
        assert raw_kirbi[0] == 0x76, "a KRB-CRED is [APPLICATION 22]"
        raw = bytes.fromhex(out["ccache_hex"])
        assert raw[:2] == b"\x05\x04", "the ccache version is 0x0504"

    def test_a_group_list_is_what_puts_domain_admins_in_the_ticket(self):
        out = GT.forge("CONTOSO.TEST", krbtgt_hash=KEY, domain_sid=SID,
                       groups=[SID + "-512", SID + "-513"])
        assert len(out["groups"]) == 2

    def test_the_service_name_is_clear_and_the_identity_is_not(self):
        out = GT.forge("CONTOSO.TEST", krbtgt_hash=KEY, domain_sid=SID)
        assert b"krbtgt/CONTOSO.TEST" in out["ticket"], "the sname is outside the cipher"
        assert out["ticket"].count(b"Administrator") == 0, \
            "the user, the groups and the PAC are all inside the cipher"

    def test_a_missing_hash_is_refused_with_the_reason(self):
        with pytest.raises(GT.GoldenTicketError) as ei:
            GT.forge("CONTOSO.TEST", domain_sid=SID)
        assert "does not obtain it" in str(ei.value)

    def test_aes_is_refused_rather_than_half_done(self):
        with pytest.raises(GT.GoldenTicketError) as ei:
            GT.forge("CONTOSO.TEST", krbtgt_hash=KEY, domain_sid=SID, etype=18)
        assert "AES" in str(ei.value)

    def test_a_missing_sid_is_refused(self):
        with pytest.raises(GT.GoldenTicketError):
            GT.forge("CONTOSO.TEST", krbtgt_hash=KEY)
        with pytest.raises(GT.GoldenTicketError):
            GT._sid_bytes("not-a-sid")

    def test_the_lifetime_is_the_ten_year_default(self):
        out = GT.forge("CONTOSO.TEST", krbtgt_hash=KEY, domain_sid=SID, now=1000)
        assert out["expires"] - out["created"] == GT.DEFAULT_LIFETIME

    def test_the_plan_names_the_correlation_that_detects_it(self):
        plan = GT.plan(realm="CONTOSO.TEST")
        assert any("AS-REQ" in item for item in plan["visible"])
        assert any("twice" in item.lower() for item in plan["limits"])


class TestPkinit:

    def test_the_auth_pack_is_a_signed_cms_blob(self):
        pack = P.auth_pack(1234, signer=lambda d: b"S" * 32, cert_der=b"CERT")
        assert b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in pack, "id-signedData"
        assert b"CERT" in pack, "the certificate travels with the signature"
        assert b"S" * 32 in pack

    def test_the_as_req_carries_the_pkinit_padata_between_msg_type_and_req_body(self):
        pack = P.auth_pack(1, signer=lambda d: b"S" * 32)
        req = P.as_req_pkinit("CONTOSO.TEST", "admin", pack)
        assert req[0] == 0x6A
        _tag, fields, _end = K._read(req)
        inner = fields[0][1]
        assert [t for t, _v in inner] == [0xA1, 0xA2, 0xA3, 0xA4], "padata sits before req-body"
        assert bytes([P.PA_PK_AS_REQ]) in req and bytes([P.PA_PAC_REQUEST]) in req

    def test_an_empty_auth_pack_is_refused(self):
        with pytest.raises(P.PkinitError):
            P.as_req_pkinit("CONTOSO.TEST", "admin", b"")

    def test_signing_without_a_key_is_refused_with_what_is_missing(self):
        with pytest.raises(P.PkinitError) as ei:
            P.auth_pack(1)
        assert "PRIVATE key" in str(ei.value)

    def test_the_session_key_needs_the_private_key_and_says_so(self):
        asrep = K._tlv(0x6B, K._tlv(0xA3, K._tlv(0x1B, b"CONTOSO.TEST"))
                       + K._tlv(0xA6, K._tlv(0x30, K._tlv(0xA0, K._int(18))
                                             + K._tlv(0xA2, K._tlv(0x04, b"ENCRYPTED")))))
        with pytest.raises(P.PkinitError) as ei:
            P.session_key(asrep)
        assert "private key" in str(ei.value)
        out = P.session_key(asrep, decrypt=lambda c: b"SESSION-KEY-16b")
        assert out["session_key"] == b"SESSION-KEY-16b" and out["etype"] == 18

    def test_a_non_as_rep_is_refused(self):
        err = K._tlv(0x7E, K._tlv(0xA6, K._int(24))
                     + K._tlv(0xA9, K._tlv(0x1B, b"Need preauth")))
        with pytest.raises(P.PkinitError):
            P.session_key(err, decrypt=lambda c: b"x")

    def test_the_plan_names_the_certificate_requirement(self):
        plan = P.plan(realm="CONTOSO.TEST")
        assert any("NTAuth" in item for item in plan["limits"])
        assert "PKINIT plan" in P.describe(plan)


class TestShadowCredentials:

    def test_the_value_is_the_b_hex_form_the_attribute_takes(self):
        cred = SC.key_credential(public_key=b"PUBKEY" * 4,
                                 device_id="11111111-2222-3333-4444-555555555555")
        assert cred.startswith("B:") and len(cred) > 40
        bytes.fromhex(cred[2:]), "the payload must be valid hex"

    def test_the_key_material_and_the_device_id_are_in_the_blob(self):
        cred = SC.key_credential(public_key=b"MATERIAL", device_id="22222222-2222-2222-2222-222222222222")
        raw = bytes.fromhex(cred[2:])
        assert b"MATERIAL" in raw
        assert bytes.fromhex("22222222222222222222222222222222") in raw

    def test_a_credential_without_a_key_is_refused(self):
        with pytest.raises(SC.ShadowError):
            SC.key_credential(public_key=b"")

    def test_a_non_b_value_is_refused_by_add(self):
        class C:
            def modify(self, *a, **kw):
                return True

        with pytest.raises(SC.ShadowError):
            SC.add(C(), "CN=x", "not-a-credential")

    def test_add_and_remove_use_the_attribute_operations(self):
        calls = []

        class C:
            def modify(self, dn, changes, operation=2):
                calls.append((dn, list(changes), operation))
                return True

            def search(self, **kw):
                return [{"dn": "CN=x", "attrs": {"msDS-KeyCredentialLink": ["B:aa"]}}]

        cred = SC.key_credential(public_key=b"K")
        client = C()
        SC.add(client, "CN=admin,DC=x", cred)
        SC.remove(client, "CN=admin,DC=x", cred)
        assert [c[2] for c in calls] == [0, 1], "0 = add, 1 = delete"
        assert calls[0][1] == ["msDS-KeyCredentialLink"]
        assert SC.list_for(client, "CN=admin,DC=x") == ["B:aa"]

    def test_the_layout_is_declared_unverified_until_confirmed(self):
        plan = SC.plan(target="admin")
        assert plan["layout_verified"] is SC.LAYOUT_VERIFIED
        assert any("silently ignored" in item for item in plan["limits"])
        assert any("5136" in item for item in plan["visible"])

    def test_the_plan_states_the_write_access_precondition(self):
        plan = SC.plan()
        assert any("GenericWrite" in item for item in plan["needs"])
