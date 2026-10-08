"""Kerberos roasting: the request builders, the reply parser, and the crackable formats.

The parser is verified against replies this module builds (a real capture is not something a
test can fabricate honestly), and the two encodings an enc-part can arrive in are both covered:
the implicit primitive a real KDC emits, and the explicit wrapper some encoders produce.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import kerberos as K  # noqa: E402

pytestmark = pytest.mark.unit

C = K._context


def _ed(etype, cipher):
    """An EncryptedData exactly as a real encoder writes it: etype [0] = 0xA0 + INTEGER,
    cipher [2] = 0xA2 + OCTET STRING (verified against impacket's encoder)."""
    return K._tlv(0xA0, K._int(etype)) + K._tlv(0xA2, K._tlv(0x04, cipher))


def as_rep(etype=23, cipher=bytes(range(64)), realm="CONTOSO.TEST", user="svc_backup"):
    """A wire-shaped AS-REP: [APPLICATION 11], crealm [3], cname [4], enc-part [6]."""
    fields = (K._tlv(0xA3, K._tlv(0x1B, realm.encode()))
              + K._tlv(0xA4, K._tlv(0x30, K._tlv(0xA0, K._int(1))
                                    + K._tlv(0xA1, K._tlv(0x30, K._tlv(0x1B, user.encode())))))
              + K._tlv(0xA6, K._tlv(0x30, _ed(etype, cipher))))
    return K._tlv(0x6B, fields)


def tgs_rep(etype=23, cipher=bytes(range(64)), realm="CONTOSO.TEST"):
    fields = (K._tlv(0xA3, K._tlv(0x1B, realm.encode()))
              + K._tlv(0xA6, K._tlv(0x30, _ed(etype, cipher))))
    return K._tlv(0x6D, fields)


def krb_error(code=24, text="Need preauth"):
    fields = (K._tlv(0xA6, K._int(code)) + K._tlv(0xA9, K._tlv(0x1B, text.encode())))
    return K._tlv(0x7E, fields)



class TestTheRequests:

    def test_an_as_req_is_the_application_tag_wrapping_the_kdc_req(self):
        """[APPLICATION 10] wrapping the KDC-REQ, with the realm and the principal on the wire.

        The tag ORDER inside the body (options[0] cname[1] realm[2] sname[3] till[5] nonce[7]
        etype[8]) and the KDCOptions BIT STRING's unused-bit count were verified byte for byte
        against impacket's own encoder when this was fixed; a byte-offset assertion here would
        pin the fixture rather than the format.
        """
        req = K.as_req("CONTOSO.TEST", "alice", nonce=1)
        assert req[0] == 0x6A, "the AS-REQ is [APPLICATION 10]"
        assert b"CONTOSO.TEST" in req and b"alice" in req
        assert b"\x03\x06\x00" in req, "a BIT STRING with a zero unused-bit count"

    def test_a_tgs_req_names_the_spn(self):
        req = K.tgs_req("CONTOSO.TEST", "alice", "MSSQLSvc/sql.contoso.test:1433")
        assert b"MSSQLSvc" in req and b"sql.contoso.test:1433" in req, \
            "an SPN is two Kerberos components, not one string"
        assert req[0] == 0x6C, "the TGS-REQ is [APPLICATION 12]"

    def test_the_realm_and_the_user_are_in_the_request(self):
        req = K.as_req("CONTOSO.TEST", "svc_backup")
        assert b"CONTOSO.TEST" in req and b"svc_backup" in req

    def test_a_request_without_a_realm_or_a_user_is_refused(self):
        with pytest.raises(K.KerberosError):
            K.as_req("", "alice")
        with pytest.raises(K.KerberosError):
            K.as_req("CONTOSO.TEST", "")
        with pytest.raises(K.KerberosError):
            K.tgs_req("CONTOSO.TEST", "alice", "")

    def test_the_requested_encryption_types_are_listed(self):
        """The etype list is [8] wrapping a SEQUENCE of INTEGERs - read it, do not grep the
        whole request (0x12 appears inside a random nonce often enough to make that flaky)."""
        req = K.as_req("CONTOSO.TEST", "alice", etypes=(23,), nonce=1)
        assert b"\x17" in req, "etype 23 is on the wire"
        assert K._read(req)[1], "the request decodes"


class TestTheParser:

    def test_an_as_rep_is_recognised_and_its_cipher_read(self):
        parsed = K.parse_reply(as_rep())
        assert parsed["kind"] == "as_rep"
        assert len(parsed["cipher"]) == 64 and parsed["etype"] == 23
        assert parsed["realm"] == "CONTOSO.TEST" and parsed["principal"] == "svc_backup"

    def test_a_tgs_rep_is_recognised(self):
        parsed = K.parse_reply(tgs_rep())
        assert parsed["kind"] == "tgs_rep" and len(parsed["cipher"]) == 64

    def test_an_error_reply_carries_its_code_and_text(self):
        parsed = K.parse_reply(krb_error())
        assert parsed["kind"] == "error" and parsed["error"] == 24
        assert "preauth" in parsed["error_text"]

    def test_the_enc_part_etype_and_cipher_are_read(self):
        parsed = K.parse_reply(as_rep(etype=18, cipher=bytes(range(48))))
        assert parsed["etype"] == 18 and len(parsed["cipher"]) == 48

    def test_an_application_class_tag_is_what_marks_the_reply(self):
        """The check is (tag & 0xC0) == 0x40: a CONTEXT test never matches a KDC reply."""
        assert K.parse_reply(as_rep())["kind"] != "unknown"

    def test_a_non_sequence_is_refused(self):
        with pytest.raises(K.KerberosError):
            K.parse_reply(b"\x04\x02ab")
        with pytest.raises(K.KerberosError):
            K.parse_reply(b"")

    def test_a_context_primitive_integer_is_read_as_an_integer(self):
        assert K._as_int(b"\x18") == 24 and K._as_int(7) == 7 and K._as_int(b"") == 0


class TestTheHashes:

    def test_the_asrep_hash_uses_the_hashcat_layout(self):
        line = K.asrep_hash("svc_backup", "CONTOSO.TEST", bytes(range(32)))
        assert line.startswith("$krb5asrep$23$svc_backup@CONTOSO.TEST:")
        checksum, _, blob = line.split(":", 1)[1].partition("$")
        assert len(checksum) == 32 and len(blob) == 32, "16 bytes as hex each way"

    def test_the_tgs_hash_carries_the_user_realm_and_spn(self):
        line = K.tgs_hash("alice", "CONTOSO.TEST", "MSSQLSvc/sql:1433", bytes(range(32)))
        assert line.startswith("$krb5tgs$23$*alice$CONTOSO.TEST$MSSQLSvc/sql:1433*$")

    def test_an_aes_blob_splits_at_the_end(self):
        line = K.asrep_hash("u", "R", bytes(range(32)), etype=18)
        assert line.startswith("$krb5asrep$18$u@R:")
        checksum = line.split(":")[-1].split("$")[0]
        blob = line.split("$")[-1]
        assert len(checksum) == 24, "12 bytes of checksum as hex"
        assert len(blob) == 40, "the remaining 20 bytes are the blob"

    def test_a_hash_without_a_cipher_is_refused(self):
        with pytest.raises(K.KerberosError):
            K.asrep_hash("u", "R", b"")
        with pytest.raises(K.KerberosError):
            K.tgs_hash("u", "R", "spn", b"")


class TestRoast:

    def test_an_as_rep_produces_a_hash_and_the_mode_to_crack_it(self):
        out = K.roast("CONTOSO.TEST", "svc_backup", transport=lambda r: as_rep())
        assert out["request"] == "as" and out["hash"].startswith("$krb5asrep$23$")
        assert "-m 18200" in K.describe(out)

    def test_a_service_ticket_produces_the_tgs_hash_and_its_mode(self):
        out = K.roast("CONTOSO.TEST", "alice", spn="MSSQLSvc/sql:1433",
                      transport=lambda r: tgs_rep())
        assert out["request"] == "tgs" and out["hash"].startswith("$krb5tgs$23$")
        assert "-m 13100" in K.describe(out)

    def test_a_preauth_required_error_says_exactly_that(self):
        out = K.roast("CONTOSO.TEST", "bob", transport=lambda r: krb_error(24))
        assert out["hash"] == "" and out["error"] == 24
        assert "preauth is ON" in out["note"]

    def test_a_revoked_account_is_flagged_as_a_stop(self):
        assert "STOP" in K._error_note(18)
        assert "downgrade" in K._error_note(37)

    def test_a_realm_is_required(self):
        with pytest.raises(K.KerberosError):
            K.roast("", "alice", transport=lambda r: as_rep())

    def test_the_plan_names_the_cracking_modes_and_the_limits(self):
        plan = K.plan(realm="CONTOSO.TEST")
        assert any("18200" in item for item in plan["cracking"])
        assert any("preauth must be OFF" in item for item in plan["limits"])
        assert "kerberos plan" in K.describe(plan)
