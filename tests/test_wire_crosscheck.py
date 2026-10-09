"""Cross-checks of the Kerberos and AD wire formats against impacket (test-only).

A test that asserts the bytes this project happens to emit proves only that the code agrees
with itself; it cannot catch a layout that no other parser accepts. That failure mode is not
hypothetical here: an earlier RBCD descriptor was written in a shape no parser reads, the
domain controller silently ignored the write, and RBCD simply never took effect.

impacket is an independent implementation of the same published formats, so it is the ground
truth in both directions:

* a request THIS module encodes is decoded by impacket's own ASN.1 schema;
* a reply built to the RFC 4120 wire layout (hand-rolled in this file, no project helpers)
  is decoded by impacket's schema AND read by `core.kerberos.parse_reply`;
* the RBCD security descriptor is parsed by impacket's `ldaptypes` and must come back as one
  ACE granting full control to the intended SID.

The hand-rolled reply is deliberately complete (pvno, msg-type, a ticket, enc-part): a reply
without those is not a reply any KDC or impacket will accept, and testing against a shortcut
shape is how a parser that only understands its own fixtures stays green.

`impacket` is a test-only dependency; the product stays standard library only.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ad_hunt as H  # noqa: E402
from core import kerberos as K  # noqa: E402

pytestmark = pytest.mark.unit

ldaptypes = pytest.importorskip("impacket.ldap.ldaptypes",
                                reason="impacket is the cross-check implementation")
asn1 = pytest.importorskip("impacket.krb5.asn1",
                           reason="impacket is the cross-check implementation")
der_decode = pytest.importorskip("pyasn1.codec.der.decoder",
                                 reason="impacket's encoder/decoder")
der_encode = pytest.importorskip("pyasn1.codec.der.encoder",
                                 reason="impacket's encoder/decoder")

SID = "S-1-5-21-1-2-3-1105"
REALM = "CONTOSO.TEST"


# --- the RFC 4120 wire layout, written here by hand so the checker is independent ----------

def _t(tag, body):
    """A TLV with a definite length (DER short form, then 0x81/0x82 for longer bodies)."""
    n = len(body)
    if n < 128:
        head = bytes([tag, n])
    elif n < 256:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82]) + n.to_bytes(2, "big")
    return head + body


def _seq(*parts):
    return _t(0x30, b"".join(parts))


def _ctx(number, body):
    return _t(0xA0 | number, body)


def _gstr(text):
    return _t(0x1B, text.encode("utf-8"))


def _int(value, width=1):
    return _t(0x02, value.to_bytes(width, "big"))


def _octets(data):
    return _t(0x04, data)


def _pname(name_type, *parts):
    return _seq(_ctx(0, _int(name_type)),
                _ctx(1, _seq(*[_gstr(p) for p in parts])))


def _encdata(etype, cipher):
    return _seq(_ctx(0, _int(etype)), _ctx(2, _octets(cipher)))


def as_rep(etype=18, cipher=bytes(range(32))):
    """A complete AS-REP: [APPLICATION 11] SEQUENCE, crealm [3], cname [4], ticket [5],
    enc-part [6]. The ticket is what makes this a reply impacket's schema accepts."""
    ticket = _t(0x61, _seq(_ctx(0, _int(5)), _ctx(1, _gstr(REALM)),
                           _ctx(2, _pname(2, "krbtgt", REALM)),
                           _ctx(3, _encdata(18, bytes(range(16))))))
    body = _seq(_ctx(0, _int(5)),                       # pvno
                _ctx(1, _int(11)),                      # msg-type: AS-REP
                _ctx(3, _gstr(REALM)),                  # crealm
                _ctx(4, _pname(1, "svc_backup")),       # cname
                _ctx(5, ticket),                        # ticket
                _ctx(6, _encdata(etype, cipher)))       # enc-part
    return _t(0x6B, body)


def krb_error(code=24, text="Need preauth"):
    """A complete KRB-ERROR: pvno [0], msg-type [1], stime [4], susec [5], error-code [6],
    realm [9], sname [10], e-text [11].

    stime/susec/realm/sname are mandatory in impacket's KRB_ERROR schema, so a reply without
    them is not one impacket's own decoder accepts - the point of building it in full here.
    """
    body = _seq(_ctx(0, _int(5)),                                  # pvno
                _ctx(1, _int(30)),                                 # msg-type: KRB-ERROR
                _ctx(4, _t(0x18, b"20261010091940Z")),             # stime (GeneralizedTime)
                _ctx(5, _int(0, width=4)),                         # susec
                _ctx(6, _int(code)),                               # error-code
                _ctx(9, _gstr(REALM)),                             # realm
                _ctx(10, _pname(2, "krbtgt", REALM)),              # sname
                _ctx(11, _gstr(text)))                             # e-text
    return _t(0x7E, body)


class TestOurRequestsThroughImpacket:
    """What this module encodes must be what an independent KDC-side parser reads."""

    def test_an_as_req_is_accepted_by_impacket_and_names_the_realm_and_principal(self):
        req = K.as_req(REALM, "alice", nonce=1)
        decoded, rest = der_decode.decode(req, asn1Spec=asn1.AS_REQ())
        assert rest == b"", "impacket consumed the whole request, nothing left over"
        assert int(decoded["pvno"]) == 5 and int(decoded["msg-type"]) == 10
        body = decoded["req-body"]
        assert str(body["realm"]) == REALM
        assert [str(p) for p in body["cname"]["name-string"]] == ["alice"]
        assert [int(e) for e in body["etype"]] == [23, 18, 17]

    def test_the_kdc_options_impacket_reads_carry_the_expected_flags(self):
        """0x40810010, read by impacket itself: bit 1 (forwardable), bits 8 and 15, bit 27
        (renewable-ok). The pre-fix five-octet word shifted every one of these by 8."""
        req = K.as_req(REALM, "alice", nonce=1)
        decoded, _rest = der_decode.decode(req, asn1Spec=asn1.AS_REQ())
        options = decoded["req-body"]["kdc-options"]
        assert str(options.asBinary()) == "01000000100000010000000000010000"
        assert int(options.asInteger()) == 0x40810010, "the options word this module sets"

    def test_a_tgs_req_is_accepted_by_impacket_with_the_spn_split_in_two(self):
        req = K.tgs_req(REALM, "alice", "MSSQLSvc/sql.contoso.test:1433")
        decoded, rest = der_decode.decode(req, asn1Spec=asn1.TGS_REQ())
        assert rest == b""
        assert int(decoded["msg-type"]) == 12
        assert [str(p) for p in decoded["req-body"]["sname"]["name-string"]] == \
            ["MSSQLSvc", "sql.contoso.test:1433"]


class TestRealRepliesThroughOurParser:
    """A reply built to the RFC layout must read identically in impacket and in this module."""

    def test_an_as_rep_reads_the_same_in_impacket_and_in_parse_reply(self):
        raw = as_rep(etype=18, cipher=bytes(range(32)))
        decoded, rest = der_decode.decode(raw, asn1Spec=asn1.AS_REP())
        assert rest == b"", "the hand-rolled reply is what impacket expects"
        assert int(decoded["enc-part"]["etype"]) == 18
        assert bytes(decoded["enc-part"]["cipher"]) == bytes(range(32))

        parsed = K.parse_reply(raw)
        assert parsed["kind"] == "as_rep"
        assert parsed["etype"] == 18
        assert parsed["cipher"] == bytes(range(32))
        assert parsed["realm"] == REALM
        assert parsed["principal"] == "svc_backup"

    def test_a_krb_error_reads_its_code_and_text_in_both(self):
        raw = krb_error(code=24, text="Need preauth")
        decoded, rest = der_decode.decode(raw, asn1Spec=asn1.KRB_ERROR())
        assert rest == b""
        assert int(decoded["error-code"]) == 24
        assert str(decoded["e-text"]) == "Need preauth"

        parsed = K.parse_reply(raw)
        assert parsed["kind"] == "error"
        assert parsed["error"] == 24
        assert "preauth" in parsed["error_text"]

    def test_a_reserialized_reply_still_parses(self):
        """Round-trip through impacket's schema: the bytes are canonicalized by an
        independent encoder and this module's parser must still read them."""
        raw = as_rep(etype=23, cipher=bytes(range(64)))
        decoded, _rest = der_decode.decode(raw, asn1Spec=asn1.AS_REP())
        again = der_encode.encode(decoded)
        parsed = K.parse_reply(again)
        assert parsed["kind"] == "as_rep" and parsed["etype"] == 23
        assert len(parsed["cipher"]) == 64 and parsed["realm"] == REALM


class TestTheRbcdDescriptorThroughImpacket:
    """The descriptor a DC must accept: impacket's ldaptypes is the parser here."""

    def test_it_parses_as_one_allow_ace_granting_full_control_to_the_sid(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=H.rbcd_value(SID))
        assert int(sd["Control"]) & 0x8004 == 0x8004, "self-relative with a DACL present"
        dacl = sd["Dacl"]
        assert int(dacl["AclRevision"]) == 4
        assert int(dacl["AceCount"]) == 1, "one ACE, not a list of them"
        ace = dacl.aces[0]
        assert int(ace["AceType"]) == 0, "ACCESS_ALLOWED"
        assert int(ace["Ace"]["Mask"]["Mask"]) == 0x000F01FF, "full control"
        assert ace["Ace"]["Sid"].formatCanonical() == SID

    def test_a_different_principal_lands_in_the_sid_field(self):
        other = "S-1-5-21-9-9-9-500"
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=H.rbcd_value(other))
        assert sd["Dacl"].aces[0]["Ace"]["Sid"].formatCanonical() == other
