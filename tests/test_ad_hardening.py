"""Protocol-level hardening for the AD/network tier: byte vectors, not round-trips.

Every vector below is GROUND TRUTH produced by an independent implementation, captured here as
literal bytes so the test does not need the tool installed:

  * the AS-REQ / AS-REP / TGS-REP / KRB-ERROR blobs are impacket 0.11.0's own encoder output
    (`impacket.krb5.asn1`, `pyasn1.codec.der.encoder`), and the module's AS-REQ is asserted
    EQUAL to impacket's byte for byte;
  * the LDAP filter encodings are ldap3 2.9.1's `compile_filter` output (RFC 4515 escapes
    included);
  * the NTLM messages are built by hand from MS-NLMP 2.2.1.x (the CHALLENGE layout, and the
    AUTHENTICATE layout with the declared payload offsets) - impacket's own type-3 `getData()`
    is internally inconsistent (it reserves a 16-byte MIC in the offsets but does not emit one),
    so it is deliberately NOT used here;
  * the RBCD security descriptor is impacket's `ldaptypes` output (Control 0x8004, AclRevision
    4, mask 0x000F01FF);
  * the DNS record is the `DNS_RECORD` layout from krbrelayx/dnstool ([MS-DNSP] 2.3.2.2) and
    impacket's `new_dns_record`.

If a fix regresses, the assertion fails against these bytes - never against the module's own
encoder, which would happily agree with a bug in itself.
"""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ad_hunt as H  # noqa: E402
from core import kerberos as K  # noqa: E402
from core import ldap as L  # noqa: E402
from core import relay as R  # noqa: E402

pytestmark = pytest.mark.unit

# ------------------------------------------------------------------ vectors --
# impacket 0.11.0, realm CONTOSO.TEST, user alice, nonce 1, etypes (23,18,17),
# kdc-options 0x40810010, till 2030-01-01T00:00:00Z (1893456000.0).
IMPACKET_AS_REQ = bytes.fromhex(
    "6a8186308183a103020105a20302010aa4773075a00703050040810010a1123010a003020101a1093007"
    "1b05616c696365a20e1b0c434f4e544f534f2e54455354a321301fa003020102a11830161b066b726274"
    "67741b0c434f4e544f534f2e54455354a511180f32303330303130313030303030305aa703020101a80b"
    "3009020117020112020111")
# impacket AS-REP: crealm CONTOSO.TEST, cname svc_backup, enc-part etype 23, cipher bytes(0..63).
IMPACKET_AS_REP = bytes.fromhex(
    "6b81db3081d8a003020105a10302010ba30e1b0c434f4e544f534f2e54455354a4173015a003020101a1"
    "0e300c1b0a7376635f6261636b7570a55661543052a003020105a10e1b0c434f4e544f534f2e54455354a2"
    "21301fa003020102a11830161b066b72627467741b0c434f4e544f534f2e54455354a3183016a0030201"
    "17a20f040d5449434b45542d434950484552a64b3049a003020117a2420440000102030405060708090a"
    "0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334"
    "35363738393a3b3c3d3e3f")
# impacket TGS-REP: cname alice, sname MSSQLSvc/sql.contoso.test:1433, enc-part etype 23, 48 bytes.
IMPACKET_TGS_REP = bytes.fromhex(
    "6d81d13081cea003020105a10302010da30e1b0c434f4e544f534f2e54455354a4123010a003020101a1"
    "0930071b05616c696365a561615f305da003020105a10e1b0c434f4e544f534f2e54455354a22c302aa003"
    "020102a12330211b084d5353514c5376631b1573716c2e636f6e746f736f2e746573743a31343333a31830"
    "16a003020117a20f040d5449434b45542d434950484552a63b3039a003020117a232043000010203040506"
    "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
# impacket KRB-ERROR: error-code 24, realm CONTOSO.TEST, e-text "Need preauth" at [11].
IMPACKET_KRB_ERROR = bytes.fromhex(
    "7e6c306aa003020105a10302011ea411180f32303330303130313030303030305aa503020100a6030201"
    "18a90e1b0c434f4e544f534f2e54455354aa21301fa003020102a11830161b066b72627467741b0c434f"
    "4e544f534f2e54455354ab0e1b0c4e6565642070726561757468")
# ldap3 2.9.1 filter encodings.
LDAP3_FILTERS = {
    r"(cn=a\2ab)": "a3090402636e0403612a62",
    r"(cn=a\28b\29)": "a30a0402636e040461286229",
    r"(cn=a\5cb)": "a3090402636e0403615c62",
    r"(cn=a\2a*b)": "a40d0402636e30078002612a820162",
    "(cn=admin)": "a30b0402636e040561646d696e",
    "(cn=ab*cd*ef)": "a4120402636e300c800261628102636482026566",
    "(objectClass=*)": "870b6f626a656374436c617373",
}
# MS-NLMP 2.2.1.2 CHALLENGE_MESSAGE, flags 0xe28a8215, challenge 0123456789abcdef.
NTLM_TYPE2 = bytes.fromhex(
    "4e544c4d5353500002000000070007003800000015828ae20123456789abcdef000000000000000000"
    "0000003f0000000601b11d0000000f434f4e544f534f")
# MS-NLMP 2.2.1.3 AUTHENTICATE_MESSAGE, domain CONTOSO, user Administrator, workstation WS01.
NTLM_TYPE3 = bytes.fromhex(
    "4e544c4d5353500003000000180018005800000018001800700000000e000e00880000001a001a009600000008000800"
    "b000000010001000b800000015828ae20601b11d0000000f000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000011111111111111111111111111111111111111111111111143004f004e005400"
    "4f0053004f00410064006d0069006e006900730074007200610074006f00720057005300300031002222222222222222"
    "2222222222222222")
# impacket ldaptypes RBCD descriptor granting full control (0x000F01FF) to the SID.
IMPACKET_RBCD = bytes.fromhex(
    "010004800000000000000000000000001400000004002c000100000000002400ff010f000105000000"
    "0000051500000001000000020000000300000051040000")
# krbrelayx/dnstool DNS_RECORD for A 10.0.0.5, ttl 600 (TtlSeconds is big-endian).
DNSTOOL_A_RECORD = bytes.fromhex("0400010005f00000000000000000025800000000000000000a000005")


class _FakeSock:
    """A socket that hands back canned chunks and records what was written."""

    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def recv(self, _size=8192):
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True


def _client(sock=None):
    return L.LdapClient("dc.test", connect=lambda addr, timeout: sock)


def _capture_search(**kwargs):
    """Run a search against a stubbed _send and return the encoded SearchRequest op."""
    client = L.LdapClient("dc.test")
    seen = {}

    def fake_send(_mid, op):
        seen["op"] = op
        return [(0x65, [(0x0A, 0), (0x04, b""), (0x04, b"")])]

    client._send = fake_send
    client.search(base="DC=x", filter_text="(cn=a)", **kwargs)
    return seen["op"]


# --------------------------------------------------------------------- LDAP --
class TestLdapBer:
    def test_a_multi_byte_length_round_trips(self):
        blob = L.encode(0x04, "x" * 300)
        assert blob[1] == 0x82 and int.from_bytes(blob[2:4], "big") == 300
        assert L.decode(blob)[1] == b"x" * 300

    def test_a_frame_split_mid_message_is_reassembled(self):
        entry = L.encode(0x30, [L.encode(0x02, 1),
                               L.encode(0x64, [L.encode(0x04, "uid=x"), L.encode(0x30, [])])])
        done = L.encode(0x30, [L.encode(0x02, 1),
                              L.encode(0x65, [L.encode(0x0A, 0), L.encode(0x04, ""),
                                              L.encode(0x04, "")])])
        whole = entry + done
        # cut the SECOND frame in half: the reader must wait for the rest, not fail
        sock = _FakeSock([whole[:len(entry) + 3], whole[len(entry) + 3:]])
        client = _client(sock)
        client.sock = sock
        bodies = client._read_response(1)
        rows = L.LdapClient._parse_entries(bodies)
        assert rows == [{"dn": "uid=x", "attrs": {}}]
        assert L.LdapClient._result(bodies)[0] == 0

    def test_a_truncated_element_is_refused(self):
        with pytest.raises(L.LdapError):
            L.decode(b"\x04\x05ab")


class TestLdapRfc4515Escapes:
    @pytest.mark.parametrize("text,expected", sorted(LDAP3_FILTERS.items()))
    def test_the_encoding_matches_ldap3(self, text, expected):
        assert L.parse_filter(text).hex() == expected

    def test_an_escaped_wildcard_is_a_literal_not_a_wildcard(self):
        # (cn=a\2ab) is an EQUALITY match on the three bytes a*b, not the substring "a*b"
        encoded = L.parse_filter(r"(cn=a\2ab)")
        assert encoded[0] == 0xA3
        assert L.decode(encoded)[1][1][1] == b"a*b"

    def test_a_real_wildcard_still_splits(self):
        _tag, fields, _end = L.decode(L.parse_filter(r"(cn=a\2a*b)"))
        subs = fields[1][1]
        assert [v for _t, v in subs] == [b"a*", b"b"]

    def test_the_escape_helpers(self):
        assert L._unescape(r"a\2ab") == b"a*b"
        assert L._unescape(r"a\5cb") == b"a\\b"
        assert L._unescape("plain") == b"plain"
        assert L._split_wildcards(r"a\2a*b") == ([b"a*", b"b"], True)
        assert L._split_wildcards(r"a\2ab") == ([b"a*b"], False)


class TestLdapSearch:
    def test_an_explicit_zero_size_limit_is_not_rewritten_to_1000(self):
        _tag, fields, _end = L.decode(_capture_search(size_limit=0, timeout=0))
        # fields: base, scope, deref, sizeLimit, timeLimit, typesOnly, filter, attrs
        assert fields[3][1] == 0, "sizeLimit 0 means 'no client limit', not 1000"
        assert fields[4][1] == 0, "timeLimit 0 means 'no client limit', not 15"

    def test_the_defaults_are_still_1000_and_15(self):
        _tag, fields, _end = L.decode(_capture_search())
        assert fields[3][1] == 1000 and fields[4][1] == 15


class TestLdapModify:
    def test_an_out_of_range_operation_is_refused(self):
        client = L.LdapClient("dc.test")
        for bad in (9, -1, 100):
            with pytest.raises(L.LdapError):
                client.modify("CN=x", {"cn": ["y"]}, operation=bad)

    def test_the_four_defined_operations_are_accepted(self):
        client = L.LdapClient("dc.test")
        seen = []

        def fake_send(_mid, op):
            seen.append(op)
            return [(0x67, [(0x0A, 0), (0x04, b""), (0x04, b"")])]

        client._send = fake_send
        for op in (0, 1, 2, 3):
            assert client.modify("CN=x", {"cn": ["y"]}, operation=op) is True
        assert len(seen) == 4


class TestLdapUnbind:
    def test_unbind_writes_application_2_null_and_closes(self):
        sock = _FakeSock()
        client = _client(sock)
        client.sock = sock
        assert client.unbind() is True
        # LDAPMessage{ messageID 1, [APPLICATION 2] NULL } - and NO read (the server never replies)
        assert sock.sent[-1] == bytes.fromhex("30050201014200")
        assert sock.closed and client.sock is None


# ----------------------------------------------------------------- Kerberos --
class TestKerberosRequests:
    def test_the_as_req_is_byte_for_byte_impacket(self):
        req = K.as_req("CONTOSO.TEST", "alice", etypes=(23, 18, 17), nonce=1, till=1893456000.0)
        assert req == IMPACKET_AS_REQ

    def test_kdc_options_is_a_four_byte_bit_string(self):
        # KDCOptions is a 32-bit BIT STRING: `03 05 00` (4 value bytes), never `03 06 00`
        req = K.as_req("CONTOSO.TEST", "alice", nonce=1)
        assert b"\x03\x05\x00\x40\x81\x00\x10" in req
        assert b"\x03\x06\x00" not in req, "a 5-byte BIT STRING shifts every option bit by 8"

    def test_the_tgs_req_names_the_spn_as_two_components(self):
        req = K.tgs_req("CONTOSO.TEST", "alice", "MSSQLSvc/sql.contoso.test:1433")
        assert req[0] == 0x6C
        assert b"MSSQLSvc" in req and b"sql.contoso.test:1433" in req


class TestKerberosReply:
    def test_a_real_explicit_tagged_as_rep_parses(self):
        parsed = K.parse_reply(IMPACKET_AS_REP)
        assert parsed["kind"] == "as_rep"
        assert parsed["etype"] == 23
        assert parsed["cipher"] == bytes(range(64))
        assert parsed["realm"] == "CONTOSO.TEST"
        assert parsed["principal"] == "svc_backup"

    def test_a_real_explicit_tagged_tgs_rep_parses(self):
        parsed = K.parse_reply(IMPACKET_TGS_REP)
        assert parsed["kind"] == "tgs_rep" and len(parsed["cipher"]) == 48
        assert parsed["principal"] == "alice"

    def test_a_real_error_reports_its_code_and_e_text(self):
        parsed = K.parse_reply(IMPACKET_KRB_ERROR)
        assert parsed["kind"] == "error"
        assert parsed["error"] == 24
        assert parsed["error_text"] == "Need preauth", "e-text is [11], realm is [9]"
        assert parsed["realm"] == "CONTOSO.TEST"

    def test_the_implicit_form_the_old_fixtures_used_still_parses(self):
        # regression guard: the module must not have traded one shape for the other
        fields = (K._tlv(0xA3, K._tlv(0x1B, b"CONTOSO.TEST"))
                  + K._tlv(0xA6, K._tlv(0x30, K._tlv(0xA0, K._int(23))
                                        + K._tlv(0xA2, K._tlv(0x04, bytes(range(32)))))))
        parsed = K.parse_reply(K._tlv(0x6B, fields))
        assert parsed["kind"] == "as_rep" and parsed["etype"] == 23

    def test_the_reply_unwrap_helper(self):
        assert K._unwrap_app([(0x30, [(0xA3, b"x")])]) == [(0xA3, b"x")]
        assert K._unwrap_app([(0xA3, b"x"), (0xA6, b"y")]) == [(0xA3, b"x"), (0xA6, b"y")]


# -------------------------------------------------------------------- relay --
class TestRelayNtlm:
    def test_a_real_challenge_message_parses_its_offsets(self):
        msg = R.parse_ntlm(NTLM_TYPE2)
        assert msg.type == 2
        assert msg.challenge == bytes.fromhex("0123456789abcdef")
        assert msg.flags == 0xe28a8215

    def test_a_real_authenticate_message_parses_the_identity(self):
        msg = R.parse_ntlm(NTLM_TYPE3)
        assert msg.type == 3
        assert msg.domain == "CONTOSO" and msg.user == "Administrator"
        assert msg.workstation == "WS01"

    def test_the_base64_authorization_form_parses_too(self):
        import base64
        msg = R.parse_ntlm("NTLM " + base64.b64encode(NTLM_TYPE3).decode())
        assert msg.user == "Administrator"

    def test_a_short_challenge_is_refused_not_crashed(self):
        assert R.parse_ntlm(b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 8) is None

    def test_a_non_ntlm_value_is_not_a_message(self):
        assert R.parse_ntlm("Basic Zm9v") is None
        assert R.ntlm_type(b"") == 0


# ------------------------------------------------------------------ ad_hunt --
class TestAdHuntWrites:
    def test_the_rbcd_descriptor_matches_impacket(self):
        assert H.rbcd_value("S-1-5-21-1-2-3-1105") == IMPACKET_RBCD

    def test_the_rbcd_descriptor_header_is_well_formed(self):
        sd = H.rbcd_value("S-1-5-21-1-2-3-1105")
        assert sd[:2] == b"\x01\x00" and int.from_bytes(sd[2:4], "little") == 0x8004
        # OffsetOwner, OffsetGroup, OffsetSacl, OffsetDacl
        assert struct.unpack_from("<IIII", sd, 4) == (0, 0, 0, 20)
        assert sd[20:22] == b"\x04\x00"                      # AclRevision 4, Sbz1
        acl_size, ace_count = struct.unpack_from("<HH", sd, 22)
        assert acl_size == len(sd) - 20 and ace_count == 1
        ace_size = struct.unpack_from("<H", sd, 30)[0]
        # S-1-5-21-1-2-3-1105 has 5 sub-authorities: the SID is 8 + 5*4 = 28 bytes and the ACE
        # is AceType(1)+AceFlags(1)+AceSize(2)+Mask(4)+Sid(28) = 36.
        assert ace_size == 8 + 28, "AceType+AceFlags+AceSize+Mask+Sid"

    def test_the_dns_record_matches_dnstool(self):
        record = H.dns_record("wpad", "10.0.0.5", "DC=x.test", ttl=600)["attrs"]["dnsRecord"][0]
        assert record == DNSTOOL_A_RECORD

    def test_the_dns_ttl_is_big_endian(self):
        record = H.dns_record("wpad", "10.0.0.5", "DC=x.test", ttl=600)["attrs"]["dnsRecord"][0]
        assert record[12:16] == struct.pack(">I", 600)
