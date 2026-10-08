"""The LDAP client: BER, RFC 4515 filters, and the frame walker.

The live behaviour was verified against a real directory server while this was written (bind,
substring, present, AND/OR/NOT, root DSE), and what is pinned here is the byte-level contract so
a regression shows up without a network: the IMPLICIT TAGS rule that makes an equality filter
`a3 <fields>` rather than `a3 <SEQUENCE>`, the substring tags, and the reader keeping the
operation tag that distinguishes an entry from the Done.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ldap as L  # noqa: E402

pytestmark = pytest.mark.unit


class TestBer:

    def test_a_short_form_length_and_a_long_form_one(self):
        assert L.encode(0x04, "ab") == b"\x04\x02ab"
        long_value = "x" * 200
        encoded = L.encode(0x04, long_value)
        assert encoded[1] == 0x81 and encoded[2] == 200, "200 needs the long form"

    def test_an_integer_keeps_its_value_and_its_sign(self):
        assert L.encode(0x02, 0) == b"\x02\x01\x00"
        assert L.encode(0x02, 127) == b"\x02\x01\x7f"
        assert L.encode(0x02, 128) == b"\x02\x02\x00\x80", "a high bit needs a leading zero"
        tag, value, _end = L.decode(L.encode(0x02, 300))
        assert tag == 0x02 and value == 300

    def test_a_constructed_element_decodes_into_children(self):
        blob = L.encode(0x30, [L.encode(0x02, 1), L.encode(0x04, "cn")])
        tag, children, end = L.decode(blob)
        assert tag == 0x30 and len(children) == 2 and end == len(blob)
        assert children[1][1] == b"cn"

    def test_a_truncated_element_is_refused_not_guessed(self):
        with pytest.raises(L.LdapError):
            L.decode(b"\x04\x05ab")

    def test_a_boolean_decodes_to_a_boolean(self):
        tag, value, _end = L.decode(L.encode(0x01, False))
        assert tag == 0x01 and value is False


class TestFilters:

    def test_a_presence_filter_is_the_attribute_alone(self):
        assert L.parse_filter("(objectClass=*)") == L.encode(0x87, "objectClass")

    def test_an_equality_filter_uses_implicit_tags(self):
        encoded = L.parse_filter("(cn=admin)")
        assert encoded[0] == 0xA3
        _tag, fields, _end = L.decode(encoded)
        assert fields[0][1] == b"cn" and fields[1][1] == b"admin", \
            "the [3] tag REPLACES the SEQUENCE tag: no nested SEQUENCE"
        assert all(t != 0x30 for t, _v in fields), "a nested SEQUENCE makes a real server " \
                                                   "answer protocolError"

    def test_a_substring_filter_carries_initial_any_and_final(self):
        _tag, fields, _end = L.decode(L.parse_filter("(cn=ab*cd*ef)"))
        assert fields[0][1] == b"cn"
        subs = fields[1][1]
        assert [t for t, _v in subs] == [0x80, 0x81, 0x82]
        assert [v for _t, v in subs] == [b"ab", b"cd", b"ef"]

    def test_a_trailing_wildcard_only_is_an_initial(self):
        _tag, fields, _end = L.decode(L.parse_filter("(cn=adm*)"))
        assert [t for t, _v in fields[1][1]] == [0x80]

    def test_a_leading_wildcard_only_is_a_final(self):
        _tag, fields, _end = L.decode(L.parse_filter("(cn=*min)"))
        assert [t for t, _v in fields[1][1]] == [0x82]

    def test_and_or_not(self):
        assert L.parse_filter("(&(a=b)(c=d))")[0] == 0xA0
        assert L.parse_filter("(|(a=b)(c=d))")[0] == 0xA1
        assert L.parse_filter("(!(a=b))")[0] == 0xA2

    def test_an_extensible_match_carries_the_rule_and_the_attribute(self):
        _tag, fields, _end = L.decode(
            L.parse_filter("(userAccountControl:1.2.840.113556.1.4.803:=2)"))
        assert fields[0][1] == b"1.2.840.113556.1.4.803"
        assert fields[1][1] == b"userAccountControl" and fields[2][1] == b"2"

    def test_the_ordering_operators(self):
        assert L.parse_filter("(cn>=a)")[0] == 0xA5
        assert L.parse_filter("(cn<=a)")[0] == 0xA6

    def test_a_nested_filter_list_is_split_correctly(self):
        parts = L._split_filter_list("(a=b)(&(c=d)(e=f))")
        assert parts == ["(a=b)", "(&(c=d)(e=f))"]

    def test_a_filter_that_is_not_one_is_refused(self):
        with pytest.raises(L.LdapError):
            L.parse_filter("")
        with pytest.raises(L.LdapError):
            L.parse_filter("(no-operator-here)")


class TestTheReadyMadeQuestions:

    def test_asrep_roastable_asks_for_no_preauth_and_not_disabled(self):
        f = L.filters.asrep_roastable()
        assert "0x400000" not in f and "1.2.840.113556.1.4.803:=4194304" in f
        assert "1.2.840.113556.1.4.803:=2" in f, "disabled accounts are excluded"
        assert L.parse_filter(f)[0] == 0xA0

    def test_kerberoastable_asks_for_an_spn(self):
        f = L.filters.kerberoastable()
        assert "servicePrincipalName=*" in f
        assert L.parse_filter(f)[0] == 0xA0

    def test_the_template_and_ca_queries(self):
        assert "pKICertificateTemplate" in L.filters.certificate_templates()
        assert "pKIEnrollmentService" in L.filters.enrollment_services()
        assert L.parse_filter(L.filters.certificate_templates())[0] == 0xA0

    def test_the_attribute_lists_name_what_each_attack_needs(self):
        assert "msPKI-Certificate-Name-Flag" in L.ATTRS["templates"]
        assert "servicePrincipalName" in L.ATTRS["kerberoast"]
        assert "msDS-KeyCredentialLink" in L.ATTRS["shadow"]
        assert "lockoutThreshold" in L.ATTRS["domain"]


class TestTheReader:

    def test_a_response_keeps_the_operation_tag(self):
        """The tag is what separates a SearchResultEntry from the SearchResultDone."""
        entry = (0x64, [(0x04, b"uid=x"), (0x30, [])])
        done = (0x65, [(0x0A, 0), (0x04, b""), (0x04, b"")])
        assert L.LdapClient._parse_entries([entry, done]) == [{"dn": "uid=x", "attrs": {}}]

    def test_the_result_code_is_read_from_the_last_body(self):
        entry = (0x64, [(0x04, b"uid=x")])
        done = (0x65, [(0x0A, 0), (0x04, b""), (0x04, b"")])
        assert L.LdapClient._result([entry, done])[0] == 0
        refused = (0x65, [(0x0A, 49), (0x04, b""), (0x04, b"invalid credentials")])
        code, _dn, msg = L.LdapClient._result([refused])
        assert code == 49 and "invalid credentials" in msg

    def test_a_done_body_is_final_and_an_entry_body_is_not(self):
        assert L._is_final([(0x0A, 0), (0x04, b"")]) is True
        assert L._is_final([(0x04, b"uid=x"), (0x30, [])]) is False

    def test_the_attribute_list_is_parsed_one_level_deep(self):
        # PartialAttributeList: SEQUENCE { SEQUENCE { type, SET OF value } ... }
        attrs_seq = (0x30, [
            (0x30, [(0x04, b"cn"), (0x31, [(0x04, b"Isaac Newton")])]),
            (0x30, [(0x04, b"mail"), (0x31, [(0x04, b"n@x.test")])]),
        ])
        rows = L.LdapClient._parse_entries([(0x64, [(0x04, b"uid=newton"), attrs_seq])])
        assert rows[0]["attrs"] == {"cn": ["Isaac Newton"], "mail": ["n@x.test"]}

    def test_the_client_reports_what_it_is(self):
        client = L.LdapClient("dc.test", 389)
        assert "dc.test:389" in client.describe()
        assert "anonymous" in client.describe()
