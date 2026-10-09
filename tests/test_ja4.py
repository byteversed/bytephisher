"""JA4 and JA4H, checked against the published FoxIO vectors.

Every expected value below comes from the FoxIO reference test data (the pcap-derived
JSON in `FoxIO-LLC/ja4/python/test/testdata` and the canonical examples in
`technical_details/`). They are the reason a wrong sort order, a missing GREASE filter or a
trailing underscore cannot pass unnoticed: those mistakes produce a plausible-looking string
that simply is not JA4.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import tls_fp as T  # noqa: E402

pytestmark = pytest.mark.unit

# The canonical TLS 1.3 ClientHello from the FoxIO JA4 specification.
CANONICAL_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
                     0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
CANONICAL_EXTENSIONS = [0x0000, 0x0017, 0x001B, 0x0023, 0x002B, 0x002D, 0x0033, 0x000A,
                        0x000B, 0x000D, 0x0012, 0x0015, 0x4469, 0xFF01, 0x0010, 0x0005]
CANONICAL_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


class TestThePublishedHashVectors:

    def test_ja4_b_sorted_cipher_list(self):
        joined = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
        assert T._sha12(joined) == "8daaf6152771"

    def test_ja4_c_with_signature_algorithms(self):
        joined = ("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
                  "_0403,0804,0401,0503,0805,0501,0806,0601")
        assert T._sha12(joined) == "e5627efa2ab1"

    def test_ja4_c_without_signature_algorithms_has_no_trailing_underscore(self):
        joined = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
        assert T._sha12(joined) == "6d807ffa2a79"

    def test_the_raw_cipher_order_vector(self):
        joined = "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035"
        assert T._sha12(joined) == "acb858a92679"


class TestJA4:

    def _hello(self, **over):
        hello = {"tls_version": 0x0303, "ciphers": list(CANONICAL_CIPHERS),
                 "extensions": list(CANONICAL_EXTENSIONS), "sni": "example.test",
                 "alpn": ["h2"], "supported_versions": [0x0304],
                 "sigalgs": list(CANONICAL_SIGALGS)}
        hello.update(over)
        return hello

    def test_the_canonical_fingerprint(self):
        assert T.ja4(self._hello()) == "t13d1516h2_8daaf6152771_e5627efa2ab1"

    def test_the_version_comes_from_supported_versions_not_the_record(self):
        # a TLS 1.3 hello carries the legacy 0x0303 in the record: reporting "12" is the
        # classic mistake, and it is invisible unless the vector is checked
        assert T.ja4(self._hello())[:3] == "t13"
        assert T.ja4(self._hello(tls_version=0x0303, supported_versions=[]))[:3] == "t12"

    def test_the_sni_flag(self):
        assert T.ja4(self._hello())[3] == "d"
        assert T.ja4(self._hello(sni=None))[3] == "i"

    def test_the_counts_exclude_grease(self):
        with_grease = self._hello(ciphers=[0x0A0A] + list(CANONICAL_CIPHERS) + [0x1A1A],
                                  extensions=[0x2A2A] + list(CANONICAL_EXTENSIONS))
        assert T.ja4(with_grease) == T.ja4(self._hello())

    def test_the_counts_are_two_digits_and_capped(self):
        many = self._hello(ciphers=[0x1301] * 150)
        assert T.ja4(many)[4:6] == "99"
        assert T.ja4(self._hello())[4:6] == "15"

    def test_the_alpn_field(self):
        assert T.ja4(self._hello(alpn=["http/1.1"]))[8:10] == "h1"
        assert T.ja4(self._hello(alpn=[]))[8:10] == "00"

    def test_a_quic_hello_uses_the_q_prefix(self):
        assert T.ja4(self._hello(), transport="q").startswith("q13")

    def test_no_hello_gives_an_empty_fingerprint(self):
        assert T.ja4({}) == "" and T.ja4(None) == ""

    def test_an_empty_cipher_list_is_twelve_zeros_not_a_hash_of_nothing(self):
        fp = T.ja4(self._hello(ciphers=[]))
        assert fp.split("_")[1] == "000000000000"

    def test_the_raw_form_lists_what_was_hashed(self):
        raw = T.ja4_r(self._hello())
        assert raw.startswith("t13d1516h2_")
        assert "1301" in raw and "0403" in raw


class TestJA4H:

    def test_the_canonical_http1_with_cookies_vector(self):
        fp = T.ja4h("GET", "HTTP/1.1", [
            ("Host", "x.test"), ("User-Agent", "curl/8"), ("Accept", "*/*"),
            ("Accept-Language", "da"), ("Referer", "https://x.test/"),
            ("Cookie", "yummy_cookie=choco; tasty_cookie=strawberry")])
        assert fp == "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"

    def test_the_empty_user_agent_vector(self):
        assert T.ja4h("GET", "HTTP/1.0", [("User-Agent", "")]) == \
            "ge10nn010000_b8bcd45ac095_000000000000_000000000000"

    def test_the_post_vector(self):
        fp = T.ja4h("POST", "HTTP/1.1", [
            ("Host", "x"), ("Accept", "*/*"), ("User-Agent", "curl"), ("Content-Type", "x"),
            ("Content-Length", "0")])
        assert fp == "po11nn050000_530ceba2075f_000000000000_000000000000"

    def test_the_range_vector(self):
        fp = T.ja4h("GET", "HTTP/1.1", [
            ("Host", "x"), ("User-Agent", "curl"), ("Accept", "*/*"), ("Range", "bytes=0-1")])
        assert fp == "ge11nn040000_ad0fd3707af2_000000000000_000000000000"

    def test_the_accept_encoding_vector(self):
        # the published raw form for this capture starts with "he": it is a HEAD request
        fp = T.ja4h("HEAD", "HTTP/1.1", [
            ("Host", "x"), ("Connection", "keep-alive"), ("User-Agent", "curl"),
            ("Accept-Encoding", "gzip"), ("Accept-Language", "en-US")])
        assert fp == "he11nn05enus_6f8992deff94_000000000000_000000000000"

    def test_the_http2_vector(self):
        fp = T.ja4h("GET", "HTTP/2", [
            ("Host", "x"), ("User-Agent", "curl"), ("Accept", "*/*"),
            ("Accept-Language", "en-US"), ("Accept-Encoding", "gzip"),
            ("Referer", "https://x.test/"),
            ("X-A", "1"), ("X-B", "2"), ("X-C", "3"), ("X-D", "4"), ("X-E", "5"),
            ("X-F", "6"), ("X-G", "7"), ("X-H", "8"),
            ("Cookie", "a=1; b=2; c=3; d=4; e=5; f=6; g=7; h=8; i=9; j=10; k=11; l=12")])
        assert fp.split("_")[0] == "ge20cr13enus", fp

    def test_the_header_name_hash_is_the_only_thing_hashed(self):
        # the User-Agent VALUE never enters a hash: only the name
        a = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("User-Agent", "curl/8")])
        b = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("User-Agent", "Mozilla/5.0")])
        assert a == b

    def test_the_header_case_is_preserved_in_the_hash(self):
        lower = T.ja4h("GET", "HTTP/1.1", [("host", "x"), ("user-agent", "c")])
        upper = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("User-Agent", "c")])
        assert lower.split("_")[1] != upper.split("_")[1]

    def test_pseudo_headers_are_excluded_from_count_and_hash(self):
        with_pseudo = T.ja4h("GET", "HTTP/2", [(":method", "GET"), (":path", "/"),
                                               ("Host", "x"), ("User-Agent", "c")])
        without = T.ja4h("GET", "HTTP/2", [("Host", "x"), ("User-Agent", "c")])
        assert with_pseudo == without

    def test_cookie_and_referer_are_excluded_from_the_count_but_flag_it(self):
        fp = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("User-Agent", "c"),
                                        ("Cookie", "a=1"), ("Referer", "https://y")])
        # four headers, two of them excluded from the count: "02", with both flags set
        assert fp.split("_")[0] == "ge11cr020000", fp

    def test_the_language_field(self):
        def lang(value):
            return T.ja4h("GET", "HTTP/1.1", [("Host", "x"),
                                              ("Accept-Language", value)]).split("_")[0][8:]
        assert lang("en-US,en;q=0.9") == "enus"
        assert lang("en") == "en00"
        assert lang("da") == "da00"
        assert lang("") == "0000"

    def test_the_cookie_hashes_split_names_from_values(self):
        one = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("Cookie", "a=1; b=2")])
        two = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("Cookie", "b=2; a=1")])
        assert one == two, "the cookie order must not change the fingerprint"
        other = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("Cookie", "a=1; c=2")])
        assert other.split("_")[2] != one.split("_")[2], "the names hash must differ"
        same_names = T.ja4h("GET", "HTTP/1.1", [("Host", "x"), ("Cookie", "a=9; b=9")])
        assert same_names.split("_")[2] == one.split("_")[2]
        assert same_names.split("_")[3] != one.split("_")[3]

    def test_the_method_and_version_are_mapped(self):
        for method, want in (("GET", "ge"), ("POST", "po"), ("PUT", "pu"), ("HEAD", "he"),
                             ("DELETE", "de"), ("PATCH", "pa")):
            fp = T.ja4h(method, "HTTP/1.1", [("Host", "x")])
            assert fp.startswith(want), (method, fp)
        assert T.ja4h("GET", "HTTP/2", [("Host", "x")]).startswith("ge20")
        assert T.ja4h("GET", "HTTP/1.0", [("Host", "x")]).startswith("ge10")
        assert T.ja4h("GET", "WEIRD", [("Host", "x")]).startswith("ge11")

    def test_the_raw_form_shows_the_header_names(self):
        raw = T.ja4h_r("GET", "HTTP/1.1", [("Host", "x"), ("User-Agent", "c"),
                                           ("Cookie", "a=1")])
        assert raw == "ge11cn020000_Host,User-Agent_a_a=1"


class TestTheParserExposesWhatJA4Needs:

    def test_a_real_client_hello_yields_ja4_material(self):
        # a minimal but well-formed ClientHello built here, so the parser is exercised
        # without a socket
        import struct

        def ext(etype, payload):
            return struct.pack(">HH", etype, len(payload)) + payload

        name = b"example.test"
        # server_name (RFC 6066): list length (2) + name type (1) + name length (2) + name
        sni = (struct.pack(">H", 3 + len(name)) + b"\x00"
               + struct.pack(">H", len(name)) + name)
        alpn = struct.pack(">H", 3) + b"\x02h2"
        versions = b"\x04" + struct.pack(">HH", 0x0304, 0x0303)
        sigs = struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804)
        exts = (ext(0x0000, sni) + ext(0x0010, alpn) + ext(0x002b, versions)
                + ext(0x000d, sigs) + ext(0x0a0a, b""))
        ciphers = struct.pack(">H", 6) + struct.pack(">HHH", 0x0a0a, 0x1301, 0xc02b)
        body = (struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00" + ciphers
                + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
        hello_msg = b"\x01" + struct.pack(">I", len(body))[1:] + body
        record = b"\x16\x03\x01" + struct.pack(">H", len(hello_msg)) + hello_msg
        parsed = T.parse_client_hello(record)
        assert parsed.get("sni") == "example.test"
        assert parsed.get("alpn") == ["h2"]
        assert 0x0403 in parsed.get("sigalgs", [])
        fp = T.ja4(parsed)
        assert fp.startswith("t13d") and len(fp.split("_")) == 3
        # the GREASE cipher and extension are gone from the counts
        assert fp[4:6] == "02" and fp[6:8] == "04"
