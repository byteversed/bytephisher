"""DNS exfil/beacon encoding: base32hex, label chunking, reassembly, records.

The encoding is checked against an INDEPENDENT implementation (Python's own
base64.b32hexencode/b32hexdecode) and the RFC 4648 section 10 vectors, over a
corpus that includes empty input, one byte, the 63/64-character label boundary
and all 256 byte values. No sockets: this file exercises the pure logic only;
the responder half lives in core.rebind and is covered by tests/test_rebind.py.

Run:  ./.venv/bin/python -m pytest tests/test_dnsx.py -q
"""
import base64
import ipaddress
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import dnsx as D  # noqa: E402
from core import rebind as R  # noqa: E402

pytestmark = pytest.mark.unit

# The exact keys core/rebind.py's responder reads off a parsed query, quoted from
# the source: core/rebind.py builds this dict at lines 99-100
#   {"id": tid, "name": ..., "qtype": qtype, "qclass": qclass, "flags": flags,
#    "question": data[12:pos + 4]}
# and core/rebind.py:build_response reads "id" (line 115), "question" (116),
# "qtype" (117) and "qclass" (117). A record from records_for() must carry these
# names so that responder can consume it unchanged.
REBIND_QUERY_KEYS = {"id", "name", "qtype", "qclass", "flags", "question"}

# RFC 4648 section 10 base32hex test vectors, normalised to this module's form:
# lowercase and unpadded. These are the spec's own numbers, not this code's.
RFC4648_SECTION_10 = {
    b"": "",
    b"f": "co",
    b"fo": "cpng",
    b"foo": "cpnmu",
    b"foob": "cpnmuog",
    b"fooba": "cpnmuoj1",
    b"foobar": "cpnmuoj1e8",
}

CORPUS = [
    b"",
    b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
    b"\x00",
    bytes(range(39)),                              # 39 bytes -> 63 base32hex chars -> one label
    bytes(range(40)),                              # 40 bytes -> 64 chars -> two labels
    bytes(range(256)),                             # every byte value once
    bytes((i * 7) % 256 for i in range(200)),
]

ZONE = "exfil.example.test"


def _joined(labels):
    return "".join(labels)


def _independent_b32hex(data):
    """Python's base32hex, normalised the way this module emits it."""
    return base64.b32hexencode(bytes(data)).decode("ascii").lower().rstrip("=")


def _pad(s):
    return s.upper() + "=" * ((-len(s)) % 8)


# =========================================================== base32hex check ==
class TestBase32HexCrossCheck:
    def test_matches_the_stdlib_encoder_over_the_corpus(self):
        for data in CORPUS:
            assert _joined(D.encode_labels(data)) == _independent_b32hex(data)

    def test_round_trips_over_the_corpus(self):
        for data in CORPUS:
            assert D.decode_labels(D.encode_labels(data)) == data

    def test_the_stdlib_decoder_reads_what_we_emit(self):
        """The reverse direction: Python decodes our labels back to the payload."""
        for data in CORPUS:
            joined = _joined(D.encode_labels(data))
            assert base64.b32hexdecode(_pad(joined)) == bytes(data)

    @pytest.mark.parametrize("data,expected", list(RFC4648_SECTION_10.items()))
    def test_rfc4648_section_10_vectors(self, data, expected):
        assert _joined(D.encode_labels(data)) == expected

    def test_empty_input_is_no_labels(self):
        assert D.encode_labels(b"") == []
        assert D.decode_labels([]) == b""


# ============================================================== label chunking ==
class TestLabelChunking:
    def test_no_label_is_ever_longer_than_63(self):
        for data in CORPUS:
            for label in D.encode_labels(data):
                assert 0 < len(label) <= D.MAX_LABEL == 63

    def test_the_39_to_40_byte_boundary_splits_into_two_labels(self):
        assert len(D.encode_labels(bytes(range(39)))) == 1
        assert len(D.encode_labels(bytes(range(40)))) == 2

    def test_the_labels_join_back_to_the_whole_base32_stream(self):
        data = bytes(range(120))
        labels = D.encode_labels(data)
        assert _joined(labels) == _independent_b32hex(data)
        assert all(len(label) <= 63 for label in labels)

    def test_an_over_budget_payload_raises_and_names_the_budget(self):
        with pytest.raises(ValueError) as excinfo:
            D.encode_labels(b"\x00" * 4096)
        message = str(excinfo.value)
        assert "budget" in message
        assert str(D.MAX_DEPTH) in message, "the refusal must quote the budget"

    def test_qname_refuses_a_name_over_253_characters(self):
        with pytest.raises(ValueError) as excinfo:
            D.qname(b"\x00", "z" * 252)                # one tiny label, plus a huge zone
        assert str(D.MAX_NAME) in str(excinfo.value)


# ================================================================== the plan ==
class TestQueryPlan:
    def test_a_small_payload_is_one_query_and_the_shape_is_filled_in(self):
        p = D.query_plan(b"hello world", ZONE)
        assert set(p) == {"qnames", "chunks", "bytes_per_query", "queries",
                          "retries", "ttl", "why"}
        assert p["queries"] == 1 and len(p["qnames"]) == 1
        assert isinstance(p["retries"], int) and p["ttl"] == D.DEFAULT_TTL
        assert p["qnames"][0].endswith("." + ZONE)

    def test_a_multi_label_payload_round_trips_through_decode_session(self):
        data = bytes(range(120))
        p = D.query_plan(data, ZONE)
        assert p["queries"] > 1, "120 bytes must need more than one query"
        assert D.decode_session(p["qnames"], ZONE) == data

    def test_every_qname_stays_under_the_name_limit(self):
        p = D.query_plan(bytes(range(250)), ZONE)
        assert p["qnames"]
        assert all(len(q) <= D.MAX_NAME for q in p["qnames"])


# =========================================================== decode_session ==
class TestDecodeSession:
    def test_reassembles_by_index_regardless_of_arrival_order(self):
        data = bytes((i * 3) % 256 for i in range(150))
        qnames = D.query_plan(data, ZONE)["qnames"]
        assert D.decode_session(list(reversed(qnames)), ZONE) == data

    def test_duplicate_and_retried_chunks_dedupe_to_the_same_bytes(self):
        data = bytes(range(120))
        qnames = D.query_plan(data, ZONE)["qnames"]
        delivered = qnames + qnames + list(reversed(qnames))   # a lossy, retrying resolver
        assert D.decode_session(delivered, ZONE) == data

    def test_missing_a_chunk_index_raises_instead_of_returning_partial(self):
        data = bytes(range(80))
        # max_labels=1 forces one payload label per query, so a chunk is a whole query
        qnames = D.query_plan(data, ZONE, max_labels=1)["qnames"]
        assert len(qnames) >= 3
        damaged = qnames[:1] + qnames[2:]                      # drop chunk index 1
        with pytest.raises(ValueError) as excinfo:
            D.decode_session(damaged, ZONE)
        assert "missing" in str(excinfo.value)

    def test_queries_for_another_zone_are_ignored(self):
        data = bytes(range(120))
        qnames = D.query_plan(data, ZONE)["qnames"]
        noise = ["0.a.other.test", "1.b.other.test"]
        assert D.decode_session(noise + qnames, ZONE) == data

    def test_no_queries_for_the_zone_is_a_refusal_not_an_empty_payload(self):
        with pytest.raises(ValueError):
            D.decode_session(["0.x.other.test"], ZONE)

    def test_a_beacon_reassembles_to_its_tagged_payload(self):
        b = D.beacon(b"hi there", ZONE, nonce="deadbeef")
        assert D.decode_session(b["qnames"], ZONE) == b["payload"]


# ================================================================ records_for ==
class TestRecordsFor:
    def test_the_record_carries_every_key_rebind_reads(self):
        rec = D.records_for("0.cpnmu." + ZONE, {"address": "203.0.113.10"})[0]
        assert set(rec) >= REBIND_QUERY_KEYS, "records_for must speak rebind's key names"
        assert rec["name"] == "0.cpnmu." + ZONE

    def test_the_operator_address_is_handed_back(self):
        rec = D.records_for("0.cpnmu." + ZONE, {"address": "203.0.113.10"})[0]
        assert rec["answer"] == "203.0.113.10" and rec["qtype"] == D.QTYPE_A

    def test_a_bare_address_string_and_a_name_keyed_store_both_work(self):
        name = "1.abc." + ZONE
        assert D.records_for(name, "198.51.100.7")[0]["answer"] == "198.51.100.7"
        assert D.records_for(name, {name: "198.51.100.7"})[0]["answer"] == "198.51.100.7"

    def test_an_ipv6_address_selects_aaaa(self):
        rec = D.records_for("2.abc." + ZONE, {"address": "2001:db8::1"})[0]
        assert rec["qtype"] == D.QTYPE_AAAA

    def test_an_empty_name_is_refused(self):
        with pytest.raises(ValueError):
            D.records_for("", {"address": "203.0.113.10"})

    def test_the_record_is_exactly_what_rebind_parses_and_answers(self):
        """The strongest cross-check: rebuild a packet from the record, parse it
        with core.rebind, and let core.rebind answer it. The record must survive
        the responder's own reader unchanged."""
        rec = D.records_for("0.cpnmu." + ZONE, {"address": "203.0.113.10"})[0]
        packet = struct.pack("!HHHHHH", rec["id"], rec["flags"], 1, 0, 0, 0) + rec["question"]
        parsed = R.parse_query(packet)
        assert parsed is not None
        # rebind returns exactly these key names (core/rebind.py:99-100)
        assert set(parsed) == REBIND_QUERY_KEYS
        assert set(parsed) <= set(rec)
        assert parsed["name"] == rec["name"]
        assert parsed["qtype"] == rec["qtype"] and parsed["qclass"] == rec["qclass"]
        # and its answer builder hands the operator address back verbatim
        answer = R.build_response(parsed, rec["answer"], ttl=0)
        assert answer is not None
        assert answer[-4:] == ipaddress.IPv4Address(rec["answer"]).packed


# ===================================================================== beacon ==
class TestBeacon:
    def test_a_beacon_carries_its_nonce_and_marker(self):
        b = D.beacon(b"payload", ZONE, nonce="cafef00d")
        assert b["kind"] == "beacon"
        assert b["nonce"] == "cafef00d"
        assert b["marker"] == D.BEACON_MARKER
        assert b["qnames"] and b["qnames"][0].startswith(D.BEACON_MARKER + ".")

    def test_a_beacon_generates_a_nonce_when_none_is_given(self):
        b = D.beacon(b"x", ZONE)
        assert b["nonce"] and b["nonce"] != D.beacon(b"x", ZONE)["nonce"]

    def test_the_marker_distinguishes_a_beacon_from_an_exfil_query(self):
        beacon_first = D.beacon(b"x", ZONE, nonce="n")["qnames"][0].split(".")[0]
        exfil_first = D.query_plan(b"some data", ZONE)["qnames"][0].split(".")[0]
        assert beacon_first == D.BEACON_MARKER
        assert exfil_first.isdigit()


class TestPlanIsHonestData:
    def test_plan_states_its_costs_and_limits(self):
        p = D.plan()
        assert p["channel"] == "dns"
        assert isinstance(p["bytes_per_second"], int) and p["bytes_per_second"] > 0
        assert any(q["qtype"] == "TXT" for q in p["query_types"])
        assert any(q["qtype"] in ("A", "AAAA") for q in p["query_types"])
        assert "outbound" in p["needs"].lower()
        assert p["lossy"] and p["visible"] and p["caching"]


class TestTheChunkIndexIsBounded:
    """The chunk index is read from a query NAME, so whoever sends one decides how much
    work the receiver does. Before the cap, `1000000000.x.<zone>` built a multi-gigabyte
    list and error message on the operator's box - a single packet, no operator mistake."""

    def test_an_absurd_index_is_refused_fast_and_without_oom(self):
        import time
        start = time.monotonic()
        with pytest.raises(ValueError) as exc:
            D.decode_session(["1000000000.a.c2.tld"], "c2.tld")
        assert time.monotonic() - start < 1.0, "the refusal must not build the range"
        assert len(str(exc.value)) < 4096, "the message must summarise, not dump the list"
        assert "cap" in str(exc.value)

    def test_the_cap_itself_is_allowed_and_one_past_it_is_not(self):
        assert D.MAX_CHUNKS == 4096
        with pytest.raises(ValueError):
            D.decode_session([f"{D.MAX_CHUNKS}.a.c2.tld"], "c2.tld")

    def test_a_missing_chunk_is_summarised(self):
        """A real gap must still be reported, but as a count and the first few indices."""
        with pytest.raises(ValueError) as exc:
            D.decode_session(["5.a.c2.tld"], "c2.tld")
        message = str(exc.value)
        assert "missing 5 chunk index(es)" in message
        assert "first: 0, 1, 2, 3, 4" in message
        assert len(message) < 4096
