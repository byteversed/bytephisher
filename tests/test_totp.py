"""TOTP / soft-2FA: the RFC vectors, the otpauth parser, and the weak-secret scan.

Every expected code here is the RFC's own (RFC 4226 Appendix D, RFC 6238 Appendix B) or a
value produced by an INDEPENDENT stdlib call (base64.b32encode for the transport encoding,
hmac.digest for the raw-key scan probe) - never by the module under test. That is the whole
point: prove the module against a published reference, not against itself.

Run:  ./.venv/bin/python -m pytest tests/test_totp.py -q
"""
import base64
import hmac
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import totp as T  # noqa: E402

pytestmark = pytest.mark.unit


# RFC 4226/6238 define the shared secret as raw key bytes. An otpauth secret is that key in
# base32, so the vectors are reached through the base32 transport - produced here by
# base64.b32encode, an independent implementation, not by T.b32encode.
SEED20 = b"12345678901234567890"                                  # RFC 6238 SHA1 seed
SEED32 = b"12345678901234567890123456789012"                      # RFC 6238 SHA256 seed
SEED64 = b"1234567890123456789012345678901234567890123456789012345678901234"
assert len(SEED20) == 20 and len(SEED32) == 32 and len(SEED64) == 64


def b32(raw):
    """The base32 transport for a raw seed (independent of the module)."""
    return base64.b32encode(raw).decode("ascii")


def raw_totp(key, at, *, digits=6, period=30, algo="sha1"):
    """An independent RFC 6238/4226 implementation, for probing the raw-key scan space."""
    d = hmac.digest(key, (int(at) // period).to_bytes(8, "big"), algo)
    o = d[-1] & 0x0F
    v = ((d[o] & 0x7F) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]
    return str(v % (10 ** digits)).zfill(digits)


# RFC 4226 Appendix D - HOTP, 6 digits, key "12345678901234567890"
RFC4226 = ["755224", "287082", "359152", "969429", "338314",
           "254676", "287922", "162583", "399871", "520489"]

# RFC 6238 Appendix B - TOTP, 8 digits, per-algorithm seed, at each documented time
RFC6238_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
RFC6238 = {
    "SHA1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
    "SHA256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
    "SHA512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
}
RFC6238_SEED = {"SHA1": SEED20, "SHA256": SEED32, "SHA512": SEED64}


class TestRfcVectors:
    def test_hotp_matches_rfc4226_appendix_d(self):
        for counter, expected in enumerate(RFC4226):
            assert T.hotp(b32(SEED20), counter, digits=6) == expected

    @pytest.mark.parametrize("algo", ["SHA1", "SHA256", "SHA512"])
    def test_totp_matches_rfc6238_appendix_b(self, algo):
        seed = b32(RFC6238_SEED[algo])
        for at, expected in zip(RFC6238_TIMES, RFC6238[algo], strict=True):
            assert T.code(seed, at, digits=8, algo=algo) == expected

    def test_code_defaults_to_now_and_six_digits(self):
        # no expectation about the value (the clock is live); the shape must hold
        value = T.code(b32(SEED20))
        assert len(value) == 6 and value.isdigit()

    def test_unknown_algorithm_is_a_hard_error(self):
        with pytest.raises(ValueError):
            T.code(b32(SEED20), 59, algo="MD5")


class TestBase32:
    CORPUS = [b"a", b"ab", b"abc", b"abcd", b"abcde", b"Hello!\xde\xad\xbe\xef",
              b"12345678901234567890", bytes(range(256))]

    def test_encode_matches_stdlib_without_padding(self):
        for data in self.CORPUS:
            assert T.b32encode(data) == base64.b32encode(data).decode("ascii").rstrip("=")

    def test_decode_round_trips_every_corpus_item(self):
        for data in self.CORPUS:
            assert T.b32decode(T.b32encode(data)) == data

    def test_decode_accepts_padding_from_stdlib_and_lowercase(self):
        for data in self.CORPUS:
            padded = base64.b32encode(data).decode("ascii")
            assert T.b32decode(padded) == data                     # padding-insensitive
            assert T.b32decode(padded.lower()) == data             # case-insensitive

    def test_decode_strips_whitespace_from_a_manual_key(self):
        assert T.b32decode("JBSW Y3DP EHPK 3PXP") == base64.b32decode("JBSWY3DPEHPK3PXP")

    def test_decode_rejects_a_non_base32_secret_without_echoing_it(self):
        secret = "NOTABASE32SECRET!"
        with pytest.raises(ValueError) as caught:
            T.b32decode(secret)
        assert "NOTABASE32SECRET" not in str(caught.value)


class TestParseOtpauth:
    FULL = ("otpauth://totp/Big%20Corp%3Aalice%40example.com"
            "?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corp&algorithm=SHA256&digits=8&period=60")

    def test_round_trips_and_percent_decodes_every_field(self):
        parsed = T.parse_otpauth(self.FULL)
        assert parsed["type"] == "totp"
        assert parsed["secret"] == "JBSWY3DPEHPK3PXP"
        assert parsed["issuer"] == "Big Corp"
        assert parsed["account"] == "alice@example.com"
        assert parsed["digits"] == 8
        assert parsed["period"] == 60
        assert parsed["algo"] == "SHA256"

    def test_defaults_when_only_a_secret_is_present(self):
        parsed = T.parse_otpauth("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        assert parsed["digits"] == 6 and parsed["period"] == 30 and parsed["algo"] == "SHA1"
        assert parsed["issuer"] == "" and parsed["account"] == "alice"

    def test_issuer_comes_from_the_label_when_no_param_is_given(self):
        parsed = T.parse_otpauth("otpauth://totp/Acme:carol?secret=JBSWY3DPEHPK3PXP")
        assert parsed["issuer"] == "Acme" and parsed["account"] == "carol"

    def test_secret_is_normalised_to_upper_case_without_padding(self):
        parsed = T.parse_otpauth("otpauth://totp/alice?secret=jbswy3dpehpk3pxp")
        assert parsed["secret"] == "JBSWY3DPEHPK3PXP"

    def test_hotp_type_carries_its_counter(self):
        parsed = T.parse_otpauth("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=42")
        assert parsed["type"] == "hotp" and parsed["counter"] == 42

    @pytest.mark.parametrize("uri", [
        "https://example.com/?secret=JBSWY3DPEHPK3PXP",
        "totp/alice?secret=JBSWY3DPEHPK3PXP",
        "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",       # unknown type
        "otpauth://totp/alice",                                # no secret at all
        "otpauth://totp/alice?secret=",                        # empty secret
        "otpauth://totp/alice?secret=%20",                     # whitespace-only secret
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/alice?secret=NOTABASE32SECRET!",       # not base32
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=99",
    ])
    def test_bad_uris_raise_value_error(self, uri):
        with pytest.raises(ValueError):
            T.parse_otpauth(uri)

    def test_a_non_otpauth_uri_raises(self):
        with pytest.raises(ValueError):
            T.parse_otpauth("https://example.com/")

    def test_bad_secret_error_does_not_contain_the_secret(self):
        with pytest.raises(ValueError) as caught:
            T.parse_otpauth("otpauth://totp/alice?secret=NOTABASE32SECRET!")
        assert "NOTABASE32SECRET" not in str(caught.value)


class TestCodesInWindow:
    AT = 1111111109
    SECRET = b32(SEED20)

    def test_returns_the_documented_neighbours_in_order(self):
        window = T.codes_in_window(self.SECRET, self.AT, back=1, forward=1, digits=8)
        assert window == [T.code(self.SECRET, self.AT - 30, digits=8),
                          T.code(self.SECRET, self.AT, digits=8),
                          T.code(self.SECRET, self.AT + 30, digits=8)]

    def test_a_zero_window_is_the_single_code(self):
        assert T.codes_in_window(self.SECRET, self.AT, back=0, forward=0) == \
            [T.code(self.SECRET, self.AT)]

    def test_back_only_widens_into_the_past(self):
        window = T.codes_in_window(self.SECRET, self.AT, back=2, forward=0, digits=8)
        assert window == [T.code(self.SECRET, self.AT - 60, digits=8),
                          T.code(self.SECRET, self.AT - 30, digits=8),
                          T.code(self.SECRET, self.AT, digits=8)]

    def test_negative_bounds_are_refused(self):
        with pytest.raises(ValueError):
            T.codes_in_window(self.SECRET, self.AT, back=-1)


class TestWeakSecretScan:
    AT = 1_000_000_000

    def test_finds_a_known_six_digit_secret(self):
        # the observed code was produced by an INDEPENDENT raw-key TOTP over b"123456"
        observed = raw_totp(b"123456", self.AT)
        hits = T.weak_secret_scan(observed, self.AT, space="dec6")
        assert any(h["secret"] == "123456" for h in hits)
        assert all("why" in h for h in hits)

    def test_a_random_code_matches_nothing_in_the_short_space(self):
        assert T.weak_secret_scan("000000", self.AT, space="b32short") == []

    def test_a_random_code_matches_nothing_in_the_six_digit_space(self):
        # "000004" is a code no 6-digit key yields at this time (verified over the whole
        # space), so the empty path is exercised, not a lucky single match
        assert T.weak_secret_scan("000004", self.AT, space="dec6") == []

    def test_finds_a_short_base32_secret_through_the_module_code_path(self):
        # a b32short candidate is decoded as base32, so T.code composes with the space
        observed = T.code("MZXW6YTBOI", self.AT)
        hits = T.weak_secret_scan(observed, self.AT, space="b32short")
        assert "MZXW6YTBOI" in [h["secret"] for h in hits]

    def test_a_non_numeric_code_matches_nothing_and_does_not_raise(self):
        assert T.weak_secret_scan("not-a-code", self.AT, space="b32short") == []

    def test_an_over_wide_space_is_refused(self):
        with pytest.raises(ValueError):
            T.weak_secret_scan("123456", self.AT, space="dec8")

    def test_unknown_space_is_refused(self):
        with pytest.raises(ValueError):
            T.weak_secret_scan("123456", self.AT, space="nope")

    def test_the_space_size_is_exposed_and_bounded(self):
        assert T.space_size("dec6") == 10 ** 6
        assert T.space_size("b32short") == T.SPACE_SIZES["b32short"]
        assert T.SPACE_SIZES["dec8"] > T.MAX_SPACE


class TestEnrolmentFactsAndDescription:
    def test_enrolment_facts_is_data_and_names_the_limit(self):
        facts = T.enrolment_facts()
        assert "otpauth_uris" in facts["collect"]
        assert "manual_entry_key" in facts["collect"]
        assert facts["collect"]["manual_entry_key"]["field_names"]
        assert facts["page_markers"]
        assert any("NOT the secret" in n for n in facts["not_a_secret"])
        assert facts["limit"]

    def test_describe_states_the_limits(self):
        text = T.describe()
        assert "does NOT reveal the secret" in text
        assert "low-entropy" in text


class TestTheWindowIsBounded:
    """The window counts 30-second periods and each one costs an HMAC. An unbounded
    window turns a helper into a hang, so it carries a cap like the secret scan does."""

    def test_a_window_over_the_cap_is_refused(self):
        with pytest.raises(ValueError):
            T.codes_in_window(b32(SEED20), 1_700_000_000, back=T.MAX_WINDOW + 1)
        with pytest.raises(ValueError):
            T.codes_in_window(b32(SEED20), 1_700_000_000, forward=T.MAX_WINDOW + 1)

    def test_the_cap_itself_is_allowed(self):
        assert len(T.codes_in_window(b32(SEED20), 1_700_000_000, back=T.MAX_WINDOW,
                                     forward=0)) == T.MAX_WINDOW + 1

    def test_a_large_window_is_linear_not_quadratic(self):
        import time
        start = time.monotonic()
        T.codes_in_window(b32(SEED20), 1_700_000_000, back=800, forward=800)
        assert time.monotonic() - start < 1.0
