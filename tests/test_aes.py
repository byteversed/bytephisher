"""The pure-Python AES: verified against the published vectors, and states what is not covered.

FIPS-197 (three key sizes, encrypt AND decrypt) and NIST SP 800-38A (CBC, CTR) are the tests
that matter: a cipher that is not checked against a published vector silently produces garbage,
and garbage is indistinguishable from a wrong key.

AES-CTS (Kerberos etype 17/18's mode) is NOT implemented - it failed its own round-trip twice -
and the test below pins that it REFUSES rather than returning something that looks like output.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import aes  # noqa: E402

pytestmark = pytest.mark.unit

PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS = {
    "000102030405060708090a0b0c0d0e0f": "69c4e0d86a7b0430d8cdb78070b4c55a",
    "000102030405060708090a0b0c0d0e0f1011121314151617":
        "dda97ca4864cdfe06eaf70a0ec0d7191",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f":
        "8ea2b7ca516745bfeafc49904b496089",
}
CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CBC_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a") \
    + bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
CBC_CT = ("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
CTR_NONCE = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
CTR_CT = ("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff")


class TestThePublishedVectors:

    @pytest.mark.parametrize("key,expected", sorted(FIPS.items()))
    def test_fips_197_encrypt(self, key, expected):
        assert aes.encrypt_block(PT, aes.expand_key(bytes.fromhex(key))).hex() == expected

    @pytest.mark.parametrize("key,expected", sorted(FIPS.items()))
    def test_fips_197_decrypt(self, key, expected):
        assert aes.decrypt_block(bytes.fromhex(expected),
                                 aes.expand_key(bytes.fromhex(key))) == PT

    def test_nist_cbc(self):
        assert aes.cbc_encrypt_no_pad(aes.expand_key(CBC_KEY), CBC_PT, CBC_IV).hex() == CBC_CT

    def test_nist_ctr(self):
        assert aes.ctr_crypt(CBC_KEY, CBC_PT, nonce=CTR_NONCE).hex() == CTR_CT

    def test_the_sbox_is_generated_not_typed(self):
        assert aes.SBOX[0x00] == 0x63 and aes.SBOX[0x01] == 0x7C
        assert aes.INV_SBOX[0x63] == 0x00 and aes.INV_SBOX[0x7C] == 0x01


class TestTheModes:

    def test_cbc_pads_and_round_trips(self):
        data = b"a short message"
        blob = aes.cbc_encrypt(CBC_KEY, data, CBC_IV)
        assert len(blob) % 16 == 0 and aes.cbc_decrypt(CBC_KEY, blob, CBC_IV) == data

    def test_cbc_refuses_a_wrong_padding(self):
        blob = aes.cbc_encrypt(CBC_KEY, b"x" * 20, CBC_IV)
        with pytest.raises(aes.AesError):
            aes.cbc_decrypt(bytes(16), blob, CBC_IV)

    def test_ctr_round_trips_and_is_its_own_inverse(self):
        data = os.urandom(100)
        blob = aes.ctr_crypt(CBC_KEY, data, nonce=CTR_NONCE)
        assert len(blob) == len(data)
        assert aes.ctr_crypt(CBC_KEY, blob, nonce=CTR_NONCE) == data

    def test_a_bad_key_size_is_refused(self):
        with pytest.raises(aes.AesError):
            aes.expand_key(b"short")
        with pytest.raises(aes.AesError):
            aes.encrypt_block(b"not16bytes!", aes.expand_key(bytes(16)))

    def test_a_bad_ctr_nonce_is_refused(self):
        with pytest.raises(aes.AesError):
            aes.ctr_crypt(CBC_KEY, b"x", nonce=b"1234")

    def test_cmac_is_deterministic_and_sized(self):
        assert aes.aes_cmac(bytes(16), bytes(16)) == aes.aes_cmac(bytes(16), bytes(16))
        assert len(aes.aes_cmac(bytes(32), b"data")) == 16
        assert aes.aes_cmac(bytes(16), b"a") != aes.aes_cmac(bytes(16), b"b")


class TestGpp:

    def test_a_cpassword_comes_back(self):
        secret = "Local*P4ssword".encode("utf-16-le")
        blob = base64.b64encode(aes.cbc_encrypt(aes.GPP_KEY, secret, iv=bytes(16))).decode()
        assert aes.gpp_decrypt(blob) == "Local*P4ssword"

    def test_the_published_key_is_256_bits(self):
        assert len(aes.GPP_KEY) == 32

    def test_an_empty_or_broken_value_is_refused(self):
        with pytest.raises(aes.AesError):
            aes.gpp_decrypt("")
        with pytest.raises(aes.AesError):
            aes.gpp_decrypt("!!!not base64!!!")


class TestWhatIsNotImplemented:

    def test_cts_refuses_instead_of_returning_garbage(self):
        with pytest.raises(aes.AesError) as ei:
            aes.cts_encrypt(bytes(16), b"x" * 20)
        assert "not implemented" in str(ei.value)
        with pytest.raises(aes.AesError):
            aes.cts_decrypt(bytes(16), b"x" * 20)

    def test_kerberos_aes_refuses_for_the_same_reason(self):
        with pytest.raises(aes.AesError) as ei:
            aes.kerberos_aes_encrypt(bytes(32), b"ticket", usage=2, etype=18)
        assert "not implemented" in str(ei.value)

    def test_a_bad_etype_is_refused(self):
        with pytest.raises(aes.AesError):
            aes.kerberos_aes_encrypt(bytes(16), b"x", etype=23)
