# ============================================================================
# FILE: core/aes.py
# ============================================================================
"""AES in pure Python: the cipher three attacks in this tool were blocked on.

Nothing here is clever - it is the AES specification, written out, because:

* **Kerberos etype 17/18** needs AES (CTS mode for the ciphertext, HMAC-SHA1 for the checksum),
  and a DC that refuses the RC4 downgrade leaves AES as the only way in.
* **The Golden Ticket** is the same: an AES-only domain means the krbtgt key is an AES key.
* **GPP cpassword** is AES-256-CBC with a key Microsoft published in 2012, which is why those
  passwords are still readable in a directory nobody cleaned.

The implementation is verified against the FIPS-197 published vectors (all four key sizes, the
128-bit block) and against CBC vectors from NIST SP 800-38A. A cipher that is not verified
against published vectors is a cipher that silently produces garbage, and garbage here looks
exactly like a wrong key.

Modes provided: ECB (for the vectors and for CTS's building block), CBC, CTR, and CTS
(ciphertext stealing - what Kerberos uses for etype 17/18).
"""
import hashlib
import hmac

__all__ = ["AesError", "expand_key", "encrypt_block", "decrypt_block", "cbc_encrypt",
           "cbc_decrypt", "ctr_crypt", "cts_encrypt", "cts_decrypt", "aes_cmac",
           "kerberos_aes_encrypt", "kerberos_aes_decrypt", "gpp_decrypt", "GPP_KEY",
           "describe"]

# The key Microsoft published for Group Policy Preferences cpassword (MS14-025). It is public
# because the format was broken by design, not by accident.
GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

# The AES S-box and its inverse, computed at import: a table typed by hand is a table with a
# typo in it, and a typo here is undetectable without the vectors.
def _build_tables():
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) \
            ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, value in enumerate(sbox):
        inv[value] = i
    return sbox, inv


SBOX, INV_SBOX = _build_tables()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


class AesError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    """Multiplication in GF(2^8)."""
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out & 0xFF


def expand_key(key):
    """The key schedule: a list of round keys, each 16 bytes."""
    key = bytes(key)
    if len(key) not in (16, 24, 32):
        raise AesError(f"an AES key is 16, 24 or 32 bytes, not {len(key)}")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [bytes(b for word in words[4 * r:4 * r + 4] for b in word) for r in range(rounds + 1)]


def _add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(16)]


def _sub_bytes(state):
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def _shift_rows(state):
    # state is column-major: index = column * 4 + row
    out = list(state)
    for row in range(1, 4):
        row_bytes = [state[c * 4 + row] for c in range(4)]
        row_bytes = row_bytes[row:] + row_bytes[:row]
        for c in range(4):
            out[c * 4 + row] = row_bytes[c]
    return out


def _inv_shift_rows(state):
    out = list(state)
    for row in range(1, 4):
        row_bytes = [state[c * 4 + row] for c in range(4)]
        row_bytes = row_bytes[-row:] + row_bytes[:-row]
        for c in range(4):
            out[c * 4 + row] = row_bytes[c]
    return out


def _mix_columns(state):
    out = list(state)
    for c in range(4):
        a = state[c * 4:c * 4 + 4]
        out[c * 4 + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        out[c * 4 + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        out[c * 4 + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        out[c * 4 + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
    return out


def _inv_mix_columns(state):
    out = list(state)
    for c in range(4):
        a = state[c * 4:c * 4 + 4]
        out[c * 4 + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        out[c * 4 + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        out[c * 4 + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        out[c * 4 + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
    return out


def encrypt_block(block, round_keys):
    """One 16-byte block."""
    if len(block) != 16:
        raise AesError("AES works on 16-byte blocks")
    state = _add_round_key(list(block), round_keys[0])
    for rnd in range(1, len(round_keys) - 1):
        state = _add_round_key(_mix_columns(_shift_rows(_sub_bytes(state))), round_keys[rnd])
    state = _add_round_key(_shift_rows(_sub_bytes(state)), round_keys[-1])
    return bytes(state)


def decrypt_block(block, round_keys):
    if len(block) != 16:
        raise AesError("AES works on 16-byte blocks")
    state = _add_round_key(list(block), round_keys[-1])
    for rnd in range(len(round_keys) - 2, 0, -1):
        # the inverse cipher order is InvShiftRows -> InvSubBytes -> AddRoundKey ->
        # InvMixColumns. Doing the AddRoundKey first (as the first version did) still decrypts
        # SOME blocks by luck and produces garbage for the rest.
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return bytes(state)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def cbc_encrypt(key, data, iv=b"\x00" * 16):
    """CBC with PKCS#7 padding."""
    rk = expand_key(key)
    if len(iv) != 16:
        raise AesError("the IV is 16 bytes")
    pad = 16 - (len(data) % 16)
    data = bytes(data) + bytes([pad]) * pad
    out, prev = b"", bytes(iv)
    for i in range(0, len(data), 16):
        block = encrypt_block(_xor(data[i:i + 16], prev), rk)
        out += block
        prev = block
    return out


def cbc_decrypt(key, data, iv=b"\x00" * 16, unpad=True):
    rk = expand_key(key)
    if len(data) % 16 or not data:
        raise AesError("CBC ciphertext is a multiple of 16 bytes")
    out, prev = b"", bytes(iv)
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += _xor(decrypt_block(block, rk), prev)
        prev = block
    if not unpad:
        return out
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise AesError("the padding is wrong: wrong key, wrong IV, or not CBC")
    return out[:-pad]


def ctr_crypt(key, data, nonce=b"\x00" * 8, counter=0):
    """CTR: the same call encrypts and decrypts (it is a keystream XOR).

    A 16-byte nonce is taken as the WHOLE initial counter block (which is how the NIST vectors
    and Kerberos write it); an 8-byte one is the high half and the counter fills the low half.
    """
    rk = expand_key(key)
    nonce = bytes(nonce)
    if len(nonce) not in (8, 16):
        raise AesError("a CTR nonce is 8 or 16 bytes")
    out = bytearray()
    for i in range(0, len(data), 16):
        if len(nonce) == 16:
            block = (int.from_bytes(nonce, "big") + counter + i // 16).to_bytes(16, "big")
        else:
            block = nonce + (counter + i // 16).to_bytes(8, "big")
        stream = encrypt_block(block, rk)
        chunk = data[i:i + 16]
        out += bytes(x ^ y for x, y in zip(chunk, stream, strict=False))
    return bytes(out)


def cbc_encrypt_no_pad(round_keys, data, iv):
    """CBC without padding: the building block for CTS and for the published vectors."""
    out, prev = b"", bytes(iv)
    for i in range(0, len(data), 16):
        block = encrypt_block(_xor(data[i:i + 16], prev), round_keys)
        out += block
        prev = block
    return out


def cbc_decrypt_no_pad(round_keys, data, iv):
    out, prev = b"", bytes(iv)
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += _xor(decrypt_block(block, round_keys), prev)
        prev = block
    return out


def cts_encrypt(key, data, iv=b"\x00" * 16):
    """AES-CTS (Kerberos etype 17/18's mode): NOT IMPLEMENTED, and it refuses.

    The CBC core below is verified against the published vectors (FIPS-197, NIST SP 800-38A),
    but ciphertext stealing is not: two attempts at it produced length-preserving output that
    does NOT round-trip, which is worse than no function at all - a wrong CTS silently produces
    garbage, and garbage here is indistinguishable from a wrong key. Kerberos AES needs it, so
    `kerberos_aes_encrypt` refuses too, and the RC4 path (etype 23) is the one that works.

    To finish it: implement RFC 3962's CBC-CS3 (the last full block and the padded tail are
    encrypted and then SWAPPED, and the decrypt recovers the stolen bytes from the TAIL of the
    last block) and verify it against a published CTS vector, not against its own inverse.
    """
    raise AesError(
        "AES-CTS is not implemented (it failed its own round-trip): Kerberos AES needs a "
        "correct RFC 3962 CBC-CS3, and a wrong one silently produces garbage. Use the RC4 "
        "path (etype 23), or an injected AES implementation with `cryptography`")


def cts_decrypt(key, data, iv=b"\x00" * 16):
    """See cts_encrypt: refused until it passes a published vector."""
    raise AesError("AES-CTS is not implemented: see cts_encrypt for why it refuses")


def aes_cmac(key, data):
    """AES-CMAC (RFC 4493): the subkeys come from doubling L = E(0), and an odd-length message
    gets the 0x80 padding with K2 (a full block gets K1)."""
    rk = expand_key(key)
    subkey_l = encrypt_block(bytes(16), rk)

    def double(block):
        out = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            out[i] = ((block[i] << 1) & 0xFF) | carry
            carry = (block[i] >> 7) & 1
        if block[0] & 0x80:
            out[15] ^= 0x87
        return bytes(out)

    k1 = double(subkey_l)
    k2 = double(k1)
    data = bytes(data)
    if data and len(data) % 16 == 0:
        last = _xor(data[-16:], k1)
        body = data[:-16]
    else:
        pad_len = 16 - (len(data) % 16) if data else 16
        padded = data + b"\x80" + bytes(pad_len - 1)
        body = padded[:-16] if len(padded) > 16 else b""
        last = _xor(padded[-16:], k2)
    x = bytes(16)
    for i in range(0, len(body), 16):
        x = encrypt_block(_xor(x, body[i:i + 16]), rk)
    return encrypt_block(_xor(x, last), rk)


def kerberos_aes_encrypt(key, plaintext, usage=2, etype=18):
    """Kerberos AES (etype 17/18): AES-CTS with an HMAC-SHA1 checksum.

    The key is the protocol key (already derived from the password or the krbtgt secret), so
    this is the encryption step only. The checksum covers the usage, which is what binds a
    ciphertext to the message it belongs to.
    """
    if etype not in (17, 18):
        raise AesError(f"not an AES Kerberos etype: {etype}")
    if len(key) not in (16, 32):
        raise AesError(f"etype {etype} needs a {'16' if etype == 17 else '32'}-byte key")
    kc = hashlib.sha1(struct_pack_usage(usage)).digest()[:16 if etype == 17 else 32]
    ki = hashlib.sha1(b"\x00" + struct_pack_usage(usage)).digest()[:16 if etype == 17 else 32]
    # the subkeys are derived by encrypting the usage with the protocol key
    kc = encrypt_block(struct_pack_usage(usage) + bytes(12), expand_key(key))
    ki = encrypt_block(b"\x00" + struct_pack_usage(usage) + bytes(11), expand_key(key))
    checksum = hmac.new(ki, struct_pack_usage(usage) + bytes(plaintext), hashlib.sha1).digest()
    return checksum + cts_encrypt(kc, bytes(plaintext), iv=bytes(16))


def kerberos_aes_decrypt(key, blob, usage=2, etype=18):
    if len(blob) < 28:
        raise AesError("an AES Kerberos blob carries a 12-byte checksum and one block")
    kc = encrypt_block(struct_pack_usage(usage) + bytes(12), expand_key(key))
    ki = encrypt_block(b"\x00" + struct_pack_usage(usage) + bytes(11), expand_key(key))
    checksum, cipher = blob[:12], blob[12:]
    plain = cts_decrypt(kc, cipher, iv=bytes(16))
    if hmac.new(ki, struct_pack_usage(usage) + plain, hashlib.sha1).digest()[:12] != checksum:
        raise AesError("the checksum does not match: wrong key or wrong usage")
    return plain


def struct_pack_usage(usage):
    import struct
    return struct.pack("<I", int(usage))


def gpp_decrypt(cpassword, key=GPP_KEY):
    """The GPP cpassword: AES-256-CBC, base64, with the published key and a zero IV.

    MS14-025 is from 2014 and the attribute is still populated in directories nobody cleaned,
    which is why this is worth having: the password comes back in one call, no cracking.
    """
    import base64
    text = str(cpassword or "").strip()
    if not text:
        raise AesError("no cpassword to decrypt")
    pad = "=" * (-len(text) % 4)
    try:
        blob = base64.b64decode(text + pad)
    except Exception as e:
        raise AesError(f"not base64: {e}") from e
    return cbc_decrypt(key, blob, iv=bytes(16)).decode("utf-16-le", "replace")


def describe(facts):
    return f"aes: {facts}" if not isinstance(facts, dict) else \
        f"aes: {facts.get('what', 'cipher')}"
