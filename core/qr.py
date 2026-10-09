"""QR codes, standard library only.

Byte mode, ECC level L/M/Q/H, versions 1-10 (a lure URL fits in version 3-5 at M). The
encoder is complete for those versions: mode indicator, character count, terminator and
pad bytes, Reed-Solomon over GF(256) per block, block interleaving, matrix placement,
the eight masks with the four penalty rules, and BCH format/version information.

Versions above 10 raise `QRTooLong` rather than emitting a wrong symbol: the capacity
tables for 11-40 are not here, and a silently truncated code is worse than a refusal.

Output is a matrix (list of rows of 0/1) plus `svg()`, `png()` and `ascii_art()` renderers.
The PNG writer is zlib + struct, so a QR can be attached to a mail or written to a file
without an imaging dependency.
"""
import struct
import zlib

__all__ = ["QRTooLong", "encode", "svg", "png", "ascii_art", "capacity"]

# data codewords per (version, ecc)
_DATA_CODEWORDS = {
    1: {"L": 19, "M": 16, "Q": 13, "H": 9},
    2: {"L": 34, "M": 28, "Q": 22, "H": 16},
    3: {"L": 55, "M": 44, "Q": 34, "H": 26},
    4: {"L": 80, "M": 64, "Q": 48, "H": 36},
    5: {"L": 108, "M": 86, "Q": 62, "H": 46},
    6: {"L": 136, "M": 108, "Q": 76, "H": 60},
    7: {"L": 156, "M": 124, "Q": 88, "H": 66},
    8: {"L": 194, "M": 154, "Q": 110, "H": 86},
    9: {"L": 232, "M": 182, "Q": 132, "H": 100},
    10: {"L": 274, "M": 216, "Q": 154, "H": 122},
}

# (blocks in group 1, data codewords each, blocks in group 2, data codewords each,
#  ecc codewords per block)
_ECC_BLOCKS = {
    (1, "L"): (1, 19, 0, 0, 7), (1, "M"): (1, 16, 0, 0, 10),
    (1, "Q"): (1, 13, 0, 0, 13), (1, "H"): (1, 9, 0, 0, 17),
    (2, "L"): (1, 34, 0, 0, 10), (2, "M"): (1, 28, 0, 0, 16),
    (2, "Q"): (1, 22, 0, 0, 22), (2, "H"): (1, 16, 0, 0, 28),
    (3, "L"): (1, 55, 0, 0, 15), (3, "M"): (1, 44, 0, 0, 26),
    (3, "Q"): (2, 17, 0, 0, 18), (3, "H"): (2, 13, 0, 0, 22),
    (4, "L"): (1, 80, 0, 0, 20), (4, "M"): (2, 32, 0, 0, 18),
    (4, "Q"): (2, 24, 0, 0, 26), (4, "H"): (4, 9, 0, 0, 16),
    (5, "L"): (1, 108, 0, 0, 26), (5, "M"): (2, 43, 0, 0, 24),
    (5, "Q"): (2, 15, 2, 16, 18), (5, "H"): (2, 11, 2, 12, 22),
    (6, "L"): (2, 68, 0, 0, 18), (6, "M"): (4, 27, 0, 0, 16),
    (6, "Q"): (4, 19, 0, 0, 24), (6, "H"): (4, 15, 0, 0, 28),
    (7, "L"): (2, 78, 0, 0, 20), (7, "M"): (4, 31, 0, 0, 18),
    (7, "Q"): (2, 14, 4, 15, 18), (7, "H"): (4, 13, 1, 14, 26),
    (8, "L"): (2, 97, 0, 0, 24), (8, "M"): (2, 38, 2, 39, 22),
    (8, "Q"): (4, 18, 2, 19, 22), (8, "H"): (4, 14, 2, 15, 26),
    (9, "L"): (2, 116, 0, 0, 30), (9, "M"): (3, 36, 2, 37, 22),
    (9, "Q"): (4, 16, 4, 17, 20), (9, "H"): (4, 12, 4, 13, 24),
    (10, "L"): (2, 68, 2, 69, 18), (10, "M"): (4, 43, 1, 44, 26),
    (10, "Q"): (6, 19, 2, 20, 24), (10, "H"): (6, 15, 2, 16, 28),
}

_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
          7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}

_ECC_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}      # as stored in format info


class QRTooLong(ValueError):
    """The payload does not fit the supported versions (1-10)."""


def capacity(version, ecc="M"):
    """Payload bytes that fit, for byte mode.

    4-bit mode indicator + the character count (8 bits up to version 9, 16 from version
    10), then whole bytes.
    """
    dc = _DATA_CODEWORDS[version][ecc]
    return dc - 2 if version <= 9 else dc - 3


# --------------------------------------------------------------- GF(256) / RS --
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1D                              # x^8 + x^4 + x^3 + x^2 + 1
        b >>= 1
    return p


def _rs_generator(n):
    poly = [1]
    for i in range(n):
        nxt = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            nxt[j] ^= _gf_mul(c, 1)
            nxt[j + 1] ^= _gf_mul(c, _gf_exp(i))
        poly = nxt
    return poly


def _gf_exp(i):
    """alpha^i in GF(256) with the QR primitive polynomial."""
    v = 1
    for _ in range(i):
        v = _gf_mul(v, 2)
    return v


def _rs_encode(data, ecc_len):
    gen = _rs_generator(ecc_len)
    rem = list(data) + [0] * ecc_len
    for i in range(len(data)):
        c = rem[i]
        if c:
            for j, g in enumerate(gen):
                rem[i + j] ^= _gf_mul(g, c)
    return rem[len(data):]


# ------------------------------------------------------------------ bit buffer --
def _bitstream(payload, version, ecc):
    data_cw = _DATA_CODEWORDS[version][ecc]
    bits = []

    def put(value, length):
        for i in range(length - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)                                  # byte mode
    put(len(payload), 8 if version <= 9 else 16)    # character count
    for byte in payload:
        put(byte, 8)
    remaining = data_cw * 8 - len(bits)
    put(0, min(4, remaining))                       # terminator
    while len(bits) % 8:
        bits.append(0)
    pad = (0xEC, 0x11)
    i = 0
    while len(bits) < data_cw * 8:
        put(pad[i % 2], 8)
        i += 1
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def _interleave(codewords, version, ecc):
    g1, d1, g2, d2, ec = _ECC_BLOCKS[(version, ecc)]
    blocks, pos = [], 0
    for _ in range(g1):
        blocks.append(list(codewords[pos:pos + d1]))
        pos += d1
    for _ in range(g2):
        blocks.append(list(codewords[pos:pos + d2]))
        pos += d2
    ecc_blocks = [_rs_encode(b, ec) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec):
        for e in ecc_blocks:
            out.append(e[i])
    return out


# ---------------------------------------------------------------- matrix layout --
def _new_matrix(size):
    return [[None] * size for _ in range(size)]


def _place_finder(m, row, col):
    """A finder pattern and its separator ring.

    The ring is part of the function pattern and must be written: leaving it unset let the
    data zigzag write bits into it.
    """
    size = len(m)
    for r in range(-1, 8):
        for c in range(-1, 8):
            rr, cc = row + r, col + c
            if not (0 <= rr < size and 0 <= cc < size):
                continue
            if r in (-1, 7) or c in (-1, 7):
                m[rr][cc] = 0                      # separator
            elif r in (0, 6) or c in (0, 6):
                m[rr][cc] = 1                      # outer ring
            elif 2 <= r <= 4 and 2 <= c <= 4:
                m[rr][cc] = 1                      # centre block
            else:
                m[rr][cc] = 0


def _place_function_patterns(m, version):
    size = len(m)
    _place_finder(m, 0, 0)
    _place_finder(m, 0, size - 7)
    _place_finder(m, size - 7, 0)
    for i in range(8, size - 8):                    # timing
        bit = 1 if i % 2 == 0 else 0
        m[6][i] = bit
        m[i][6] = bit
    for r in _ALIGN[version]:                       # alignment
        for c in _ALIGN[version]:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    rr, cc = r + dr, c + dc
                    if m[rr][cc] is not None:
                        continue
                    edge = max(abs(dr), abs(dc))
                    m[rr][cc] = 1 if edge != 1 else 0
    m[size - 8][8] = 1                              # dark module
    for i in range(9):                              # reserve format areas
        if m[8][i] is None:
            m[8][i] = 0
        if m[i][8] is None:
            m[i][8] = 0
    for i in range(8):
        m[8][size - 1 - i] = 0
        m[size - 1 - i][8] = 0
    if version >= 7:                                # reserve version areas
        for r in range(6):
            for c in range(size - 11, size - 8):
                m[r][c] = 0
                m[c][r] = 0


def _place_data(m, codewords):
    size = len(m)
    bit_index = 0
    total = len(codewords) * 8
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:                                # skip the vertical timing column
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if m[row][c] is not None:
                    continue
                bit = 0
                if bit_index < total:
                    byte = codewords[bit_index >> 3]
                    bit = (byte >> (7 - (bit_index & 7))) & 1
                    bit_index += 1
                m[row][c] = bit
        upward = not upward
        col -= 2


def _mask_bit(mask, r, c):
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _apply_mask(m, mask, reserved):
    size = len(m)
    for r in range(size):
        for c in range(size):
            if reserved[r][c]:
                continue
            if _mask_bit(mask, r, c):
                m[r][c] ^= 1


def _penalty(m):
    """The standard's four penalty rules; the lowest score picks the mask.

    Rule 3 matches the 11-module windows `10111010000` and `00001011101` exactly - a
    7-module finder-like pattern with a looser "light run nearby" test scores the edges
    differently and picks the wrong mask.
    """
    size = len(m)
    score = 0
    lines = [list(row) for row in m] + [list(col) for col in zip(*m, strict=True)]
    # rule 1: runs of five or more of the same colour
    for line in lines:
        run, prev = 1, line[0]
        for v in line[1:]:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run, prev = 1, v
        if run >= 5:
            score += run - 2
    # rule 2: every 2x2 block of one colour
    for r in range(size - 1):
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    # rule 3: the two finder-like 11-module windows, either direction
    pat_a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat_b = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for line in lines:
        for i in range(size - 10):
            win = line[i:i + 11]
            if win in (pat_a, pat_b):
                score += 40
    # rule 4: the dark-module proportion, 10 points per 5% away from 50%
    dark = sum(sum(r) for r in m)
    percent = dark / (size * size)
    score += int(abs(percent * 100 - 50) / 5) * 10
    return score


def _format_bits(ecc, mask):
    data = (_ECC_BITS[ecc] << 3) | mask
    rem = data << 10
    gen = 0b10100110111
    for i in range(14, 9, -1):
        if rem & (1 << i):
            rem ^= gen << (i - 10)
    return ((data << 10) | rem) ^ 0b101010000010010


def _version_bits(version):
    rem = version << 12
    gen = 0b1111100100101
    for i in range(17, 11, -1):
        if rem & (1 << i):
            rem ^= gen << (i - 12)
    return (version << 12) | rem


def _write_format(m, ecc, mask):
    """The 15 format bits, both copies.

    Column 8 carries bits 0-5 above the top-left finder (rows 0-5), bits 6-7 at rows 7-8,
    and bits 8-14 along the bottom-left (rows size-7..size-1). Row 8 carries bits 0-7 to
    the right of the top-right finder (cols size-1..size-8) and bits 8-14 to the left
    (col 7, then cols 5..0).
    """
    size = len(m)
    bits = _format_bits(ecc, mask)
    for i in range(15):
        bit = (bits >> i) & 1
        if i < 6:
            m[i][8] = bit
        elif i < 8:
            m[i + 1][8] = bit
        else:
            m[size - 15 + i][8] = bit
        if i < 8:
            m[8][size - i - 1] = bit
        elif i == 8:
            m[8][7] = bit
        else:
            m[8][14 - i] = bit
    m[size - 8][8] = 1


def _write_version(m, version):
    if version < 7:
        return
    size = len(m)
    bits = _version_bits(version)
    for i in range(18):
        bit = (bits >> i) & 1
        m[i // 3][size - 11 + i % 3] = bit
        m[size - 11 + i % 3][i // 3] = bit


def encode(payload, ecc="M", version=None, mask=None):
    """Return a QR matrix (list of rows of 0/1) for `payload`.

    `version=None` picks the smallest version that fits. `mask=None` picks the mask with
    the lowest penalty score (the standard's rule).
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    ecc = str(ecc).upper()
    if ecc not in _ECC_BITS:
        raise ValueError(f"ecc must be one of L/M/Q/H, not {ecc!r}")
    if version is None:
        for v in range(1, 11):
            if len(payload) <= capacity(v, ecc):
                version = v
                break
        else:
            raise QRTooLong(
                f"{len(payload)} bytes do not fit version 10-{ecc} "
                f"({capacity(10, ecc)} max): use a shorter URL")
    if not 1 <= version <= 10:
        raise QRTooLong(f"version {version} is outside the supported 1-10")
    if len(payload) > capacity(version, ecc):
        raise QRTooLong(f"{len(payload)} bytes do not fit version {version}-{ecc}")

    codewords = _interleave(_bitstream(payload, version, ecc), version, ecc)
    size = version * 4 + 17
    best = None
    for m_choice in ([mask] if mask is not None else range(8)):
        m = _new_matrix(size)
        _place_function_patterns(m, version)
        reserved = [[m[r][c] is not None for c in range(size)] for r in range(size)]
        _place_data(m, codewords)
        _apply_mask(m, m_choice, reserved)
        # The mask is scored with the format area blank (and the dark module light): the
        # format bits are DERIVED from the mask, so scoring them would let the mask
        # choice feed back into its own score. This is the common convention.
        m[size - 8][8] = 0
        score = _penalty(m)
        if best is None or score < best[0]:
            best = (score, m_choice, m)
    if best is None:                               # unreachable: the loop always runs
        raise RuntimeError("no mask was evaluated")
    _score, mask_used, matrix = best
    # the version information is derived from the version, not from the mask, so it is
    # written after the mask is chosen (the same convention as the format bits)
    _write_version(matrix, version)
    _write_format(matrix, ecc, mask_used)
    return matrix


def svg(matrix, scale=4, border=4, dark="#000000", light="#ffffff"):
    """An SVG string (no dependency, embeds in HTML mail or a PDF)."""
    n = len(matrix)
    side = (n + 2 * border) * scale
    rects = []
    for r, row in enumerate(matrix):
        for c, v in enumerate(row):
            if v:
                rects.append(f'<rect x="{(c + border) * scale}" y="{(r + border) * scale}" '
                             f'width="{scale}" height="{scale}"/>')
    return ('<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
            f'width="{side}" height="{side}" viewBox="0 0 {side} {side}">'
            f'<rect width="{side}" height="{side}" fill="{light}"/>'
            f'<g fill="{dark}">' + "".join(rects) + "</g></svg>")


def _png_chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def png(matrix, scale=4, border=4):
    """PNG bytes: greyscale, 8 bits per pixel, no dependency.

    Each module becomes a `scale` x `scale` block, and the quiet zone is `border` modules
    wide, so the image is `(n + 2*border) * scale` on both sides.
    """
    n = len(matrix)
    side = n + 2 * border
    rows = []
    for r in range(side):
        line = bytearray()
        for c in range(side):
            inside = (border <= r < border + n) and (border <= c < border + n)
            bit = matrix[r - border][c - border] if inside else 0
            line += bytes([0 if bit else 255]) * scale
        for _ in range(scale):
            rows.append(b"\x00" + bytes(line))          # filter type 0 per scanline
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", side * scale, side * scale, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(raw, 9)) + _png_chunk(b"IEND", b""))


def ascii_art(matrix, border=2):
    """A console rendering: two characters per module, ASCII only."""
    n = len(matrix)
    pad = "  " * border
    lines = []
    for _ in range(border):
        lines.append(pad + "  " * n + pad)
    for row in matrix:
        line = pad + "".join("  " if v else "##" for v in row) + pad
        lines.append(line)
    for _ in range(border):
        lines.append(pad + "  " * n + pad)
    return "\n".join(lines)
