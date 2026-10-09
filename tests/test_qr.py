"""QR encoder tests.

The strongest test here is the cross-check: every symbol this module produces is compared
cell for cell against the `qrcode` package (an independent implementation of the same
standard) across all ten supported versions and all four ECC levels. That covers the
Reed-Solomon arithmetic, the interleaving, the matrix layout, the mask choice and the
BCH format/version fields at once - a wrong capacity table or a misplaced separator shows
up immediately.

`qrcode` and `PIL` are test-only: the product stays standard library only.
"""
import io
import os
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import qr  # noqa: E402

pytestmark = pytest.mark.unit

qrcode = pytest.importorskip("qrcode", reason="qrcode is the cross-check implementation")

from qrcode.util import MODE_8BIT_BYTE, QRData  # noqa: E402

_ECC = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q, "H": qrcode.constants.ERROR_CORRECT_H}


def reference_matrix(data, version, ecc, fit=False):
    ref = qrcode.QRCode(version=None if fit else version,
                        error_correction=_ECC[ecc], box_size=1, border=0)
    ref.add_data(QRData(data, mode=MODE_8BIT_BYTE, check_data=False))
    ref.make(fit=fit)
    return [[1 if v else 0 for v in row] for row in ref.get_matrix()]


class TestAgainstTheReferenceImplementation:

    def test_every_version_and_ecc_level_matches(self):
        checked, mismatches = 0, []
        for version in range(1, 11):
            for ecc in ("L", "M", "Q", "H"):
                cap = qr.capacity(version, ecc)
                for frac in (0.05, 0.4, 0.75, 1.0):
                    n = max(1, int(cap * frac))
                    data = (b"https://login.example.test/s/" + b"y" * n)[:n]
                    mine = qr.encode(data, ecc=ecc, version=version)
                    if mine != reference_matrix(data, version, ecc):
                        mismatches.append((version, ecc, n))
                    checked += 1
        assert checked == 160
        assert not mismatches, f"symbols that differ from the reference: {mismatches}"

    def test_auto_version_matches_the_reference(self):
        for text in ("https://x.test", "https://login.example.test/auth?t=abc123def456",
                     "P" * 200):
            mine = qr.encode(text, ecc="M")
            theirs = reference_matrix(text.encode(), None, "M", fit=True)
            assert mine == theirs, f"auto version differs for {text[:24]!r}"

    def test_the_penalty_function_matches_the_reference(self):
        # the mask choice depends on it, so a rule with a different edge behaviour would
        # silently produce a non-standard symbol
        from qrcode import util as qu
        for version in (1, 3, 7, 10):
            for ecc in ("L", "H"):
                for n in (1, qr.capacity(version, ecc)):
                    m = qr.encode(b"z" * n, ecc=ecc, version=version, mask=3)
                    assert qr._penalty(m) == qu.lost_point(m), (version, ecc, n)

    def test_utf8_payloads_round_trip_the_same(self):
        text = "https://exämple.test/ü?q=1"
        mine = qr.encode(text, ecc="Q")
        theirs = reference_matrix(text.encode("utf-8"), None, "Q", fit=True)
        assert mine == theirs


class TestTheSymbolIsWellFormed:

    def test_size_follows_the_version_formula(self):
        for version in range(1, 11):
            m = qr.encode(b"x", ecc="L", version=version)
            assert len(m) == 17 + 4 * version
            assert all(len(row) == len(m) for row in m)

    def test_the_finder_patterns_and_separators_are_where_they_belong(self):
        m = qr.encode(b"x", ecc="M", version=4)
        n = len(m)
        for row, col in ((0, 0), (0, n - 7), (n - 7, 0)):
            for r in range(7):
                for c in range(7):
                    edge = r in (0, 6) or c in (0, 6)
                    centre = 2 <= r <= 4 and 2 <= c <= 4
                    assert m[row + r][col + c] == (1 if edge or centre else 0), (row, col, r, c)
        # the separator ring around each finder is light and must not carry data
        assert m[7][0:8] == [0] * 8                       # below the top-left
        assert [m[r][7] for r in range(8)] == [0] * 8     # right of the top-left
        assert m[7][n - 8:n] == [0] * 8                   # below the top-right
        assert m[n - 8][0:8] == [0] * 8                   # above the bottom-left

    def test_the_timing_patterns_alternate(self):
        m = qr.encode(b"x", ecc="M", version=3)
        n = len(m)
        for i in range(8, n - 8):
            assert m[6][i] == (1 if i % 2 == 0 else 0)
            assert m[i][6] == (1 if i % 2 == 0 else 0)

    def test_the_dark_module_is_set(self):
        for version in (1, 7, 10):
            m = qr.encode(b"x", ecc="H", version=version)
            assert m[len(m) - 8][8] == 1

    def test_version_information_is_present_from_version_seven(self):
        from qrcode import util as qu
        for version in (7, 10):
            m = qr.encode(b"x", ecc="L", version=version)
            bits = qu.BCH_type_number(version)
            n = len(m)
            for i in range(18):
                bit = (bits >> i) & 1
                assert m[i // 3][n - 11 + i % 3] == bit
                assert m[n - 11 + i % 3][i // 3] == bit

    def test_a_payload_that_does_not_fit_is_refused(self):
        with pytest.raises(qr.QRTooLong):
            qr.encode(b"x" * (qr.capacity(10, "H") + 1), ecc="H")
        with pytest.raises(qr.QRTooLong):
            qr.encode(b"x" * (qr.capacity(1, "M") + 1), ecc="M", version=1)
        with pytest.raises(qr.QRTooLong):
            qr.encode(b"x", ecc="M", version=11)

    def test_a_bad_ecc_level_is_refused(self):
        with pytest.raises(ValueError):
            qr.encode(b"x", ecc="Z")

    def test_an_explicit_mask_is_honoured_and_still_readable(self):
        # forcing a mask must still produce a symbol the reference agrees with
        data = b"https://x.test/m"
        for mask in range(8):
            mine = qr.encode(data, ecc="M", mask=mask)
            # the reference must be told the same mask: left alone it picks its own, which
            # is a different valid symbol
            theirs = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                                   box_size=1, border=0, mask_pattern=mask)
            theirs.add_data(QRData(data, mode=MODE_8BIT_BYTE, check_data=False))
            theirs.make(fit=True)
            assert mine == [[1 if v else 0 for v in row] for row in theirs.get_matrix()]


class TestCapacity:

    def test_capacity_grows_with_the_version_and_shrinks_with_ecc(self):
        for ecc in ("L", "M", "Q", "H"):
            caps = [qr.capacity(v, ecc) for v in range(1, 11)]
            assert caps == sorted(caps), ecc
        for version in range(1, 11):
            row = [qr.capacity(version, e) for e in ("L", "M", "Q", "H")]
            assert row == sorted(row, reverse=True), version

    def test_a_payload_of_exactly_the_capacity_fits(self):
        for version in range(1, 11):
            for ecc in ("L", "M", "Q", "H"):
                cap = qr.capacity(version, ecc)
                m = qr.encode(b"a" * cap, ecc=ecc, version=version)
                assert len(m) == 17 + 4 * version


class TestRenderers:

    def test_svg_is_well_formed_and_has_one_rect_per_dark_module(self):
        m = qr.encode("https://x.test", ecc="M")
        svg = qr.svg(m, scale=4, border=4)
        root = ET.fromstring(svg)
        rects = [e for e in root.iter() if e.tag.endswith("rect")]
        dark = sum(sum(r) for r in m)
        assert len(rects) == dark + 1                 # +1 is the background
        side = (len(m) + 8) * 4
        assert root.get("width") == str(side) and root.get("height") == str(side)

    def test_png_pixels_match_the_matrix(self):
        Image = pytest.importorskip("PIL.Image", reason="PIL is a test-only checker")
        m = qr.encode("https://login.example.test/auth", ecc="M")
        for scale, border in ((3, 2), (6, 4), (10, 4)):
            im = Image.open(io.BytesIO(qr.png(m, scale=scale, border=border)))
            im.load()
            px = im.load()
            side = (len(m) + 2 * border) * scale
            assert im.size == (side, side)
            for r in range(len(m)):
                for c in range(len(m)):
                    x = (c + border) * scale + scale // 2
                    y = (r + border) * scale + scale // 2
                    assert px[x, y] == (0 if m[r][c] else 255), (r, c, scale)

    def test_the_quiet_zone_is_light(self):
        Image = pytest.importorskip("PIL.Image", reason="PIL is a test-only checker")
        m = qr.encode("https://x.test", ecc="L")
        im = Image.open(io.BytesIO(qr.png(m, scale=4, border=4)))
        im.load()
        px = im.load()
        assert px[0, 0] == 255 and px[im.size[0] - 1, im.size[1] - 1] == 255

    def test_ascii_art_has_a_border_and_the_right_shape(self):
        m = qr.encode("https://x.test", ecc="M")
        art = qr.ascii_art(m, border=2).splitlines()
        assert len(art) == len(m) + 4
        assert len(art[0]) == 2 * (len(m) + 4)        # two characters per module

    def test_the_png_is_a_real_png_container(self):
        png = qr.png(qr.encode("https://x.test"), scale=2)
        assert png.startswith(b"\x89PNG\r\n\x1a\n") and png.endswith(b"IEND\xaeB`\x82")
