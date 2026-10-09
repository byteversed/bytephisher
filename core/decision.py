# BytePhisher - the click-to-access decision matrix.
#
# One click is only worth what the victim's own environment allows. This module turns
# the facts a campaign already collects (the device dump, the browser fingerprint, the
# JA3/JA4 pair, the LAN probe, the pre-serve challenge) into an ORDERED list of access
# paths, each labelled with what it needs and how confident the label is.
#
# The rules this module follows:
#
#   * The matrix never invents a capability. A path whose module is missing, or whose
#     precondition is not visible in the facts, is reported as SUSPECTED or FAILED with
#     the reason - never silently dropped and never promoted to CONFIRMED.
#   * CONFIRMED means every precondition is present IN THE FACTS. It does not mean the
#     path was executed here; the operator runs it and reads the evidence.
#   * Nothing in this file touches the network, the disk, or the database. It is pure
#     decision logic over a dict, which is also what makes it testable offline.
#   * MFA is never bypassed. The relay paths relay an authentication the victim
#     performs; they do not defeat it. The matrix says "session" or "domain-access",
#     never "bypass".
#
# The capability modules are resolved LAZILY through an injectable map, so a missing or
# half-built module degrades to "not available" instead of breaking the CLI, and the
# tests can drive every branch with stubs.
"""The click-to-access decision matrix: facts in, ranked access paths out.

Every path carries a confidence label and the exact precondition it is waiting on:

    CONFIRMED - every precondition is present in the facts as given
    SUSPECTED - one precondition is unknown (a policy, a reachability, a target)
    FAILED    - a fact rules the path out (wrong OS, no relay target, no match)

`decide()` never claims access happened. `ready` says the preconditions are met and
`payoff` says what the path is worth if it works. Read both.
"""
import re

__all__ = ["normalise", "capabilities", "decide", "explain", "PATHS", "CAPABILITIES",
           "PAYOFFS", "normalise_os", "normalise_browser", "facts_from_ua"]

# The capability modules this matrix reasons about. Lazy-resolved so a missing or
# half-built module degrades to "not available" instead of breaking the CLI.
CAPABILITIES = ("mshtml", "exploitpack", "stager", "vba", "relay", "rebind", "exploits",
                "chains", "totp", "dnsx")

# What each path is worth when it works. "channel" is not access at all - it is a way
# to move data out when normal beaconing is filtered, and it is labelled that way.
PAYOFFS = {
    "T1_intranet": "host-access",
    "T2_ntlm_relay": "domain-access",
    "T3_exploitpack": "host-access",
    "T4_macro": "host-access",
    "T5_file": "host-access",
    "C1_dns": "channel",
}

# The paths in intrinsic order (strongest first). The ranking in decide() is built from
# this order, then sorted by readiness - an operator reads top-down.
PATHS = ("T2_ntlm_relay", "T1_intranet", "T3_exploitpack", "T4_macro", "T5_file", "C1_dns")

# Device families are matched BEFORE the desktop names: an iPhone user agent also contains
# "Mac OS X" and an Android one also contains "Linux", so the order decides the answer.
_OS_DEVICE_TOKENS = (("iphone", "ios"), ("ipad", "ios"), ("ipod", "ios"),
                     ("android", "android"), ("cros", "linux"))

_OS_TOKENS = (("windows", "windows"), ("win32", "windows"), ("win64", "windows"),
              ("win nt", "windows"), ("win10", "windows"), ("win11", "windows"),
              ("mac os x", "macos"), ("macintosh", "macos"), ("macos", "macos"),
              ("darwin", "macos"), ("linux", "linux"), ("ubuntu", "linux"),
              ("debian", "linux"), ("freebsd", "linux"), ("x11", "linux"))

_BROWSER_ALIASES = {
    "msie": "ie", "internet explorer": "ie", "ie": "ie", "trident": "ie",
    "edge": "edge", "edg": "edge", "edgios": "edge", "edga": "edge",
    "chrome": "chrome", "chromium": "chrome", "crios": "chrome",
    "firefox": "firefox", "fxios": "firefox", "safari": "safari",
    "opera": "opera", "opr": "opera", "brave": "chrome", "vivaldi": "chrome",
}

# The tokens a full user-agent string carries, in match order: an Edge agent also says
# "Chrome" and "Safari", and an Opera one also says "Chrome", so the specific client has
# to be tested first or every modern browser reads as Chrome.
_BROWSER_TOKENS = (("edg", "edge"), ("opr", "opera"), ("opera", "opera"),
                   ("fxios", "firefox"), ("firefox", "firefox"), ("crios", "chrome"),
                   ("chrome", "chrome"), ("chromium", "chrome"), ("msie", "ie"),
                   ("trident", "ie"), ("version/", "safari"), ("safari/", "safari"))

# Major version per browser, read from the token that browser itself writes.
_BROWSER_VERSION = {
    "chrome": re.compile(r"(?:Chrome|Chromium|CriOS)/(\d{1,4})"),
    "edge": re.compile(r"(?:Edg|EdgA|EdgiOS)/(\d{1,4})"),
    "firefox": re.compile(r"(?:Firefox|FxiOS)/(\d{1,4})"),
    "safari": re.compile(r"Version/(\d{1,4})"),
    "ie": re.compile(r"(?:MSIE |rv:)(\d{1,4})"),
    "opera": re.compile(r"(?:OPR|Opera)/(\d{1,4})"),
}

_VERSION_RE = re.compile(r"(\d{1,4})(?:\.(\d{1,4}))?")


def normalise_os(value):
    """Any spelling of an OS the facts may carry -> one of the canonical names.

    An unrecognised or missing value is 'unknown' on purpose: guessing 'linux' for a
    blank field would silently promote a Windows-only path to available.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    for token, name in _OS_DEVICE_TOKENS:
        if token in text:
            return name
    for token, name in _OS_TOKENS:
        if token in text:
            return name
    return "unknown"


def normalise_browser(value):
    """A bare browser name or a full user-agent string -> one canonical browser name."""
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    head = re.split(r"[\s/]+", text)[0]
    for alias, name in _BROWSER_ALIASES.items():
        if head == alias:
            return name
    for token, name in _BROWSER_TOKENS:
        if token in text:
            return name
    return "unknown"


def facts_from_ua(value):
    """The facts a user-agent string states: OS, browser, major version, IE-ness.

    Only what the string itself asserts. A user agent says nothing about the LAN, the
    relay or the macro policy, and those keys are left out so the matrix reports them as
    missing instead of assuming them.
    """
    text = str(value or "")
    browser = normalise_browser(text)
    pattern = _BROWSER_VERSION.get(browser)
    found = pattern.search(text) if pattern else None
    version = int(found.group(1)) if found else None
    os_name = normalise_os(text)
    return {"os": os_name, "browser": browser, "version": version,
            "is_ie": bool(browser == "ie" and os_name == "windows")}


def _int_or_none(value):
    """A version as a major int. '91.0.4472.124', 91 and '91' all give 91."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = _VERSION_RE.search(str(value))
    return int(match.group(1)) if match else None


def _flag(value, default=False):
    """A truthy fact. Strings are read as words, so 'yes'/'true'/'1' are True and
    'no'/'false'/'0'/'' are False - a UI that posts strings must not read as True."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y", "on"):
        return True
    if text in ("0", "false", "no", "n", "off", ""):
        return False
    return default


def normalise(facts):
    """Coerce a raw fact dict into the shape every path reads.

    Unknown keys are preserved (a future path may use them) and the ones this module
    reasons about are always present, so no caller has to guard against a KeyError.
    """
    if facts is None:
        raise ValueError("facts must be a mapping, not None")
    if not isinstance(facts, dict):
        raise ValueError(f"facts must be a mapping, got {type(facts).__name__}")

    out = dict(facts)
    os_name = normalise_os(facts.get("os") or facts.get("platform") or facts.get("ua_os"))
    browser = normalise_browser(facts.get("browser") or facts.get("ua_browser"))
    out["os"] = os_name
    out["browser"] = browser
    out["version"] = _int_or_none(facts.get("version") or facts.get("browser_version"))
    out["is_ie"] = _flag(facts.get("is_ie")) or (browser == "ie" and os_name == "windows")
    out["smb_reachable"] = _flag(facts.get("smb_reachable"))
    out["http_ntlm_relay_ready"] = _flag(facts.get("http_ntlm_relay_ready"))
    out["relay_target"] = _flag(facts.get("relay_target"))
    out["intranet"] = _flag(facts.get("intranet"))
    out["h2"] = _flag(facts.get("h2"))
    out["mfa"] = str(facts.get("mfa") or "unknown").strip().lower() or "unknown"
    for key in ("ja3", "ja4h", "relay_note"):
        out[key] = str(facts.get(key) or "")
    services = facts.get("local_services") or []
    if isinstance(services, str):
        services = [s.strip() for s in services.split(",") if s.strip()]
    out["local_services"] = [str(s) for s in services]
    policy = facts.get("macro_policy")
    policy = str(policy or "unknown").strip().lower()
    out["macro_policy"] = policy if policy in ("allowed", "blocked", "unknown") else "unknown"
    hta = facts.get("hta_policy")
    hta = str(hta or "unknown").strip().lower()
    out["hta_policy"] = hta if hta in ("allowed", "blocked", "unknown") else "unknown"
    out["beacon_filtered"] = _flag(facts.get("beacon_filtered"))
    return out


def capabilities(overrides=None):
    """Resolve the capability modules this matrix reasons about, lazily.

    Returns {name: module-or-None}. A module that is absent or raises on import is None
    rather than an exception: a half-built tree must still print a plan that says which
    capability is missing, which is more useful than a traceback.
    """
    names = CAPABILITIES
    out = {}
    for name in names:
        if overrides and name in overrides:
            out[name] = overrides[name]
            continue
        try:
            module = __import__(f"core.{name}", fromlist=[name])
            out[name] = module
        except Exception:  # noqa: BLE001 - a missing module is data here, not an error
            out[name] = None
    return out


def _label(ready, missing, ruled_out):
    if ruled_out:
        return "FAILED"
    return "CONFIRMED" if ready else "SUSPECTED"


def _entry(path, why, needs, missing, ruled_out=False, extra=None):
    ready = not missing and not ruled_out
    item = {
        "path": path,
        "payoff": PAYOFFS.get(path, "unknown"),
        "why": why,
        "needs": list(needs),
        "missing": list(missing),
        "ready": bool(ready),
        "confidence": _label(ready, missing, ruled_out),
    }
    if extra:
        item.update(extra)
    return item


def _relay_path(f, caps):
    """T2: the victim's own machine authenticates to us (NTLM over HTTP) and the
    credential is relayed to something that accepts it. What makes this worth anything
    is the TARGET, not the trigger."""
    needs = ["windows host", "a listener answering 401 NTLM", "a relay target that accepts it"]
    missing = []
    if f["os"] != "windows":
        return _entry("T2_ntlm_relay", "MSHTML/IE NTLM relay is a Windows path", needs, [],
                      ruled_out=True, extra={"module": "mshtml+relay"})
    if caps.get("mshtml") is None:
        missing.append("core.mshtml (the trigger artifacts)")
    if caps.get("relay") is None:
        missing.append("core.relay (the NTLM listener)")
    if not f["http_ntlm_relay_ready"]:
        missing.append("an HTTP listener that answers 401 with WWW-Authenticate: NTLM")
    if not f["relay_target"]:
        missing.append("a relay target (AD CS ESC8, or a host that accepts the auth)")
    note = "IE/MSHTML issues the NTLM handshake on our sub-resource; the relay is the access"
    if f["is_ie"] or f["http_ntlm_relay_ready"]:
        note += "; the client is one that speaks NTLM"
    return _entry("T2_ntlm_relay", note, needs, missing,
                  extra={"module": "mshtml+relay", "note": f.get("relay_note", "")})


def _intranet_path(f, caps):
    """T1: a service on the victim's own network that needs no authentication, reached
    through DNS rebinding. This is host access out of the browser, no file needed."""
    needs = ["a reachable local service with no/predictable auth", "rebinding or a same-site hop"]
    missing = []
    if caps.get("rebind") is None:
        missing.append("core.rebind (the rebinding responder)")
    if caps.get("exploits") is None:
        missing.append("core.exploits (the local service table)")
    if not f["intranet"] and not f["local_services"]:
        missing.append("a local service seen from the victim (the LAN probe has not run)")
    services = f["local_services"]
    return _entry("T1_intranet",
                  "a local service the victim's browser can reach, hit through rebinding",
                  needs, missing,
                  extra={"module": "rebind+exploits", "services": services})


def _pack_path(f, caps):
    """T3: a fingerprint-matched entry from the operator's exploit pack."""
    needs = ["a browser/service fingerprint", "a pack entry that matches it", "the payload on disk"]
    module = caps.get("exploitpack")
    if module is None:
        return _entry("T3_exploitpack", "no pack module available", needs,
                      ["core.exploitpack (the pack registry)"], extra={"module": "exploitpack"})
    try:
        matches = module.match({"browser": f["browser"], "version": f["version"],
                                "os": f["os"], "ja3": f["ja3"], "ja4h": f["ja4h"]})
    except Exception as exc:  # noqa: BLE001 - a broken matcher must not kill the plan
        return _entry("T3_exploitpack", f"the pack matcher raised: {exc}", needs,
                      [], ruled_out=True, extra={"module": "exploitpack"})
    matches = [m for m in matches if isinstance(m, dict)]
    if not matches:
        return _entry("T3_exploitpack",
                      f"no pack entry matches {f['browser']} {f['version']}",
                      needs, [], ruled_out=True, extra={"module": "exploitpack"})
    top = matches[0]
    missing = []
    if not top.get("verified"):
        missing.append("a payload verified on disk for the matched entry")
    return _entry("T3_exploitpack",
                  f"{top.get('name', 'entry')} matches {f['browser']} {f['version']}",
                  needs, missing,
                  extra={"module": "exploitpack", "entry": top.get("name", ""),
                         "cve": top.get("cve", ""), "matches": len(matches)})


def _macro_path(f, caps):
    """T4: a macro document. Needs Windows, macros enabled, and the victim to open it."""
    needs = ["windows host", "a .docm with a macro container", "macros enabled by policy",
             "the victim opening the document"]
    missing = []
    if f["os"] != "windows":
        return _entry("T4_macro", "a macro document is a Windows/Office path", needs, [],
                      ruled_out=True, extra={"module": "vba"})
    if caps.get("vba") is None:
        missing.append("core.vba (the .docm builder)")
    if caps.get("stager") is None:
        missing.append("core.stager (the payload the macro runs)")
    if f["macro_policy"] == "blocked":
        return _entry("T4_macro", "macro execution is blocked on this host", needs, [],
                      ruled_out=True, extra={"module": "vba"})
    if f["macro_policy"] == "unknown":
        missing.append("the host's macro policy (unverified)")
    return _entry("T4_macro", "a macro document runs the stager when it is opened",
                  needs, missing, extra={"module": "vba"})


def _file_path(f, caps):
    """T5: an opened shortcut/scriptlet. The weakest Windows path, but it needs no
    browser support and no rebinding."""
    needs = ["windows host", "an artifact the victim opens", "policy allows the target"]
    missing = []
    if f["os"] != "windows":
        return _entry("T5_file", "a .lnk/.hta/.sct is a Windows path", needs, [],
                      ruled_out=True, extra={"module": "mshtml"})
    if caps.get("mshtml") is None:
        missing.append("core.mshtml (the artifact builders)")
    if caps.get("stager") is None:
        missing.append("core.stager (the command the artifact runs)")
    if f["hta_policy"] == "blocked":
        return _entry("T5_file", "script-host execution is blocked on this host", needs, [],
                      ruled_out=True, extra={"module": "mshtml"})
    if f["hta_policy"] == "unknown":
        missing.append("the host's script-host policy (unverified)")
    if not f["smb_reachable"]:
        missing.append("SMB reachability for the shortcut variants")
    return _entry("T5_file", "a shortcut or scriptlet the victim opens runs the stager",
                  needs, missing, extra={"module": "mshtml"})


def _dns_path(f, caps):
    """C1: a data channel, not access. It is ranked last on purpose and labelled
    'channel' - an operator must not read it as a way in."""
    needs = ["a resolver the victim can query", "an authoritative responder for the zone",
             "filtered or monitored normal egress"]
    missing = []
    if caps.get("dnsx") is None:
        missing.append("core.dnsx (the label codec)")
    if caps.get("rebind") is None:
        missing.append("core.rebind (the authoritative responder)")
    if not f["beacon_filtered"]:
        missing.append("a reason to use DNS (normal beaconing does not look filtered)")
    return _entry("C1_dns", "move data out over DNS when the normal beacon is filtered",
                  needs, missing, extra={"module": "dnsx+rebind"})


_BUILDERS = {
    "T2_ntlm_relay": _relay_path,
    "T1_intranet": _intranet_path,
    "T3_exploitpack": _pack_path,
    "T4_macro": _macro_path,
    "T5_file": _file_path,
    "C1_dns": _dns_path,
}


def decide(facts, caps=None):
    """Rank this victim's access paths. Returns a dict, never raises on bad facts
    beyond a non-mapping input.

    The order is: every ready path first (in intrinsic strength order), then the
    SUSPECTED ones with their missing precondition, then the FAILED ones. `best` is the
    first ready path or None - and a None `best` is a legitimate answer that the summary
    states plainly instead of dressing up a broken path.
    """
    f = normalise(facts)
    cap_map = caps if caps is not None else capabilities()
    paths = [_BUILDERS[name](f, cap_map) for name in PATHS]
    rank = {name: i for i, name in enumerate(PATHS)}
    confidence_order = {"CONFIRMED": 0, "SUSPECTED": 1, "FAILED": 2}
    paths.sort(key=lambda p: (0 if p["ready"] else 1,
                              confidence_order.get(p["confidence"], 3),
                              rank.get(p["path"], 99)))
    best = next((p["path"] for p in paths if p["ready"]), None)
    blocked = [p for p in paths if p["confidence"] == "FAILED"]
    if best:
        summary = (f"{best} is the strongest path available for this victim "
                   f"({PAYOFFS.get(best, 'unknown')})")
    elif len(blocked) == len(paths):
        summary = "no path applies to this victim: every option is ruled out by the facts"
    else:
        waiting = [p["path"] for p in paths if p["confidence"] == "SUSPECTED"]
        summary = ("nothing is ready yet; waiting on: " + ", ".join(waiting)
                   if waiting else "nothing is ready and nothing is ruled out either")
    return {"facts": f, "paths": paths, "best": best, "summary": summary,
            "payoff": PAYOFFS.get(best, "none") if best else "none",
            "capabilities": {k: bool(v) for k, v in cap_map.items()}}


def explain(decision):
    """A plain-text report. One line per path, ready first, each with its label - this
    is what the CLI prints, and it must not overstate anything the dict does not say."""
    if not isinstance(decision, dict) or "paths" not in decision:
        raise ValueError("explain() needs a decide() result")
    lines = [decision.get("summary", ""), ""]
    for path in decision["paths"]:
        mark = "READY" if path["ready"] else path["confidence"]
        lines.append(f"[{mark}] {path['path']} ({path['payoff']}): {path['why']}")
        if path.get("module"):
            lines.append(f"        module: {path['module']}")
        for need in path.get("missing") or []:
            lines.append(f"        missing: {need}")
        if path.get("note"):
            lines.append(f"        note: {path['note']}")
    return "\n".join(lines)
