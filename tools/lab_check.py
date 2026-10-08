"""Real-world preflight: what this host can and cannot actually do.

Measured reason this exists: on the development box Chrome launches and renders a
`data:` URL but every live host returns `ERR_ACCESS_DENIED`, so the 13 browser tasks,
the takeover path and any live view are **unverifiable there** - they are not broken,
they are unproven. Without a check, that shows up in the middle of a campaign instead of
before it.

Every check answers three things: what was tested, what happened, and **what to do about
it**. The verdict is `READY` only when nothing required failed. Checks that need the
network are marked, so an offline box reports `skip` instead of a false failure.

Usage:
    python3 tools/lab_check.py                     # all checks
    python3 tools/lab_check.py --domain camp.test --client-id <id> --tunnel https://x
    python3 tools/lab_check.py --json              # machine-readable report
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

PASS, FAIL, SKIP = "pass", "fail", "skip"


def _res(name, status, detail, fix="", required=True):
    return {"name": name, "status": status, "detail": detail, "fix": fix,
            "required": required}


# ------------------------------------------------------------------ local ====
def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 10)
    return _res("python", PASS if ok else FAIL, f"{v.major}.{v.minor}.{v.micro}",
                "BytePhisher needs Python 3.10+" if not ok else "")


def check_deps():
    """Optional capabilities, never a blocker.

    `playwright` gates the browser layer (takeover, the 13 tasks, live view) and
    `curl_cffi` gates upstream TLS impersonation - both are capabilities, not
    prerequisites for serving a page, so a host without them still runs a campaign.
    Marking this required made the campaign launcher refuse to start on a machine that
    simply had not installed playwright.
    """
    missing = []
    for mod in ("playwright",):
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    optional = []
    for mod in ("curl_cffi",):
        try:
            __import__(mod)
        except Exception:
            optional.append(mod)
    detail = "playwright present" if "playwright" not in missing else "playwright MISSING"
    if missing:
        detail += " (the browser layer: takeover, the 13 tasks, live view)"
    if optional:
        detail += "; curl_cffi missing (browser TLS impersonation off)"
    fix = ""
    if missing:
        fix = ("pip install playwright   # needed only for browser-driven tasks; "
               "everything else runs without it")
    return _res("dependencies", FAIL if missing else PASS, detail, fix, required=False)


def check_db(path=None):
    # honour $BYTEPHISHER_HOME, exactly like the CLI does: the check used to report (and
    # create) a database in the checkout while the campaign wrote somewhere else
    # the filename must match DEFAULT_DB in the CLI (data/bytephisher.db): the check used
    # to report and create data/campaigns.db, a file no campaign ever writes
    path = path or os.path.join(os.environ.get("BYTEPHISHER_HOME") or HERE,
                                "data", "bytephisher.db")
    d = os.path.dirname(path) or "."
    try:
        os.makedirs(d, exist_ok=True)
        probe = os.path.join(d, ".labcheck")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
    except Exception as e:
        return _res("database", FAIL, f"{d} is not writable: {e}",
                    f"fix permissions on {d} (or pass --db elsewhere)")
    return _res("database", PASS, f"{path} (directory writable)")


def check_clock(tolerance=180):
    """A wrong clock breaks token expiry, TTLs and every signed token we issue."""
    local = time.time()
    try:
        req = urllib.request.Request("https://www.cloudflare.com/",
                                     method="HEAD",
                                     headers={"User-Agent": "labcheck"})
        with urllib.request.urlopen(req, timeout=10) as r:
            date_hdr = r.headers.get("Date")
    except Exception as e:
        return _res("clock", SKIP, f"no network to compare against ({type(e).__name__})",
                    "", required=False)
    if not date_hdr:
        return _res("clock", SKIP, "the reference host sent no Date header", "",
                    required=False)
    from email.utils import parsedate_to_datetime
    try:
        remote = parsedate_to_datetime(date_hdr).timestamp()
    except Exception:
        return _res("clock", SKIP, f"unparsable Date: {date_hdr!r}", "", required=False)
    drift = int(abs(local - remote))
    if drift > tolerance:
        return _res("clock", FAIL, f"local clock is {drift}s off the reference",
                    "sync the clock (timedatectl / NTP): token expiry and TTLs depend on it")
    return _res("clock", PASS, f"drift {drift}s")


# ----------------------------------------------------------------- network ====
def check_egress():
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json",
                                    timeout=10) as r:
            ip = json.loads(r.read().decode()).get("ip", "")
    except Exception as e:
        return _res("egress", SKIP, f"could not determine the public IP ({type(e).__name__})",
                    "", required=False)
    detail = f"public IP {ip}"
    dc = False
    try:
        from core import classify
        dc = bool(classify.is_datacenter(_org_of(ip) or ""))
        detail += f"; looks like {'a datacenter' if dc else 'residential/other'}"
    except Exception:
        pass
    fix = ("a datacenter egress is a signal to the target's anti-bot layer; "
           "use a residential/mobile egress for the upstream leg") if dc else ""
    return _res("egress", PASS, detail, fix, required=False)


def _org_of(ip):
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=10) as r:
            d = json.loads(r.read().decode())
        return f"{d.get('org', '')} {d.get('asn', '')}".strip()
    except Exception:
        return ""


def check_dns_tls(domain):
    if not domain:
        return _res("domain", SKIP, "no --domain given", "", required=False)
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return _res("domain", FAIL, f"{domain} does not resolve ({type(e).__name__})",
                    "point the domain's A/AAAA record at this host before a campaign")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock, \
                ctx.wrap_socket(sock, server_hostname=domain) as tls:
            cert = tls.getpeercert()
    except Exception as e:
        return _res("tls", FAIL, f"{domain}:443 TLS failed ({type(e).__name__}: {e})",
                    "issue a certificate for this domain (and check the CT-log exposure "
                    "of a brand-named cert)")
    subject = dict(x[0] for x in cert.get("subject", []))
    not_after = cert.get("notAfter", "")
    days = None
    if not_after:
        from email.utils import parsedate_to_datetime
        days = int((parsedate_to_datetime(not_after).timestamp() - time.time()) / 86400)
    detail = f"{domain} -> {ip}; CN={subject.get('commonName', '?')}; expires in {days}d"
    if days is not None and days < 7:
        return _res("tls", FAIL, detail, "the certificate expires within a week - renew it")
    return _res("tls", PASS, detail)


def check_browser():
    """The decisive check: can a browser reach a LIVE host on this machine?

    Rendering a data: URL is not enough - a browser that cannot open a socket makes
    every browser-driven task (takeover, the 13 tasks, live view) unverifiable.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return _res("browser", FAIL, f"playwright missing: {e}", "pip install playwright")
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = b"<h1 id=m>live</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = None
            for kw in ({"channel": "chrome"}, {}):
                try:
                    browser = p.chromium.launch(headless=True, **kw)
                    break
                except Exception:
                    continue
            if browser is None:
                return _res("browser", FAIL, "no Chrome/Chromium could be launched",
                            "install Chrome, or run on a host where Playwright can")
            page = browser.new_page()
            page.goto("data:text/html,<h1>render</h1>", timeout=15000)
            rendered = page.inner_text("h1") == "render"
            why = "the marker was not found in the page"
            try:
                page.goto(f"http://127.0.0.1:{port}/", timeout=15000)
                live = page.inner_text("#m") == "live"
            except Exception as e:
                live = False
                why = f"{type(e).__name__}: {str(e).splitlines()[0][:120]}"
            browser.close()
    finally:
        srv.shutdown()
    if not rendered:
        return _res("browser", FAIL, "the browser could not even render a data: URL",
                    "check the Chrome install")
    if not live:
        return _res("browser", FAIL,
                    f"renders but cannot reach a live host ({why})",
                    "this sandbox denies the browser process network access: the 13 "
                    "browser tasks, takeover and live view CANNOT be verified here - run "
                    "this on a normal host/VPS")
    return _res("browser", PASS, "launches, renders, and reaches a live host")


def check_tunnel(url):
    if not url:
        return _res("tunnel", SKIP, "no --tunnel given", "", required=False)
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "labcheck"})
        with urllib.request.urlopen(req, timeout=12) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        return _res("tunnel", FAIL, f"{url} is not reachable ({type(e).__name__})",
                    "start the tunneler and re-run (cloudflared rate-limits new "
                    "quick tunnels: error 1015)")
    return _res("tunnel", PASS if code < 500 else FAIL, f"{url} answered {code}",
                "the tunnel is up but the origin errored" if code >= 500 else "")


def check_tenant(provider="microsoft", client_id="", tenant="common"):
    """Does this tenant actually allow the device-code grant for this client?"""
    if not client_id:
        return _res("device-code", SKIP, "no --client-id given", "", required=False)
    try:
        from core import devicecode as dc
    except Exception as e:
        return _res("device-code", SKIP, f"cannot import core.devicecode: {e}", "",
                    required=False)
    try:
        flow = dc.DeviceCodeFlow(provider, client_id, tenant=tenant)
        flow.start()
    except dc.DeviceCodeError as e:
        return _res("device-code", FAIL, f"{provider} refused the grant: {e}",
                    "the tenant blocks device-code (or the client id is wrong / has the "
                    "flow disabled). Register a public client with device-code enabled, "
                    "or fall back to the OAuth consent path")
    except Exception as e:
        return _res("device-code", SKIP, f"probe failed ({type(e).__name__})", "",
                    required=False)
    return _res("device-code", PASS,
                f"{provider} issued a code ({flow.user_code}) at {flow.verification_uri}")


CHECKS = ("python", "dependencies", "database", "clock", "egress", "domain", "tls",
          "browser", "tunnel", "device-code")


def run(domain="", client_id="", tunnel="", db=None, tenant="common",
        provider="microsoft", only=None, results=None, warn_only=()):
    """Run every check. `results` lets a caller inject results (used by the tests)."""
    if results is not None:
        res = list(results)
    else:
        res = [check_python(), check_deps(), check_db(db), check_clock(), check_egress(),
               check_dns_tls(domain), check_browser(), check_tunnel(tunnel),
               check_tenant(provider, client_id, tenant)]
    if only:
        res = [r for r in res if r["name"] in only]
    # a check the caller knows it does not need (the browser, for a campaign that never
    # runs a takeover or a live view) must not block the start - but it is still shown
    for r in res:
        if r["name"] in set(warn_only or ()):
            r["required"] = False
    failed = [r for r in res if r["status"] == FAIL and r["required"]]
    verdict = "BLOCKED" if failed else "READY"
    return {"verdict": verdict, "checks": res,
            "blocking": [r["name"] for r in failed]}


def render(report):
    icon = {PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP"}
    lines = ["", "  real-world preflight", "  " + "-" * 64]
    for r in report["checks"]:
        lines.append(f"  {icon[r['status']]:4}  {r['name']:12} {r['detail']}")
        if r["status"] == FAIL and r["fix"]:
            lines.append(f"        -> {r['fix']}")
    lines.append("  " + "-" * 64)
    if report["verdict"] == "READY":
        lines.append("  VERDICT: READY - nothing required failed")
    else:
        lines.append(f"  VERDICT: BLOCKED - {', '.join(report['blocking'])}")
        lines.append("  a campaign started in this state fails in the middle, not at the start")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lab_check",
                                 description="what this host can actually do")
    ap.add_argument("--domain", default="", help="the campaign domain to check DNS/TLS")
    ap.add_argument("--client-id", default="", help="probe the device-code grant")
    ap.add_argument("--tenant", default="common")
    ap.add_argument("--provider", default="microsoft")
    ap.add_argument("--tunnel", default="", help="the public URL to probe")
    ap.add_argument("--db", default=None)
    ap.add_argument("--only", default="", help="comma-separated check names")
    ap.add_argument("--warn-only", default="", metavar="NAMES",
                    help="comma-separated checks that may fail without blocking the "
                         "start (e.g. browser, when this campaign never runs a "
                         "browser-driven task)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    only = [s.strip() for s in a.only.split(",") if s.strip()] or None
    warn_only = [s.strip() for s in a.warn_only.split(",") if s.strip()]
    rep = run(domain=a.domain, client_id=a.client_id, tunnel=a.tunnel, db=a.db,
              tenant=a.tenant, provider=a.provider, only=only, warn_only=warn_only)
    print(json.dumps(rep, indent=2) if a.json else render(rep))
    return 0 if rep["verdict"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
