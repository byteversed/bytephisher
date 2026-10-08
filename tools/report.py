#!/usr/bin/env python3
"""Generate a self-contained HTML campaign report from a BytePhisher capture DB.

    python3 tools/report.py --db data/bytephisher.db --out report.html
    python3 tools/report.py --campaign q3-payroll --out q3.html

The report is one file: no external CSS/JS/CDN, so it opens anywhere and can be
attached to a client email. It contains: KPIs, per-campaign breakdown, geo and
device distribution, an hourly timeline and every captured submission.
"""
import argparse
import html
import json
import os
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap            # noqa: E402
from core import links                     # noqa: E402

CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;
      --acc:#58a6ff;--good:#3fb950;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 22px 64px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:16px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line);
   text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
.sub{color:var(--dim);margin:0 0 22px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0 6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
      padding:16px 20px;min-width:150px;flex:1}
.card .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:26px;font-weight:600;margin-top:6px}
.card.good .v{color:var(--good)} .card.acc .v{color:var(--acc)}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;
      overflow:hidden;border:1px solid var(--line)}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#1c2230;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}
tr:last-child td{border-bottom:0}
code{background:#1c2230;padding:1px 5px;border-radius:4px;font-size:12.5px}
.bar{height:9px;background:var(--acc);border-radius:5px;min-width:2px;display:inline-block}
.barwrap{display:flex;align-items:center;gap:8px}
.barwrap span{color:var(--dim);font-size:12px;min-width:52px}
.pill{padding:2px 8px;border-radius:99px;font-size:11.5px;border:1px solid var(--line)}
.pill.ok{color:var(--good);border-color:#1f6f3f;background:#0f2a19}
.pill.no{color:var(--dim)}
.foot{margin-top:34px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
.two{display:flex;gap:18px;flex-wrap:wrap}
.two>div{flex:1;min-width:300px}
"""


def _esc(v):
    return html.escape(str(v if v is not None else ""))


def _bars(counter, total, limit=12):
    if not counter or not total:
        return "<p class='sub'>no data</p>"
    rows = []
    for key, n in counter.most_common(limit):
        pct = int(max(2, round(n / total * 100)))
        rows.append(
            f"<div class='barwrap'><span>{_esc(key or '—')}</span>"
            f"<div class='bar' style='width:{pct}%'></div>"
            f"<span>{n} ({round(n/total*100)}%)</span></div>")
    return "".join(rows)


def build_report(db_path, out_path=None, campaign=None, title=None,
                 qr_url=None):
    db = cap.CaptureDB(db_path)
    rows = db.all(limit=100000, campaign=campaign)
    stats = db.stats(campaign=campaign)
    campaigns = db.campaigns()
    name = title or (f"BytePhisher campaign report — {campaign}" if campaign
                     else "BytePhisher campaign report")

    geo = Counter(f"{(r['city'] + ', ') if r['city'] else ''}{r['country'] or 'unknown'}"
                  for r in rows)
    devices = Counter(r["device"] or "unknown" for r in rows)
    isps = Counter(r["isp"] or "unknown" for r in rows)
    hourly = Counter(time.strftime("%Y-%m-%d %H:00", time.localtime(r["ts"])) for r in rows)
    creds = [r for r in rows if r["is_cred"]]

    campaign_rows = "".join(
        f"<tr><td>{_esc(c['campaign'])}</td><td>{c['captures']}</td>"
        f"<td>{c['credentials']}</td></tr>" for c in campaigns) or "<tr><td>—</td><td>0</td><td>0</td></tr>"

    detail_rows = []
    for r in rows[:500]:
        fields = "; ".join(f"{k}={v}" for k, v in r["fields"].items())
        pill = "<span class='pill ok'>CREDENTIALS</span>" if r["is_cred"] else "<span class='pill no'>fields</span>"
        risk = int(r.get("risk") or 0)
        rl = "high" if risk >= 70 else "med" if risk >= 30 else "low"
        detail_rows.append(
            f"<tr><td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))}</td>"
            f"<td>{_esc(r['campaign'] or '—')}</td><td>{_esc(r['ip'])}</td>"
            f"<td>{_esc((r['city'] + ', ') if r['city'] else '')}{_esc(r['country'])}</td>"
            f"<td>{_esc(r['device'])}</td><td>{pill}</td>"
            f"<td>{rl} ({risk})<br><span class='sub'>{_esc('; '.join(r.get('risk_reasons') or []))}</span></td>"
            f"<td><code>{_esc(fields)}</code></td></tr>")
    detail = "".join(detail_rows) or "<tr><td colspan='8'>no captures yet</td></tr>"

    timeline = _bars(hourly, len(rows), limit=24)
    try:
        blocked = db.blocked_stats()
    except Exception:
        blocked = {"total_blocked": 0, "by_reason": []}
    blocked_rows = "".join(
        f"<tr><td>{_esc(b['reason'])}</td><td>{b['count']}</td></tr>"
        for b in blocked["by_reason"]) or "<tr><td>nothing gated out</td><td>0</td></tr>"
    blocked_block = f"""
<h2>Gated out ({blocked['total_blocked']})</h2>
<table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>{blocked_rows}</tbody></table>""" if blocked["total_blocked"] else ""

    try:
        reuse = db.reuse_stats()
    except Exception:
        reuse = {"repeated_identities": [], "repeated_passwords": [],
                 "total_reused_identities": 0, "total_reused_passwords": 0}
    if reuse["total_reused_identities"] or reuse["total_reused_passwords"]:
        id_rows = "".join(
            f"<tr><td><code>{_esc(r['identity'])}</code></td><td>{r['count']}</td>"
            f"<td>{_esc(', '.join(r['campaigns']) or '—')}</td></tr>"
            for r in reuse["repeated_identities"][:50]) or "<tr><td>none</td><td>0</td><td>—</td></tr>"
        pw_rows = "".join(
            f"<tr><td><code>{_esc(r['password'])}</code></td><td>{r['count']}</td>"
            f"<td>{len(r['identities'])}</td>"
            f"<td>{_esc(', '.join(r['campaigns']) or '—')}</td></tr>"
            for r in reuse["repeated_passwords"][:50]) or "<tr><td>none</td><td>0</td><td>0</td><td>—</td></tr>"
        reuse_block = f"""
<h2>Reused credentials ({reuse['total_reused_identities']} identities / {reuse['total_reused_passwords']} passwords)</h2>
<p class="sub">A repeated identity means the same account was submitted more than once;
a repeated password across different identities is a password-reuse finding.</p>
<table><thead><tr><th>Identity</th><th>Times seen</th><th>Campaigns</th></tr></thead>
<tbody>{id_rows}</tbody></table>
<table style="margin-top:10px"><thead><tr><th>Password</th><th>Times seen</th><th>Distinct identities</th><th>Campaigns</th></tr></thead>
<tbody>{pw_rows}</tbody></table>"""
    else:
        reuse_block = ""
    qr_block = ""
    if qr_url:
        png = links.qr_png(qr_url, path=os.path.join(os.path.dirname(out_path or ".") or ".",
                                                     "campaign_qr.png"))
        if png:
            qr_block = (f"<h2>Campaign link</h2><p><code>{_esc(qr_url)}</code></p>"
                        f"<img src='{_esc(os.path.basename(png))}' alt='QR' "
                        f"style='background:#fff;padding:10px;border-radius:8px'>")
        else:
            qr_block = (f"<h2>Campaign link</h2><p><code>{_esc(qr_url)}</code></p>"
                        "<p class='sub'>install segno for QR output</p>")

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(name)}</title>
<meta name="robots" content="noindex,nofollow">
<style>{CSS}</style></head>
<body><div class="wrap">
<h1>{_esc(name)}</h1>
<p class="sub">Generated {time.strftime('%Y-%m-%d %H:%M:%S')} ·
database <code>{_esc(os.path.basename(db_path))}</code>{' · campaign <code>%s</code>' % _esc(campaign) if campaign else ''}</p>

<div class="cards">
  <div class="card acc"><div class="k">Submissions</div><div class="v">{stats['total_captures']}</div></div>
  <div class="card good"><div class="k">Credential pairs</div><div class="v">{stats['credentials']}</div></div>
  <div class="card"><div class="k">Credible (low risk)</div><div class="v">{stats.get('credible_credentials', 0)}</div></div>
  <div class="card"><div class="k">Unique visitors</div><div class="v">{stats['visitors']}</div></div>
  <div class="card"><div class="k">Countries</div><div class="v">{len([k for k in geo if k and k != 'unknown'])}</div></div>
  <div class="card"><div class="k">Submit rate</div><div class="v">{round(len(creds) / max(1, stats['visitors']) * 100)}%</div></div>
</div>

<h2>Campaigns</h2>
<table><thead><tr><th>Campaign</th><th>Submissions</th><th>Credentials</th></tr></thead>
<tbody>{campaign_rows}</tbody></table>

<div class="two">
  <div><h2>Geography</h2>{_bars(geo, len(rows))}</div>
  <div><h2>Devices</h2>{_bars(devices, len(rows))}</div>
</div>
<div class="two">
  <div><h2>Networks / ISP</h2>{_bars(isps, len(rows))}</div>
  <div><h2>Timeline (hourly)</h2>{timeline}</div>
</div>

{qr_block}

{blocked_block}

{reuse_block}

<h2>Captured submissions ({len(rows)})</h2>
<table><thead><tr><th>Time</th><th>Campaign</th><th>IP</th><th>Geo</th>
<th>Device</th><th>Type</th><th>Risk</th><th>Fields</th></tr></thead>
<tbody>{detail}</tbody></table>
<p class="sub">{'Showing first 500 rows.' if len(rows) > 500 else ''}</p>

<div class="foot">
BytePhisher report · authorized security-awareness / red-team use only ·
{len(rows)} submissions analysed{'' if campaign is None else ' for campaign ' + _esc(campaign)}
</div>
</div></body></html>"""

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(doc)
    db.close()
    return {"path": out_path, "rows": len(rows), "stats": stats,
            "campaigns": campaigns, "html": doc if not out_path else None}


def main():
    ap = argparse.ArgumentParser(description="BytePhisher HTML campaign report")
    ap.add_argument("--db", default=os.path.join(HERE, "data", "bytephisher.db"))
    ap.add_argument("--out", default=os.path.join(HERE, "data", "report.html"))
    ap.add_argument("--campaign", help="only this campaign")
    ap.add_argument("--title")
    ap.add_argument("--qr", metavar="URL", help="also embed a QR code for this link")
    args = ap.parse_args()

    res = build_report(args.db, args.out, campaign=args.campaign, title=args.title,
                       qr_url=args.qr)
    print(f"[bytephisher] report written -> {res['path']}")
    print(f"[bytephisher] rows: {res['rows']}  stats: {res['stats']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
