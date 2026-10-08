#!/usr/bin/env python3
"""BytePhisher — PDF campaign report (dark theme, client-facing).

    python3 tools/report_pdf.py --out data/report.pdf
    python3 tools/report_pdf.py --campaign q3-payroll --out q3.pdf --qr https://link

Layout (A4, dark "Martand" style):
  page 1  KPIs · campaign breakdown · gated-out reasons
  page 2  geography · devices · networks · hourly timeline
  page 3+ every submission, each labelled:
            CONFIRMED  credential pair from a low-risk (human-looking) source
            SUSPECTED  credential pair that looks automated/datacenter
            OTP ONLY   a verification-code submission without a credential pair
            FIELDS     other field submissions
Labels are deliberately conservative — nothing is presented as a real victim
unless the evidence supports it.
"""
import argparse
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap            # noqa: E402
from core import links                     # noqa: E402

BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1c2230"
LINE = "#30363d"
FG = "#e6edf3"
DIM = "#8b949e"
ACC = "#58a6ff"
GOOD = "#3fb950"
WARN = "#d29922"
BAD = "#f85149"


def _label(rec):
    """Evidence label for one submission (no overclaims)."""
    fields = rec.get("fields") or {}
    is_otp = any(k.lower().startswith("otp") for k in fields)
    risk = int(rec.get("risk") or 0)
    if rec.get("is_cred"):
        return ("CONFIRMED", GOOD) if risk < 30 else ("SUSPECTED", WARN)
    if is_otp:
        return ("OTP ONLY", ACC)
    return ("FIELDS", DIM)


def _esc(v):
    from xml.sax.saxutils import escape
    return escape(str(v if v is not None else ""))


def build_report_pdf(db_path, out_path, campaign=None, title=None, qr_url=None):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, PageBreak)

    def C(hexstr):
        return colors.HexColor(hexstr)

    db = cap.CaptureDB(db_path)
    rows = db.all(limit=1000000, campaign=campaign)
    stats = db.stats(campaign=campaign)
    campaigns = db.campaigns()
    try:
        blocked = db.blocked_stats()
    except Exception:
        blocked = {"total_blocked": 0, "by_reason": []}

    name = title or (f"Campaign report — {campaign}" if campaign else "Campaign report")
    geo = Counter(f"{(r['city'] + ', ') if r['city'] else ''}{r['country'] or 'unknown'}" for r in rows)
    devices = Counter(r["device"] or "unknown" for r in rows)
    isps = Counter(r["isp"] or "unknown" for r in rows)
    hourly = Counter(time.strftime("%Y-%m-%d %H:00", time.localtime(r["ts"])) for r in rows)

    H1 = ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=17, textColor=C(FG), spaceAfter=3)
    SUB = ParagraphStyle("SUB", fontName="Helvetica", fontSize=8.5, textColor=C(DIM), spaceAfter=10)
    H2 = ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=10.5, textColor=C(ACC),
                        spaceBefore=12, spaceAfter=5)
    CELL = ParagraphStyle("CELL", fontName="Helvetica", fontSize=7.4, textColor=C(FG), leading=9)
    CELLDIM = ParagraphStyle("CELLDIM", fontName="Helvetica", fontSize=7.4, textColor=C(DIM), leading=9)
    FOOT = ParagraphStyle("FOOT", fontName="Helvetica", fontSize=7, textColor=C(DIM))

    def table(data, widths, header=True, small=False):
        t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("BACKGROUND", (0, 0), (-1, -1), C(PANEL)),
            ("GRID", (0, 0), (-1, -1), 0.4, C(LINE)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), C(PANEL2)),
                      ("TEXTCOLOR", (0, 0), (-1, 0), C(DIM)),
                      ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                      ("FONTSIZE", (0, 0), (-1, 0), 7.5)]
        t.setStyle(TableStyle(style))
        return t

    def bars(counter, total, limit=10, width=150):
        out = []
        for key, n in counter.most_common(limit):
            pct = round(n / max(1, total) * 100)
            bar = "█" * max(1, int(pct / 4))
            out.append([Paragraph(_esc(key or "—"), CELL),
                        Paragraph(f"{n} ({pct}%)", CELLDIM),
                        Paragraph(f'<font color="{ACC}">{bar}</font>', CELL)])
        return out or [[Paragraph("no data", CELLDIM), "", ""]]

    story = []
    story.append(Paragraph(_esc(name), H1))
    story.append(Paragraph(
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} · database "
        f"<b>{_esc(os.path.basename(db_path))}</b>"
        + (f" · campaign <b>{_esc(campaign)}</b>" if campaign else "")
        + " · BytePhisher v1.0", SUB))

    # ---- KPI cards as a table ----
    kpi = [[Paragraph("<b>SUBMISSIONS</b>", CELLDIM), Paragraph("<b>CREDENTIAL PAIRS</b>", CELLDIM),
            Paragraph("<b>CREDIBLE (LOW RISK)</b>", CELLDIM), Paragraph("<b>VISITORS</b>", CELLDIM)],
           [Paragraph(f'<font size="16" color="{ACC}">{stats["total_captures"]}</font>', CELL),
            Paragraph(f'<font size="16" color="{GOOD}">{stats["credentials"]}</font>', CELL),
            Paragraph(f'<font size="16" color="{GOOD}">{stats.get("credible_credentials", 0)}</font>', CELL),
            Paragraph(f'<font size="16" color="{FG}">{stats["visitors"]}</font>', CELL)]]
    story.append(table(kpi, [40 * mm] * 4, header=False))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Gated out before serving: <b>{blocked['total_blocked']}</b> visitor(s) "
        f"(scanner/datacenter/time-window/rate rules) — refusals are excluded from the "
        f"visitor and submission counts above.", FOOT))

    story.append(Paragraph("Campaigns", H2))
    cdata = [[Paragraph("Campaign", CELLDIM), Paragraph("Submissions", CELLDIM),
              Paragraph("Credentials", CELLDIM)]]
    for c in campaigns:
        cdata.append([Paragraph(_esc(c["campaign"]), CELL),
                      Paragraph(str(c["captures"]), CELL),
                      Paragraph(str(c["credentials"]), CELL)])
    story.append(table(cdata, [90 * mm, 40 * mm, 40 * mm]))

    if blocked["total_blocked"]:
        story.append(Paragraph("Gated out", H2))
        bdata = [[Paragraph("Reason", CELLDIM), Paragraph("Count", CELLDIM)]]
        for b in blocked["by_reason"]:
            bdata.append([Paragraph(_esc(b["reason"]), CELL), Paragraph(str(b["count"]), CELL)])
        story.append(table(bdata, [130 * mm, 40 * mm]))

    try:
        reuse = db.reuse_stats()
    except Exception:
        reuse = {"repeated_identities": [], "repeated_passwords": [],
                 "total_reused_identities": 0, "total_reused_passwords": 0}
    if reuse["total_reused_identities"] or reuse["total_reused_passwords"]:
        story.append(Paragraph(
            f"Reused credentials ({reuse['total_reused_identities']} identities / "
            f"{reuse['total_reused_passwords']} passwords)", H2))
        story.append(Paragraph(
            "A repeated identity means the same account was submitted more than once; a "
            "repeated password across different identities is a password-reuse finding.", FOOT))
        story.append(Spacer(1, 3))
        rdata = [[Paragraph("Identity", CELLDIM), Paragraph("Times", CELLDIM),
                  Paragraph("Campaigns", CELLDIM)]]
        for r in reuse["repeated_identities"][:30]:
            rdata.append([Paragraph(_esc(r["identity"]), CELL),
                          Paragraph(str(r["count"]), CELL),
                          Paragraph(_esc(", ".join(r["campaigns"]) or "—"), CELL)])
        story.append(table(rdata, [80 * mm, 20 * mm, 70 * mm]))
        story.append(Spacer(1, 4))
        pdata = [[Paragraph("Password", CELLDIM), Paragraph("Times", CELLDIM),
                  Paragraph("Distinct identities", CELLDIM), Paragraph("Campaigns", CELLDIM)]]
        for r in reuse["repeated_passwords"][:30]:
            pdata.append([Paragraph(_esc(r["password"]), CELL),
                          Paragraph(str(r["count"]), CELL),
                          Paragraph(str(len(r["identities"])), CELL),
                          Paragraph(_esc(", ".join(r["campaigns"]) or "—"), CELL)])
        story.append(table(pdata, [60 * mm, 20 * mm, 30 * mm, 60 * mm]))

    story.append(PageBreak())

    story.append(Paragraph("Distribution", H2))
    story.append(table([[Paragraph("<b>Geography</b>", CELLDIM), Paragraph("<b>Devices</b>", CELLDIM),
                         Paragraph("<b>Networks / ISP</b>", CELLDIM)]],
                       [60 * mm] * 3, header=False))
    g_rows, d_rows, i_rows = bars(geo, len(rows)), bars(devices, len(rows)), bars(isps, len(rows))
    n = max(len(g_rows), len(d_rows), len(i_rows))
    dist = []
    for idx in range(n):
        dist.append([(g_rows[idx][0] if idx < len(g_rows) else Paragraph("", CELL)),
                     (d_rows[idx][0] if idx < len(d_rows) else Paragraph("", CELL)),
                     (i_rows[idx][0] if idx < len(i_rows) else Paragraph("", CELL))])
    story.append(table(dist, [60 * mm] * 3, header=False))

    story.append(Paragraph("Timeline (hourly submissions)", H2))
    tdata = [[Paragraph("Hour", CELLDIM), Paragraph("Submissions", CELLDIM), Paragraph("", CELLDIM)]]
    for hour, count in sorted(hourly.items()):
        tdata.append([Paragraph(_esc(hour), CELL), Paragraph(str(count), CELL),
                      Paragraph(f'<font color="{ACC}">{"█" * max(1, count)}</font>', CELL)])
    story.append(table(tdata, [45 * mm, 30 * mm, 95 * mm]))

    if qr_url:
        png = links.qr_png(qr_url, path=os.path.join(os.path.dirname(out_path) or ".",
                                                     "campaign_qr.png"))
        if png:
            from reportlab.platypus import Image
            story.append(Paragraph("Campaign link", H2))
            story.append(Paragraph(f"<font color='{ACC}'>{_esc(qr_url)}</font>", CELL))
            story.append(Spacer(1, 4))
            story.append(Image(png, width=38 * mm, height=38 * mm))

    story.append(PageBreak())
    story.append(Paragraph(f"Submissions ({len(rows)})", H2))
    story.append(Paragraph(
        "Labels: <b>CONFIRMED</b> = credential pair from a low-risk source · "
        "<b>SUSPECTED</b> = credential pair that looks automated/datacenter · "
        "<b>OTP ONLY</b> = verification code without a credential pair · "
        "<b>FIELDS</b> = other field submissions.", FOOT))
    story.append(Spacer(1, 4))

    head = [Paragraph("<b>Time</b>", CELLDIM), Paragraph("<b>Campaign</b>", CELLDIM),
            Paragraph("<b>IP</b>", CELLDIM), Paragraph("<b>Geo</b>", CELLDIM),
            Paragraph("<b>Device</b>", CELLDIM), Paragraph("<b>Label</b>", CELLDIM),
            Paragraph("<b>Fields</b>", CELLDIM)]
    sdata = [head]
    for r in rows[:400]:
        label, colour = _label(r)
        fields = "; ".join(f"{k}={v}" for k, v in r["fields"].items())
        sdata.append([
            Paragraph(time.strftime("%m-%d %H:%M:%S", time.localtime(r["ts"])), CELL),
            Paragraph(_esc(r["campaign"] or "—"), CELL),
            Paragraph(_esc(r["ip"]), CELL),
            Paragraph(_esc(((r["city"] + ", ") if r["city"] else "") + (r["country"] or "")), CELL),
            Paragraph(_esc(r["device"]), CELL),
            Paragraph(f'<font color="{colour}"><b>{label}</b></font>', CELL),
            Paragraph(_esc(fields[:260]), CELL),
        ])
    if len(sdata) == 1:
        sdata.append([Paragraph("no submissions captured", CELLDIM)] + [Paragraph("", CELL)] * 6)
    story.append(table(sdata, [22 * mm, 24 * mm, 26 * mm, 26 * mm, 17 * mm, 20 * mm, 35 * mm]))
    if len(rows) > 400:
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"Showing the first 400 of {len(rows)} submissions.", FOOT))

    # ---- dark page background + footer ----
    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C(BG))
        canvas.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
        canvas.setFillColor(C(DIM))
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(15 * mm, 9 * mm,
                          "BytePhisher — authorized security-awareness / red-team use only")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(out_path, pagesize=A4,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=14 * mm, bottomMargin=16 * mm,
                            title=name, author="BytePhisher",
                            subject="Phishing-simulation campaign report")
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    db.close()

    pages = 0
    try:
        from pypdf import PdfReader
        pages = len(PdfReader(out_path).pages)
    except Exception:
        pass
    return {"path": out_path, "rows": len(rows), "stats": stats, "pages": pages,
            "blocked": blocked["total_blocked"]}


def main():
    ap = argparse.ArgumentParser(description="BytePhisher PDF campaign report")
    ap.add_argument("--db", default=os.path.join(HERE, "data", "bytephisher.db"))
    ap.add_argument("--out", default=os.path.join(HERE, "data", "report.pdf"))
    ap.add_argument("--campaign")
    ap.add_argument("--title")
    ap.add_argument("--qr", metavar="URL")
    args = ap.parse_args()
    res = build_report_pdf(args.db, args.out, campaign=args.campaign,
                           title=args.title, qr_url=args.qr)
    print(f"[bytephisher] pdf written -> {res['path']} ({res['pages']} pages, "
          f"{res['rows']} submissions, {res['stats']['credentials']} credential pairs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
