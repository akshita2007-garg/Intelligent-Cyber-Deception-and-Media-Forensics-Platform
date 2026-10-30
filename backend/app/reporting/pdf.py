"""PDF export of the unified investigation report (ReportLab)."""
from __future__ import annotations

from pathlib import Path


def report_pdf(report: dict, out: Path, audit_rows: list[dict] | None = None) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5)
    mono = ParagraphStyle("m", parent=small, fontName="Courier")
    h1, h2 = ss["Title"], ss["Heading2"]

    def esc(t):
        return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Forensic report - {report['case']['name']}")
    st = [Paragraph("Unified Forensic Investigation Report", h1),
          Paragraph(f"<b>Case:</b> {esc(report['case']['name'])} &nbsp; <b>Generated:</b> {report['generated_at']} "
                    f"&nbsp; <b>Generator:</b> {esc(report['generator'])}", body),
          Paragraph(f"<b>Statement verification:</b> {report['verification'].get('verified', 0)} of "
                    f"{report['verification']['sentences']} sentences verified against cited evidence "
                    f"(traceability {report['verification']['traceability'] * 100:.1f}%).", body), Spacer(1, 6)]
    if report.get("note"):
        st.append(Paragraph(f"<i>{esc(report['note'])}</i>", small))
    st.append(Paragraph("Evidence inventory", h2))
    rows = [["ID", "File", "Module", "SHA-256", "Integrity"]]
    for e in report["evidence"]:
        rows.append([f"E{e['id']}", Paragraph(esc(e["filename"]), small), e["module"],
                     Paragraph(e["sha256"], mono), "OK" if e["integrity_ok"] else "MISMATCH"])
    t = Table(rows, colWidths=[12 * mm, 42 * mm, 20 * mm, 82 * mm, 18 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ccd6")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    st += [t, Spacer(1, 8)]
    for s in report["sections"]:
        st.append(Paragraph(esc(s["title"]), h2))
        for r in s["sentences"]:
            mark = "" if r["status"] == "verified" else f" <font color='#b00020'>[{r['status']}: {esc(r['reason'])}]</font>"
            st.append(Paragraph("• " + esc(r["text"]) + mark, body))
    if report.get("timeline"):
        st += [PageBreak(), Paragraph("Correlated timeline (suspicious and pivot events)", h2)]
        rows = [["Time (UTC)", "Evidence", "Severity", "Event"]]
        for r in report["timeline"]:
            rows.append([r["ts"][:19].replace("T", " "), f"E{r['evidence_id']}", r["severity"], Paragraph(esc(r["title"][:160]), small)])
        t = Table(rows, colWidths=[32 * mm, 16 * mm, 16 * mm, 110 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ccd6")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        st.append(t)
    if audit_rows:
        st += [Spacer(1, 10), Paragraph("Chain of custody (hash-chained audit log)", h2)]
        rows = [["Time (UTC)", "Actor", "Action", "Entry hash"]]
        for a in audit_rows[-40:]:
            rows.append([a["ts"][:19].replace("T", " "), a["actor"], Paragraph(esc(a["action"] + ": " + a["detail"][:90]), small),
                         Paragraph(a["entry_hash"][:32] + "…", mono)])
        t = Table(rows, colWidths=[32 * mm, 22 * mm, 80 * mm, 40 * mm], repeatRows=1)
        t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 7.5), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ccd6")),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f5"))]))
        st.append(t)
    doc.build(st)
    return out
