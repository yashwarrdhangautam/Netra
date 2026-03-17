"""
netra/reports/pdf_report.py
PDF penetration test report generator using ReportLab.
Produces an A4 PDF with professional styling, cover page,
severity-coloured findings table, and embedded screenshots.
"""

import re
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

# ReportLab colour palette
COLOR_NAVY     = (0x1F/255, 0x38/255, 0x64/255)
COLOR_BLUE     = (0x2E/255, 0x75/255, 0xB6/255)
COLOR_CRITICAL = (1.0, 0.0, 0.0)
COLOR_HIGH     = (1.0, 0.40, 0.0)
COLOR_MEDIUM   = (1.0, 0.75, 0.0)
COLOR_LOW      = (0.57, 0.82, 0.31)
COLOR_INFO     = (0.53, 0.53, 0.53)
COLOR_WHITE    = (1.0, 1.0, 1.0)
COLOR_LGREY    = (0.95, 0.95, 0.95)

SEV_RGB = {
    "critical": COLOR_CRITICAL,
    "high":     COLOR_HIGH,
    "medium":   COLOR_MEDIUM,
    "low":      COLOR_LOW,
    "info":     COLOR_INFO,
}


def generate_pdf_report(ctx: dict, reports_dir: Path) -> Path:
    """
    Generate a PDF penetration test report.

    Args:
        ctx:         Report context dict.
        reports_dir: Directory to save the output file.

    Returns:
        Path to the generated .pdf file.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        from reportlab.platypus.flowables import KeepTogether
    except ImportError:
        raise ImportError("reportlab required. Run: pip3 install reportlab --break-system-packages")

    filename = _report_filename(ctx, "pdf")
    out_path = reports_dir / filename

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        rightMargin=2.5*cm, leftMargin=3.0*cm,
        topMargin=2.5*cm,   bottomMargin=2.5*cm,
        title=f"NETRA Penetration Test Report — {ctx.get('engagement', ctx.get('scan_id', ''))}",
        author="NETRA Security Platform",
    )

    styles  = _build_styles()
    story   = []

    # Cover page
    story += _cover_page(ctx, styles)
    story.append(PageBreak())

    # Executive summary
    story += _section_header("Executive Summary", styles)
    story += _executive_summary_section(ctx, styles)
    story.append(Spacer(1, 0.4*cm))

    # Risk scorecard
    story += _section_header("Risk Scorecard", styles)
    story += _risk_scorecard(ctx, styles)
    story.append(Spacer(1, 0.4*cm))

    # Findings overview
    story += _section_header("Findings Overview", styles)
    story += _findings_overview_table(ctx, styles)
    story.append(Spacer(1, 0.4*cm))

    # Detailed findings
    story += _section_header("Detailed Findings", styles)
    for f in ctx.get("findings", []):
        story += _finding_detail(f, styles)

    # Attack chains
    chains = ctx.get("chains", [])
    if chains:
        story.append(PageBreak())
        story += _section_header("Attack Chain Analysis", styles)
        story += _attack_chains_section(chains, ctx.get("findings", []), styles)

    # Remediation roadmap
    story.append(PageBreak())
    story += _section_header("Remediation Roadmap", styles)
    story += _remediation_roadmap_section(ctx, styles)

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return out_path


def _build_styles() -> dict:
    """Build custom paragraph styles."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    return {
        "title": ParagraphStyle(
            "NetraTitle",
            fontName="Helvetica-Bold",
            fontSize=28,
            textColor=colors.HexColor("#1F3864"),
            spaceAfter=12,
            alignment=1,    # centre
        ),
        "subtitle": ParagraphStyle(
            "NetraSubtitle",
            fontName="Helvetica",
            fontSize=14,
            textColor=colors.HexColor("#2E75B6"),
            spaceAfter=8,
            alignment=1,
        ),
        "h1": ParagraphStyle(
            "NetraH1",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=colors.HexColor("#1F3864"),
            spaceBefore=12,
            spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "NetraH2",
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=colors.HexColor("#2E75B6"),
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "NetraBody",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            spaceAfter=6,
        ),
        "mono": ParagraphStyle(
            "NetraMono",
            fontName="Courier",
            fontSize=8,
            leading=11,
            backColor=colors.HexColor("#F5F5F5"),
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "NetraSmall",
            fontName="Helvetica",
            fontSize=8,
            textColor=colors.HexColor("#666666"),
        ),
    }


def _section_header(title: str, styles: dict) -> list:
    """Return a styled section header flowable list."""
    from reportlab.lib import colors
    from reportlab.platypus import HRFlowable, Spacer, Paragraph
    return [
        Paragraph(title, styles["h1"]),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2E75B6")),
        Spacer(1, 0.2*__import__("reportlab").lib.units.cm),
    ]


def _cover_page(ctx: dict, styles: dict) -> list:
    """Build the cover page flowables."""
    from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    story = [
        Spacer(1, 4*cm),
        Paragraph("PENETRATION TEST REPORT", styles["title"]),
        Paragraph("NETRA नेत्र — The Third Eye of Security", styles["subtitle"]),
        Spacer(1, 2*cm),
    ]

    data = [
        ["Client",       ctx.get("client", "Confidential")],
        ["Engagement",   ctx.get("engagement", "Security Assessment")],
        ["Date",         ctx.get("date", datetime.now().strftime("%Y-%m-%d"))],
        ["Operator",     ctx.get("operator", "Security Team")],
        ["Risk Grade",   f"{ctx.get('risk_grade', '?')} ({ctx.get('risk_score', 0)}/100)"],
        ["Scan ID",      ctx.get("scan_id", "N/A")],
    ]

    t = Table(data, colWidths=[5*cm, 10*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 11),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#F0F4F8")),
        ("PADDING",     (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    return story


def _executive_summary_section(ctx: dict, styles: dict) -> list:
    """Build executive summary flowables."""
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.units import cm

    story = []
    try:
        from netra.ai_brain.narrative import generate_executive_summary
        summary = generate_executive_summary(ctx)
    except Exception:
        summary = ""

    if not summary:
        stats = ctx.get("stats", {})
        total = sum(stats.values())
        grade = ctx.get("risk_grade", "?")
        score = ctx.get("risk_score", 0)
        summary = (
            f"This security assessment identified {total} vulnerabilities across the assessed scope, "
            f"resulting in an overall risk grade of {grade} ({score}/100). "
            f"The findings require prioritised remediation."
        )

    for para in summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["body"]))
            story.append(Spacer(1, 0.2*cm))

    return story


def _risk_scorecard(ctx: dict, styles: dict) -> list:
    """Build risk scorecard table flowables."""
    from reportlab.platypus import Table, TableStyle, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    stats = ctx.get("stats", {})
    data  = [["Severity", "Count", "Risk Level", "SLA"]]
    rows_data = [
        ("Critical", stats.get("critical", 0), "Immediate action required",  "< 24 hours"),
        ("High",     stats.get("high", 0),     "Urgent remediation",         "< 72 hours"),
        ("Medium",   stats.get("medium", 0),   "Scheduled remediation",      "1-2 sprints"),
        ("Low",      stats.get("low", 0),      "Backlog item",               "Next release"),
        ("Info",     stats.get("info", 0),     "Informational",              "Optional"),
    ]
    data += list(rows_data)

    sev_colors_rl = {
        "Critical": colors.HexColor("#FF0000"),
        "High":     colors.HexColor("#FF6600"),
        "Medium":   colors.HexColor("#FFC000"),
        "Low":      colors.HexColor("#92D050"),
        "Info":     colors.HexColor("#888888"),
    }

    t = Table(data, colWidths=[3*cm, 2*cm, 6*cm, 3*cm])
    style_cmds = [
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]
    for i, (sev, _, __, ___) in enumerate(rows_data, 1):
        col = sev_colors_rl.get(sev)
        if col:
            style_cmds.append(("BACKGROUND", (0, i), (0, i), col))
            if sev in ("Critical", "High"):
                style_cmds.append(("TEXTCOLOR", (0, i), (0, i), colors.white))

    t.setStyle(TableStyle(style_cmds))
    return [t, Spacer(1, 0.4*cm)]


def _findings_overview_table(ctx: dict, styles: dict) -> list:
    """Build findings overview table flowables."""
    from reportlab.platypus import Table, TableStyle, Spacer, Paragraph
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    findings = ctx.get("findings", [])
    if not findings:
        return [Paragraph("No findings identified.", styles["body"])]

    data  = [["#", "Title", "Sev", "CVSS", "Host"]]
    for i, f in enumerate(findings[:100], 1):
        data.append([
            str(i),
            (f.get("title") or "")[:55],
            (f.get("severity") or "").capitalize(),
            str(f.get("cvss_score") or "N/A"),
            (f.get("host") or "")[:35],
        ])

    t = Table(data, colWidths=[0.8*cm, 8*cm, 2*cm, 1.5*cm, 5*cm])
    sev_map = {
        "Critical": colors.HexColor("#FF0000"),
        "High":     colors.HexColor("#FF6600"),
        "Medium":   colors.HexColor("#FFC000"),
        "Low":      colors.HexColor("#92D050"),
        "Info":     colors.HexColor("#888888"),
    }
    cmds = [
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#FFFFFF"), colors.HexColor("#F5F5F5")]),
    ]
    for i, f in enumerate(findings[:100], 1):
        sev   = (f.get("severity") or "").capitalize()
        col   = sev_map.get(sev)
        if col:
            cmds.append(("BACKGROUND", (2, i), (2, i), col))
            if sev in ("Critical", "High"):
                cmds.append(("TEXTCOLOR", (2, i), (2, i), colors.white))

    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 0.4*cm)]


def _finding_detail(f: dict, styles: dict) -> list:
    """Build a detail block for one finding."""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    sev = (f.get("severity") or "info").lower()
    story = [
        Paragraph(f.get("title", "Unnamed Finding"), styles["h2"]),
        HRFlowable(width="100%", thickness=0.5,
                   color=colors.HexColor(
                       {"critical": "#FF0000", "high": "#FF6600",
                        "medium": "#FFC000", "low": "#92D050"}.get(sev, "#AAAAAA")
                   )),
        Spacer(1, 0.2*cm),
    ]

    meta = [
        ["Severity", (f.get("severity") or "").capitalize(),
         "CVSS", str(f.get("cvss_score") or "N/A")],
        ["CVE", f.get("cve_id") or "N/A",
         "CWE", f.get("cwe_id") or "N/A"],
        ["Host", f.get("host") or "N/A",
         "MITRE", f.get("mitre_technique") or "N/A"],
        ["OWASP", f.get("owasp_web") or "N/A",
         "Status", (f.get("status") or "open").capitalize()],
    ]
    t = Table(meta, colWidths=[2.5*cm, 6*cm, 2.5*cm, 6*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("GRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",   (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F8F8")),
    ]))
    story += [t, Spacer(1, 0.2*cm)]

    if f.get("description"):
        story.append(Paragraph("<b>Description</b>", styles["body"]))
        story.append(Paragraph(f["description"][:600], styles["body"]))

    if f.get("impact"):
        story.append(Paragraph("<b>Impact</b>", styles["body"]))
        story.append(Paragraph(f["impact"][:300], styles["body"]))

    if f.get("remediation"):
        story.append(Paragraph("<b>Remediation</b>", styles["body"]))
        story.append(Paragraph(f["remediation"][:300], styles["body"]))

    if f.get("poc_command"):
        story.append(Paragraph("<b>PoC Command</b>", styles["body"]))
        story.append(Paragraph(f["poc_command"][:200], styles["mono"]))

    story.append(Spacer(1, 0.4*cm))
    return story


def _attack_chains_section(chains: list, all_findings: list, styles: dict) -> list:
    """Build attack chains section flowables."""
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.units import cm
    import json as _json

    id_map = {f["id"]: f for f in all_findings}
    story  = []

    for i, chain in enumerate(chains[:10], 1):
        story.append(Paragraph(
            f"Chain {i} — Combined CVSS: {chain.get('combined_cvss', 'N/A')}",
            styles["h2"]
        ))
        story.append(Paragraph(
            f"MITRE Sequence: {chain.get('mitre_sequence', 'N/A')}",
            styles["body"]
        ))

        if chain.get("narrative"):
            story.append(Paragraph(chain["narrative"][:400], styles["body"]))

        try:
            node_ids = _json.loads(chain.get("nodes", "[]")) if isinstance(chain.get("nodes"), str) else chain.get("nodes", [])
        except Exception:
            node_ids = []

        for j, fid in enumerate(node_ids, 1):
            f = id_map.get(fid)
            if f:
                story.append(Paragraph(
                    f"  Step {j}: {f.get('title')} [{f.get('severity', '').upper()}] "
                    f"→ {f.get('host')}",
                    styles["small"]
                ))

        story.append(Spacer(1, 0.3*cm))

    return story


def _remediation_roadmap_section(ctx: dict, styles: dict) -> list:
    """Build remediation roadmap flowables."""
    from reportlab.platypus import Table, TableStyle, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    try:
        from netra.ai_brain.analyzer import build_remediation_roadmap
        roadmap = build_remediation_roadmap(ctx.get("findings", []))
    except Exception:
        roadmap = []

    if not roadmap:
        from reportlab.platypus import Paragraph
        return [Paragraph("No findings to remediate.", styles["body"])]

    data = [["Priority", "Severity", "Count", "Effort", "Top Findings"]]
    for item in roadmap:
        data.append([
            str(item["priority"]),
            item["severity"].capitalize(),
            str(item["count"]),
            item["effort"],
            ", ".join(item["top_titles"][:2])[:50],
        ])

    t = Table(data, colWidths=[1.5*cm, 2.5*cm, 1.5*cm, 2.5*cm, 9*cm])
    sev_map = {
        "Critical": colors.HexColor("#FF0000"),
        "High":     colors.HexColor("#FF6600"),
        "Medium":   colors.HexColor("#FFC000"),
        "Low":      colors.HexColor("#92D050"),
    }
    cmds = [
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0, 0), (-1, -1), 5),
    ]
    for i, item in enumerate(roadmap, 1):
        col = sev_map.get(item["severity"].capitalize())
        if col:
            cmds.append(("BACKGROUND", (1, i), (1, i), col))
            if item["severity"] in ("critical", "high"):
                cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.white))

    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 0.4*cm)]


def _page_footer(canvas, doc) -> None:
    """Draw page number and branding footer on each page."""
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(3*cm, 1.2*cm, "NETRA नेत्र — The Third Eye of Security — CONFIDENTIAL")
    canvas.drawRightString(
        doc.pagesize[0] - 2.5*cm, 1.2*cm,
        f"Page {doc.page}"
    )
    canvas.restoreState()


def _report_filename(ctx: dict, ext: str) -> str:
    """Generate a standardised report filename."""
    scan_id = ctx.get("scan_id", "unknown")
    date    = ctx.get("date", datetime.now().strftime("%Y%m%d")).replace("-", "")
    target  = re.sub(r"[^a-zA-Z0-9]", "_", ctx.get("engagement", scan_id))[:20]
    return f"NETRA_vapt_{target}_{date}.{ext}"
