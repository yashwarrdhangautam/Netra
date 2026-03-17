"""
netra/reports/compliance_report.py
HIPAA §164.312 + PCI DSS v4.0 gap analysis PDF report.
Produces a formal compliance assessment document showing which controls
are passing, failing, or at risk based on discovered vulnerabilities.
"""

import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict

from netra.ai_brain.analyzer import compute_compliance_gaps


# ── Control descriptions ──────────────────────────────────────────────

HIPAA_CONTROLS: Dict[str, str] = {
    "§164.306(a)(1)": "Ensure confidentiality, integrity, and availability of all ePHI",
    "§164.308(a)(1)": "Security Management Process — risk analysis and management",
    "§164.312(a)(1)": "Access Control — unique user ID, emergency access procedures",
    "§164.312(a)(2)(iii)": "Automatic Logoff — end sessions after period of inactivity",
    "§164.312(a)(2)(iv)": "Encryption and Decryption of ePHI",
    "§164.312(b)":    "Audit Controls — hardware/software activity logging",
    "§164.312(d)":    "Person or Entity Authentication — verify user identity",
    "§164.312(e)(1)": "Transmission Security — guard against unauthorised access to ePHI",
}

PCI_CONTROLS: Dict[str, str] = {
    "Req 1":   "Install and Maintain Network Security Controls",
    "Req 2":   "Apply Secure Configurations to All System Components",
    "Req 3":   "Protect Stored Account Data",
    "Req 4":   "Protect Cardholder Data with Strong Cryptography During Transmission",
    "Req 5":   "Protect All Systems Against Malware",
    "Req 6":   "Develop and Maintain Secure Systems and Software",
    "Req 6.2": "Protect Bespoke and Custom Software",
    "Req 6.3": "Identify and Manage Security Vulnerabilities",
    "Req 7":   "Restrict Access to System Components and Cardholder Data",
    "Req 8":   "Identify Users and Authenticate Access to System Components",
    "Req 8.2": "User Identification and Related Accounts",
    "Req 10":  "Log and Monitor All Access to System Components and Cardholder Data",
}

STATUS_COLORS = {
    "fail": (1.0, 0.27, 0.27),
    "pass": (0.53, 0.80, 0.31),
    "warn": (1.0, 0.75, 0.0),
    "na":   (0.67, 0.67, 0.67),
}


def generate_compliance_report(ctx: dict, reports_dir: Path) -> Path:
    """
    Generate a HIPAA + PCI DSS v4.0 gap analysis PDF.

    Args:
        ctx:         Report context dict.
        reports_dir: Directory to save the output file.

    Returns:
        Path to the generated compliance .pdf file.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        from reportlab.lib.styles import ParagraphStyle
    except ImportError:
        raise ImportError("reportlab required. Run: pip3 install reportlab --break-system-packages")

    findings = ctx.get("findings", [])
    filename = _report_filename(ctx)
    out_path = reports_dir / filename

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        rightMargin=2.5*cm, leftMargin=3.0*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title="NETRA Compliance Gap Report",
    )

    styles = _build_styles()
    story  = []

    # Cover
    story += _cover(ctx, styles)
    story.append(PageBreak())

    # Executive overview
    story += _section_hdr("Executive Compliance Overview", styles)
    story += _exec_overview(findings, styles)
    story.append(Spacer(1, 0.4*cm))

    # HIPAA gap analysis
    story += _section_hdr("HIPAA §164.312 Gap Analysis", styles)
    story += _framework_section(findings, "HIPAA", HIPAA_CONTROLS, styles)
    story.append(PageBreak())

    # PCI DSS gap analysis
    story += _section_hdr("PCI DSS v4.0 Gap Analysis", styles)
    story += _framework_section(findings, "PCI", PCI_CONTROLS, styles)
    story.append(Spacer(1, 0.4*cm))

    # Findings mapped to controls
    story += _section_hdr("Findings Mapped to Controls", styles)
    story += _findings_mapping_table(findings, styles)

    # Remediation recommendations
    story += _section_hdr("Remediation Recommendations", styles)
    story += _recommendations(findings, styles)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path


def _build_styles() -> dict:
    """Build paragraph styles for the compliance report."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors

    return {
        "title": ParagraphStyle(
            "CompTitle",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=colors.HexColor("#1F3864"),
            alignment=1,
            spaceAfter=10,
        ),
        "subtitle": ParagraphStyle(
            "CompSub",
            fontName="Helvetica",
            fontSize=13,
            textColor=colors.HexColor("#2E75B6"),
            alignment=1,
            spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "CompH1",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=colors.HexColor("#1F3864"),
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "CompBody",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "CompSmall",
            fontName="Helvetica",
            fontSize=8,
            textColor=colors.HexColor("#666666"),
        ),
    }


def _section_hdr(title: str, styles: dict) -> list:
    """Return a styled section header."""
    from reportlab.platypus import Paragraph, HRFlowable, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    return [
        Paragraph(title, styles["h1"]),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2E75B6")),
        Spacer(1, 0.2*cm),
    ]


def _cover(ctx: dict, styles: dict) -> list:
    """Build the cover page."""
    from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    story = [
        Spacer(1, 3*cm),
        Paragraph("COMPLIANCE GAP ASSESSMENT REPORT", styles["title"]),
        Paragraph("HIPAA §164.312  |  PCI DSS v4.0", styles["subtitle"]),
        Paragraph("NETRA नेत्र — The Third Eye of Security", styles["subtitle"]),
        Spacer(1, 2*cm),
    ]

    data = [
        ["Client",       ctx.get("client", "Confidential")],
        ["Engagement",   ctx.get("engagement", "Security Assessment")],
        ["Date",         ctx.get("date", datetime.now().strftime("%Y-%m-%d"))],
        ["Operator",     ctx.get("operator", "Security Team")],
        ["Risk Grade",   f"{ctx.get('risk_grade', '?')} ({ctx.get('risk_score', 0)}/100)"],
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


def _exec_overview(findings: list, styles: dict) -> list:
    """Build the executive overview section."""
    from reportlab.platypus import Paragraph, Table, TableStyle, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    hipaa_gaps = compute_compliance_gaps(findings, "HIPAA")
    pci_gaps   = compute_compliance_gaps(findings, "PCI")

    def count_status(gaps: list, status: str) -> int:
        """Count gaps with a given status string."""
        return sum(1 for g in gaps if g["status"] == status)

    data = [
        ["Framework", "Total Controls", "Passing", "Failing", "Warning"],
        ["HIPAA §164.312",
         len(hipaa_gaps),
         count_status(hipaa_gaps, "pass"),
         count_status(hipaa_gaps, "fail"),
         count_status(hipaa_gaps, "warn")],
        ["PCI DSS v4.0",
         len(pci_gaps),
         count_status(pci_gaps, "pass"),
         count_status(pci_gaps, "fail"),
         count_status(pci_gaps, "warn")],
    ]

    t = Table(data, colWidths=[5*cm, 3*cm, 3*cm, 3*cm, 3*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("PADDING",     (0, 0), (-1, -1), 8),
        ("BACKGROUND",  (3, 1), (3, -1), colors.HexColor("#FFEEEE")),
    ]))

    total_fail = count_status(hipaa_gaps, "fail") + count_status(pci_gaps, "fail")
    intro = (
        f"This compliance gap assessment evaluated the target systems against "
        f"HIPAA §164.312 technical safeguard requirements and PCI DSS v4.0 controls. "
        f"A total of {total_fail} control failures were identified, representing areas "
        f"where discovered vulnerabilities directly map to regulatory non-compliance."
    )

    return [Paragraph(intro, styles["body"]), Spacer(1, 0.3*cm), t, Spacer(1, 0.4*cm)]


def _framework_section(findings: list, framework: str,
                        control_desc: Dict[str, str], styles: dict) -> list:
    """Build a full framework gap analysis table."""
    from reportlab.platypus import Paragraph, Table, TableStyle, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    gaps = compute_compliance_gaps(findings, framework)

    data = [["Control", "Description", "Status", "Related Findings"]]
    for gap in gaps:
        ctrl    = gap["control"]
        desc    = control_desc.get(ctrl, "")
        status  = gap["status"].upper()
        f_ids   = ", ".join(str(fid) for fid in gap.get("finding_ids", [])[:5])
        data.append([ctrl, desc, status, f_ids or "—"])

    status_colors_rl = {
        "FAIL": colors.HexColor("#FF4444"),
        "PASS": colors.HexColor("#88CC44"),
        "WARN": colors.HexColor("#FFB800"),
        "NA":   colors.HexColor("#AAAAAA"),
    }

    cmds = [
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",     (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#FFFFFF"), colors.HexColor("#F8F8F8")]),
    ]
    for i, gap in enumerate(gaps, 1):
        st    = gap["status"].upper()
        col   = status_colors_rl.get(st, colors.grey)
        cmds += [
            ("BACKGROUND",  (2, i), (2, i), col),
            ("TEXTCOLOR",   (2, i), (2, i), colors.white
             if st in ("FAIL", "PASS") else colors.black),
            ("FONTNAME",    (2, i), (2, i), "Helvetica-Bold"),
        ]

    t = Table(data, colWidths=[3*cm, 7*cm, 2*cm, 5*cm])
    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 0.4*cm)]


def _findings_mapping_table(findings: list, styles: dict) -> list:
    """Build a table of findings with their compliance control mappings."""
    from reportlab.platypus import Paragraph, Table, TableStyle, Spacer
    from reportlab.lib import colors

    mapped = [f for f in findings if f.get("hipaa_ref") or f.get("pci_ref")]
    if not mapped:
        return [Paragraph("No findings map directly to compliance controls.", styles["body"])]

    data = [["Finding", "Severity", "HIPAA", "PCI"]]
    for f in mapped[:30]:
        data.append([
            (f.get("title") or "")[:60],
            (f.get("severity") or "").capitalize(),
            f.get("hipaa_ref") or "—",
            f.get("pci_ref") or "—",
        ])

    t = Table(data, colWidths=[8*cm, 2.5*cm, 4*cm, 3*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F8F8F8")]),
    ]))
    return [t, Spacer(1, 0.4*cm)]


def _recommendations(findings: list, styles: dict) -> list:
    """Build prioritised remediation recommendations."""
    from reportlab.platypus import Paragraph, Spacer

    story = []
    critical = [f for f in findings if f.get("severity") == "critical"]
    high     = [f for f in findings if f.get("severity") == "high"]

    if critical:
        story.append(Paragraph(
            f"<b>Immediate (< 24 hours):</b> Address {len(critical)} critical findings. "
            "Critical vulnerabilities represent immediate compliance violations and must "
            "be remediated before the next audit.",
            styles["body"]
        ))

    if high:
        story.append(Paragraph(
            f"<b>Urgent (< 72 hours):</b> Remediate {len(high)} high severity findings. "
            "These represent significant compliance gaps that regulators may flag during audits.",
            styles["body"]
        ))

    story.append(Paragraph(
        "<b>Recommended immediate actions:</b>\n"
        "1. Engage the development team to patch all critical vulnerabilities\n"
        "2. Implement enhanced logging and monitoring to detect exploitation attempts\n"
        "3. Conduct a follow-up scan after remediation to verify compliance restoration\n"
        "4. Document all remediation actions for audit evidence",
        styles["body"]
    ))

    story.append(Spacer(1, 0.3*__import__("reportlab").lib.units.cm))
    return story


def _footer(canvas, doc) -> None:
    """Draw compliance report footer."""
    from reportlab.lib.units import cm
    from reportlab.lib import colors

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(3*cm, 1.2*cm,
                      "NETRA नेत्र Compliance Report — HIPAA §164.312 | PCI DSS v4.0 — CONFIDENTIAL")
    canvas.drawRightString(doc.pagesize[0] - 2.5*cm, 1.2*cm, f"Page {doc.page}")
    canvas.restoreState()


def _report_filename(ctx: dict) -> str:
    """Generate standardised compliance report filename."""
    scan_id = ctx.get("scan_id", "unknown")
    date    = ctx.get("date", datetime.now().strftime("%Y%m%d")).replace("-", "")
    target  = re.sub(r"[^a-zA-Z0-9]", "_", ctx.get("engagement", scan_id))[:20]
    return f"NETRA_compliance_{target}_{date}.pdf"
