"""Security assessment report for one scan: PDF, JSON and CSV from a single data model.

The report is built from stored records only (scan, authorization snapshot, phase rows and
their tool runs, finding rows). It works for partial scans: failed, timed-out and skipped
tools are listed with their reasons, and the coverage section says what was not assessed.
Nothing is invented: findings keep the tool's severity, and explanations come from the
reviewed knowledge base or are marked unavailable.
"""

from __future__ import annotations

import csv
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.bugbounty.evidence.redactor import redact_text
from netra.core.config import settings
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.scan_phase import ScanPhase
from netra.intel.finding_knowledge import knowledge_for
from netra.services.owasp_coverage import owasp_coverage
from netra.services.scan_coverage import scan_coverage
from netra.services.scan_execution import REASON_LABELS, phase_view, stored_findings_by_phase

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SECRET_HEADER = re.compile(r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:.*$")
_EVIDENCE_LIMIT = 4000

PHASE_LABELS = {
    "scope": "Scope and passive discovery",
    "recon_discovery": "Reconnaissance (live hosts, headers, TLS)",
    "vuln_scan": "Vulnerability scanning",
    "pentest": "Active testing",
    "ai_analysis": "AI analysis",
    "reporting": "Reporting",
}

METHODOLOGY = [
    "Scope: the target and its rules were checked against a signed authorization before any "
    "request was sent. Every tool request is re-checked against that authorization.",
    "Passive discovery: certificate transparency and passive DNS sources, plus DNS posture "
    "(SPF, DMARC, CAA). No traffic to the target.",
    "Reconnaissance: httpx probes discovered hosts, records status, titles, technologies and "
    "security headers; a TLS probe inspects HTTPS endpoints.",
    "Vulnerability scanning: nuclei (pinned template set, non-intrusive, methods limited to "
    "the authorization) and nikto (filtered non-exploit tests), at the authorized rate.",
    "Active testing (SQL injection, XSS, fuzzing) runs only when the authorization includes "
    "active_test.",
    "All testing is unauthenticated unless stated otherwise.",
]


def _redact(value: Any) -> Any:
    """Exports never carry credentials: strip auth/cookie headers and known secret patterns."""
    if isinstance(value, str):
        text = _SECRET_HEADER.sub(lambda m: f"{m.group(1)}: [REDACTED]", value)
        text, _ = redact_text(text)
        return text[:_EVIDENCE_LIMIT] + ("… [truncated]" if len(text) > _EVIDENCE_LIMIT else "")
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value[:50]]
    return value


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _seconds(start: datetime | None, end: datetime | None) -> int | None:
    if not start or not end:
        return None
    return int((end - start).total_seconds())


async def build_assessment(db: AsyncSession, scan_id: uuid.UUID) -> dict[str, Any]:
    """All report content for one scan, as plain data."""
    scan = (
        await db.execute(select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id))
    ).scalar_one()
    phases = list(
        (
            await db.scalars(
                select(ScanPhase).where(ScanPhase.scan_id == scan_id).order_by(ScanPhase.started_at)
            )
        ).all()
    )
    rows = list((await db.scalars(select(Finding).where(Finding.scan_id == scan_id))).all())
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda f: (rank.get(str(f.severity), 9), f.title))

    stored = await stored_findings_by_phase(db, scan_id)
    phase_views = [phase_view(p, stored) for p in phases]
    coverage = scan_coverage(scan, phases)
    checkpoint = scan.checkpoint_data or {}
    snapshot = checkpoint.get("authorization_snapshot") or {}
    policy = snapshot.get("policy") or {}

    findings = []
    for f in rows:
        findings.append(
            {
                "id": str(f.id),
                "title": f.title,
                "severity": str(f.severity),
                "status": str(f.status),
                "confidence": f.confidence,
                "tool": f.tool_source,
                "url": f.url,
                "parameter": f.parameter,
                "cwe_id": f.cwe_id,
                "cve_ids": list(f.cve_ids or []),
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": _redact(f.evidence or {}),
                "detected_at": _iso(f.created_at),
                "knowledge": knowledge_for(f.title, f.evidence, f.tool_source),
            }
        )

    by_severity = dict.fromkeys(SEVERITIES, 0)
    by_tool: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1

    runs = [{**r, "phase": v.phase_type} for v in phase_views for r in v.runs]
    limitations = [
        f"{r['tool']} on {r['target']}: {r['status'].replace('_', ' ')}"
        + (f" — {r['reason']}" if r.get("reason") else (f" — {r['error']}" if r["error"] else ""))
        for r in runs
        if r["status"] != "completed"
    ]
    for v in phase_views:
        if v.status == "skipped":
            reason = REASON_LABELS.get(str(v.error_message), v.error_message or "")
            limitations.append(
                f"Phase {PHASE_LABELS.get(v.phase_type, v.phase_type)} skipped: {reason}"
            )
    limitations += [
        "Testing was unauthenticated: functionality behind login was not assessed.",
        "Automated scanning cannot prove the absence of vulnerabilities; zero findings in a "
        "category does not mean the category is secure.",
    ]
    if policy.get("max_requests_per_second"):
        limitations.append(
            f"Request rate was limited to {policy['max_requests_per_second']} per second by the "
            "authorization, which bounds how many checks fit in the scan window."
        )

    return {
        "report": {
            "type": "security_assessment",
            "version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "netra_revision": os.environ.get("NETRA_REVISION"),
        },
        "scan": {
            "id": str(scan.id),
            "name": scan.name,
            "profile": str(scan.profile),
            "status": str(scan.status),
            "config": scan.config or {},
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
            "duration_seconds": _seconds(scan.started_at, scan.completed_at),
        },
        "target": {
            "value": scan.target.value if scan.target else None,
            "type": str(scan.target.target_type) if scan.target else None,
            "live_hosts": checkpoint.get("live_hosts") or [],
            "hosts": [
                {k: h.get(k) for k in ("url", "status_code", "title", "tech")}
                for h in (checkpoint.get("http_hosts") or [])
                if isinstance(h, dict)
            ],
        },
        "authorization": {
            "allowed_actions": policy.get("allowed_actions") or [],
            "http_methods": policy.get("http_methods") or [],
            "ports": policy.get("ports") or [],
            "max_requests_per_second": policy.get("max_requests_per_second"),
            "expires_at": (snapshot.get("record") or {}).get("expires_at"),
        },
        "methodology": METHODOLOGY,
        "coverage": {
            "outcome": coverage.outcome,
            "reason": coverage.coverage_reason,
            "tools": [c.model_dump() for c in coverage.coverage],
        },
        "phases": [
            {
                "phase": v.phase_type,
                "label": PHASE_LABELS.get(v.phase_type, v.phase_type),
                "status": v.status,
                "outcome": v.outcome,
                "started_at": _iso(v.started_at),
                "completed_at": _iso(v.completed_at),
                "duration_seconds": _seconds(v.started_at, v.completed_at),
                "stored_findings": v.stored_findings,
                "note": v.error_message,
            }
            for v in phase_views
        ],
        "tool_runs": runs,
        "owasp_top10_2025": owasp_coverage(
            runs, list(policy.get("allowed_actions") or []), findings
        ),
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_tool": dict(sorted(by_tool.items())),
            "actionable": len(findings) - by_severity["info"],
            "informational": by_severity["info"],
        },
        "findings": findings,
        "limitations": limitations,
    }


def _out(scan_id: str, ext: str, output_dir: Path | None) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = output_dir or settings.reports_dir
    directory.mkdir(parents=True, exist_ok=True)
    # Timestamped names: a new report never overwrites an earlier one.
    return directory / f"assessment_{scan_id}_{stamp}.{ext}"


def render_json(data: dict[str, Any], output_dir: Path | None = None) -> Path:
    path = _out(data["scan"]["id"], "json", output_dir)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


CSV_COLUMNS = (
    "id",
    "severity",
    "title",
    "status",
    "tool",
    "url",
    "parameter",
    "cwe_id",
    "cve_ids",
    "cvss_score",
    "confidence",
    "owasp",
    "detected_at",
    "description",
    "remediation",
)


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: a leading = + - @ is stored as text.
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def render_csv(data: dict[str, Any], output_dir: Path | None = None) -> Path:
    path = _out(data["scan"]["id"], "csv", output_dir)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for f in data["findings"]:
            owasp = sorted({o for k in f["knowledge"] for o in k.get("owasp", [])})
            remediation = f["remediation"] or "; ".join(k["remediation"] for k in f["knowledge"])
            writer.writerow(
                [
                    _csv_safe(v)
                    for v in (
                        f["id"],
                        f["severity"],
                        f["title"],
                        f["status"],
                        f["tool"],
                        f["url"],
                        f["parameter"],
                        f["cwe_id"],
                        ", ".join(f["cve_ids"]),
                        f["cvss_score"],
                        f["confidence"],
                        ", ".join(owasp),
                        f["detected_at"],
                        f["description"],
                        remediation,
                    )
                ]
            )
    return path


STATE_LABELS = {
    "tested": "Tested",
    "partially_tested": "Partially tested",
    "not_tested": "Not tested",
    "requires_credentials": "Requires credentials",
    "requires_manual_review": "Requires manual review",
    "failed_interrupted": "Failed / interrupted",
}


def _duration(seconds: int | None) -> str:
    if seconds is None:
        return "n/a"
    hours, rest = divmod(seconds, 3600)
    return f"{hours}h {rest // 60}m" if hours else f"{rest // 60}m {rest % 60}s"


def render_pdf(data: dict[str, Any], output_dir: Path | None = None) -> Path:
    """PDF version of the assessment. Every dynamic value is escaped for reportlab markup."""
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    path = _out(data["scan"]["id"], "pdf", output_dir)
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, leading=12)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=7, leading=9)

    def p(text: Any, style: Any = body) -> Any:
        return Paragraph(escape("" if text is None else str(text)), style)

    def table(rows: list[list[Any]], widths: list[float]) -> Any:
        cells = [[c if hasattr(c, "wrap") else p(c, small) for c in row] for row in rows]
        t = Table(cells, colWidths=widths, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return t

    scan, target, auth = data["scan"], data["target"], data["authorization"]
    summary, coverage = data["summary"], data["coverage"]
    e: list[Any] = [
        Paragraph("Security Assessment Report", styles["Title"]),
        p(f"Scan: {scan['name']} ({scan['id']})"),
        p(f"Target: {target['value']}   Profile: {scan['profile']}   Status: {scan['status']}"),
        p(
            f"Started: {scan['started_at']}   Completed: {scan['completed_at']}   "
            f"Duration: {_duration(scan['duration_seconds'])}"
        ),
        p(f"Generated: {data['report']['generated_at']}"),
        Spacer(1, 0.4 * cm),
        Paragraph("1. Executive summary", styles["Heading2"]),
        p(
            f"The scan stored {summary['total']} findings: {summary['actionable']} with a "
            f"severity of low or higher and {summary['informational']} informational "
            "observations. Severities are those reported by the tools; none were raised."
        ),
        p(
            "Coverage outcome: "
            + (
                "complete."
                if coverage["outcome"] == "complete"
                else f"INCOMPLETE ({coverage['reason']}). Some checks did not run to completion; "
                "see Coverage and Limitations."
            )
        ),
        Spacer(1, 0.2 * cm),
        table(
            [["Severity", "Count"], *[[s.title(), summary["by_severity"][s]] for s in SEVERITIES]],
            [5 * cm, 3 * cm],
        ),
        Paragraph("2. Scope and authorization", styles["Heading2"]),
        p(f"Allowed actions: {', '.join(auth['allowed_actions']) or 'n/a'}"),
        p(
            f"HTTP methods: {', '.join(auth['http_methods']) or 'n/a'}   "
            f"Ports: {', '.join(str(x) for x in auth['ports']) or 'n/a'}   "
            f"Rate: {auth['max_requests_per_second'] or 'n/a'} req/s   "
            f"Expires: {auth['expires_at'] or 'n/a'}"
        ),
        p("Hosts tested:"),
        table(
            [
                ["Host", "Status", "Title", "Technology"],
                *[
                    [h["url"], h["status_code"], h["title"], ", ".join(h["tech"] or [])]
                    for h in target["hosts"]
                ],
            ],
            [6 * cm, 1.6 * cm, 4.4 * cm, 5 * cm],
        ),
        Paragraph("3. Methodology", styles["Heading2"]),
        *[p("• " + line) for line in data["methodology"]],
        p(
            f"Scan configuration: profile {scan['profile']}, options "
            f"{json.dumps(scan['config']) if scan['config'] else 'none'}."
        ),
        Paragraph("4. Tool execution", styles["Heading2"]),
        table(
            [
                ["Phase", "Status", "Duration", "Stored findings", "Note"],
                *[
                    [
                        ph["label"],
                        ph["outcome"],
                        _duration(ph["duration_seconds"]),
                        ph["stored_findings"],
                        ph["note"] or "",
                    ]
                    for ph in data["phases"]
                ],
            ],
            [4.5 * cm, 3 * cm, 2 * cm, 2 * cm, 5.5 * cm],
        ),
        Spacer(1, 0.2 * cm),
        table(
            [
                ["Tool", "Target", "Status", "Reason"],
                *[
                    [
                        r["tool"],
                        r["target"],
                        r["status"].replace("_", " "),
                        r.get("reason") or r.get("error") or "",
                    ]
                    for r in data["tool_runs"]
                ],
            ],
            [2.2 * cm, 5 * cm, 2.6 * cm, 7.2 * cm],
        ),
        Paragraph("5. Coverage (OWASP Top 10:2025)", styles["Heading2"]),
        p(
            "States describe what NETRA ran in this scan. Running a scanner does not by itself "
            "cover a category."
        ),
        table(
            [
                ["Category", "State", "Findings", "Checks and limitations"],
                *[
                    [
                        c["name"],
                        STATE_LABELS[c["state"]],
                        c["findings"],
                        f"{c['checks']} {c['limitations']}",
                    ]
                    for c in data["owasp_top10_2025"]
                ],
            ],
            [4.5 * cm, 2.8 * cm, 1.5 * cm, 8.2 * cm],
        ),
        PageBreak(),
        Paragraph("6. Findings", styles["Heading2"]),
    ]
    if not data["findings"]:
        e.append(p("No findings were stored for this scan."))
    for i, f in enumerate(data["findings"], 1):
        block = [
            Paragraph(escape(f"{i}. [{f['severity'].upper()}] {f['title']}"), styles["Heading4"]),
            p(
                f"Tool: {f['tool']}   Status: {f['status']}   Confidence: {f['confidence']}   "
                f"CWE: {f['cwe_id'] or 'n/a'}   CVE: {', '.join(f['cve_ids']) or 'none'}"
            ),
            p(
                f"Affected: {f['url'] or 'n/a'}"
                + (f"  parameter {f['parameter']}" if f["parameter"] else "")
            ),
            p(f"Detected: {f['detected_at']}"),
            p(f"Description: {f['description']}"),
        ]
        for k in f["knowledge"]:
            block += [
                p(f"Why it matters: {k['purpose']} {k['impact']}"),
                p(f"Exploitation conditions: {k['conditions']}"),
                p(f"False-positive notes: {k['false_positive']}"),
                p(f"Remediation: {k['remediation']}"),
                p(f"Retest: {k['retest']}"),
                p(
                    "Mapping: "
                    + ", ".join([*(k.get("owasp") or []), *([k["cwe"]] if k.get("cwe") else [])])
                    or "none"
                ),
            ]
        if f["remediation"]:
            block.append(p(f"Remediation (finding): {f['remediation']}"))
        if not f["knowledge"] and not f["remediation"]:
            block.append(
                p(
                    "No reviewed explanation is available for this check; see the "
                    "tool evidence below and verify manually."
                )
            )
        evidence = json.dumps(f["evidence"], default=str)[:1500]
        block += [p("Evidence (redacted):", small), p(evidence, mono), Spacer(1, 0.3 * cm)]
        e.append(KeepTogether(block[:6]))
        e.extend(block[6:])
    e += [
        Paragraph("7. Limitations and coverage gaps", styles["Heading2"]),
        *[p("• " + line) for line in data["limitations"]],
    ]
    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        title=f"NETRA assessment {scan['name']}",
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    ).build(e)
    return path
