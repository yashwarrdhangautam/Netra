"""Tool execution view of a scan: per-phase runs, honest outcomes, stored finding counts.

Phase rows say whether the pipeline step finished. They do not say whether every tool in it
succeeded: a vulnerability phase whose nuclei run timed out still "completes". This module
derives the outcome from the recorded tool runs instead, and counts findings from the stored
rows so every number reconciles with the findings list and the report.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.finding import Finding
from netra.schemas.scan import ScanPhaseResponse

# Which phase stores findings under each tool_source (see worker/tasks.py _persist_findings).
TOOL_PHASE: dict[str, str] = {
    "recontool": "scope",
    "passive_posture": "scope",
    "http_analysis": "recon_discovery",
    "nuclei": "vuln_scan",
    "nikto": "vuln_scan",
    "sqlmap": "pentest",
    "dalfox": "pentest",
    "ffuf": "pentest",
}

# Run states that mean the tool did not cover its target.
_NOT_COVERED = {"failed", "parse_error", "unavailable"}

# Human labels for the reason codes the worker records.
REASON_LABELS: dict[str, str] = {
    "timeout": "Timed out: stopped at its time budget; findings made before the limit are kept.",
    "host_unresponsive": (
        "Stopped early: the tool gave up on the host after repeated request errors."
    ),
    "light_scan_4xx_root": (
        "Light pass only: the host answered 4xx at its root, so it got a short "
        "misconfiguration/exposure check and no nikto run."
    ),
    "tech_targeted": (
        "Fast mode: only templates for the detected technology plus general checks ran."
    ),
    "active_test_not_authorized": (
        "Not run: the signed authorization does not allow active testing (SQLi, XSS, fuzzing)."
    ),
    "host_not_tested": "No host was tested: the tool produced an empty report.",
    "output_truncated": "Output was truncated, so results may be incomplete.",
    "not_run_yet": "Not reached yet.",
    "run_missing": "Required but no run was recorded.",
}


def run_status(run: dict[str, Any]) -> str:
    """Completed | Completed with warnings | Skipped | Timed out | Failed | Not configured."""
    state = run.get("state")
    reason = run.get("reason_code")
    if state == "completed":
        return (
            "completed_with_warnings"
            if reason in {"light_scan_4xx_root", "tech_targeted"}
            else "completed"
        )
    if state == "skipped":
        return "skipped"
    if state == "unavailable":
        return "not_configured"
    if reason == "timeout":
        return "timed_out"
    return "failed"


def phase_outcome(status: str, runs: list[dict[str, Any]]) -> str:
    if status != "completed":
        return status
    if any(r.get("state") in _NOT_COVERED for r in runs):
        return "completed_with_warnings"
    return "completed"


async def stored_findings_by_phase(db: AsyncSession, scan_id: uuid.UUID) -> dict[str, int]:
    rows = (
        await db.execute(
            select(Finding.tool_source, func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.tool_source)
        )
    ).all()
    counts: dict[str, int] = {}
    for tool, count in rows:
        phase = TOOL_PHASE.get(str(tool), "other")
        counts[phase] = counts.get(phase, 0) + count
    return counts


def phase_view(phase: Any, stored: dict[str, int]) -> ScanPhaseResponse:
    raw_runs = (
        (phase.tool_outputs or {}).get("runs") if isinstance(phase.tool_outputs, dict) else None
    )
    runs = [
        {
            "tool": r.get("tool"),
            "target": r.get("target"),
            "state": r.get("state"),
            "status": run_status(r),
            "reason_code": r.get("reason_code"),
            "reason": REASON_LABELS.get(str(r.get("reason_code"))),
            "error": r.get("error"),
            # Raw items the tool returned (hosts, subdomains, matches): not stored findings.
            "raw_results": r.get("findings_count"),
        }
        for r in (raw_runs or [])
        if isinstance(r, dict)
    ]
    view = ScanPhaseResponse.model_validate(phase)
    view.outcome = phase_outcome(str(phase.status), runs)
    view.stored_findings = stored.get(str(phase.phase_type), 0)
    view.runs = runs
    return view
