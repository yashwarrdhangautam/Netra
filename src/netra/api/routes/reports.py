"""Report routes for generating security reports."""

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import apply, can_see_scan, report_filter
from netra.core.config import settings
from netra.db.models.finding import Finding
from netra.db.models.report import Report, ReportStatus, ReportType
from netra.db.models.scan import Scan
from netra.db.models.user import User
from netra.schemas.report import ReportResponse

router = APIRouter()
logger = structlog.get_logger()


def _render_sarif(data: dict) -> Path:
    from netra.reports.sarif import build_sarif

    rows = [SimpleNamespace(**{**f, "tool_source": f["tool"]}) for f in data["findings"]]
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = settings.reports_dir / f"sarif_{data['scan']['id']}_{stamp}.sarif"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sarif(rows), indent=2), encoding="utf-8")
    return path


def _assessment_renderers() -> dict:
    """Report types built from the assessment data model (imported lazily: reportlab)."""
    from netra.services.assessment_report import render_csv, render_json, render_pdf

    return {
        ReportType.ASSESSMENT_PDF: render_pdf,
        ReportType.ASSESSMENT_JSON: render_json,
        ReportType.FINDINGS_CSV: render_csv,
        ReportType.SARIF: _render_sarif,
    }


_MEDIA = {
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".csv": "text/csv",
    ".sarif": "application/sarif+json",
    ".html": "text/html",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".zip": "application/zip",
}


# Background report jobs. asyncio only keeps weak references to tasks, so an unreferenced
# job could be garbage-collected mid-run and leave its report "generating" forever.
_JOBS: set[asyncio.Task] = set()
# A job still "generating" after this long was lost (e.g. the API restarted mid-job).
STALE_AFTER = timedelta(minutes=15)


async def _expire_stale(db: AsyncSession) -> None:
    cutoff = datetime.now(UTC) - STALE_AFTER
    stale = (
        await db.scalars(
            select(Report).where(
                Report.status == ReportStatus.GENERATING, Report.created_at < cutoff
            )
        )
    ).all()
    for report in stale:
        report.status = ReportStatus.FAILED
        report.error_message = "Report job was interrupted (the API restarted). Generate it again."
    if stale:
        await db.commit()


@router.post("/{scan_id}/generate", response_model=ReportResponse)
async def generate_report(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    report_type: ReportType = Query(...),
    db: AsyncSession = Depends(get_db_session),
) -> ReportResponse:
    """Generate a report for a scan.

    Args:
        scan_id: Scan UUID
        report_type: Type of report to generate
        db: Database session

    Returns:
        Report details
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan or not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    # Create report record
    report = Report(
        scan_id=scan_id,
        report_type=report_type,
        status=ReportStatus.GENERATING,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # The request session closes when the response is sent, so the task gets only IDs.
    task = asyncio.create_task(_generate_report_async(report.id, scan.id))
    _JOBS.add(task)
    task.add_done_callback(_JOBS.discard)

    return ReportResponse.model_validate(report)


async def _generate_report_async(report_id: uuid.UUID, scan_id: uuid.UUID) -> None:
    """Run report generation in its own session, after the request has finished."""
    from netra.db.session import async_session_factory

    async with async_session_factory() as db:
        report = await db.get(Report, report_id)
        # Load the target now: the builder reads it, and lazy loads cannot run in async code.
        result = await db.execute(
            select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if report is None or scan is None:
            return
        await _build_report(db, report, scan)


async def _build_report(db: AsyncSession, report: Report, scan: Scan) -> None:
    """Generate report asynchronously."""
    try:
        from netra.services.report_service import (
            generate_api_report,
            generate_cloud_report,
            generate_compliance_report,
            generate_delta_report,
            generate_evidence_zip,
            generate_excel_report,
            generate_executive_report,
            generate_full_report,
            generate_html_report,
            generate_pentest_report,
            generate_technical_report,
        )

        renderers = _assessment_renderers()
        if report.report_type in renderers:
            from netra.services.assessment_report import build_assessment

            data = await build_assessment(db, scan.id)
            path = await asyncio.to_thread(renderers[report.report_type], data)
            report.file_path = str(path)
            report.file_size = path.stat().st_size
            # What the report was built from, so a later change never rewrites its meaning.
            report.config = {
                "built_from": {
                    "scan_status": data["scan"]["status"],
                    "coverage_outcome": data["coverage"]["outcome"],
                    "findings": data["summary"]["total"],
                    "netra_revision": data["report"]["netra_revision"],
                }
            }
            report.status = ReportStatus.COMPLETED
            await db.commit()
            return

        # Get findings
        result = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
        findings = list(result.scalars().all())

        # Convert findings to dict format
        findings_data = [
            {
                "id": str(f.id),
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "url": f.url,
                "cwe_id": f.cwe_id,
                "cve_ids": f.cve_ids,
                "tool_source": f.tool_source,
                "evidence": f.evidence,
                "ai_analysis": f.ai_analysis,
                "tags": f.tags,
            }
            for f in findings
        ]

        # Scan data
        scan_data = {
            "id": str(scan.id),
            "name": scan.name,
            "target": scan.target.value if scan.target else "N/A",
            "profile": scan.profile,
            "created_at": scan.created_at.isoformat() if scan.created_at else "N/A",
            "attack_chains": (scan.checkpoint_data or {}).get("attack_chains", []),
        }

        # Generate based on type
        output_path = None
        if report.report_type == ReportType.EXECUTIVE:
            output_path = await generate_executive_report(scan_data, findings_data)
        elif report.report_type == ReportType.TECHNICAL:
            output_path = await generate_technical_report(scan_data, findings_data)
        elif report.report_type == ReportType.PENTEST:
            output_path = await generate_pentest_report(scan_data, findings_data)
        elif report.report_type == ReportType.HTML:
            output_path = await generate_html_report(scan_data, findings_data)
        elif report.report_type == ReportType.EXCEL:
            output_path = await generate_excel_report(scan_data, findings_data)
        elif report.report_type == ReportType.EVIDENCE:
            output_path = await generate_evidence_zip(scan_data, findings_data)
        elif report.report_type == ReportType.DELTA:
            # Delta needs two scans - use previous scan if available
            output_path = await generate_delta_report(
                scan_data, scan_data, findings_data, findings_data
            )
        elif report.report_type == ReportType.API:
            output_path = await generate_api_report(scan_data, findings_data)
        elif report.report_type == ReportType.CLOUD:
            output_path = await generate_cloud_report(scan_data, findings_data)
        elif report.report_type == ReportType.COMPLIANCE:
            # Get compliance data from service
            from netra.services.compliance_service import ComplianceService

            service = ComplianceService(db)
            compliance_data = await service.get_framework_gap_analysis(scan.id, "iso27001")
            output_path = await generate_compliance_report(
                "iso27001", scan_data, compliance_data, findings_data
            )
        elif report.report_type == ReportType.FULL:
            output_path = await generate_full_report(scan_data, findings_data)
        else:
            report.error_message = f"Unknown report type: {report.report_type}"
            report.status = ReportStatus.FAILED
            await db.commit()
            return

        # Update report
        report.status = ReportStatus.COMPLETED
        report.file_path = str(output_path) if output_path else None
        if output_path and output_path.exists():
            import os

            report.file_size = os.path.getsize(output_path)

    except Exception as e:
        await db.rollback()
        report.status = ReportStatus.FAILED
        report.error_message = f"{type(e).__name__}: {e}"[:2000]
        logger.error("report_failed", report_id=str(report.id), error=report.error_message)

    await db.commit()


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
    limit: int = Query(100, ge=1, le=500),
) -> list[ReportResponse]:
    """All reports, newest first. The GUI report history uses this."""
    await _expire_stale(db)
    result = await db.execute(
        apply(select(Report), report_filter(current_user))
        .order_by(Report.created_at.desc())
        .limit(limit)
    )
    return [ReportResponse.model_validate(r) for r in result.scalars().all()]


@router.get("/{report_id}/download")
async def download_report(
    current_user: Annotated[User, Depends(get_current_active_user)],
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    """Download a finished report file."""
    report = await db.get(Report, report_id)
    if report and not await can_see_scan(db, current_user, report.scan_id):
        report = None
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != ReportStatus.COMPLETED or not report.file_path:
        raise HTTPException(status_code=409, detail="Report is not ready yet")
    path = Path(report.file_path)
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Report file is no longer on disk")
    return FileResponse(path, filename=path.name, media_type=_MEDIA.get(path.suffix.lower()))


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    current_user: Annotated[User, Depends(get_current_active_user)],
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ReportResponse:
    """Get report details by ID.

    Args:
        report_id: Report UUID
        db: Database session

    Returns:
        Report details
    """
    report = await db.get(Report, report_id)
    if report and not await can_see_scan(db, current_user, report.scan_id):
        report = None
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportResponse.model_validate(report)


@router.get("/scan/{scan_id}/sarif")
async def scan_sarif(
    current_user: Annotated[User, Depends(get_current_active_user)],
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """SARIF 2.1.0 document for a scan's findings, for CI and code-scanning dashboards."""
    from netra.reports.sarif import build_sarif

    if not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return build_sarif(list(result.scalars().all()))


@router.get("/scan/{scan_id}")
async def list_reports_for_scan(
    current_user: Annotated[User, Depends(get_current_active_user)],
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[ReportResponse]:
    """List all reports for a scan.

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        List of reports
    """
    if not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    await _expire_stale(db)
    result = await db.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )
    reports = list(result.scalars().all())

    return [ReportResponse.model_validate(r) for r in reports]


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Delete a report.

    Args:
        report_id: Report UUID
        db: Database session
    """
    report = await db.get(Report, report_id)
    if not report or not await can_see_scan(db, current_user, report.scan_id):
        raise HTTPException(status_code=404, detail="Report not found")

    # Delete file if exists
    if report.file_path:
        import os

        if os.path.exists(report.file_path):
            os.remove(report.file_path)

    await db.delete(report)
    await db.commit()
