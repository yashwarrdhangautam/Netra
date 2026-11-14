"""Report routes for generating security reports."""

import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import apply, can_see_scan, report_filter
from netra.db.models.finding import Finding
from netra.db.models.report import Report, ReportStatus, ReportType
from netra.db.models.scan import Scan
from netra.db.models.user import User
from netra.schemas.report import ReportResponse

router = APIRouter()


@router.post("/{scan_id}/generate", response_model=ReportResponse)
async def generate_report(
    scan_id: uuid.UUID,
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
    if not scan:
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

    # Generate report in background
    import asyncio

    # The request session closes when the response is sent, so the task gets only IDs.
    asyncio.create_task(_generate_report_async(report.id, scan.id))

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
        report.status = ReportStatus.FAILED
        report.error_message = str(e)

    await db.commit()


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
    limit: int = Query(100, ge=1, le=500),
) -> list[ReportResponse]:
    """All reports, newest first. The GUI report history uses this."""
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
    return FileResponse(path, filename=path.name)


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
    result = await db.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )
    reports = list(result.scalars().all())

    return [ReportResponse.model_validate(r) for r in reports]


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Delete a report.

    Args:
        report_id: Report UUID
        db: Database session
    """
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Delete file if exists
    if report.file_path:
        import os

        if os.path.exists(report.file_path):
            os.remove(report.file_path)

    await db.delete(report)
    await db.commit()
