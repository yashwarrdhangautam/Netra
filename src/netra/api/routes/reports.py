"""Report routes for generating security reports."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.db.models.finding import Finding
from netra.db.models.report import Report, ReportStatus, ReportType
from netra.db.models.scan import Scan
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

    asyncio.create_task(_generate_report_async(db, report, scan))

    return ReportResponse.model_validate(report)


async def _generate_report_async(
    db: AsyncSession, report: Report, scan: Scan
) -> None:
    """Generate report asynchronously."""
    try:
        from netra.services.report_service import (
            generate_executive_report,
            generate_pentest_report,
            generate_technical_report,
            generate_html_report,
            generate_excel_report,
            generate_evidence_zip,
            generate_delta_report,
            generate_api_report,
            generate_cloud_report,
            generate_compliance_report,
            generate_full_report,
        )

        # Get findings
        result = await db.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        )
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
            output_path = await generate_delta_report(scan_data, scan_data, findings_data, findings_data)
        elif report.report_type == ReportType.API:
            output_path = await generate_api_report(scan_data, findings_data)
        elif report.report_type == ReportType.CLOUD:
            output_path = await generate_cloud_report(scan_data, findings_data)
        elif report.report_type == ReportType.COMPLIANCE:
            # Get compliance data from service
            from netra.services.compliance_service import ComplianceService
            service = ComplianceService(db)
            compliance_data = await service.get_framework_gap_analysis(scan.id, "iso27001")
            output_path = await generate_compliance_report("iso27001", scan_data, compliance_data, findings_data)
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


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
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
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportResponse.model_validate(report)


@router.get("/scan/{scan_id}")
async def list_reports_for_scan(
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
