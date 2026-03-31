"""Compliance routes for compliance framework analysis."""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import CurrentUser, get_current_active_user, get_db_session
from netra.db.models.scan import Scan
from netra.schemas.compliance import (
    ComplianceFrameworkResponse,
    ComplianceGapAnalysisResponse,
    ComplianceMapRequest,
    ComplianceScoreResponse,
)

router = APIRouter()


@router.post("/map", response_model=dict)
async def map_findings_to_compliance(
    payload: ComplianceMapRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict:
    """Map findings from a scan to compliance frameworks.

    Args:
        payload: Compliance mapping request
        db: Database session

    Returns:
        Mapping summary
    """
    # Verify scan exists
    scan = await db.get(Scan, payload.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from netra.services.compliance_service import ComplianceService

    service = ComplianceService(db)
    result = await service.map_findings_to_frameworks(
        payload.scan_id, payload.frameworks
    )

    return result


@router.get("/{scan_id}/score/{framework}", response_model=ComplianceScoreResponse)
async def get_compliance_score(
    scan_id: uuid.UUID,
    framework: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> ComplianceScoreResponse:
    """Get compliance score for a scan and framework.

    Args:
        scan_id: Scan UUID
        framework: Framework name (iso27001, pci_dss, soc2, hipaa)
        db: Database session

    Returns:
        Compliance score and details
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from netra.services.compliance_service import ComplianceService

    service = ComplianceService(db)
    score_data = await service.get_compliance_score(scan_id, framework)

    return ComplianceScoreResponse(
        scan_id=scan_id,
        framework=score_data["framework"],
        score=score_data["score"],
        total_controls=score_data["total_controls_assessed"],
        passed=score_data["passed"],
        failed=score_data["failed"],
        failed_controls=score_data["failed_controls"],
    )


@router.get(
    "/{scan_id}/framework/{framework}", response_model=ComplianceFrameworkResponse
)
async def get_framework_status(
    scan_id: uuid.UUID,
    framework: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> ComplianceFrameworkResponse:
    """Get full framework compliance status.

    Args:
        scan_id: Scan UUID
        framework: Framework name
        db: Database session

    Returns:
        Full framework compliance status
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from netra.services.compliance_service import ComplianceService

    service = ComplianceService(db)

    # Get score
    score_data = await service.get_compliance_score(scan_id, framework)

    return ComplianceFrameworkResponse(
        scan_id=scan_id,
        framework=score_data["framework"],
        score=score_data["score"],
        total_controls=score_data["total_controls_assessed"],
        passed=score_data["passed"],
        failed=score_data["failed"],
        status="pass" if score_data["score"] >= 80 else "fail",
    )


@router.get("/{scan_id}/gap-analysis/{framework}", response_model=ComplianceGapAnalysisResponse)
async def get_gap_analysis(
    scan_id: uuid.UUID,
    framework: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> ComplianceGapAnalysisResponse:
    """Get detailed gap analysis for a framework.

    Args:
        scan_id: Scan UUID
        framework: Framework name
        db: Database session

    Returns:
        Gap analysis report
    """
    # Verify scan exists
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from netra.services.compliance_service import ComplianceService

    service = ComplianceService(db)
    gap_data = await service.get_framework_gap_analysis(scan_id, framework)

    return ComplianceGapAnalysisResponse(
        scan_id=scan_id,
        framework=gap_data["framework"],
        total_gaps=gap_data["total_gaps"],
        gaps_by_severity=gap_data["gaps_by_severity"],
        gaps=gap_data["gaps"],
    )
