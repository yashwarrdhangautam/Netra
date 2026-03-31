"""Scan routes for managing security scans."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import CurrentUser, get_current_active_user, get_db_session
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.target import Target
from netra.schemas.common import PaginatedResponse
from netra.schemas.scan import (
    ScanCreate,
    ScanDiffRequest,
    ScanDiffResponse,
    ScanListResponse,
    ScanPhaseResponse,
    ScanResponse,
    ScanUpdate,
)

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> ScanResponse:
    """Create and start a new scan (requires authentication).

    Args:
        payload: Scan creation data
        db: Database session

    Returns:
        Created scan details
    """
    # Validate target exists
    target = await db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Create scan record
    scan = Scan(
        name=payload.name,
        target_id=payload.target_id,
        profile=payload.profile,
        config=payload.config or {},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch scan pipeline (in production, this would be a Celery task)
    # For Phase 1, we'll start it directly
    from netra.scanner.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(db, scan.id)
    # Run async in background
    import asyncio
    asyncio.create_task(orchestrator.execute())

    return ScanResponse.model_validate(scan)


@router.get("/", response_model=PaginatedResponse[ScanListResponse])
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str | None = None,
    profile: str | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanListResponse]:
    """List all scans with filtering and pagination.

    Args:
        page: Page number
        per_page: Items per page
        status: Filter by status
        profile: Filter by profile
        db: Database session

    Returns:
        Paginated list of scans
    """
    query = select(Scan)

    if status:
        query = query.where(Scan.status == status)
    if profile:
        query = query.where(Scan.profile == profile)

    # Order by created_at descending
    query = query.order_by(Scan.created_at.desc())

    # Pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    scans = list(result.scalars().all())

    # Get total count using SQL COUNT() instead of len()
    count_query = select(func.count(Scan.id))
    if status:
        count_query = count_query.where(Scan.status == status)
    if profile:
        count_query = count_query.where(Scan.profile == profile)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    return PaginatedResponse(
        items=[ScanListResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Get scan details by ID.

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        Scan details
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: uuid.UUID,
    payload: ScanUpdate,
    db: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Update scan (pause, resume, cancel).

    Args:
        scan_id: Scan UUID
        payload: Update data
        db: Database session

    Returns:
        Updated scan details
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if payload.status:
        scan.status = payload.status
    if payload.name:
        scan.name = payload.name

    await db.commit()
    await db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Delete a scan and all its data.

    Args:
        scan_id: Scan UUID
        db: Database session
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/phases")
async def get_scan_phases(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[ScanPhaseResponse]:
    """Get all phases for a scan with progress.

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        List of scan phases
    """
    from netra.db.models.scan_phase import ScanPhase

    result = await db.execute(
        select(ScanPhase).where(ScanPhase.scan_id == scan_id).order_by(ScanPhase.started_at)
    )
    phases = list(result.scalars().all())

    return [ScanPhaseResponse.model_validate(p) for p in phases]


@router.post("/{scan_id}/resume", response_model=ScanResponse)
async def resume_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Resume a paused or failed scan from last checkpoint.

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        Resumed scan details
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PAUSED, ScanStatus.FAILED]:
        raise HTTPException(
            status_code=400,
            detail="Can only resume paused or failed scans",
        )

    scan.status = ScanStatus.RUNNING
    await db.commit()
    await db.refresh(scan)

    # Restart orchestrator
    from netra.scanner.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(db, scan.id)
    import asyncio
    asyncio.create_task(orchestrator.execute())

    return ScanResponse.model_validate(scan)


@router.post("/diff", response_model=ScanDiffResponse)
async def diff_scans(
    payload: ScanDiffRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ScanDiffResponse:
    """Compare two scans and return delta.

    Args:
        payload: Scan comparison request
        db: Database session

    Returns:
        Scan comparison results
    """
    from netra.db.models.finding import Finding

    # Get findings from both scans
    scan_a_result = await db.execute(
        select(Finding).where(Finding.scan_id == payload.scan_a_id)
    )
    scan_a_findings = list(scan_a_result.scalars().all())

    scan_b_result = await db.execute(
        select(Finding).where(Finding.scan_id == payload.scan_b_id)
    )
    scan_b_findings = list(scan_b_result.scalars().all())

    # Create sets of dedup hashes for comparison
    scan_a_hashes = {f.dedup_hash for f in scan_a_findings if f.dedup_hash}
    scan_b_hashes = {f.dedup_hash for f in scan_b_findings if f.dedup_hash}

    # Calculate differences
    new_findings = len(scan_b_hashes - scan_a_hashes)
    resolved_findings = len(scan_a_hashes - scan_b_hashes)
    unchanged_findings = len(scan_a_hashes & scan_b_hashes)

    # Changed findings (same dedup hash but different severity/status)
    changed_findings = 0
    for a_finding in scan_a_findings:
        if a_finding.dedup_hash in scan_b_hashes:
            for b_finding in scan_b_findings:
                if b_finding.dedup_hash == a_finding.dedup_hash:
                    if (
                        a_finding.severity != b_finding.severity
                        or a_finding.status != b_finding.status
                    ):
                        changed_findings += 1
                    break

    return ScanDiffResponse(
        scan_a_id=payload.scan_a_id,
        scan_b_id=payload.scan_b_id,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        changed_findings=changed_findings,
        unchanged_findings=unchanged_findings,
        diff_data={
            "scan_a_total": len(scan_a_findings),
            "scan_b_total": len(scan_b_findings),
            "scan_a_hashes": list(scan_a_hashes)[:50],
            "scan_b_hashes": list(scan_b_hashes)[:50],
        },
    )
