"""Scan routes for managing security scans."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import CurrentUser, get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import apply, can_see_scan, scan_filter
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import ScanPhase
from netra.db.models.target import Target
from netra.db.models.user import User
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
from netra.services.audit import record_audit
from netra.services.scan_authorization import (
    AuthorizationDenied,
    prepare_scan_authorization,
    require_scan_authorization,
)
from netra.services.scan_coverage import build_coverage_manifest, scan_coverage

router = APIRouter()


async def _scan_response(db: AsyncSession, scan: Scan) -> ScanResponse:
    phases = list((await db.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id))).all())
    coverage = scan_coverage(scan, phases)
    return ScanResponse.model_validate(scan).model_copy(update=coverage.model_dump())


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Create and start a new scan.

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

    if payload.config and any("authorization" in key.lower() for key in payload.config):
        raise HTTPException(
            status_code=422, detail="Server-managed authorization fields are forbidden"
        )
    try:
        snapshot = await prepare_scan_authorization(db, target.id)
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=503 if exc.code == "policy_unavailable" else 403, detail=exc.code
        ) from exc

    from netra.worker.tasks import _passive_host

    snapshot_actions = set((snapshot.get("record") or {}).get("allowed_actions") or [])

    # Create scan record
    scan = Scan(
        name=payload.name,
        target_id=payload.target_id,
        profile=payload.profile,
        config=payload.config or {},
        user_id=current_user.id,
        # The expected-tool manifest is fixed here, before dispatch, so a run that never
        # happens shows as missing coverage rather than disappearing from the count.
        checkpoint_data={
            "authorization_snapshot": snapshot,
            "coverage_manifest": build_coverage_manifest(
                str(payload.profile),
                payload.config,
                passive_discovery=_passive_host(target.value) is not None,
                active_test_allowed="active_test" in snapshot_actions,
            ),
        },
    )
    db.add(scan)
    await db.flush()
    await record_audit(
        db,
        actor=current_user,
        action="scan.create",
        resource_type="scan",
        resource_id=str(scan.id),
        detail={"profile": str(payload.profile), "target_id": str(payload.target_id)},
    )
    await db.commit()

    # Queue the scan on the Celery worker. The worker runs the phase chain and sets the final
    # status. Running it inside this request would share a session that closes with the response.
    from netra.worker.tasks import run_scan

    try:
        run_scan.delay(str(scan.id))
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = "dispatch_unavailable"
        await db.commit()
        raise HTTPException(status_code=503, detail="dispatch_unavailable") from exc

    await db.refresh(scan)
    return await _scan_response(db, scan)


@router.get("/", response_model=PaginatedResponse[ScanListResponse])
async def list_scans(
    current_user: Annotated[User, Depends(get_current_active_user)],
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
    query = apply(select(Scan), scan_filter(current_user))

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

    # Get total count
    count_query = apply(select(Scan), scan_filter(current_user))
    if status:
        count_query = count_query.where(Scan.status == status)
    if profile:
        count_query = count_query.where(Scan.profile == profile)
    total_result = await db.execute(count_query)
    total = len(list(total_result.scalars().all()))

    phase_rows = (
        list(
            (
                await db.scalars(
                    select(ScanPhase).where(ScanPhase.scan_id.in_([scan.id for scan in scans]))
                )
            ).all()
        )
        if scans
        else []
    )
    by_scan = {}
    for phase in phase_rows:
        by_scan.setdefault(phase.scan_id, []).append(phase)
    return PaginatedResponse(
        items=[
            ScanListResponse.model_validate(s).model_copy(
                update=scan_coverage(s, by_scan.get(s.id, [])).model_dump()
            )
            for s in scans
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
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
    if not scan or not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.refresh(scan)
    return await _scan_response(db, scan)


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: uuid.UUID,
    payload: ScanUpdate,
    current_user: CurrentUser,
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
        if payload.status not in (ScanStatus.PAUSED, ScanStatus.CANCELLED):
            raise HTTPException(
                status_code=422, detail="Use resume to run; execution owns terminal outcomes"
            )
        if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED):
            raise HTTPException(
                status_code=409, detail="Terminal scans cannot be changed through PATCH"
            )
        scan.status = payload.status
    if payload.name:
        scan.name = payload.name

    await record_audit(
        db, actor=current_user, action="scan.update", resource_type="scan", resource_id=str(scan_id)
    )
    await db.commit()
    await db.refresh(scan)
    return await _scan_response(db, scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
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
    await record_audit(
        db, actor=current_user, action="scan.delete", resource_type="scan", resource_id=str(scan_id)
    )
    await db.commit()


@router.get("/{scan_id}/phases")
async def get_scan_phases(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
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

    if not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(
        select(ScanPhase).where(ScanPhase.scan_id == scan_id).order_by(ScanPhase.started_at)
    )
    phases = list(result.scalars().all())
    from netra.services.scan_execution import phase_view, stored_findings_by_phase

    stored = await stored_findings_by_phase(db, scan_id)
    return [phase_view(p, stored) for p in phases]


@router.post("/{scan_id}/resume", response_model=ScanResponse)
async def resume_scan(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
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

    try:
        await require_scan_authorization(db, scan.id)
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=503 if exc.code == "policy_unavailable" else 403, detail=exc.code
        ) from exc
    # The status stays paused or failed until the worker claims the scan, so a duplicate
    # dispatch cannot start a second run.
    await record_audit(
        db, actor=current_user, action="scan.resume", resource_type="scan", resource_id=str(scan.id)
    )
    await db.commit()

    # Re-queue the pipeline on the worker. Without this the scan would sit at RUNNING forever.
    from netra.worker.tasks import run_scan

    try:
        run_scan.delay(str(scan.id))
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = "dispatch_unavailable"
        await db.commit()
        raise HTTPException(status_code=503, detail="dispatch_unavailable") from exc

    await db.refresh(scan)
    return await _scan_response(db, scan)


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
    scan_a_result = await db.execute(select(Finding).where(Finding.scan_id == payload.scan_a_id))
    scan_a_findings = list(scan_a_result.scalars().all())

    scan_b_result = await db.execute(select(Finding).where(Finding.scan_id == payload.scan_b_id))
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
