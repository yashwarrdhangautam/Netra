"""Finding routes for managing security findings."""

import uuid
from datetime import UTC, datetime
from json import dumps as json_dumps
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import CurrentUser, get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import apply, can_see_scan, finding_filter, is_client
from netra.core.ssrf_protection import SSRFProtection, SSRFProtectionError
from netra.db.models.finding import Finding, FindingStatus
from netra.db.models.user import User
from netra.schemas.common import PaginatedResponse
from netra.schemas.finding import (
    FindingBulkUpdate,
    FindingClientResponse,
    FindingCreate,
    FindingListResponse,
    FindingResponse,
    FindingUpdate,
)
from netra.services.audit import record_audit

router = APIRouter()


@router.post("/", response_model=FindingResponse, status_code=201)
async def create_finding(
    payload: FindingCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> FindingResponse:
    """Create a new finding.

    Args:
        payload: Finding creation data
        db: Database session

    Returns:
        Created finding details
    """
    finding = Finding(
        scan_id=payload.scan_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status=payload.status,
        cvss_score=payload.cvss_score,
        cvss_vector=payload.cvss_vector,
        cwe_id=payload.cwe_id,
        cve_ids=payload.cve_ids or [],
        url=payload.url,
        parameter=payload.parameter,
        evidence=payload.evidence,
        tool_source=payload.tool_source,
        confidence=payload.confidence,
        remediation=payload.remediation,
        tags=payload.tags or [],
    )

    db.add(finding)
    await db.flush()
    await record_audit(
        db,
        actor=current_user,
        action="finding.create",
        resource_type="finding",
        resource_id=str(finding.id),
        detail={"scan_id": str(payload.scan_id), "severity": str(payload.severity)},
    )
    await db.commit()
    await db.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.get("/", response_model=PaginatedResponse[FindingListResponse])
async def list_findings(
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    scan_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[FindingListResponse]:
    """List findings with filtering and pagination.

    Args:
        page: Page number
        per_page: Items per page
        severity: Filter by severity
        status: Filter by status
        scan_id: Filter by scan ID
        db: Database session

    Returns:
        Paginated list of findings
    """
    query = apply(select(Finding), finding_filter(current_user))

    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    # Order by severity (critical first) then created_at
    query = query.order_by(Finding.severity, Finding.created_at.desc())

    # Pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    findings = list(result.scalars().all())

    # Get total count
    count_query = apply(select(Finding), finding_filter(current_user))
    if severity:
        count_query = count_query.where(Finding.severity == severity)
    if status:
        count_query = count_query.where(Finding.status == status)
    if scan_id:
        count_query = count_query.where(Finding.scan_id == scan_id)
    total_result = await db.execute(count_query)
    total = len(list(total_result.scalars().all()))

    return PaginatedResponse(
        items=[FindingListResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{finding_id}", response_model=FindingResponse | FindingClientResponse)
async def get_finding(
    finding_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
) -> FindingResponse | FindingClientResponse:
    """Get finding details by ID.

    Args:
        finding_id: Finding UUID
        db: Database session

    Returns:
        Finding details
    """
    finding = await db.get(Finding, finding_id)
    if not finding or not await can_see_scan(db, current_user, finding.scan_id):
        raise HTTPException(status_code=404, detail="Finding not found")

    if is_client(current_user):
        return FindingClientResponse.model_validate(finding)
    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> FindingResponse:
    """Update a finding.

    Args:
        finding_id: Finding UUID
        payload: Update data
        db: Database session

    Returns:
        Updated finding details
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.status is not None:
        finding.status = payload.status
    if payload.severity is not None:
        finding.severity = payload.severity
    if payload.assignee is not None:
        finding.assignee = payload.assignee
    if payload.notes is not None:
        finding.notes = (finding.notes or "") + payload.notes
    if payload.remediation is not None:
        finding.remediation = payload.remediation
    if payload.tags is not None:
        finding.tags = payload.tags

    await record_audit(
        db,
        actor=current_user,
        action="finding.update",
        resource_type="finding",
        resource_id=str(finding_id),
    )
    await db.commit()
    await db.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Delete a finding.

    Args:
        finding_id: Finding UUID
        db: Database session
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    await db.delete(finding)
    await record_audit(
        db,
        actor=current_user,
        action="finding.delete",
        resource_type="finding",
        resource_id=str(finding_id),
    )
    await db.commit()


@router.post("/bulk-update")
async def bulk_update_findings(
    payload: FindingBulkUpdate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Bulk update multiple findings.

    Args:
        payload: Bulk update data
        db: Database session

    Returns:
        Update summary
    """
    updated_count = 0

    for finding_id in payload.finding_ids:
        finding = await db.get(Finding, finding_id)
        if finding:
            if payload.status is not None:
                finding.status = payload.status
            if payload.severity is not None:
                finding.severity = payload.severity
            if payload.assignee is not None:
                finding.assignee = payload.assignee
            if payload.tags is not None:
                finding.tags = payload.tags
            updated_count += 1

    await record_audit(
        db,
        actor=current_user,
        action="finding.bulk_update",
        resource_type="finding",
        detail={"updated": updated_count},
    )
    await db.commit()

    return {"updated_count": updated_count}


@router.post("/{finding_id}/mark-false-positive", response_model=FindingResponse)
async def mark_false_positive(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db_session),
) -> FindingResponse:
    """Mark a finding as false positive.

    Args:
        finding_id: Finding UUID
        db: Database session

    Returns:
        Updated finding details
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus.FALSE_POSITIVE
    await record_audit(
        db,
        actor=current_user,
        action="finding.false_positive",
        resource_type="finding",
        resource_id=str(finding_id),
    )
    await db.commit()
    await db.refresh(finding)

    return FindingResponse.model_validate(finding)


async def _retest_request(finding: Finding) -> dict:
    """Make the single request for a retest. Kept separate so tests can replace it."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(finding.url)
    except httpx.HTTPError as exc:
        return {"outcome": "unreachable", "reason": type(exc).__name__}

    status_code = response.status_code
    marker = (finding.evidence or {}).get("match")
    if not isinstance(marker, str) or not marker:
        return {
            "outcome": "inconclusive",
            "reason": "no stored match string to look for",
            "status_code": status_code,
        }
    if marker in response.text[:200_000]:
        return {"outcome": "reproduced", "status_code": status_code}
    return {"outcome": "not_reproduced", "status_code": status_code}


@router.post("/{finding_id}/retest")
async def retest_finding(
    finding_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Request the finding's URL once and check whether the stored match string is still there.

    The request goes through the SSRF guard and does not follow redirects. The result is kept
    on the finding under evidence.last_retest. The finding's status is left for an analyst.
    """
    finding = await db.get(Finding, finding_id)
    if not finding or not await can_see_scan(db, current_user, finding.scan_id):
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.url:
        outcome = {"outcome": "unverifiable", "reason": "finding has no URL to re-request"}
    else:
        from netra.services.scan_authorization import (
            AuthorizationDenied,
            require_scan_authorization,
            require_target_action,
        )

        try:
            scan, target, _, _ = await require_scan_authorization(db, finding.scan_id)
            await require_target_action(
                db,
                target.id,
                finding.url,
                "retest",
                method="GET",
                snapshot=(scan.checkpoint_data or {}).get("authorization_snapshot"),
            )
        except AuthorizationDenied as exc:
            raise HTTPException(
                status_code=503 if exc.code == "policy_unavailable" else 403, detail=exc.code
            ) from exc
        try:
            allowed, reason = SSRFProtection.validate_url(finding.url)
        except SSRFProtectionError as exc:  # unresolvable host or private address
            raise HTTPException(status_code=422, detail=f"URL refused: {exc}") from exc
        if not allowed:
            raise HTTPException(status_code=422, detail=f"URL refused by SSRF guard: {reason}")
        outcome = await _retest_request(finding)

    checked_at = datetime.now(UTC).isoformat()
    finding.evidence = {
        **(finding.evidence or {}),
        "last_retest": {**outcome, "checked_at": checked_at},
    }
    await record_audit(
        db,
        actor=current_user,
        action="finding.retest",
        resource_type="finding",
        resource_id=str(finding_id),
    )
    await db.commit()
    return {"finding_id": str(finding_id), **outcome, "checked_at": checked_at}


@router.get("/{finding_id}/curl")
async def export_finding_curl(
    finding_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Export finding as cURL command.

    Args:
        finding_id: Finding UUID
        db: Database session

    Returns:
        cURL command string
    """
    finding = await db.get(Finding, finding_id)
    if not finding or not await can_see_scan(db, current_user, finding.scan_id):
        raise HTTPException(status_code=404, detail="Finding not found")

    # Extract request data from evidence
    evidence = finding.evidence or {}

    # Build cURL command
    curl_parts = ["curl"]

    # Add method if specified
    method = evidence.get("method", "GET")
    if method != "GET":
        curl_parts.append(f"-X {method}")

    # Add URL
    url = finding.url or evidence.get("url", "")
    if url:
        curl_parts.append(f'"{url}"')

    # Add headers
    headers = evidence.get("headers", {})
    for header_name, header_value in headers.items():
        curl_parts.append(f'-H "{header_name}: {header_value}"')

    # Add cookies if present
    cookies = evidence.get("cookies", {})
    if cookies:
        cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        curl_parts.append(f'-H "Cookie: {cookie_string}"')

    # Add body if present (for POST/PUT/PATCH)
    body = evidence.get("body") or evidence.get("data") or evidence.get("payload")
    if body and method in ["POST", "PUT", "PATCH"]:
        if isinstance(body, dict | list):
            body_str = json_dumps(body)
        else:
            body_str = str(body)
        curl_parts.append(f"-d '{body_str}'")

    # Add user agent if present
    user_agent = evidence.get("user_agent")
    if user_agent:
        curl_parts.append(f'-A "{user_agent}"')

    curl_command = " ".join(curl_parts)

    return {
        "finding_id": str(finding_id),
        "curl_command": curl_command,
        "method": method,
        "url": url,
        "has_body": bool(body),
    }
