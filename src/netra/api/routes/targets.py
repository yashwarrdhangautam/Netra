"""Target routes: create, list, edit, delete and CSV import, with SSRF protection."""

import csv
import io
import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user, require_admin
from netra.api.scope import can_see_target, target_filter
from netra.core.rate_limiter import RateLimitProfiles, rate_limit
from netra.core.ssrf_protection import SSRFProtectionError, validate_scan_target
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.schemas.authorization import AuthorizationRequest
from netra.schemas.common import PaginatedResponse
from netra.services.audit import record_audit
from netra.services.scan_authorization import (
    AuthorizationDenied,
    grant_authorization,
    revoke_authorization,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/targets", tags=["Targets"])

VALID_TARGET_TYPES = {"domain", "ip", "url", "ip_range", "domain_list"}
MAX_IMPORT_ROWS = 1000


# ── Schemas ───────────────────────────────────────────────────────────────────


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=255)
    target_type: str
    value: str = Field(..., min_length=1)
    group_name: str | None = Field(default=None, max_length=100)
    scope_includes: list[str] = Field(default_factory=list)
    scope_excludes: list[str] = Field(default_factory=list)


class TargetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=255)
    value: str | None = Field(None, min_length=1)
    group_name: str | None = Field(None, max_length=100)
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None
    # Assign to a client user, or send null to unassign. Analysts and admins only.
    client_id: str | None = None


class TargetResponse(BaseModel):
    id: str
    name: str
    target_type: str
    value: str
    group_name: str | None
    scope_includes: list | None
    scope_excludes: list | None
    client_id: str | None = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class ImportResult(BaseModel):
    imported: int
    failed: int
    errors: list[str]


def _to_response(target: Target) -> TargetResponse:
    return TargetResponse(
        id=str(target.id),
        name=target.name,
        target_type=str(target.target_type),
        value=target.value,
        group_name=target.group_name,
        scope_includes=target.scope_includes or [],
        scope_excludes=target.scope_excludes or [],
        client_id=str(target.client_id) if target.client_id else None,
        created_at=target.created_at.isoformat(),
    )


async def _validate(target_type: str, value: str) -> dict:
    if target_type not in VALID_TARGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"target_type must be one of: {', '.join(sorted(VALID_TARGET_TYPES))}",
        )
    # validate_scan_target reports a violation as {"valid": False, ...} rather than raising,
    # so the flag must be checked here. Ignoring it let private addresses through.
    try:
        result = validate_scan_target(target_type=target_type, value=value)
    except SSRFProtectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {exc}",
        ) from exc
    if not result.get("valid"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {result.get('error', 'not allowed')}",
        )
    return result


async def _get_target(db: AsyncSession, target_id: str) -> Target:
    try:
        parsed = uuid.UUID(target_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        ) from exc
    target = await db.get(Target, parsed)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/", response_model=PaginatedResponse[TargetResponse])
async def list_targets(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    group: str | None = Query(None, max_length=100),
    search: str | None = Query(None, max_length=200),
) -> PaginatedResponse[TargetResponse]:
    """List targets, optionally filtered by group or a name/value search."""
    filters = []
    if group:
        filters.append(Target.group_name == group)
    if search:
        pattern = f"%{search}%"
        filters.append(or_(Target.name.ilike(pattern), Target.value.ilike(pattern)))

    scoped = target_filter(current_user)
    if scoped is not None:
        filters.append(scoped)
    query = select(Target)
    count_query = select(func.count()).select_from(Target)
    for condition in filters:
        query = query.where(condition)
        count_query = count_query.where(condition)

    rows = await db.execute(
        query.order_by(Target.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    )
    total = (await db.execute(count_query)).scalar_one()
    return PaginatedResponse(
        items=[_to_response(t) for t in rows.scalars().all()],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/groups", response_model=list[str])
async def list_groups(db: Annotated[AsyncSession, Depends(get_db_session)]) -> list[str]:
    """Distinct group names, for the group filter."""
    rows = await db.execute(
        select(Target.group_name).where(Target.group_name.is_not(None)).distinct()
    )
    return sorted(g for g in rows.scalars().all() if g)


@router.get("/clients")
async def list_client_users(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> list[dict]:
    """Active client accounts, for assigning targets. Not shown to client users themselves."""
    if current_user.role == UserRole.CLIENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not available to clients"
        )
    rows = await db.execute(
        select(User.id, User.email, User.full_name)
        .where(User.role == UserRole.CLIENT, User.is_active.is_(True))
        .order_by(User.email)
    )
    return [{"id": str(r.id), "email": r.email, "full_name": r.full_name} for r in rows]


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> TargetResponse:
    target = await _get_target(db, target_id)
    # 404 rather than 403, so a client cannot tell that a target exists.
    if not await can_see_target(db, current_user, target):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return _to_response(target)


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
@rate_limit(RateLimitProfiles.SCAN_CREATE)
async def create_target(
    payload: TargetCreate,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> TargetResponse:
    """Create a target after SSRF validation."""
    await _validate(payload.target_type, payload.value)
    target = Target(
        id=uuid.uuid4(),
        user_id=current_user.id,
        name=payload.name,
        target_type=payload.target_type,
        value=payload.value,
        group_name=payload.group_name,
        scope_includes=payload.scope_includes,
        scope_excludes=payload.scope_excludes,
    )
    db.add(target)
    await record_audit(
        db,
        actor=current_user,
        action="target.create",
        resource_type="target",
        resource_id=str(target.id),
        detail={"name": target.name, "target_type": payload.target_type},
    )
    await db.commit()
    await db.refresh(target)
    logger.info("target_created", target_id=str(target.id), user_id=str(current_user.id))
    return _to_response(target)


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: str,
    payload: TargetUpdate,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> TargetResponse:
    target = await _get_target(db, target_id)
    changes = payload.model_dump(exclude_unset=True)
    if "value" in changes and changes["value"] is not None:
        await _validate(str(target.target_type), changes["value"])
    if changes.get("client_id") is not None:
        try:
            changes["client_id"] = uuid.UUID(changes["client_id"])
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="client_id is not a UUID"
            ) from exc
        client = await db.get(User, changes["client_id"])
        if client is None or client.role != UserRole.CLIENT:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="client_id must be a user with the client role",
            )
    if any(
        key in changes and changes[key] != getattr(target, key)
        for key in ("value", "scope_includes", "scope_excludes")
    ):
        # Serialize policy mutation with grant/revoke and preserve its version history.
        await db.refresh(target, with_for_update=True)
        await revoke_authorization(db, target.id, current_user)
    for field, value in changes.items():
        setattr(target, field, value)
    await record_audit(
        db,
        actor=current_user,
        action="target.update",
        resource_type="target",
        resource_id=str(target.id),
        detail={"fields": sorted(changes)},
    )
    await db.commit()
    await db.refresh(target)
    return _to_response(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: str,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Delete a target. Refused while scans still reference it."""
    target = await _get_target(db, target_id)
    scans = (
        await db.execute(select(func.count()).select_from(Scan).where(Scan.target_id == target.id))
    ).scalar_one()
    if scans:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target has {scans} scan(s). Delete those scans first.",
        )
    await record_audit(
        db,
        actor=current_user,
        action="target.delete",
        resource_type="target",
        resource_id=str(target.id),
        detail={"name": target.name},
    )
    await db.delete(target)
    await db.commit()


@router.post("/import", response_model=ImportResult)
async def import_targets(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    file: UploadFile = File(...),  # noqa: B008 - FastAPI idiom
) -> ImportResult:
    """Import targets from a CSV file.

    Columns: name, target_type, value, group (optional). Each row is SSRF-checked.
    Rows that fail are reported, not imported.
    """
    raw = await file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="CSV is over 2 MB"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="CSV must be UTF-8"
        ) from exc

    reader = csv.DictReader(io.StringIO(text))
    required = {"name", "target_type", "value"}
    if not reader.fieldnames or not required.issubset({f.strip() for f in reader.fieldnames}):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="CSV needs the header columns: name, target_type, value (optional: group)",
        )

    imported = 0
    errors: list[str] = []
    for line_no, row in enumerate(reader, start=2):
        if line_no - 1 > MAX_IMPORT_ROWS:
            errors.append(f"stopped after {MAX_IMPORT_ROWS} rows")
            break
        row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
        try:
            await _validate(row.get("target_type", ""), row.get("value", ""))
        except HTTPException as exc:
            errors.append(f"line {line_no}: {exc.detail}")
            continue
        if not row.get("name") or not row.get("value"):
            errors.append(f"line {line_no}: name and value are required")
            continue
        db.add(
            Target(
                id=uuid.uuid4(),
                user_id=current_user.id,
                name=row["name"][:255],
                target_type=row["target_type"],
                value=row["value"],
                group_name=row["group"][:100] if row.get("group") else None,
                scope_includes=[],
                scope_excludes=[],
            )
        )
        imported += 1

    await record_audit(
        db,
        actor=current_user,
        action="target.import",
        resource_type="target",
        detail={"imported": imported, "failed": len(errors)},
    )
    await db.commit()
    return ImportResult(imported=imported, failed=len(errors), errors=errors[:50])


@router.put("/{target_id}/authorization")
async def grant_target_authorization(
    target_id: uuid.UUID,
    payload: AuthorizationRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    try:
        record = await grant_authorization(db, target_id, payload, current_user)
        await db.commit()
        return record.model_dump(mode="json")
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=404 if exc.code == "target_missing" else 422, detail=exc.code
        ) from exc


@router.delete("/{target_id}/authorization")
async def revoke_target_authorization(
    target_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    try:
        record = await revoke_authorization(db, target_id, current_user)
        await db.commit()
        return record.model_dump(mode="json") if record else {"revoked": True}
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=404 if exc.code == "target_missing" else 422, detail=exc.code
        ) from exc
