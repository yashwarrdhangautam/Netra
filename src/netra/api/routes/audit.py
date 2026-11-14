"""Audit log view for admins: who changed what, and when."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.rbac import require_admin
from netra.db.models.audit_log import AuditLog
from netra.db.models.user import User

router = APIRouter(prefix="/audit", tags=["Audit"])


class AuditEntry(BaseModel):
    id: str
    created_at: str
    actor_email: str | None
    action: str
    resource_type: str
    resource_id: str | None
    detail: dict | None


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int


@router.get("", response_model=AuditPage)
async def list_audit(
    _admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=120),
) -> AuditPage:
    query = select(AuditLog)
    count = select(func.count()).select_from(AuditLog)
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
        count = count.where(AuditLog.action.ilike(f"%{action}%"))
    rows = (
        (await db.execute(query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)))
        .scalars()
        .all()
    )
    total = (await db.execute(count)).scalar_one()
    return AuditPage(
        items=[
            AuditEntry(
                id=str(r.id),
                created_at=r.created_at.isoformat(),
                actor_email=r.actor_email,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                detail=r.detail,
            )
            for r in rows
        ],
        total=total,
    )
