"""Global search across findings, scans and targets (the header search box)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import apply, finding_filter, scan_filter, target_filter
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("")
async def global_search(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(10, ge=1, le=50),
) -> dict[str, list[dict]]:
    pattern = f"%{q}%"
    findings = (
        (
            await db.execute(
                apply(select(Finding), finding_filter(current_user))
                .where(or_(Finding.title.ilike(pattern), Finding.description.ilike(pattern)))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    scans = (
        (
            await db.execute(
                apply(select(Scan), scan_filter(current_user))
                .where(Scan.name.ilike(pattern))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    targets = (
        (
            await db.execute(
                apply(select(Target), target_filter(current_user))
                .where(or_(Target.name.ilike(pattern), Target.value.ilike(pattern)))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return {
        "findings": [
            {"id": str(f.id), "title": f.title, "severity": str(f.severity)} for f in findings
        ],
        "scans": [{"id": str(s.id), "name": s.name, "status": str(s.status)} for s in scans],
        "targets": [{"id": str(t.id), "name": t.name, "value": t.value} for t in targets],
    }
