"""Write general audit rows. Callers commit the session with their own change."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.audit_log import AuditLog
from netra.db.models.user import User


async def record_audit(
    db: AsyncSession,
    *,
    actor: User | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Add an audit row to the session. The caller commits."""
    db.add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail or {},
        )
    )
