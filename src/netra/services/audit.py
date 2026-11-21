"""Write general audit rows. Callers commit the session with their own change."""

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.audit_log import AuditLog
from netra.db.models.user import User

_SECRET_KEY = re.compile(
    r"password|passwd|secret|token|credential|authorization|cookie|api[_-]?key|private[_-]?key|headers?",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _safe_url(match: re.Match[str]) -> str:
    try:
        parsed = urlsplit(match.group())
        if not parsed.hostname:
            return "[REDACTED_URL]"
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return "[REDACTED_URL]"


def _secret_field(key: str, value: Any) -> bool:
    # The policy record's random UUID is provenance, not a bearer credential.
    if key == "authorization_id" and isinstance(value, str):
        try:
            return str(UUID(value)) != value
        except ValueError:
            return True
    return bool(_SECRET_KEY.search(key))


def sanitize_audit_detail(value: Any, *, depth: int = 0) -> Any:
    """Copy bounded JSON-like detail, removing secret fields and URL access material.

    This is a final persistence guard. Callers should still supply minimal summaries,
    rather than raw request bodies, provider output, or arbitrary secret-bearing prose.
    """
    if depth > 20:
        return "[REDACTED_DEPTH]"
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]"
            if _secret_field(str(key), item)
            else sanitize_audit_detail(item, depth=depth + 1)
            for key, item in list(value.items())[:1000]
        }
    if isinstance(value, list | tuple):
        return [sanitize_audit_detail(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, str):
        return _URL.sub(_safe_url, value)[:8192]
    if value is None or isinstance(value, bool | int | float):
        return value
    return "[REDACTED_UNSUPPORTED]"


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
            detail=sanitize_audit_detail(detail or {}),
        )
    )
