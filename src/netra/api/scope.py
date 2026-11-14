"""Client-role scoping: a client sees only the targets an analyst or admin assigned to it.

Everything a client can reach hangs off a target: its scans, their findings and their reports.
Analysts, admins and viewers are not limited here. Clients are read-only, so writes are
already refused by the role checks in ``require_access``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.sql import ColumnElement

from netra.db.models.finding import Finding
from netra.db.models.report import Report
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole


def is_client(user: User) -> bool:
    return user.role == UserRole.CLIENT


def target_filter(user: User) -> ColumnElement[bool] | None:
    """Clause limiting a Target query, or None when the user is not a client."""
    if not is_client(user):
        return None
    return Target.client_id == user.id


def scan_filter(user: User) -> ColumnElement[bool] | None:
    if not is_client(user):
        return None
    return Scan.target_id.in_(select(Target.id).where(Target.client_id == user.id))


def finding_filter(user: User) -> ColumnElement[bool] | None:
    if not is_client(user):
        return None
    return Finding.scan_id.in_(
        select(Scan.id).where(
            Scan.target_id.in_(select(Target.id).where(Target.client_id == user.id))
        )
    )


def report_filter(user: User) -> ColumnElement[bool] | None:
    if not is_client(user):
        return None
    return Report.scan_id.in_(
        select(Scan.id).where(
            Scan.target_id.in_(select(Target.id).where(Target.client_id == user.id))
        )
    )


def apply(query, clause: ColumnElement[bool] | None):
    """Add a scope clause to a query when there is one."""
    return query if clause is None else query.where(clause)


async def can_see_target(db, user: User, target: Target | None) -> bool:
    if target is None:
        return False
    return not is_client(user) or target.client_id == user.id


async def can_see_scan(db, user: User, scan_id: uuid.UUID | None) -> bool:
    """True when the scan exists and the user may see it. Unknown scans are not visible."""
    if scan_id is None:
        return False
    if not is_client(user):
        return True
    target_id = await db.scalar(select(Scan.target_id).where(Scan.id == scan_id))
    if target_id is None:
        return False
    return bool(
        await db.scalar(
            select(Target.id).where(Target.id == target_id, Target.client_id == user.id)
        )
    )
