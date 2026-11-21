import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.schemas.authorization import AuthorizationRequest
from netra.services.scan_authorization import (
    AuthorizationDenied,
    grant_authorization,
    prepare_scan_authorization,
    require_target_action,
    revoke_authorization,
)


def request(**changes):
    return AuthorizationRequest(
        **{
            "evidence_reference": "signed-lab-record",
            "expires_at": datetime.now(UTC) + timedelta(days=1),
            "allowed_actions": ["http_probe"],
            "http_methods": ["GET"],
            "ports": [443],
            "max_requests_per_second": 2,
            **changes,
        }
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence_reference": " "},
        {"expires_at": datetime(2020, 1, 1)},
        {"http_methods": ["GET", "GET"]},
        {"allowed_actions": ["shell"]},
        {"ports": [0]},
        {"authorized_by": str(uuid.uuid4())},
    ],
)
def test_request_rejects_invalid_policy(changes):
    with pytest.raises(ValidationError):
        request(**changes)


async def test_grant_snapshot_and_revocation(db_session):
    actor = User(
        id=uuid.uuid4(), email="policy@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    target = Target(
        name="fixture", target_type="domain", value="example.org", scope_includes=["*.example.org"]
    )
    db_session.add_all([actor, target])
    await db_session.flush()
    record = await grant_authorization(db_session, target.id, request(), actor)
    await db_session.commit()
    snapshot = await prepare_scan_authorization(db_session, target.id)
    assert snapshot["record"]["authorization_id"] == str(record.authorization_id)
    await require_target_action(
        db_session,
        target.id,
        "https://api.example.org/",
        "http_probe",
        method="GET",
        snapshot=snapshot,
    )
    with pytest.raises(AuthorizationDenied, match="scope_denied"):
        await require_target_action(
            db_session, target.id, "https://example.org.evil.test/", "http_probe"
        )
    with pytest.raises(AuthorizationDenied, match="action_denied"):
        await require_target_action(
            db_session, target.id, "http://example.org/", "http_probe", method="GET"
        )
    await revoke_authorization(db_session, target.id, actor)
    await db_session.commit()
    with pytest.raises(AuthorizationDenied, match="authorization_revoked"):
        await require_target_action(db_session, target.id, "https://example.org/", "http_probe")


async def test_changed_scope_invalidates_grant(db_session):
    actor = User(
        id=uuid.uuid4(), email="changed@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    target = Target(name="fixture", target_type="domain", value="example.org")
    db_session.add_all([actor, target])
    await db_session.flush()
    await grant_authorization(db_session, target.id, request(), actor)
    target.scope_includes = ["*.example.org"]
    await db_session.commit()
    with pytest.raises(AuthorizationDenied, match="policy_changed"):
        await prepare_scan_authorization(db_session, target.id)


async def test_snapshot_regrant_expiry_and_cancel_fail_closed(db_session):
    from netra.db.models.scan import Scan
    from netra.services.scan_authorization import require_scan_authorization

    actor = User(
        id=uuid.uuid4(), email="snapshot@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    target = Target(name="fixture", target_type="domain", value="example.org")
    db_session.add_all([actor, target])
    await db_session.flush()
    first = await grant_authorization(db_session, target.id, request(), actor)
    snapshot = await prepare_scan_authorization(db_session, target.id)
    scan = Scan(
        name="fixture",
        target_id=target.id,
        profile="quick",
        checkpoint_data={"authorization_snapshot": snapshot},
    )
    db_session.add(scan)
    await db_session.commit()
    await require_scan_authorization(db_session, scan.id)
    with pytest.raises(AuthorizationDenied, match="authorization_expired"):
        await require_scan_authorization(db_session, scan.id, now=first.expires_at)
    await revoke_authorization(db_session, target.id, actor)
    second = await grant_authorization(db_session, target.id, request(), actor)
    await db_session.commit()
    assert second.policy_version == first.policy_version + 1
    assert second.authorization_id != first.authorization_id
    with pytest.raises(AuthorizationDenied, match="policy_changed"):
        await require_scan_authorization(db_session, scan.id)
    scan.checkpoint_data = {
        "authorization_snapshot": await prepare_scan_authorization(db_session, target.id)
    }
    scan.status = "cancelled"
    await db_session.commit()
    with pytest.raises(AuthorizationDenied, match="authorization_revoked"):
        await require_scan_authorization(db_session, scan.id)


async def test_database_failure_denies():
    from unittest.mock import AsyncMock

    from sqlalchemy.exc import OperationalError

    db = AsyncMock()
    db.scalar.side_effect = OperationalError("statement", {}, Exception("offline"))
    with pytest.raises(AuthorizationDenied, match="policy_unavailable"):
        await prepare_scan_authorization(db, uuid.uuid4())


@pytest.mark.parametrize(
    "changes", [{"ports": [True]}, {"ports": ["443"]}, {"max_requests_per_second": 0}]
)
def test_numeric_policy_is_strict(changes):
    with pytest.raises(ValidationError):
        request(**changes)


async def test_authorised_scan_exposes_its_target_without_a_lazy_load(db_session):
    """A real async session cannot lazy-load scan.target; every phase reads it right after."""
    from netra.db.models.scan import Scan
    from netra.services.scan_authorization import require_scan_authorization

    actor = User(
        id=uuid.uuid4(), email="eager@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    target = Target(
        name="fixture", target_type="domain", value="example.org", scope_includes=["*.example.org"]
    )
    db_session.add_all([actor, target])
    await db_session.flush()
    await grant_authorization(db_session, target.id, request(), actor)
    snapshot = await prepare_scan_authorization(db_session, target.id)
    scan = Scan(
        name="eager",
        target_id=target.id,
        profile="deep",
        checkpoint_data={"authorization_snapshot": snapshot},
    )
    db_session.add(scan)
    await db_session.commit()
    db_session.expunge_all()

    loaded, _, _, _ = await require_scan_authorization(db_session, scan.id)

    assert loaded.target.value == "example.org"
