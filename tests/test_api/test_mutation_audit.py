"""P3 role and mutation/audit transaction regressions."""

import importlib
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from netra.api.app import create_app
from netra.api.deps import get_current_user, get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole


def api(db, role):
    app = create_app()
    user = User(
        id=uuid.uuid4(),
        email=f"{role}@example.org",
        hashed_password="unused",
        role=role,
        is_active=True,
    )

    async def session():
        yield db

    async def actor():
        return user

    app.dependency_overrides[get_db_session] = session
    app.dependency_overrides[get_current_user] = actor
    app.dependency_overrides[get_current_active_user] = actor
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.parametrize("role", list(UserRole))
@pytest.mark.parametrize(
    "operation",
    ["create", "update", "delete", "resume", "finding-update", "finding-delete", "finding-bulk"],
)
async def test_mutation_role_matrix(db_session, role, operation):
    missing = str(uuid.uuid4())
    cases = {
        "create": (
            "POST",
            "/api/v1/scans/",
            {"target_id": missing, "name": "role-test", "profile": "quick"},
        ),
        "update": ("PATCH", f"/api/v1/scans/{missing}", {"name": "role-test"}),
        "delete": ("DELETE", f"/api/v1/scans/{missing}", None),
        "resume": ("POST", f"/api/v1/scans/{missing}/resume", None),
        "finding-update": ("PATCH", f"/api/v1/findings/{missing}", {"status": "confirmed"}),
        "finding-delete": ("DELETE", f"/api/v1/findings/{missing}", None),
        "finding-bulk": (
            "POST",
            "/api/v1/findings/bulk-update",
            {"finding_ids": [missing], "status": "confirmed"},
        ),
    }
    method, path, body = cases[operation]
    async with api(db_session, role) as client:
        response = await client.request(method, path, json=body)
    if role in (UserRole.VIEWER, UserRole.CLIENT):
        assert response.status_code == 403
    else:
        assert response.status_code == (200 if operation == "finding-bulk" else 404)


async def test_finding_create_and_audit_rollback_together(db_session, monkeypatch):
    target = Target(name="audit", target_type="domain", value="example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="audit", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.commit()

    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    routes = importlib.import_module("netra.api.routes.findings")
    monkeypatch.setattr(routes, "record_audit", fail)
    async with api(db_session, UserRole.ADMIN) as client:
        with pytest.raises(RuntimeError, match="audit unavailable"):
            await client.post(
                "/api/v1/findings/",
                json={
                    "scan_id": str(scan.id),
                    "title": "never committed",
                    "description": "synthetic",
                    "severity": "low",
                    "tool_source": "fixture",
                },
            )
    await db_session.rollback()
    assert not list((await db_session.scalars(select(Finding))).all())


async def test_finding_status_change_audits_old_and_new(db_session):
    from netra.db.models.audit_log import AuditLog

    target = Target(name="audit2", target_type="domain", value="example.net")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="audit2", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.flush()
    finding = Finding(
        scan_id=scan.id, title="t", description="d", severity="low", tool_source="fixture"
    )
    db_session.add(finding)
    await db_session.commit()

    async with api(db_session, UserRole.ANALYST) as client:
        response = await client.patch(
            f"/api/v1/findings/{finding.id}", json={"status": "needs_review"}
        )
    assert response.status_code == 200
    assert response.json()["status"] == "needs_review"
    row = (
        await db_session.scalars(select(AuditLog).where(AuditLog.action == "finding.update"))
    ).one()
    assert row.detail["changes"] == {"status": ["new", "needs_review"]}
