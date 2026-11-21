import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from netra.api.app import create_app
from netra.api.deps import get_current_user, get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models.audit_log import AuditLog
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole


def grant_payload():
    return {
        "evidence_reference": "lab-engagement",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "allowed_actions": ["http_probe", "passive_recon", "retest"],
        "http_methods": ["GET", "HEAD"],
        "ports": [80, 443],
        "max_requests_per_second": 2,
    }


def api(db, role=UserRole.ADMIN):
    app = create_app()
    user = User(
        id=uuid.uuid4(),
        email="authorization@example.org",
        hashed_password="unused",
        role=role,
        is_active=True,
        is_verified=True,
    )

    async def session():
        yield db

    async def actor():
        return user

    app.dependency_overrides[get_db_session] = session
    app.dependency_overrides[get_current_active_user] = actor
    app.dependency_overrides[get_current_user] = actor
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def make_target(db):
    target = Target(
        name="Lab", target_type="domain", value="example.org", metadata_={"unrelated": "retained"}
    )
    db.add(target)
    await db.commit()
    return target


async def test_ungranted_scan_cannot_queue(db_session, monkeypatch):
    import netra.worker.tasks as tasks

    target = await make_target(db_session)
    queued = []
    monkeypatch.setattr(tasks.run_scan, "delay", lambda scan_id: queued.append(scan_id))
    async with api(db_session) as client:
        response = await client.post(
            "/api/v1/scans/",
            json={"target_id": str(target.id), "name": "Denied", "profile": "quick"},
        )
    assert response.status_code == 403
    assert queued == []
    assert not list((await db_session.scalars(select(Scan))).all())


async def test_admin_can_grant_revoke_and_audit(db_session):
    target = await make_target(db_session)
    async with api(db_session) as client:
        url = f"/api/v1/targets/{target.id}/authorization"
        response = await client.put(url, json=grant_payload())
        assert response.status_code == 200, response.text
        assert response.json()["scope_digest"]
        response = await client.delete(url)
        assert response.status_code == 200, response.text
        assert response.json()["revoked_at"]
    await db_session.refresh(target)
    assert target.metadata_["unrelated"] == "retained"
    events = list((await db_session.scalars(select(AuditLog))).all())
    assert {event.action for event in events} >= {
        "target.authorization.grant",
        "target.authorization.revoke",
    }


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER, UserRole.CLIENT])
async def test_non_admin_cannot_grant_or_revoke(db_session, role):
    target = await make_target(db_session)
    async with api(db_session, role) as client:
        url = f"/api/v1/targets/{target.id}/authorization"
        assert (await client.put(url, json=grant_payload())).status_code == 403
        assert (await client.delete(url)).status_code == 403
    await db_session.refresh(target)
    assert "scan_authorization" not in target.metadata_


async def test_caller_cannot_forge_metadata(db_session):
    async with api(db_session) as client:
        response = await client.post(
            "/api/v1/targets/",
            json={
                "name": "Forged",
                "target_type": "domain",
                "value": "example.org",
                "metadata": {"scan_authorization": {}},
            },
        )
    assert response.status_code == 422


async def test_scope_edit_invalidates_grant(db_session):
    target = await make_target(db_session)
    async with api(db_session) as client:
        url = f"/api/v1/targets/{target.id}/authorization"
        assert (await client.put(url, json=grant_payload())).status_code == 200
        response = await client.patch(
            f"/api/v1/targets/{target.id}", json={"scope_includes": ["*.example.org"]}
        )
        assert response.status_code == 200, response.text
    await db_session.refresh(target)
    assert target.metadata_["scan_authorization"]["revoked_at"]


async def test_resume_revoked_scan_does_not_queue(db_session, monkeypatch):
    import netra.worker.tasks as tasks

    target = await make_target(db_session)
    queued = []
    monkeypatch.setattr(tasks.run_scan, "delay", lambda scan_id: queued.append(scan_id))
    async with api(db_session) as client:
        url = f"/api/v1/targets/{target.id}/authorization"
        assert (await client.put(url, json=grant_payload())).status_code == 200
        response = await client.post(
            "/api/v1/scans/",
            json={"target_id": str(target.id), "name": "Granted", "profile": "quick"},
        )
        assert response.status_code == 201, response.text
        scan = await db_session.get(Scan, uuid.UUID(response.json()["id"]))
        scan.status = "paused"
        await db_session.commit()
        assert (await client.delete(url)).status_code == 200
        response = await client.post(f"/api/v1/scans/{scan.id}/resume")
        assert response.status_code == 403, response.text
    assert len(queued) == 1
    await db_session.refresh(scan)
    assert scan.status == "paused"


async def test_grant_audit_failure_rolls_back_record(db_session, monkeypatch):
    import netra.services.scan_authorization as service

    target = await make_target(db_session)

    async def failed_audit(*args, **kwargs):
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(service, "record_audit", failed_audit)
    async with api(db_session) as client:
        with pytest.raises(RuntimeError, match="synthetic audit failure"):
            await client.put(f"/api/v1/targets/{target.id}/authorization", json=grant_payload())
    await db_session.rollback()
    await db_session.refresh(target)
    assert "scan_authorization" not in target.metadata_


async def test_fake_snapshot_in_scan_config_refused(db_session):
    target = await make_target(db_session)
    async with api(db_session) as client:
        response = await client.post(
            "/api/v1/scans/",
            json={
                "target_id": str(target.id),
                "name": "Forged",
                "profile": "quick",
                "config": {"authorization_snapshot": {"forged": True}},
            },
        )
    assert response.status_code == 422


@pytest.mark.parametrize("status", ["completed", "running", "pending", "failed"])
async def test_client_cannot_forge_scan_lifecycle(db_session, status):
    target = await make_target(db_session)
    scan = Scan(
        name="Blocked",
        target_id=target.id,
        profile="quick",
        status="failed",
        checkpoint_data={"policy_denial": "authorization_revoked"},
    )
    db_session.add(scan)
    await db_session.commit()
    async with api(db_session) as client:
        response = await client.patch(f"/api/v1/scans/{scan.id}", json={"status": status})
    assert response.status_code == 422
    await db_session.refresh(scan)
    assert scan.status == "failed"
