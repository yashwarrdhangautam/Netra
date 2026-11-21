"""Creating a scan through the API must queue the worker task. Regression: it never started."""

import importlib
import uuid

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from netra.api.app import create_app
from netra.api.deps import get_current_user, get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models.audit_log import AuditLog
from netra.db.models.user import User, UserRole


def _admin() -> User:
    return User(
        id=uuid.uuid4(),
        email="scan-dispatch@example.com",
        hashed_password="not-used",  # noqa: S106 - never used for login in tests
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )


def _client(db_session) -> AsyncClient:
    app = create_app()
    admin = _admin()

    async def override_db():
        yield db_session

    async def override_user():
        return admin

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_current_active_user] = override_user
    app.dependency_overrides[get_current_user] = override_user
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_create_scan_queues_worker_task(db_session, monkeypatch) -> None:
    targets_routes = importlib.import_module("netra.api.routes.targets")
    monkeypatch.setattr(
        targets_routes,
        "validate_scan_target",
        lambda value, target_type: {"valid": True, "normalized": value, "resolved_ips": []},
    )
    tasks = importlib.import_module("netra.worker.tasks")
    queued: list[str] = []
    monkeypatch.setattr(tasks.run_scan, "delay", lambda scan_id: queued.append(scan_id))

    async with _client(db_session) as client:
        target = await client.post(
            "/api/v1/targets/",
            json={"name": "Dispatch", "target_type": "domain", "value": "example.org"},
        )
        assert target.status_code == 201, target.text
        from datetime import UTC, datetime, timedelta

        grant = await client.put(
            f"/api/v1/targets/{target.json()['id']}/authorization",
            json={
                "evidence_reference": "dispatch-lab",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "allowed_actions": ["passive_recon", "http_probe"],
                "http_methods": ["GET", "HEAD"],
                "ports": [80, 443],
                "max_requests_per_second": 2,
            },
        )
        assert grant.status_code == 200, grant.text
        scan = await client.post(
            "/api/v1/scans/",
            json={"target_id": target.json()["id"], "name": "Queued", "profile": "quick"},
        )
        assert scan.status_code == 201, scan.text
        assert queued == [scan.json()["id"]]
        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "scan.create")))
            .scalars()
            .all()
        )
        assert [r.resource_id for r in rows] == [scan.json()["id"]]
        assert rows[0].actor_email == "scan-dispatch@example.com"


async def test_create_scan_with_unknown_target_queues_nothing(db_session, monkeypatch) -> None:
    tasks = importlib.import_module("netra.worker.tasks")
    queued: list[str] = []
    monkeypatch.setattr(tasks.run_scan, "delay", lambda scan_id: queued.append(scan_id))

    async with _client(db_session) as client:
        scan = await client.post(
            "/api/v1/scans/",
            json={
                "target_id": str(uuid.uuid4()),
                "name": "Orphan",
                "profile": "quick",
            },
        )
        assert scan.status_code == 404
        assert queued == []
