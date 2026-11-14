"""Finding retest: one guarded request to the finding's URL, result kept on the finding."""

import importlib
import uuid

from httpx import ASGITransport, AsyncClient

from netra.api.app import create_app
from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole

findings_module = importlib.import_module("netra.api.routes.findings")


def _analyst() -> User:
    return User(
        id=uuid.uuid4(),
        email="retest-analyst@example.com",
        hashed_password="not-used",  # noqa: S106 - never used for login in tests
        role=UserRole.ANALYST,
        is_active=True,
        is_verified=True,
    )


def _client_for(db_session, signed_in: User) -> AsyncClient:
    app = create_app()

    async def override_db():
        yield db_session

    async def override_user():
        return signed_in

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_current_active_user] = override_user
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _finding(db_session, url: str | None, evidence: dict | None = None) -> Finding:
    analyst = _analyst()
    db_session.add(analyst)
    target = Target(name="R", target_type="domain", value="retest.example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="retest-scan", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.flush()
    finding = Finding(
        scan_id=scan.id,
        title="retest-finding",
        description="d",
        severity="high",
        status="new",
        tool_source="test",
        url=url,
        evidence=evidence or {},
    )
    db_session.add(finding)
    await db_session.commit()
    return finding


async def test_reproduced_when_match_string_is_present(db_session, monkeypatch) -> None:
    async def fake_request(_finding):
        return {"outcome": "reproduced", "status_code": 200}

    monkeypatch.setattr(findings_module, "_retest_request", fake_request)
    # The host is fake, so skip DNS in the guard for this case only.
    monkeypatch.setattr(findings_module.SSRFProtection, "validate_url", lambda url: (True, "ok"))
    finding = await _finding(db_session, "https://retest.example.org/x", {"match": "<script>"})
    async with _client_for(db_session, _analyst()) as client:
        response = await client.post(f"/api/v1/findings/{finding.id}/retest")
    body = response.json()
    assert response.status_code == 200
    assert body["outcome"] == "reproduced"
    assert body["status_code"] == 200
    assert "checked_at" in body


async def test_ssrf_guard_refuses_a_private_url(db_session, monkeypatch) -> None:
    called = False

    async def fake_request(_finding):
        nonlocal called
        called = True
        return {"outcome": "reproduced"}

    monkeypatch.setattr(findings_module, "_retest_request", fake_request)
    finding = await _finding(db_session, "http://169.254.169.254/latest/meta-data")
    async with _client_for(db_session, _analyst()) as client:
        response = await client.post(f"/api/v1/findings/{finding.id}/retest")
    assert response.status_code == 422
    assert called is False


async def test_finding_without_url_is_unverifiable(db_session) -> None:
    finding = await _finding(db_session, None)
    async with _client_for(db_session, _analyst()) as client:
        response = await client.post(f"/api/v1/findings/{finding.id}/retest")
    assert response.status_code == 200
    assert response.json()["outcome"] == "unverifiable"


async def test_unknown_finding_is_404(db_session) -> None:
    async with _client_for(db_session, _analyst()) as client:
        response = await client.post(f"/api/v1/findings/{uuid.uuid4()}/retest")
    assert response.status_code == 404
