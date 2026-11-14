"""Client role: read-only, and limited to the targets an analyst or admin assigned to it."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from netra.api.app import create_app
from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole


def _user(role: UserRole, email: str) -> User:
    return User(
        id=uuid.uuid4(),
        email=email,
        hashed_password="not-used",  # noqa: S106 - never used for login in tests
        role=role,
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


@pytest.fixture
async def seeded(db_session):
    """Two clients, an analyst, and one target and scan for each client plus one unassigned."""
    client_a = _user(UserRole.CLIENT, "client-a@example.com")
    client_b = _user(UserRole.CLIENT, "client-b@example.com")
    analyst = _user(UserRole.ANALYST, "analyst-scope@example.com")
    db_session.add_all([client_a, client_b, analyst])
    await db_session.flush()

    target_a = Target(name="A", target_type="domain", value="a.example.org", client_id=client_a.id)
    target_b = Target(name="B", target_type="domain", value="b.example.org", client_id=client_b.id)
    target_free = Target(name="Free", target_type="domain", value="free.example.org")
    db_session.add_all([target_a, target_b, target_free])
    await db_session.flush()

    scan_a = Scan(name="scan-a", target_id=target_a.id, profile="quick")
    scan_b = Scan(name="scan-b", target_id=target_b.id, profile="quick")
    scan_free = Scan(name="scan-free", target_id=target_free.id, profile="quick")
    db_session.add_all([scan_a, scan_b, scan_free])
    await db_session.flush()

    finding_a = Finding(
        scan_id=scan_a.id,
        title="finding-a",
        description="d",
        severity="high",
        status="new",
        tool_source="test",
    )
    finding_b = Finding(
        scan_id=scan_b.id,
        title="finding-b",
        description="d",
        severity="high",
        status="new",
        tool_source="test",
    )
    db_session.add_all([finding_a, finding_b])
    await db_session.commit()
    return {
        "client_a": client_a,
        "analyst": analyst,
        "target_a": target_a,
        "target_free": target_free,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "finding_a": finding_a,
        "finding_b": finding_b,
    }


async def test_client_lists_only_its_targets(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["client_a"]) as client:
        response = await client.get("/api/v1/targets/")
    assert response.status_code == 200
    values = [t["value"] for t in response.json()["items"]]
    assert values == ["a.example.org"]


async def test_client_gets_404_for_a_target_it_does_not_own(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["client_a"]) as client:
        own = await client.get(f"/api/v1/targets/{seeded['target_a'].id}")
        other = await client.get(f"/api/v1/targets/{seeded['target_free'].id}")
    assert own.status_code == 200
    assert other.status_code == 404


async def test_client_sees_only_scans_and_findings_under_its_targets(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["client_a"]) as client:
        scans = await client.get("/api/v1/scans/")
        findings = await client.get("/api/v1/findings/")
        hidden_scan = await client.get(f"/api/v1/scans/{seeded['scan_b'].id}")
        hidden_finding = await client.get(f"/api/v1/findings/{seeded['finding_b'].id}")
        own_finding = await client.get(f"/api/v1/findings/{seeded['finding_a'].id}")
    assert [s["name"] for s in scans.json()["items"]] == ["scan-a"]
    assert [f["title"] for f in findings.json()["items"]] == ["finding-a"]
    assert hidden_scan.status_code == 404
    assert hidden_finding.status_code == 404
    assert own_finding.status_code == 200


async def test_client_search_does_not_leak_other_targets(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["client_a"]) as client:
        targets = await client.get("/api/v1/search", params={"q": "example"})
        scans = await client.get("/api/v1/search", params={"q": "scan"})
    assert targets.status_code == 200 and scans.status_code == 200
    assert [t["value"] for t in targets.json()["targets"]] == ["a.example.org"]
    assert [s["name"] for s in scans.json()["scans"]] == ["scan-a"]


async def test_analyst_is_not_scoped(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["analyst"]) as client:
        response = await client.get("/api/v1/targets/")
    assert response.status_code == 200
    assert response.json()["total"] >= 3


async def test_assigning_a_non_client_user_is_refused(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["analyst"]) as client:
        response = await client.patch(
            f"/api/v1/targets/{seeded['target_free'].id}",
            json={"client_id": str(seeded["analyst"].id)},
        )
    assert response.status_code == 422


async def test_analyst_lists_client_accounts_and_clients_cannot(db_session, seeded) -> None:
    async with _client_for(db_session, seeded["analyst"]) as client:
        listed = await client.get("/api/v1/targets/clients")
    assert listed.status_code == 200
    emails = {row["email"] for row in listed.json()}
    assert "client-a@example.com" in emails
    assert "analyst-scope@example.com" not in emails

    async with _client_for(db_session, seeded["client_a"]) as client:
        refused = await client.get("/api/v1/targets/clients")
    assert refused.status_code == 403


async def test_client_gets_limited_finding_view(db_session, seeded) -> None:
    """Client role gets no analyst-only fields (PRD 5.3.2 limited view)."""
    finding = seeded["finding_a"]
    finding.notes = "internal triage note"
    finding.assignee = "analyst-scope@example.com"
    finding.evidence = {"raw": "secret-request"}
    finding.ai_analysis = {"summary": "internal"}
    await db_session.commit()
    await db_session.refresh(finding)

    async with _client_for(db_session, seeded["client_a"]) as client:
        response = await client.get(f"/api/v1/findings/{finding.id}")
    body = response.json()
    assert response.status_code == 200
    assert body["title"] == "finding-a"
    for hidden in ("notes", "assignee", "evidence", "ai_analysis", "tool_source"):
        assert hidden not in body


async def test_analyst_gets_full_finding_view(db_session, seeded) -> None:
    finding = seeded["finding_a"]
    finding.notes = "internal triage note"
    await db_session.commit()
    await db_session.refresh(finding)

    async with _client_for(db_session, seeded["analyst"]) as client:
        response = await client.get(f"/api/v1/findings/{finding.id}")
    assert response.status_code == 200
    assert response.json()["notes"] == "internal triage note"
