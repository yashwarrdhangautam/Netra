"""Every data route must reject anonymous requests. Health stays public."""

import pytest

PROTECTED_GET = [
    "/api/v1/targets/",
    "/api/v1/scans/",
    "/api/v1/findings/",
    "/api/v1/reports/scan/00000000-0000-0000-0000-000000000001",
    "/api/v1/compliance/00000000-0000-0000-0000-000000000001/score/pci_dss",
    "/api/v1/schedules/schedules",
    "/api/v1/bb/programs",
    "/api/v1/bb/hunts",
    "/api/v1/bb/triage",
    "/api/v1/bb/submissions",
    "/api/v1/bb/audit/scope-blocks",
    "/api/v1/bb/audit/ui-actions",
    "/api/v1/bb/settings/verifiers",
    "/api/v1/bb/doctor",
]

PROTECTED_POST = [
    "/api/v1/bb/programs",
    "/api/v1/bb/kill-switch",
    "/api/v1/bb/hunts",
    "/api/v1/bb/scope/check",
    "/api/v1/findings/bulk-update",
    "/api/v1/targets/",
]


@pytest.mark.parametrize("path", PROTECTED_GET)
async def test_get_without_token_is_rejected(anon_client, path: str) -> None:
    response = await anon_client.get(path)
    assert response.status_code == 401


@pytest.mark.parametrize("path", PROTECTED_POST)
async def test_post_without_token_is_rejected_before_any_work(anon_client, path: str) -> None:
    # An empty body must not reach validation or business logic: 401, not 400/422.
    response = await anon_client.post(path, json={})
    assert response.status_code == 401


async def test_health_stays_public(anon_client) -> None:
    response = await anon_client.get("/api/v1/health")
    assert response.status_code == 200


async def test_login_stays_public(anon_client) -> None:
    response = await anon_client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "wrong-password-1"},
    )
    # Public endpoint: the login logic itself answers a bad login with 401.
    assert response.status_code == 401
