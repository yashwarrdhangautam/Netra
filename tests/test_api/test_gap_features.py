"""Tests for the gap-closing features: roles, users, settings, search, audit, SARIF, scanners."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netra.api.app import create_app
from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.core.passwords import validate_password
from netra.core.secretbox import decrypt_value, encrypt_value, mask
from netra.db.models.user import User, UserRole
from netra.reports.sarif import build_sarif
from netra.scanner.tools.base import ToolResult


def _user(role: UserRole, email: str) -> User:
    return User(
        id=uuid.uuid4(),
        email=email,
        hashed_password="not-used",  # noqa: S106 - never used for login in tests
        role=role,
        is_active=True,
        is_verified=True,
    )


def _client_for(db_session, user: User):
    app = create_app()

    async def override_db():
        yield db_session

    async def override_user():
        return user

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_current_active_user] = override_user
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── WebSocket authentication ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    ["/ws/scans/00000000-0000-0000-0000-000000000001", "/ws/findings", "/ws/agent/abc"],
)
def test_websocket_without_token_is_closed(path: str) -> None:
    app = create_app()
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(path):
            pass
    assert excinfo.value.code == 1008


def test_websocket_with_garbage_token_is_closed() -> None:
    app = create_app()
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/findings?token=not-a-real-jwt"):
            pass
    assert excinfo.value.code == 1008


# ── Roles ─────────────────────────────────────────────────────────────────────


async def test_viewer_can_read_but_not_write(db_session) -> None:
    viewer = _user(UserRole.VIEWER, "viewer@example.com")
    async with _client_for(db_session, viewer) as client:
        read = await client.get("/api/v1/targets/")
        assert read.status_code == 200
        write = await client.post(
            "/api/v1/targets/import",
            files={"file": ("t.csv", b"name,target_type,value\n", "text/csv")},
        )
        assert write.status_code == 403


async def test_analyst_can_write_targets_csv(db_session) -> None:
    analyst = _user(UserRole.ANALYST, "analyst@example.com")
    async with _client_for(db_session, analyst) as client:
        response = await client.post(
            "/api/v1/targets/import",
            files={"file": ("t.csv", b"name,target_type,value\n", "text/csv")},
        )
        assert response.status_code == 200
        assert response.json()["imported"] == 0


async def test_non_admin_cannot_list_users(db_session) -> None:
    analyst = _user(UserRole.ANALYST, "analyst2@example.com")
    async with _client_for(db_session, analyst) as client:
        response = await client.get("/api/v1/auth/users")
        assert response.status_code == 403


# ── User management (admin) ───────────────────────────────────────────────────


async def test_admin_creates_lists_and_deactivates_users(db_session) -> None:
    admin = _user(UserRole.ADMIN, "admin@example.com")
    async with _client_for(db_session, admin) as client:
        created = await client.post(
            "/api/v1/auth/users",
            json={
                "email": "new.user@example.com",
                "password": "Strong-Pass-2026",
                "role": "viewer",
            },
        )
        assert created.status_code == 201
        new_id = created.json()["id"]

        listed = await client.get("/api/v1/auth/users")
        assert listed.status_code == 200
        assert any(u["email"] == "new.user@example.com" for u in listed.json())

        promoted = await client.patch(f"/api/v1/auth/users/{new_id}", json={"role": "analyst"})
        assert promoted.json()["role"] == "analyst"

        removed = await client.delete(f"/api/v1/auth/users/{new_id}")
        assert removed.status_code == 204


async def test_admin_cannot_deactivate_or_demote_self(db_session) -> None:
    admin = _user(UserRole.ADMIN, "self@example.com")
    db_session.add(admin)
    await db_session.commit()
    async with _client_for(db_session, admin) as client:
        demote = await client.patch(f"/api/v1/auth/users/{admin.id}", json={"role": "viewer"})
        assert demote.status_code == 409
        delete = await client.delete(f"/api/v1/auth/users/{admin.id}")
        assert delete.status_code == 409


async def test_create_user_rejects_weak_password(db_session) -> None:
    admin = _user(UserRole.ADMIN, "admin3@example.com")
    async with _client_for(db_session, admin) as client:
        response = await client.post(
            "/api/v1/auth/users",
            json={"email": "weak@example.com", "password": "short1", "role": "viewer"},
        )
        assert response.status_code == 422


# ── Password policy ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("password", "fails"),
    [
        ("short1A", True),
        ("alllowercase123", True),
        ("ALLUPPERCASE123", True),
        ("NoDigitsHereAtAll", True),
        ("Strong-Pass-2026", False),
    ],
)
def test_password_policy(password: str, fails: bool) -> None:
    assert (validate_password(password) is not None) is fails


# ── Settings encryption and integrations ──────────────────────────────────────


def test_secretbox_round_trip_and_mask() -> None:
    token = encrypt_value("shodan-key-12345")
    assert token != "shodan-key-12345"
    assert decrypt_value(token) == "shodan-key-12345"
    assert mask("shodan-key-12345").endswith("2345")
    assert "shodan" not in mask("shodan-key-12345")


async def test_admin_saves_and_masks_integration_key(db_session) -> None:
    admin = _user(UserRole.ADMIN, "admin4@example.com")
    async with _client_for(db_session, admin) as client:
        saved = await client.put(
            "/api/v1/settings/integrations/shodan_api_key", json={"value": "abcd-efgh-1234"}
        )
        assert saved.status_code == 200
        assert saved.json()["configured"] is True
        assert "abcd-efgh" not in saved.text

        listed = await client.get("/api/v1/settings/integrations")
        shodan = next(i for i in listed.json() if i["name"] == "shodan_api_key")
        assert shodan["source"] in {"gui", "environment"}
        assert "abcd-efgh" not in listed.text


async def test_unknown_integration_is_404(db_session) -> None:
    admin = _user(UserRole.ADMIN, "admin5@example.com")
    async with _client_for(db_session, admin) as client:
        response = await client.put("/api/v1/settings/integrations/not_real", json={"value": "x"})
        assert response.status_code == 404


async def test_non_admin_cannot_change_integrations(db_session) -> None:
    analyst = _user(UserRole.ANALYST, "analyst3@example.com")
    async with _client_for(db_session, analyst) as client:
        response = await client.put(
            "/api/v1/settings/integrations/shodan_api_key", json={"value": "x"}
        )
        assert response.status_code == 403


# ── Search and audit ──────────────────────────────────────────────────────────


async def test_search_requires_two_characters(db_session) -> None:
    analyst = _user(UserRole.ANALYST, "search@example.com")
    async with _client_for(db_session, analyst) as client:
        assert (await client.get("/api/v1/search?q=a")).status_code == 422
        ok = await client.get("/api/v1/search?q=nothing-matches-this")
        assert ok.status_code == 200
        assert set(ok.json()) == {"findings", "scans", "targets"}


async def test_audit_log_records_user_creation_and_is_admin_only(db_session) -> None:
    admin = _user(UserRole.ADMIN, "audit-admin@example.com")
    async with _client_for(db_session, admin) as client:
        await client.post(
            "/api/v1/auth/users",
            json={"email": "audited@example.com", "password": "Strong-Pass-2026", "role": "viewer"},
        )
        page = await client.get("/api/v1/audit?action=user.create")
        assert page.status_code == 200
        assert any(e["resource_id"] == "audited@example.com" for e in page.json()["items"])

    viewer = _user(UserRole.VIEWER, "audit-viewer@example.com")
    async with _client_for(db_session, viewer) as client:
        assert (await client.get("/api/v1/audit")).status_code == 403


# ── SARIF ─────────────────────────────────────────────────────────────────────


def test_sarif_document_shape_and_levels() -> None:
    findings = [
        {
            "title": "SQL injection",
            "severity": "critical",
            "cwe": 89,
            "description": "x",
            "url": "https://a.example/x",
        },
        {"title": "Missing header", "severity": "low", "tool_name": "nikto"},
    ]
    doc = build_sarif(findings)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "NETRA"
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {"CWE-89": "error", "nikto": "note"}
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "https://a.example/x"
    )


# ── Scanner output parsers (no binaries needed) ───────────────────────────────


async def _fake_exec(output: str):
    async def _exec(self, args, stdin=None, timeout=300):  # noqa: ARG001
        return ToolResult(tool_name="fake", success=True, raw_output=output)

    return _exec


async def test_dnsx_parses_resolved_hosts(monkeypatch) -> None:
    from netra.scanner.tools.dnsx import DnsxTool

    monkeypatch.setattr(
        DnsxTool,
        "_exec",
        await _fake_exec("a.example.com [1.2.3.4]\nb.example.com [5.6.7.8,9.9.9.9]\n"),
    )
    result = await DnsxTool().run(["a.example.com", "b.example.com"])
    assert [f["hostname"] for f in result.findings] == ["a.example.com", "b.example.com"]
    assert result.findings[1]["ips"] == ["5.6.7.8", "9.9.9.9"]


async def test_naabu_parses_host_port_pairs(monkeypatch) -> None:
    from netra.scanner.tools.naabu import NaabuTool

    monkeypatch.setattr(NaabuTool, "_exec", await _fake_exec("10.0.0.5:443\n10.0.0.5:80\n"))
    result = await NaabuTool().run("https://10.0.0.5/app")
    assert sorted(f["port"] for f in result.findings) == [80, 443]


async def test_gau_and_katana_keep_only_urls(monkeypatch) -> None:
    from netra.scanner.tools.gau import GauTool
    from netra.scanner.tools.katana import KatanaTool

    monkeypatch.setattr(
        GauTool,
        "_exec",
        await _fake_exec("https://a.example.com/x\nnoise\nhttps://a.example.com/x\n"),
    )
    gau = await GauTool().run("example.com")
    assert [f["url"] for f in gau.findings] == ["https://a.example.com/x"]

    monkeypatch.setattr(KatanaTool, "_exec", await _fake_exec("https://a.example.com/login\n"))
    katana = await KatanaTool().run("https://a.example.com")
    assert katana.findings == [{"url": "https://a.example.com/login"}]


async def test_wpscan_maps_json_vulnerabilities(monkeypatch) -> None:
    import json

    from netra.scanner.tools.wpscan import WpscanTool

    report = {
        "version": {"vulnerabilities": [{"title": "Core XSS", "references": {"cve": ["2024-1"]}}]},
        "plugins": {"contact-form": {"vulnerabilities": [{"title": "SQLi", "references": {}}]}},
    }
    monkeypatch.setattr(WpscanTool, "_exec", await _fake_exec(json.dumps(report)))
    result = await WpscanTool().run("https://wp.example.com")
    titles = [f["title"] for f in result.findings]
    assert any("Core XSS" in t for t in titles)
    assert any("contact-form" in t for t in titles)


async def test_subzy_reports_vulnerable_lines(monkeypatch) -> None:
    from netra.scanner.tools.subzy import SubzyTool

    monkeypatch.setattr(
        SubzyTool,
        "_exec",
        await _fake_exec(
            "old.example.com - VULNERABLE (github)\nok.example.com - not vulnerable\n"
        ),
    )
    result = await SubzyTool().run(["old.example.com", "ok.example.com"])
    assert [f["hostname"] for f in result.findings] == ["old.example.com"]


async def test_assetfinder_dedupes_and_strips_wildcards(monkeypatch) -> None:
    from netra.scanner.tools.assetfinder import AssetfinderTool

    monkeypatch.setattr(
        AssetfinderTool, "_exec", await _fake_exec("*.A.example.com\na.example.com\n")
    )
    result = await AssetfinderTool().run("example.com")
    assert [f["hostname"] for f in result.findings] == ["a.example.com"]


async def test_admin_creates_target_with_group(db_session, monkeypatch) -> None:
    """Regression: target creation awaited a synchronous SSRF validator and returned 500."""
    import importlib

    targets_routes = importlib.import_module("netra.api.routes.targets")

    def fake_validate(value: str, target_type: str) -> dict:
        return {"valid": True, "normalized": value, "resolved_ips": ["93.184.216.34"]}

    monkeypatch.setattr(targets_routes, "validate_scan_target", fake_validate)
    admin = _user(UserRole.ADMIN, "creator@example.com")
    async with _client_for(db_session, admin) as client:
        created = await client.post(
            "/api/v1/targets/",
            json={
                "name": "Grouped",
                "target_type": "domain",
                "value": "example.org",
                "group_name": "prod",
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["group_name"] == "prod"
        listed = await client.get("/api/v1/targets/", params={"group": "prod"})
        assert listed.json()["total"] == 1
        deleted = await client.delete(f"/api/v1/targets/{body['id']}")
        assert deleted.status_code == 204


async def test_target_rejected_when_ssrf_validator_flags_it(db_session, monkeypatch) -> None:
    """Regression: an {"valid": False} result from the SSRF validator must block creation."""
    import importlib

    targets_routes = importlib.import_module("netra.api.routes.targets")

    def flagged(value: str, target_type: str) -> dict:
        return {
            "valid": False,
            "error": "Private/internal IP address",
            "violation_type": "private_ip",
        }

    monkeypatch.setattr(targets_routes, "validate_scan_target", flagged)
    admin = _user(UserRole.ADMIN, "ssrf-check@example.com")
    async with _client_for(db_session, admin) as client:
        created = await client.post(
            "/api/v1/targets/",
            json={"name": "Internal", "target_type": "ip", "value": "10.0.0.5"},
        )
        assert created.status_code == 400
        assert "Private" in created.json()["detail"]


def test_bugbounty_routes_follow_the_feature_switch(monkeypatch) -> None:
    """NETRA_BB_ENABLED=false must remove the bug bounty API and keep the core API."""
    from netra.api import app as app_module

    monkeypatch.setattr(app_module.settings, "bb_enabled", False)
    off = list(app_module.create_app().openapi()["paths"])
    assert not any(p.startswith("/api/v1/bb") for p in off)
    assert "/api/v1/scans/" in off or "/api/v1/scans" in off

    monkeypatch.setattr(app_module.settings, "bb_enabled", True)
    on = list(app_module.create_app().openapi()["paths"])
    assert any(p.startswith("/api/v1/bb") for p in on)


async def test_features_endpoint_is_public_and_reports_the_switch(monkeypatch) -> None:
    from netra.api import app as app_module

    monkeypatch.setattr(app_module.settings, "bb_enabled", False)
    async with AsyncClient(
        transport=ASGITransport(app=app_module.create_app()), base_url="http://test"
    ) as anon:
        response = await anon.get("/api/v1/features")
    assert response.status_code == 200
    assert response.json() == {"bugbounty": False}
