"""Every MCP scanner registration must fail closed before invoking an adapter."""

import ast
import inspect
from unittest.mock import AsyncMock

import pytest

from netra.mcp import server


async def test_unregistered_target_never_constructs_tool(monkeypatch):
    monkeypatch.setattr(
        server,
        "_authorize_mcp",
        AsyncMock(return_value={"success": False, "error": "authorization_missing"}),
    )
    monkeypatch.setattr(server, "SubfinderTool", lambda: pytest.fail("adapter constructed"))
    result = await server.subfinder_enum("example.org")
    assert result["error"] == "authorization_missing"


async def test_database_outage_denies_without_adapter(monkeypatch):
    def unavailable():
        raise RuntimeError("database credential must not leak")

    monkeypatch.setattr(server, "_policy_session", unavailable)
    monkeypatch.setattr(server, "SubfinderTool", lambda: pytest.fail("adapter constructed"))
    result = await server.subfinder_enum("example.org")
    assert result == {"success": False, "status": "blocked", "error": "policy_unavailable"}


async def test_federation_does_not_trust_caller_rules(monkeypatch):
    monkeypatch.delenv("NETRA_MCP_PROGRAM_ID", raising=False)
    result = await server.bb_passive_recon("evil.example", [{"pattern": "evil.example"}])
    assert result["error"] == "program_binding_required"


async def test_unsafe_redirect_and_template_modes_are_unavailable(monkeypatch):
    monkeypatch.setattr(
        server, "_authorize_mcp", AsyncMock(return_value={"success": True, "rate_limit": 1})
    )
    assert (await server.httpx_probe(["https://example.org"], follow_redirects=True))[
        "status"
    ] == "unavailable"
    assert (await server.nuclei_scan("https://example.org", templates="../../x"))[
        "status"
    ] == "unavailable"


@pytest.mark.parametrize(
    "name,args",
    [
        ("semgrep_scan", ["/etc"]),
        ("gitleaks_scan", ["/etc"]),
        ("pip_audit_scan", ["/etc"]),
        ("trivy_scan", ["image"]),
        ("checkov_scan", ["/etc"]),
        ("prowler_audit", []),
        ("shodan_search", ["query"]),
        ("llm_security_scan", ["url"]),
    ],
)
async def test_deferred_modes_never_run(name, args):
    assert (await getattr(server, name)(*args))["status"] == "unavailable"


def test_every_registered_tool_is_classified():
    module = ast.parse(inspect.getsource(server))
    registered = {
        node.name
        for node in ast.walk(module)
        if isinstance(node, ast.AsyncFunctionDef)
        and any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "mcp"
            and d.func.attr == "tool"
            for d in node.decorator_list
        )
    }
    assert registered == set(server.MCP_TOOL_POLICY)


async def test_database_authorization_resolves_exactly_one_policy(db_session, monkeypatch):
    import uuid
    from contextlib import asynccontextmanager
    from datetime import UTC, datetime, timedelta

    from netra.db.models.target import Target
    from netra.db.models.user import User, UserRole
    from netra.schemas.authorization import AuthorizationRequest
    from netra.services.scan_authorization import grant_authorization

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.delenv("NETRA_MCP_TARGET_ID", raising=False)
    monkeypatch.setattr(server, "_policy_session", session)
    target = Target(name="MCP", target_type="domain", value="example.org")
    actor = User(
        id=uuid.uuid4(), email="mcp@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    db_session.add_all([target, actor])
    await db_session.flush()
    request = AuthorizationRequest(
        evidence_reference="letter-1",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        allowed_actions=["passive_recon"],
        http_methods=["GET"],
        ports=[443],
        max_requests_per_second=1,
    )
    await grant_authorization(db_session, target.id, request, actor)
    await db_session.commit()
    assert (await server._authorize_mcp(["example.org"], "passive_recon", None))["rate_limit"] == 1
    assert (await server._authorize_mcp(["outside.org"], "passive_recon", None))[
        "error"
    ] == "authorization_missing"
    other = Target(name="Other", target_type="domain", value="example.org")
    db_session.add(other)
    await db_session.flush()
    await grant_authorization(db_session, other.id, request, actor)
    await db_session.commit()
    assert (await server._authorize_mcp(["example.org"], "passive_recon", None))[
        "error"
    ] == "authorization_ambiguous"
    monkeypatch.setenv("NETRA_MCP_TARGET_ID", str(target.id))
    assert (await server._authorize_mcp(["example.org"], "passive_recon", None))["rate_limit"] == 1


async def test_stored_federated_policy_ignores_claimed_rules(db_session, monkeypatch):
    from contextlib import asynccontextmanager

    from netra.db.models.bb_program import BBPlatform, BBProgram
    from netra.db.models.bb_scope_rule import BBScopeRule

    @asynccontextmanager
    async def session():
        yield db_session

    program = BBProgram(name="Stored", handle="stored", platform=BBPlatform.PRIVATE)
    db_session.add(program)
    await db_session.flush()
    db_session.add(
        BBScopeRule(
            program_id=program.id, rule_type="in", asset_type="domain", pattern="allowed.example"
        )
    )
    await db_session.commit()
    monkeypatch.setenv("NETRA_MCP_PROGRAM_ID", str(program.id))
    monkeypatch.setattr(server, "_policy_session", session)
    result = await server.bb_passive_recon("evil.example", [{"pattern": "evil.example"}])
    assert result["error"] == "scope_violation"


async def test_http_probe_requires_explicit_url_and_applies_grant_rate(monkeypatch):
    from netra.scanner.tools.base import ToolResult

    monkeypatch.setattr(
        server, "_authorize_mcp", AsyncMock(return_value={"success": True, "rate_limit": 2})
    )
    run = AsyncMock(return_value=ToolResult("httpx", True))
    monkeypatch.setattr(server.HttpxTool, "is_installed", lambda self: True)
    monkeypatch.setattr(server.HttpxTool, "run", run)
    assert (await server.httpx_probe(["example.org"], follow_redirects=False))[
        "error"
    ] == "explicit_url_required"
    run.assert_not_awaited()
    assert (await server.httpx_probe(["https://example.org:443/api"], follow_redirects=False))[
        "success"
    ]
    assert run.await_args.kwargs["rate_limit"] == 2
    assert run.await_args.kwargs["follow_redirects"] is False


async def test_httpx_adapter_applies_rate_argument(monkeypatch):
    from netra.scanner.tools.base import ToolResult

    tool = server.HttpxTool()
    execute = AsyncMock(return_value=ToolResult("httpx", True))
    monkeypatch.setattr(tool, "_exec", execute)
    await tool.run("https://example.org", follow_redirects=False, rate_limit=2)
    args = execute.await_args.args[0]
    assert args[args.index("-rate-limit") + 1] == "2"
    assert "-follow-redirects" not in args
