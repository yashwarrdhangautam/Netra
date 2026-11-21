"""Worker entry points fail closed before scanners receive unauthorized targets."""

import uuid
from unittest.mock import AsyncMock

from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.scanner.orchestrator import ScanOrchestrator
from netra.worker import tasks


async def _scan(db):
    target = Target(name="scope-test", target_type="domain", value="example.org")
    db.add(target)
    await db.flush()
    scan = Scan(name="unauthorized", target_id=target.id, profile="quick")
    db.add(scan)
    await db.commit()
    return scan


async def test_scope_phase_denies_missing_authorization_before_tool(db_session, monkeypatch):
    scan = await _scan(db_session)
    run = AsyncMock()
    from netra.scanner.tools.subfinder import SubfinderTool

    monkeypatch.setattr(SubfinderTool, "run", run)
    result = await tasks._execute_scope_resolution(db_session, scan.id)
    assert result["status"] == "failed"
    assert result["error"] == "authorization_missing"
    run.assert_not_awaited()


async def test_recon_denies_untrusted_previous_result_before_tool(db_session, monkeypatch):
    scan = await _scan(db_session)
    run = AsyncMock()
    monkeypatch.setattr(tasks.HttpxTool, "run", run)
    result = await tasks._execute_recon(db_session, scan.id, {"subdomains": ["attacker.example"]})
    assert result["status"] == "failed"
    run.assert_not_awaited()


async def test_legacy_standard_orchestrator_refuses_execution(db_session, monkeypatch):
    scan = await _scan(db_session)
    orchestrator = ScanOrchestrator(db_session, scan.id)
    bounty_path = AsyncMock()
    monkeypatch.setattr(ScanOrchestrator, "_execute_bugbounty_scan", bounty_path)
    await orchestrator.execute()
    await db_session.refresh(scan)
    assert scan.status == "failed"
    assert scan.error_message == "standard_orchestrator_unavailable"
    bounty_path.assert_not_awaited()
    assert not hasattr(ScanOrchestrator, "_run_subdomain_enum")
    assert not hasattr(ScanOrchestrator, "_run_vuln_scan")


def _passive_setup(monkeypatch, scan, *, record=None, discovery=None, posture=None):
    """Authorised scope phase with both providers stubbed. Returns (recontool, posture, saved)."""
    from types import SimpleNamespace

    from netra.scanner.passive import PassivePosture
    from netra.scanner.tools.base import ToolResult
    from netra.scanner.tools.recontool import RecontoolTool

    record = record or SimpleNamespace(max_requests_per_second=1)
    monkeypatch.setattr(
        tasks,
        "require_scan_authorization",
        AsyncMock(return_value=(scan, scan.target, record, None)),
    )
    monkeypatch.setattr(tasks, "require_target_action", AsyncMock())
    monkeypatch.setattr(
        tasks,
        "compile_rules",
        lambda _target: SimpleNamespace(
            check=lambda name: SimpleNamespace(allowed=name.endswith("example.org"))
        ),
    )
    discovery = discovery or ToolResult(
        tool_name="recontool",
        success=True,
        findings=[
            {"kind": "asset", "type": "domain", "value": "example.org"},
            {"kind": "asset", "type": "domain", "value": "www.example.org"},
            {"kind": "asset", "type": "domain", "value": "metabase.other.test"},
            {
                "kind": "finding",
                "title": "Exposed panel",
                "severity": "low",
                "asset": "www.example.org",
            },
        ],
        metadata={"state": "completed"},
    )
    posture = posture or ToolResult(
        tool_name="passive_posture",
        success=True,
        findings=[],
        metadata={"state": "completed", "zone": "example.org"},
    )
    recon_run = AsyncMock(return_value=discovery)
    posture_run = AsyncMock(return_value=posture)
    monkeypatch.setattr(RecontoolTool, "run", recon_run)
    monkeypatch.setattr(PassivePosture, "run", posture_run)
    saved: list[tuple[str, list]] = []

    async def capture(_db, _scan_id, tool, findings):
        saved.append((tool, findings))
        return len(findings)

    monkeypatch.setattr(tasks, "_persist_findings", capture)
    return recon_run, posture_run, saved


async def test_passive_discovery_needs_the_passive_recon_action(db_session, monkeypatch):
    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    recon_run, posture_run, _ = _passive_setup(monkeypatch, scan)
    from netra.services.scan_authorization import AuthorizationDenied

    monkeypatch.setattr(
        tasks, "require_target_action", AsyncMock(side_effect=AuthorizationDenied("action_denied"))
    )
    result = await tasks._execute_scope_resolution(db_session, scan.id)
    assert result["policy_denial"] == "action_denied"
    recon_run.assert_not_awaited()
    posture_run.assert_not_awaited()


async def test_passive_discovery_is_passive_only_and_scope_filtered(db_session, monkeypatch):
    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    recon_run, posture_run, saved = _passive_setup(monkeypatch, scan)

    result = await tasks._execute_scope_resolution(db_session, scan.id)

    assert result["status"] == "completed"
    # Discovery never runs an active phase from the scope phase, whatever the scan allows later.
    assert recon_run.await_args.kwargs == {"profile": "passive_only", "authorize_active": False}
    assert posture_run.await_count == 1
    # Names outside the authorised scope are observed, never handed to recon.
    assert result["subdomains"] == ["example.org", "www.example.org"]
    by_tool = dict(saved)
    assert [f["title"] for f in by_tool["recontool"]] == ["Exposed panel"]
    observed = [
        f for f in by_tool["passive_posture"] if "metabase.other.test" in str(f["evidence"])
    ]
    assert observed and "metabase.other.test" in observed[0]["evidence"]["outside_scope"]


async def test_passive_discovery_survives_a_missing_recontool(db_session, monkeypatch):
    from netra.scanner.tools.base import ToolResult

    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    missing = ToolResult(
        tool_name="recontool",
        success=False,
        error="recontool not installed",
        metadata={"state": "unavailable", "reason_code": "tool_missing"},
    )
    _passive_setup(monkeypatch, scan, discovery=missing)

    result = await tasks._execute_scope_resolution(db_session, scan.id)

    assert result["status"] == "completed"
    assert result["subdomains"] == ["example.org"]
    assert any("recontool" in w for w in result["warnings"])
    states = {run["tool"]: run["state"] for run in result["runs"]}
    assert states == {"recontool": "unavailable", "passive_posture": "completed"}


async def test_ip_targets_skip_passive_discovery(db_session, monkeypatch):
    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    scan.target.value = "192.0.2.10"
    recon_run, posture_run, _ = _passive_setup(monkeypatch, scan)

    result = await tasks._execute_scope_resolution(db_session, scan.id)

    assert result["status"] == "completed" and result["subdomains"] == ["192.0.2.10"]
    recon_run.assert_not_awaited()
    posture_run.assert_not_awaited()


async def test_recon_rechecks_each_payload_host(db_session, monkeypatch, tmp_path):
    from types import SimpleNamespace

    from netra.services.scan_authorization import AuthorizationDenied

    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    monkeypatch.setattr(
        tasks,
        "require_scan_authorization",
        AsyncMock(return_value=(scan, scan.target, SimpleNamespace(ports=[80, 443]), None)),
    )
    monkeypatch.setattr(
        tasks, "require_target_action", AsyncMock(side_effect=AuthorizationDenied("scope_denied"))
    )
    monkeypatch.setattr(tasks, "_phase_dir", lambda *args: tmp_path)
    run = AsyncMock()
    monkeypatch.setattr(tasks.HttpxTool, "run", run)
    result = await tasks._execute_recon(db_session, scan.id, {"subdomains": ["outside.example"]})
    assert result["policy_denial"] == "scope_denied"
    assert scan.status == "failed"
    run.assert_not_awaited()


async def test_policy_denial_is_a_blocked_required_phase(db_session):
    from sqlalchemy import select

    from netra.db.models.scan_phase import PhaseType, ScanPhase

    scan = await _scan(db_session)
    await tasks._update_phase_status(
        db_session,
        scan.id,
        PhaseType.RECON_DISCOVERY,
        {"status": "failed", "error": "scope_denied", "policy_denial": "scope_denied"},
    )
    phase = await db_session.scalar(select(ScanPhase).where(ScanPhase.scan_id == scan.id))
    assert phase.status == "blocked"
    assert phase.tool_outputs["policy_denials"][0]["required"] is True


async def test_scheduler_does_not_create_unauthorized_occurrence(db_session):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from netra.db.models.user import User
    from netra.worker.scheduler import ScanSchedule, _prepare_scheduled_scan

    scan = await _scan(db_session)
    user = User(email="schedule-test@example.org", hashed_password="unused", role="admin")
    db_session.add(user)
    await db_session.flush()
    schedule = ScanSchedule(
        name="blocked",
        target_id=scan.target_id,
        schedule_type="interval",
        interval_seconds=60,
        profile="quick",
        created_by=user.id,
        next_run_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    db_session.add(schedule)
    await db_session.commit()
    before = await db_session.scalar(select(func.count()).select_from(Scan))
    result = await _prepare_scheduled_scan(db_session, schedule.id)
    assert result == {"status": "blocked", "message": "authorization_missing"}
    assert await db_session.scalar(select(func.count()).select_from(Scan)) == before
    assert schedule.failed_runs == 1


async def test_httpx_uses_only_explicit_granted_ports_and_rate(db_session, monkeypatch, tmp_path):
    from types import SimpleNamespace

    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    record = SimpleNamespace(ports=[443], max_requests_per_second=7)
    monkeypatch.setattr(
        tasks,
        "require_scan_authorization",
        AsyncMock(return_value=(scan, scan.target, record, None)),
    )
    gate = AsyncMock()
    monkeypatch.setattr(tasks, "require_target_action", gate)
    monkeypatch.setattr(tasks, "_phase_dir", lambda *args: tmp_path)
    run = AsyncMock(return_value=SimpleNamespace(success=True, error=None, findings=[]))
    monkeypatch.setattr(tasks.HttpxTool, "run", run)
    result = await tasks._execute_recon(db_session, scan.id, {"subdomains": ["example.org"]})
    assert result["status"] == "completed"
    assert run.await_args.kwargs == {
        "target": "https://example.org:443",
        "follow_redirects": False,
        "tech_detect": True,
        "rate_limit": 7,
    }
    assert gate.await_args.args[2] == "https://example.org:443"


async def test_httpx_does_not_infer_an_ungranted_port(db_session, monkeypatch, tmp_path):
    from types import SimpleNamespace

    scan = await _scan(db_session)
    await db_session.refresh(scan, ["target"])
    record = SimpleNamespace(ports=[8443], max_requests_per_second=7)
    monkeypatch.setattr(
        tasks,
        "require_scan_authorization",
        AsyncMock(return_value=(scan, scan.target, record, None)),
    )
    monkeypatch.setattr(tasks, "_phase_dir", lambda *args: tmp_path)
    run = AsyncMock()
    monkeypatch.setattr(tasks.HttpxTool, "run", run)
    result = await tasks._execute_recon(db_session, scan.id, {"subdomains": ["example.org"]})
    assert result["policy_denial"] == "adapter_unavailable"
    run.assert_not_awaited()


def test_dispatch_denial_never_builds_pipeline(monkeypatch):
    from netra.services.scan_authorization import AuthorizationDenied

    monkeypatch.setattr(
        tasks, "_in_session", AsyncMock(side_effect=AuthorizationDenied("authorization_expired"))
    )
    monkeypatch.setattr(tasks, "_update_scan_row", AsyncMock())
    from unittest.mock import Mock

    pipeline = Mock()
    monkeypatch.setattr(tasks, "create_scan_pipeline", pipeline)
    result = tasks.run_scan.run(str(uuid.uuid4()))
    assert result["status"] == "failed"
    pipeline.assert_not_called()


async def test_reporting_cannot_overwrite_cancelled_scan(db_session, monkeypatch):
    from contextlib import asynccontextmanager

    scan = await _scan(db_session)
    scan.status = "cancelled"
    await db_session.commit()

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_db_session", session)
    await tasks._update_scan_row(scan.id, status="completed")
    assert scan.status == "cancelled"


async def test_policy_denial_remains_failed_after_reporting(db_session, monkeypatch):
    from contextlib import asynccontextmanager

    scan = await _scan(db_session)
    await tasks._policy_failure(db_session, scan.id, "scope_denied")

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_db_session", session)
    await tasks._update_scan_row(scan.id, status="completed")
    assert scan.status == "failed"


async def test_scheduler_captures_current_grant_in_server_snapshot(db_session):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from netra.db.models.user import User
    from netra.schemas.authorization import AuthorizationRequest
    from netra.services.scan_authorization import grant_authorization, require_scan_authorization
    from netra.worker.scheduler import ScanSchedule, _prepare_scheduled_scan

    original = await _scan(db_session)
    actor = User(email="schedule-grant@example.org", hashed_password="unused", role="admin")
    db_session.add(actor)
    await db_session.flush()
    grant = await grant_authorization(
        db_session,
        original.target_id,
        AuthorizationRequest(
            evidence_reference="synthetic-lab-approval",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            allowed_actions=["http_probe"],
            http_methods=["GET"],
            ports=[443],
            max_requests_per_second=3,
        ),
        actor,
    )
    schedule = ScanSchedule(
        name="authorized",
        target_id=original.target_id,
        schedule_type="interval",
        interval_seconds=60,
        profile="quick",
        created_by=actor.id,
        config={"authorization_snapshot": {"forged": True}},
    )
    db_session.add(schedule)
    await db_session.commit()
    result = await _prepare_scheduled_scan(db_session, schedule.id)
    assert result["status"] == "prepared"
    created = await db_session.scalar(select(Scan).where(Scan.id == uuid.UUID(result["scan_id"])))
    assert created.user_id == actor.id
    snapshot = created.checkpoint_data["authorization_snapshot"]
    assert snapshot["record"]["authorization_id"] == str(grant.authorization_id)
    assert snapshot != schedule.config["authorization_snapshot"]
    assert schedule.total_runs == 1
    checked, _, record, _ = await require_scan_authorization(db_session, created.id)
    assert checked.id == created.id
    assert record.authorization_id == grant.authorization_id


async def test_recon_header_and_tls_findings_only_for_hosts_with_header_data(
    db_session, monkeypatch
):
    from netra.scanner.tools.base import ToolResult

    scan = await _scan(db_session)
    gate = AsyncMock()
    monkeypatch.setattr(tasks, "require_target_action", gate)
    tls = AsyncMock(
        return_value=ToolResult(
            tool_name="tls_probe", success=True, metadata={"state": "completed"}
        )
    )
    monkeypatch.setattr(tasks, "probe_tls", tls)
    saved: list = []

    async def capture(_db, _scan_id, tool, findings):
        saved.append((tool, findings))
        return len(findings)

    monkeypatch.setattr(tasks, "_persist_findings", capture)
    rows = [
        # No header data from httpx: must not read as "every header missing".
        {"url": "https://a.example.org:443", "status_code": 200, "headers": None},
        {"url": "https://b.example.org:443", "status_code": 200, "headers": {"server": "nginx"}},
        {"url": "https://b.example.org:443", "status_code": 200, "headers": {"server": "nginx"}},
        {"url": "http://c.example.org:80", "status_code": 0, "headers": {}},
    ]
    runs: list[dict] = []
    await db_session.refresh(scan, ["target"])

    await tasks._analyze_http(db_session, scan, runs, rows)

    (tool, findings) = saved[0]
    assert tool == "http_analysis"
    assert [f["url"] for f in findings if f["title"].startswith("Missing security headers")] == [
        "https://b.example.org:443",
        "https://b.example.org:443",
    ]
    # One TLS handshake per host and port, each one re-checked against the http_probe gate.
    assert [c.args[0] for c in tls.await_args_list] == ["a.example.org", "b.example.org"]
    assert [c.args[3] for c in gate.await_args_list] == ["http_probe", "http_probe"]
    assert {r["tool"] for r in runs} == {"tls_probe"}
