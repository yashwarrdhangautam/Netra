"""Phase tools run inside the signed grant: rate, methods, ports, and no active testing unless
the grant allows it. Phase rows keep real start times."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.scanner.tools.base import ToolResult
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.schemas.authorization import AuthorizationRequest
from netra.services.scan_authorization import grant_authorization, prepare_scan_authorization
from netra.worker import tasks


def _record(rps: int = 1, ports=(80, 443), methods=("GET", "HEAD")):
    return SimpleNamespace(
        max_requests_per_second=rps, ports=list(ports), http_methods=list(methods)
    )


def test_rate_never_exceeds_the_grant() -> None:
    # The deep profile asks for 50 rps; a 1 rps grant must win.
    assert tasks._granted_rate(50, _record(rps=1)) == 1
    assert tasks._granted_rate(3, _record(rps=10)) == 3
    assert tasks._granted_rate("bad", _record(rps=10)) == 1
    assert tasks._granted_rate(0, _record(rps=10)) == 1


def test_nuclei_args_follow_grant_methods_and_ports() -> None:
    args = tasks._nuclei_grant_args(_record())
    assert args["allowed_methods"] == ["GET", "HEAD"]
    assert args["protocol_types"] == ["http", "dns", "ssl"]
    assert set(args["exclude_tags"]) == {"intrusive", "dos", "fuzz"}
    # ssl templates connect to 443, so they only run when 443 is granted.
    assert "ssl" not in tasks._nuclei_grant_args(_record(ports=(80,)))["protocol_types"]


async def test_sqlmap_and_dalfox_are_paced_to_the_grant(monkeypatch) -> None:
    seen: dict[str, list[str]] = {}

    async def fake_exec(self, args, **kwargs):
        seen[self.tool_name] = args
        return ToolResult(tool_name=self.tool_name, success=True, raw_output="", metadata={})

    monkeypatch.setattr(SqlmapTool, "_exec", fake_exec)
    monkeypatch.setattr(DalfoxTool, "_exec", fake_exec)
    await SqlmapTool().run("https://a.example.org/?id=1", max_rps=2)
    await DalfoxTool().run("https://a.example.org/?q=1", max_rps=2)
    assert "--threads=1" in seen["sqlmap"]
    assert "--delay=0.500" in seen["sqlmap"]
    dalfox = seen["dalfox"]
    assert dalfox[dalfox.index("--worker") + 1] == "1"
    assert dalfox[dalfox.index("--delay") + 1] == "500"


async def _granted_scan(db, actions: list[str]) -> Scan:
    actor = User(
        id=uuid.uuid4(),
        email=f"grant-{uuid.uuid4().hex[:6]}@example.org",
        hashed_password="unused",
        role=UserRole.ADMIN,
    )
    target = Target(name="grant", target_type="domain", value="grant.example.org")
    db.add_all([actor, target])
    await db.flush()
    request = AuthorizationRequest(
        evidence_reference="unit-test",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        allowed_actions=actions,
        http_methods=["GET", "HEAD"],
        ports=[80, 443],
        max_requests_per_second=1,
    )
    await grant_authorization(db, target.id, request, actor)
    snapshot = await prepare_scan_authorization(db, target.id)
    scan = Scan(
        name="grant",
        target_id=target.id,
        profile="deep",
        status=ScanStatus.RUNNING,
        checkpoint_data={"authorization_snapshot": snapshot},
    )
    db.add(scan)
    await db.commit()
    return scan


async def test_active_test_is_skipped_when_the_grant_has_no_active_testing(
    db_session, monkeypatch
) -> None:
    scan = await _granted_scan(db_session, ["passive_recon", "http_probe", "vulnerability_scan"])

    async def must_not_run(*args, **kwargs):
        raise AssertionError("no active tool may run without an active_test grant")

    monkeypatch.setattr(SqlmapTool, "run", must_not_run)
    monkeypatch.setattr(DalfoxTool, "run", must_not_run)
    result = await tasks._execute_active_test(
        db_session, scan.id, {"live_hosts": ["https://grant.example.org:443"]}
    )
    assert result["status"] == "skipped"
    assert result["reason"] == "active_test_not_authorized"

    await tasks._update_phase_status(db_session, scan.id, PhaseType.PENTEST, result)
    phase = await db_session.scalar(select(ScanPhase).where(ScanPhase.scan_id == scan.id))
    assert phase.status == PhaseStatus.SKIPPED
    assert phase.error_message == "active_test_not_authorized"
    # A skipped phase is not a policy denial, so the scan is not forced to failed.
    await db_session.refresh(scan)
    assert not (scan.checkpoint_data or {}).get("policy_denial")
    assert scan.status == ScanStatus.RUNNING


async def test_phase_row_keeps_the_real_start_time(db_session) -> None:
    target = Target(name="T", target_type="domain", value="time.example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="time", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.commit()

    started = datetime.now(UTC) - timedelta(minutes=12)
    await tasks._update_phase_status(
        db_session, scan.id, PhaseType.SCOPE, {"status": "completed"}, started
    )
    phase = await db_session.scalar(select(ScanPhase).where(ScanPhase.scan_id == scan.id))
    duration = phase.completed_at.replace(tzinfo=UTC) - phase.started_at.replace(tzinfo=UTC)
    assert duration >= timedelta(minutes=11)
    assert phase.progress == 1.0


def test_nuclei_timeout_shares_the_phase_budget() -> None:
    from netra.worker.celery_app import celery_app

    two_hosts = tasks._nuclei_timeout(2)
    assert two_hosts * 2 <= tasks.VULN_SCAN_SOFT_LIMIT
    assert two_hosts > 4 * 3600  # enough for a full template run at 1 rps per host
    assert tasks._nuclei_timeout(500) == 300
    # Re-delivery must not start a second copy of a long vuln scan.
    visibility = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert visibility > tasks.VULN_SCAN_TIME_LIMIT
    assert tasks.vuln_scan.soft_time_limit == tasks.VULN_SCAN_SOFT_LIMIT


def test_nuclei_and_nikto_together_fit_the_phase_budget() -> None:
    nuclei, nikto = tasks._nuclei_timeout(2, nikto_hosts=2), tasks._nikto_timeout(2)
    assert nuclei * 2 + nikto * 2 <= tasks.VULN_SCAN_SOFT_LIMIT
    assert nikto >= 80 * 60  # ~4,700 nikto requests per host at 1 rps (measured on the lab)
    assert nuclei > 3 * 3600


async def test_vuln_scan_runs_nikto_with_grant_limits(monkeypatch) -> None:
    """Nikto gets the granted rate, the granted methods and its share of the budget."""
    calls: dict[str, dict] = {}

    def fake(name):
        class Fake:
            def __init__(self, work_dir=None):
                pass

            async def run(self, target, **kwargs):
                calls[name] = kwargs
                return ToolResult(tool_name=name, success=True, metadata={"state": "completed"})

        return Fake

    record = SimpleNamespace(max_requests_per_second=1, http_methods={"GET", "HEAD"}, ports=[443])
    scan = SimpleNamespace(profile="deep", config={}, checkpoint_data={}, target=None)

    async def fake_auth(db, scan_id):
        return scan, None, record, None

    async def nothing(*args, **kwargs):
        return 0

    class FakeDb:
        async def execute(self, *_):
            return SimpleNamespace(scalar_one_or_none=lambda: scan)

    monkeypatch.setattr(tasks, "require_scan_authorization", fake_auth)
    monkeypatch.setattr(tasks, "_require_action", nothing)
    monkeypatch.setattr(tasks, "_persist_findings", nothing)
    monkeypatch.setattr(tasks, "NucleiTool", fake("nuclei"))
    monkeypatch.setattr(tasks, "NiktoTool", fake("nikto"))
    result = await tasks._execute_vuln_scan(
        FakeDb(), uuid.uuid4(), {"live_hosts": ["https://example.test"]}
    )
    assert result["status"] == "completed"
    assert calls["nikto"]["max_rps"] == 1
    assert calls["nikto"]["allowed_methods"] == ["GET", "HEAD"]
    assert calls["nikto"]["timeout"] == tasks._nikto_timeout(1)
    assert calls["nuclei"]["timeout"] == tasks._nuclei_timeout(1, nikto_hosts=1)
    assert [r["tool"] for r in result["runs"]] == ["nuclei", "nikto"]
