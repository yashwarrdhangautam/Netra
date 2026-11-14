"""Phase outcomes: a failed tool run must not pass as a completed phase, and a missing phase row
must not pass as completed either."""

import uuid
from types import SimpleNamespace

from netra.db.models.scan import Scan
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.worker import tasks


def _run(tool: str, success: bool, error: str | None = None) -> dict:
    return {"tool": tool, "target": "t.example.org", "success": success, "error": error}


def test_verdict_completes_when_every_run_succeeds() -> None:
    assert tasks._phase_verdict([_run("nuclei", True)]) == {"status": "completed"}


def test_verdict_completes_with_warnings_on_partial_failure() -> None:
    verdict = tasks._phase_verdict([_run("nuclei", True), _run("nikto", False, "not installed")])
    assert verdict["status"] == "completed"
    assert verdict["warnings"] == ["nikto t.example.org: not installed"]


def test_verdict_fails_when_every_attempted_run_failed() -> None:
    verdict = tasks._phase_verdict([_run("nuclei", False, "exit 127")])
    assert verdict["status"] == "failed"
    assert "exit 127" in verdict["error"]


def test_verdict_with_no_runs_is_completed() -> None:
    # A profile that disables every tool in a phase is a normal, completed phase.
    assert tasks._phase_verdict([]) == {"status": "completed"}


def test_record_run_keeps_the_tool_outcome() -> None:
    runs: list[dict] = []
    result = SimpleNamespace(success=False, error="timeout")
    tasks._record_run(runs, "ffuf", "https://a.example.org", result)
    assert runs == [
        {"tool": "ffuf", "target": "https://a.example.org", "success": False, "error": "timeout"}
    ]


def test_phase_note_stores_error_or_warnings() -> None:
    assert tasks._phase_note({"status": "failed", "error": "boom"}) == "boom"
    assert tasks._phase_note({"status": "completed", "warnings": ["a", "b"]}) == "a; b"
    assert tasks._phase_note({"status": "completed"}) is None


async def _scan_with_phases(db_session, statuses: dict[PhaseType, PhaseStatus]) -> uuid.UUID:
    target = Target(name="T", target_type="domain", value="phase.example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="phase-scan", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.flush()
    for phase_type, status in statuses.items():
        db_session.add(ScanPhase(scan_id=scan.id, phase_type=phase_type, status=status))
    await db_session.commit()
    return scan.id


async def test_problems_is_none_when_every_required_phase_completed(db_session) -> None:
    statuses = {phase: PhaseStatus.COMPLETED for phase in tasks.REQUIRED_PHASES}
    scan_id = await _scan_with_phases(db_session, statuses)
    assert await tasks._phase_problems(db_session, scan_id) is None


async def test_missing_phase_row_counts_as_failed(db_session) -> None:
    # The vuln scan never wrote its row, e.g. because its status write raised.
    statuses = {
        phase: PhaseStatus.COMPLETED
        for phase in tasks.REQUIRED_PHASES
        if phase != PhaseType.VULN_SCAN
    }
    scan_id = await _scan_with_phases(db_session, statuses)
    problems = await tasks._phase_problems(db_session, scan_id)
    assert problems is not None
    assert "vuln_scan=missing" in problems


async def test_failed_phase_row_is_reported(db_session) -> None:
    statuses = {phase: PhaseStatus.COMPLETED for phase in tasks.REQUIRED_PHASES}
    statuses[PhaseType.PENTEST] = PhaseStatus.FAILED
    scan_id = await _scan_with_phases(db_session, statuses)
    assert "pentest=failed" in await tasks._phase_problems(db_session, scan_id)


def test_scope_result_is_recorded_under_the_scope_phase() -> None:
    # Regression: the scope phase used to write its row as recon_subdomains.
    source = open(tasks.__file__, encoding="utf-8").read()
    assert "PhaseType.SCOPE, result)" in source
    assert "PhaseType.RECON_SUBDOMAINS, result)" not in source
