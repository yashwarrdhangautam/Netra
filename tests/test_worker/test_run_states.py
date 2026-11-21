"""Every tool run is recorded with one coverage state and its evidence is persisted (spec 6.2)."""

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from netra.db.models.scan import Scan
from netra.db.models.scan_phase import PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.worker import tasks


def _result(success=True, findings=(), metadata=None, error=None):
    return SimpleNamespace(
        success=success, findings=list(findings), metadata=metadata or {}, error=error
    )


def _run(result):
    runs: list[dict] = []
    tasks._record_run(runs, "tool", "example.org", result)
    return runs[0]


def test_clean_run_is_completed_with_count():
    run = _run(_result(findings=[{"a": 1}, {"b": 2}]))
    assert run["state"] == "completed"
    assert run["findings_count"] == 2
    assert run["reason_code"] is None


def test_clean_zero_findings_is_completed_zero():
    run = _run(_result(findings=[]))
    assert run["state"] == "completed"
    assert run["findings_count"] == 0


def test_failed_run_records_reason():
    run = _run(_result(success=False, error="timed out after 30s"))
    assert run["state"] == "failed"
    assert run["reason_code"] == "timed out after 30s"
    assert run["findings_count"] is None


def test_wrapper_reported_state_is_kept():
    run = _run(_result(success=True, metadata={"state": "parse_error", "reason_code": "bad_json"}))
    assert run["state"] == "parse_error"
    assert run["reason_code"] == "bad_json"


@pytest.mark.parametrize("key", ["output_truncated", "truncated"])
def test_truncated_output_is_never_completed(key):
    run = _run(_result(success=True, findings=[{"a": 1}], metadata={key: True}))
    assert run["state"] == "parse_error"
    assert run["reason_code"] == "output_truncated"
    assert run["truncated"] is True


async def test_phase_runs_are_persisted_to_tool_outputs(db_session):
    target = Target(name="persist", target_type="domain", value="example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="persist", target_id=target.id, profile="quick")
    db_session.add(scan)
    await db_session.commit()

    runs = [{"tool": "httpx", "state": "completed", "findings_count": 3}]
    await tasks._update_phase_status(
        db_session, scan.id, PhaseType.RECON_DISCOVERY, {"status": "completed", "runs": runs}
    )
    await db_session.commit()

    phase = (await db_session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id))).one()
    assert phase.tool_outputs["runs"] == runs
