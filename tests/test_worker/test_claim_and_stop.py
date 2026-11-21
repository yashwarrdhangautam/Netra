"""Atomic claim, boundary stop and cancel/pause behaviour (spec 6.6)."""

import uuid

import pytest

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.target import Target
from netra.worker import tasks


async def _scan(db, status=ScanStatus.PENDING):
    target = Target(name="claim-test", target_type="domain", value="example.org")
    db.add(target)
    await db.flush()
    scan = Scan(name="claim", target_id=target.id, profile="quick", status=status)
    db.add(scan)
    await db.commit()
    return scan


async def test_duplicate_delivery_claims_only_once(db_session):
    scan = await _scan(db_session)
    assert await tasks._claim_scan(db_session, scan.id) is True
    assert await tasks._claim_scan(db_session, scan.id) is False


@pytest.mark.parametrize(
    "status",
    [ScanStatus.RUNNING, ScanStatus.CANCELLED, ScanStatus.COMPLETED],
)
async def test_claim_refuses_active_or_terminal_scans(db_session, status):
    scan = await _scan(db_session, status=status)
    assert await tasks._claim_scan(db_session, scan.id) is False
    await db_session.refresh(scan)
    assert scan.status == status


@pytest.mark.parametrize("status", [ScanStatus.PAUSED, ScanStatus.FAILED])
async def test_resume_states_can_be_claimed(db_session, status):
    scan = await _scan(db_session, status=status)
    assert await tasks._claim_scan(db_session, scan.id) is True
    await db_session.refresh(scan)
    assert scan.status == ScanStatus.RUNNING


@pytest.mark.parametrize("status", [ScanStatus.CANCELLED, ScanStatus.PAUSED])
async def test_stop_requested_for_cancel_and_pause(db_session, status):
    scan = await _scan(db_session, status=status)
    assert await tasks._stop_requested(db_session, scan.id) is True


async def test_running_scan_is_not_stopped(db_session):
    scan = await _scan(db_session, status=ScanStatus.RUNNING)
    assert await tasks._stop_requested(db_session, scan.id) is False


def test_boundary_returns_stopped_without_running_phase(monkeypatch):
    calls = []

    async def stop_requested(*_args):
        return True

    @tasks._stop_at_boundary
    def phase(self, previous_result, scan_id):
        calls.append(scan_id)
        return {"status": "completed"}

    monkeypatch.setattr(tasks, "_in_session", stop_requested)
    scan_id = str(uuid.uuid4())
    result = phase(None, {}, scan_id=scan_id)
    assert result == {"scan_id": scan_id, "phase": "phase", "status": "stopped", "stopped": True}
    assert calls == []


def test_boundary_runs_phase_when_not_stopped(monkeypatch):
    async def keep_going(*_args):
        return False

    @tasks._stop_at_boundary
    def phase(self, previous_result, scan_id):
        return {"status": "completed", "previous": previous_result}

    monkeypatch.setattr(tasks, "_in_session", keep_going)
    result = phase(None, {"x": 1}, scan_id=str(uuid.uuid4()))
    assert result == {"status": "completed", "previous": {"x": 1}}
