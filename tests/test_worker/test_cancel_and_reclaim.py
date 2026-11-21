"""Cancel stops a running tool; a crashed worker's RUNNING scan can be reclaimed."""

import asyncio
import os
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.target import Target
from netra.scanner.tools import base as tool_base
from netra.scanner.tools.base import CliTool
from netra.worker import tasks


@pytest.fixture(scope="module")
def event_loop_policy():
    # Subprocess tools need the Proactor loop on Windows; the root conftest selects Selector.
    if os.name == "nt":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


class _SleepTool(CliTool):
    binary = sys.executable
    tool_name = "sleeper"


async def test_cancel_kills_the_running_tool_process(tmp_path, monkeypatch):
    script = tmp_path / "sleep_forever.py"
    script.write_text("import time\ntime.sleep(120)\n")
    monkeypatch.setattr(tool_base, "GUARD_INTERVAL_SECONDS", 0.2)

    async def cancelled() -> bool:
        return True

    token = tool_base.RUN_GUARD.set(cancelled)
    started = time.monotonic()
    try:
        result = await _SleepTool(work_dir=tmp_path)._exec([str(script)], timeout=60)
    finally:
        tool_base.RUN_GUARD.reset(token)

    assert time.monotonic() - started < 30, "the tool was not stopped"
    assert result.success is False
    assert result.metadata["reason_code"] == "cancelled"
    assert result.metadata["state"] == "failed"


async def test_guard_error_does_not_stop_a_healthy_tool(tmp_path, monkeypatch):
    script = tmp_path / "quick.py"
    script.write_text("print('done')\n")
    monkeypatch.setattr(tool_base, "GUARD_INTERVAL_SECONDS", 0.05)

    async def broken() -> bool:
        raise RuntimeError("database unavailable")

    token = tool_base.RUN_GUARD.set(broken)
    try:
        result = await _SleepTool(work_dir=tmp_path)._exec([str(script)], timeout=60)
    finally:
        tool_base.RUN_GUARD.reset(token)

    assert result.success is True
    assert "done" in result.raw_output


async def _scan_with_heartbeat(db, *, status: ScanStatus, age: timedelta) -> Scan:
    target = Target(
        name=f"reclaim-{uuid.uuid4().hex[:6]}", target_type="url", value="https://example.org"
    )
    db.add(target)
    await db.flush()
    scan = Scan(name="reclaim", target_id=target.id, profile="standard", status=status)
    db.add(scan)
    await db.flush()
    scan.updated_at = datetime.now(UTC) - age
    await db.commit()
    return scan


async def test_stale_running_scan_can_be_claimed_again(db_session):
    scan = await _scan_with_heartbeat(db_session, status=ScanStatus.RUNNING, age=timedelta(hours=1))

    assert await tasks._claim_scan(db_session, scan.id) is True


async def test_live_running_scan_is_not_taken_over(db_session):
    scan = await _scan_with_heartbeat(
        db_session, status=ScanStatus.RUNNING, age=timedelta(minutes=2)
    )

    assert await tasks._claim_scan(db_session, scan.id) is False


async def test_reclaim_sweep_finds_only_stale_running_scans(db_session):
    stale = await _scan_with_heartbeat(
        db_session, status=ScanStatus.RUNNING, age=timedelta(hours=1)
    )
    await _scan_with_heartbeat(db_session, status=ScanStatus.RUNNING, age=timedelta(minutes=2))
    await _scan_with_heartbeat(db_session, status=ScanStatus.COMPLETED, age=timedelta(hours=5))

    found = await tasks._stale_running_scan_ids(db_session)

    assert found == [stale.id]
