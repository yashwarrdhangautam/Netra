"""Task-boundary coverage for bug bounty worker execution."""

from __future__ import annotations

import asyncio

import pytest

from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.finding import Finding, FindingStatus, Severity
from netra.db.models.scan import Scan, ScanProfile, ScanStatus
from netra.db.models.target import Target, TargetType
from netra.worker import tasks


@pytest.mark.asyncio
async def test_run_bugbounty_scan_sets_task_id_and_completes(monkeypatch, db_session) -> None:
    async def fake_execute(self):  # noqa: ANN001
        scan = await self.db.get(Scan, self.scan_id)
        finding = Finding(
            scan_id=scan.id,
            title="Agentic test finding",
            description="created by worker test",
            severity=Severity.INFO,
            status=FindingStatus.NEW,
            tool_source="httpx",
        )
        self.db.add(finding)
        scan.status = ScanStatus.COMPLETED
        await self.db.commit()

    async def _keep_session_open() -> None:
        return None

    monkeypatch.setattr(tasks, "_get_db_session", lambda: db_session)
    monkeypatch.setattr(tasks, "_task_request_id", lambda _task: "celery-task-1")
    monkeypatch.setattr("netra.scanner.orchestrator.ScanOrchestrator.execute", fake_execute)
    monkeypatch.setattr(db_session, "close", _keep_session_open)

    program = BBProgram(platform=BBPlatform.HACKERONE, handle="shopify", name="Shopify", currency="USD")
    db_session.add(program)
    await db_session.flush()
    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        status=ScanStatus.PENDING,
        config={"program_id": str(program.id), "agentic": True},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    result = await asyncio.to_thread(tasks.run_bugbounty_scan.run, str(scan.id))

    await db_session.refresh(scan)
    assert result["status"] == "completed"
    assert result["findings"] == 1
    assert scan.status == ScanStatus.COMPLETED
    assert scan.config["celery_task_id"] == "celery-task-1"
    assert scan.checkpoint_data["findings_summary"]["total"] == 1


@pytest.mark.asyncio
async def test_run_bugbounty_scan_marks_failure_on_exception(monkeypatch, db_session) -> None:
    async def fake_execute(self):  # noqa: ANN001
        raise RuntimeError("boom")

    killed: list[str] = []

    async def _keep_session_open() -> None:
        return None

    monkeypatch.setattr(tasks, "_get_db_session", lambda: db_session)
    monkeypatch.setattr(tasks, "_task_request_id", lambda _task: "celery-task-2")
    monkeypatch.setattr(tasks, "kill_registered_processes", lambda task_id: killed.append(task_id) or [])
    monkeypatch.setattr("netra.scanner.orchestrator.ScanOrchestrator.execute", fake_execute)
    monkeypatch.setattr(db_session, "close", _keep_session_open)

    program = BBProgram(platform=BBPlatform.HACKERONE, handle="shopify", name="Shopify", currency="USD")
    db_session.add(program)
    await db_session.flush()
    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        status=ScanStatus.PENDING,
        config={"program_id": str(program.id), "agentic": True},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    result = await asyncio.to_thread(tasks.run_bugbounty_scan.run, str(scan.id))

    await db_session.refresh(scan)
    assert result["status"] == "failed"
    assert "boom" in result["error"]
    assert scan.status == ScanStatus.FAILED
    assert "boom" in (scan.error_message or "")
    assert killed == ["celery-task-2"]


@pytest.mark.asyncio
async def test_learning_ingest_tasks_delegate_to_sources(monkeypatch, db_session) -> None:
    async def _keep_session_open() -> None:
        return None

    async def fake_hacktivity(session, since_days=1):  # noqa: ANN001
        return {"added": 1, "updated": 0}

    async def fake_advisories(session):  # noqa: ANN001
        return {"added": 2, "updated": 0}

    async def fake_writeups(session):  # noqa: ANN001
        return {"added": 3, "updated": 0}

    monkeypatch.setattr(tasks, "_get_db_session", lambda: db_session)
    monkeypatch.setattr(db_session, "close", _keep_session_open)
    monkeypatch.setattr("netra.bugbounty.learning.sources.hackerone.ingest_hacktivity", fake_hacktivity)
    monkeypatch.setattr("netra.bugbounty.learning.sources.advisories.ingest_advisories", fake_advisories)
    monkeypatch.setattr("netra.bugbounty.learning.sources.rss.ingest_public_writeups", fake_writeups)

    hack = await asyncio.to_thread(tasks.ingest_hacktivity_daily.run)
    advisories = await asyncio.to_thread(tasks.ingest_advisories_daily.run)
    writeups = await asyncio.to_thread(tasks.ingest_public_writeups.run)

    assert hack["added"] == 1
    assert advisories["added"] == 2
    assert writeups["added"] == 3
