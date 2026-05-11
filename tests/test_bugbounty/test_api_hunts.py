"""API-level tests for bug bounty hunt controls."""

from __future__ import annotations

import pytest

from netra.worker.celery_app import celery_app
from netra.db.models import Finding, Severity
from netra.db.models.bb_agentic_step import BBAgenticStep
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.scan import Scan, ScanProfile, ScanStatus
from netra.db.models.target import Target, TargetType


@pytest.mark.asyncio
async def test_cancel_hunt_revokes_task_and_kills_registered_processes(client, db_session, monkeypatch) -> None:
    revoked: list[tuple[str, bool, str]] = []
    killed: list[str] = []

    monkeypatch.setattr(
        celery_app.control,
        "revoke",
        lambda task_id, terminate, signal: revoked.append((task_id, terminate, signal)),
    )
    monkeypatch.setattr(
        "netra.scanner.tools.process_control.kill_registered_processes",
        lambda task_id: killed.append(task_id) or [],
    )

    program = BBProgram(platform=BBPlatform.HACKERONE, handle="shopify", name="Shopify", currency="USD")
    db_session.add(program)
    await db_session.flush()
    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="NETRA-BB shopify passive",
        target_id=target.id,
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        status=ScanStatus.RUNNING,
        config={"program_id": str(program.id), "agentic": True, "celery_task_id": "task-77"},
    )
    db_session.add(scan)
    await db_session.commit()

    response = await client.post(f"/api/v1/bb/hunts/{scan.id}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert revoked == [("task-77", True, "SIGKILL")]
    assert killed == ["task-77"]


@pytest.mark.asyncio
async def test_explain_hunt_returns_agentic_steps(client, db_session) -> None:
    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="NETRA-BB shopify passive",
        target_id=target.id,
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        status=ScanStatus.COMPLETED,
        config={"agentic": True},
        checkpoint_data={
            "agentic_coordination": {
                "summary": "Graph-backed planner context",
                "focus_areas": ["idor", "ssrf"],
                "recommended_tools": ["httpx", "nuclei"],
                "retrieval_hits": [{"title": "Planner", "source": "graph.json", "snippet": "Planner -> Router"}],
                "attack_paths": [{"name": "Planner to Scope", "steps": ["Planner", "ScopeValidator"], "narrative": "control path"}],
            }
        },
    )
    db_session.add(scan)
    await db_session.flush()
    db_session.add(
        BBAgenticStep(
            scan_id=scan.id,
            step_n=1,
            status="confirmed",
            tool_chosen="httpx",
            decision_rationale="safe stack fingerprint first",
            observations_in={"count": 0},
            observations_out={"kind": "tech"},
            metadata_={"target": "api.shopify.com"},
        )
    )
    await db_session.commit()

    response = await client.get(f"/api/v1/bb/hunts/{scan.id}/explain")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == "Graph-backed planner context"
    assert body["retrieval_hits"][0]["title"] == "Planner"
    assert len(body["steps"]) == 1
    assert body["steps"][0]["tool_chosen"] == "httpx"
    assert body["steps"][0]["observations_out"]["kind"] == "tech"


@pytest.mark.asyncio
async def test_plan_preview_returns_coordination(client, db_session) -> None:
    program = BBProgram(platform=BBPlatform.HACKERONE, handle="shopify", name="Shopify", currency="USD")
    db_session.add(program)
    await db_session.commit()

    response = await client.post(
        "/api/v1/bb/hunts/plan-preview",
        json={"program_id": str(program.id), "asset": "api.shopify.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "coordination" in body
    assert "steps" in body


@pytest.mark.asyncio
async def test_finding_similar_reports_returns_corpus_hits(client, db_session, monkeypatch) -> None:
    async def fake_build_corpus_context(*args, **kwargs):  # noqa: ANN002, ANN003
        return ["[reports] Shopify IDOR :: similar report (https://example.com/report)"]

    monkeypatch.setattr("netra.bugbounty.learning.search.build_corpus_context", fake_build_corpus_context)

    program = BBProgram(platform=BBPlatform.HACKERONE, handle="shopify", name="Shopify", currency="USD")
    db_session.add(program)
    await db_session.flush()
    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="NETRA-BB shopify passive",
        target_id=target.id,
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        status=ScanStatus.COMPLETED,
        config={"program_id": str(program.id)},
    )
    db_session.add(scan)
    await db_session.flush()
    finding = Finding(
        scan_id=scan.id,
        title="Shopify order IDOR",
        description="Predictable order identifiers",
        severity=Severity.HIGH,
        url="https://api.shopify.com/orders/1",
        tags=["idor"],
        tool_source="nuclei",
    )
    db_session.add(finding)
    await db_session.commit()

    response = await client.get(f"/api/v1/bb/findings/{finding.id}/similar-reports")
    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == str(finding.id)
    assert body["similar_reports"]
