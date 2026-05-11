"""Integration-ish coverage for the agentic bug bounty orchestrator path."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netra.bugbounty.agentic.planner import PlannedStep, TestPlan as AgenticPlan
from netra.db.models import BBCorpusReport
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.bb_scope_rule import BBScopeRule, ScopeAssetType, ScopeRuleType
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan, ScanProfile, ScanStatus
from netra.db.models.target import Target, TargetType
from netra.scanner.orchestrator import ScanOrchestrator
from netra.scanner.tools.base import ToolResult


class StubPlanner:
    async def make_plan(self, asset_facts, scope, corpus_hits):  # noqa: ANN001
        return AgenticPlan(
            steps=[
                PlannedStep(
                    vuln_class="xss",
                    target="api.shopify.com",
                    hypothesis="collect tech and response metadata first",
                    suggested_tool="httpx",
                    max_attempts=1,
                    expected_signal="httpx tech facts",
                )
            ],
            rationale="test planner",
        )


@pytest.mark.asyncio
async def test_agentic_orchestrator_creates_findings_and_checkpoint(monkeypatch, db_session) -> None:
    async def fake_httpx_run(self, target, **kwargs):  # noqa: ANN001
        return ToolResult(
            tool_name="httpx",
            success=True,
            target=target,
            findings=[
                {
                    "title": "Discovered tech stack",
                    "description": "httpx saw next.js headers",
                    "severity": "info",
                    "url": f"https://{target}",
                    "evidence": {"tech": ["next.js", "react"]},
                    "tags": ["tech-fingerprint"],
                }
            ],
        )

    async def fake_ai_analysis(self, scan):  # noqa: ANN001
        return None

    async def fake_next_tool(self, plan, observations, validator, available_tools=None):  # noqa: ANN001
        from netra.bugbounty.agentic.router import ToolChoice

        return ToolChoice(
            tool="httpx",
            target="api.shopify.com",
            flags={},
            rationale="safe readonly follow-up",
            raw_response="{}",
        )

    async def fake_build_corpus_context(session, query, *, top_k=5, filters=None):  # noqa: ANN001
        del session, query, top_k, filters
        return ["[reports] Shopify reflected XSS :: Public disclosed report about a reflected XSS pattern."]

    monkeypatch.setattr("netra.bugbounty.agentic.planner.Planner.make_plan", StubPlanner().make_plan)
    monkeypatch.setattr("netra.scanner.tools.httpx.HttpxTool.run", fake_httpx_run)
    monkeypatch.setattr("netra.bugbounty.agentic.router.ToolRouter.next_tool", fake_next_tool)
    monkeypatch.setattr("netra.scanner.orchestrator.ScanOrchestrator._run_ai_analysis", fake_ai_analysis)
    monkeypatch.setattr("netra.bugbounty.learning.search.build_corpus_context", fake_build_corpus_context)

    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
        active_classes_approved=["xss"],
    )
    db_session.add(program)
    await db_session.flush()

    rule = BBScopeRule(
        program_id=program.id,
        rule_type=ScopeRuleType.IN,
        asset_type=ScopeAssetType.DOMAIN,
        pattern="api.shopify.com",
        active=True,
    )
    db_session.add(rule)
    await db_session.flush()

    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/disclosed-shopify-idor",
            author_handle="researcher",
            program_handle="shopify",
            vuln_class="xss",
            severity="medium",
            title="Shopify reflected XSS",
            body_summary="Public disclosed report about a reflected XSS pattern on Shopify APIs.",
            tech_stack=["next.js"],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            ingested_at=datetime.now(timezone.utc),
        )
    )
    await db_session.flush()

    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        status=ScanStatus.PENDING,
        config={
            "program_id": str(program.id),
            "program_handle": "shopify",
            "platform": "hackerone",
            "agentic": True,
            "dry_run": False,
        },
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    orchestrator = ScanOrchestrator(db_session, scan.id)
    await orchestrator.execute()

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.checkpoint_data["agentic"] is True
    assert scan.checkpoint_data["bb_program_handle"] == "shopify"
    assert scan.checkpoint_data["agentic_corpus_hits"]
    assert len(scan.checkpoint_data["agentic_observations"]) == 1

    findings = (await db_session.execute(
        Finding.__table__.select().where(Finding.scan_id == scan.id)
    )).all()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_agentic_executor_honors_cancelled_scan(monkeypatch, db_session) -> None:
    async def fake_ai_analysis(self, scan):  # noqa: ANN001
        return None

    monkeypatch.setattr("netra.bugbounty.agentic.planner.Planner.make_plan", StubPlanner().make_plan)
    monkeypatch.setattr("netra.scanner.orchestrator.ScanOrchestrator._run_ai_analysis", fake_ai_analysis)

    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.flush()

    rule = BBScopeRule(
        program_id=program.id,
        rule_type=ScopeRuleType.IN,
        asset_type=ScopeAssetType.DOMAIN,
        pattern="api.shopify.com",
        active=True,
    )
    db_session.add(rule)
    await db_session.flush()

    target = Target(name="bb:shopify", target_type=TargetType.DOMAIN, value="shopify")
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        name="Bug bounty passive hunt: shopify",
        profile=ScanProfile.BUGBOUNTY_PASSIVE,
        target_id=target.id,
        status=ScanStatus.CANCELLED,
        config={
            "program_id": str(program.id),
            "program_handle": "shopify",
            "platform": "hackerone",
            "agentic": True,
            "dry_run": False,
        },
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    orchestrator = ScanOrchestrator(db_session, scan.id)
    await orchestrator.execute()

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.CANCELLED
