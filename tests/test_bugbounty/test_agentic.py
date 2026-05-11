"""Focused tests for the NETRA-BB agentic loop foundations."""

from __future__ import annotations

from pathlib import Path

import pytest

from netra.bugbounty.agentic.knowledge import FileSystemKnowledgeRetriever, GraphifyKnowledgeRetriever
from netra.bugbounty.agentic.multi_agent import MultiAgentCoordinator
from netra.bugbounty.agentic.observation import observation_from_tool_result
from netra.bugbounty.agentic.executor import AgenticExecutor
from netra.bugbounty.agentic.planner import Planner
from netra.bugbounty.agentic.planner import PlannedStep
from netra.bugbounty.agentic.router import ToolRouter
from netra.bugbounty.agentic.side_effects import SideEffectClass, check
from netra.bugbounty.agentic.tool_registry import TOOL_REGISTRY
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.scanner.tools.base import ToolResult
from netra.services.scan_service import ScanService


class FakeBrain:
    """Stubbed AI brain returning a canned string."""

    def __init__(self, response: str) -> None:
        self.response = response

    async def _query_ollama(self, _prompt: str) -> str:
        return self.response

    async def query_structured(self, *, system_prompt: str, user_prompt: str, provider=None, model=None) -> dict:
        del system_prompt, user_prompt, provider, model
        import json
        return json.loads(self.response)


def test_tool_registry_covers_expected_core_tools() -> None:
    for tool_name in {
        "subfinder",
        "amass",
        "httpx",
        "ffuf",
        "nuclei",
        "gitleaks",
        "semgrep",
        "checkov",
        "trivy",
        "dalfox",
        "sqlmap",
    }:
        assert tool_name in TOOL_REGISTRY


def test_observation_normalizes_httpx_findings() -> None:
    result = ToolResult(
        tool_name="httpx",
        success=True,
        target="https://api.example.com",
        findings=[{"url": "https://api.example.com", "tech": ["next.js", "react"], "status_code": 200}],
        raw_output="",
    )
    observation = observation_from_tool_result(result)
    assert observation.kind == "tech"
    assert observation.derived_facts["tech"] == ["next.js", "react"]


def test_observation_normalizes_nuclei_findings() -> None:
    result = ToolResult(
        tool_name="nuclei",
        success=True,
        target="https://api.example.com",
        findings=[{"template_id": "exposure", "severity": "high"}],
        raw_output="",
    )
    observation = observation_from_tool_result(result)
    assert observation.kind == "findings"
    assert observation.derived_facts["findings"][0]["severity"] == "high"


def test_observation_normalizes_semgrep_and_ffuf_findings() -> None:
    semgrep = ToolResult(
        tool_name="semgrep",
        success=True,
        target="repo",
        findings=[{"rule_id": "python.flask.debug", "severity": "medium", "path": "app.py", "line": 14}],
    )
    ffuf = ToolResult(
        tool_name="ffuf",
        success=True,
        target="https://api.example.com/FUZZ",
        findings=[{"path": "/admin", "status_code": 403}, {"url": "https://api.example.com/metrics", "status_code": 200}],
    )

    semgrep_obs = observation_from_tool_result(semgrep)
    ffuf_obs = observation_from_tool_result(ffuf)

    assert semgrep_obs.kind == "code_findings"
    assert semgrep_obs.derived_facts["code_findings"][0]["rule_id"] == "python.flask.debug"
    assert ffuf_obs.kind == "paths"
    assert ffuf_obs.derived_facts["paths"] == ["/admin", "https://api.example.com/metrics"]
    assert ffuf_obs.derived_facts["interesting_statuses"] == [403, 200]


def test_side_effects_classify_readonly_and_destructive_requests() -> None:
    assert check("GET / HTTP/1.1\nHost: example.com\n").verdict == SideEffectClass.PASSIVE
    assert check("DELETE /users/1 HTTP/1.1\nHost: example.com\n").verdict == SideEffectClass.FORBIDDEN
    assert (
        check("POST /admin/delete HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n")
        .verdict
        == SideEffectClass.FORBIDDEN
    )


@pytest.mark.asyncio
async def test_planner_falls_back_when_no_tech_facts() -> None:
    plan = await Planner(brain=FakeBrain("{}")).make_plan(
        asset_facts={"target": "api.shopify.com", "tech": []},
        scope=["api.shopify.com"],
        corpus_hits=[],
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].suggested_tool == "nuclei"
    assert "agents" in plan.coordination


@pytest.mark.asyncio
async def test_planner_accepts_structured_llm_plan() -> None:
    brain = FakeBrain(
        '{"steps":[{"vuln_class":"idor","target":"api.shopify.com","hypothesis":"object references likely","suggested_tool":"httpx","max_attempts":2,"expected_signal":"exposed ids"}],"rationale":"scored by payout and probability"}'
    )
    plan = await Planner(brain=brain).make_plan(
        asset_facts={"target": "api.shopify.com", "tech": ["next.js", "stripe"]},
        scope=["api.shopify.com"],
        corpus_hits=[],
    )
    assert plan.steps[0].vuln_class == "idor"
    assert plan.steps[0].suggested_tool == "httpx"
    assert plan.coordination["focus_areas"]


@pytest.mark.asyncio
async def test_filesystem_retriever_returns_local_hits(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "ssrf.md").write_text(
        "Shopify webhook SSRF patterns and reflected XSS guidance for internal callback validation.",
        encoding="utf-8",
    )
    retriever = FileSystemKnowledgeRetriever(roots=[docs_dir])
    hits = await retriever.retrieve("shopify webhook ssrf", limit=3)
    assert hits
    assert hits[0].title == "ssrf.md"


@pytest.mark.asyncio
async def test_graphify_retriever_returns_neighbor_snippets(tmp_path: Path) -> None:
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(
        """
        {
          "nodes": [
            {"id": "planner", "label": "Planner", "source_file": "planner.py", "file_type": "code"},
            {"id": "router", "label": "Tool Router", "source_file": "router.py", "file_type": "code"},
            {"id": "scope", "label": "ScopeValidator", "source_file": "scope.py", "file_type": "code"}
          ],
          "links": [
            {"source": "planner", "target": "router", "label": "hands_off_to"},
            {"source": "router", "target": "scope", "label": "validated_by"}
          ]
        }
        """,
        encoding="utf-8",
    )
    retriever = GraphifyKnowledgeRetriever(graph_path=graph_path)
    hits = await retriever.retrieve("planner router", limit=2)
    assert hits
    assert hits[0].title in {"Planner", "Tool Router"}
    assert "hands_off_to" in hits[0].snippet or "validated_by" in hits[0].snippet


@pytest.mark.asyncio
async def test_graphify_retriever_returns_attack_paths(tmp_path: Path) -> None:
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(
        """
        {
          "graph": {
            "hyperedges": [
              {
                "label": "BB Hunt Lifecycle",
                "nodes": ["planner", "router", "scope"],
                "relation": "participate_in",
                "confidence_score": 0.95
              }
            ]
          },
          "nodes": [
            {"id": "planner", "label": "Planner", "source_file": "planner.py", "file_type": "code"},
            {"id": "router", "label": "Tool Router", "source_file": "router.py", "file_type": "code"},
            {"id": "scope", "label": "ScopeValidator", "source_file": "scope.py", "file_type": "code"}
          ],
          "links": []
        }
        """,
        encoding="utf-8",
    )
    retriever = GraphifyKnowledgeRetriever(graph_path=graph_path)
    paths = await retriever.retrieve_attack_paths("planner", limit=2)
    assert paths
    assert paths[0]["name"] == "BB Hunt Lifecycle"


@pytest.mark.asyncio
async def test_multi_agent_coordinator_enriches_context(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "docs"
    corpus_dir.mkdir()
    (corpus_dir / "idor.md").write_text(
        "IDOR patterns in order APIs and SSRF webhook validation weaknesses.",
        encoding="utf-8",
    )
    coordinator = MultiAgentCoordinator(
        brain=FakeBrain("{}"),
        retriever=FileSystemKnowledgeRetriever(roots=[corpus_dir]),
    )
    assessment = await coordinator.assess(
        asset_facts={
            "target": "api.shopify.com",
            "program_handle": "shopify",
            "seed_domains": ["api.shopify.com"],
            "known_hosts": ["api.shopify.com"],
            "tech": ["Next.js", "Stripe"],
            "prior_vuln_classes": ["idor"],
            "active_classes_approved": ["idor", "ssrf"],
        },
        scope=["api.shopify.com"],
        corpus_hits=[],
    )
    assert assessment.focus_areas
    assert any(item in assessment.corpus_hits for item in ["idor.md"])
    assert assessment.agents


@pytest.mark.asyncio
async def test_router_falls_back_to_safe_tool_when_llm_suggests_intrusive_choice() -> None:
    validator = ScopeValidator(
        [ScopeRule(rule_type=RuleType.IN, asset_type=AssetType.DOMAIN, pattern="api.shopify.com")]
    )
    router = ToolRouter(
        brain=FakeBrain('{"tool":"sqlmap","target":"api.shopify.com","flags":{},"rationale":"try sqli"}')
    )
    choice = await router.next_tool(
        plan={"steps": [{"suggested_tool": "sqlmap", "target": "api.shopify.com"}]},
        observations=[],
        validator=validator,
    )
    assert choice.tool == "nuclei"


@pytest.mark.asyncio
async def test_scan_service_persists_agentic_flag(db_session) -> None:
    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.commit()
    await db_session.refresh(program)

    scan = await ScanService(db_session).create_bugbounty_scan(
        program=program,
        profile="passive",
        agentic=True,
        enqueue=False,
    )
    assert scan.config["agentic"] is True


@pytest.mark.asyncio
async def test_scan_service_persists_dry_run_flag(db_session) -> None:
    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.commit()
    await db_session.refresh(program)

    scan = await ScanService(db_session).create_bugbounty_scan(
        program=program,
        profile="passive",
        agentic=True,
        dry_run=True,
        enqueue=False,
    )
    assert scan.config["dry_run"] is True


@pytest.mark.asyncio
async def test_scan_service_persists_celery_task_id_when_enqueued(db_session, monkeypatch) -> None:
    class DummyTask:
        id = "task-123"

    monkeypatch.setattr(
        "netra.services.scan_service.run_bugbounty_scan.delay",
        lambda scan_id: DummyTask(),
    )

    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
    )
    db_session.add(program)
    await db_session.commit()
    await db_session.refresh(program)

    scan = await ScanService(db_session).create_bugbounty_scan(
        program=program,
        profile="passive",
        agentic=True,
        enqueue=True,
    )
    assert scan.config["celery_task_id"] == "task-123"


@pytest.mark.asyncio
async def test_executor_blocks_unapproved_active_class(db_session) -> None:
    program = BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
        active_classes_approved=[],
    )
    db_session.add(program)
    await db_session.commit()
    await db_session.refresh(program)

    executor = AgenticExecutor(db_session)
    blocked = executor._program_allows_step(  # noqa: SLF001
        program,
        PlannedStep(
            vuln_class="xss",
            target="api.shopify.com",
            hypothesis="reflection",
            suggested_tool="httpx",
            max_attempts=1,
            expected_signal="payload reflected",
        ),
        "httpx",
    )
    assert blocked is False

    program.active_classes_approved = ["xss"]
    allowed = executor._program_allows_step(  # noqa: SLF001
        program,
        PlannedStep(
            vuln_class="xss",
            target="api.shopify.com",
            hypothesis="reflection",
            suggested_tool="httpx",
            max_attempts=1,
            expected_signal="payload reflected",
        ),
        "httpx",
    )
    assert allowed is True
