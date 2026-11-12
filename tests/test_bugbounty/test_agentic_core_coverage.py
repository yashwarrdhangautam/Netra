"""Coverage-focused tests for the agentic core: executor, observation, planner, knowledge, priors.

Everything external is mocked: LLM calls (fake brains), subprocess tools (fake
wrappers), DB sessions (AsyncMock), finding persistence, and the tiktoken
encoder (which may download a vocabulary on first use).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from netra.bugbounty.agentic import knowledge as knowledge_mod
from netra.bugbounty.agentic import priors as priors_mod
from netra.bugbounty.agentic import token_budget
from netra.bugbounty.agentic.budget import HuntBudget
from netra.bugbounty.agentic.executor import AgenticExecutor
from netra.bugbounty.agentic.knowledge import (
    CompositeKnowledgeRetriever,
    FileSystemKnowledgeRetriever,
    GraphifyKnowledgeRetriever,
    KnowledgeRetriever,
    NullKnowledgeRetriever,
    RetrievalHit,
    default_retriever,
)
from netra.bugbounty.agentic.observation import Observation, observation_from_tool_result
from netra.bugbounty.agentic.planner import PlannedStep, Planner
from netra.bugbounty.agentic.planner import TestPlan as AgenticPlan
from netra.bugbounty.agentic.router import ToolChoice, ToolRouter
from netra.bugbounty.agentic.sanitiser import SanitiserError, validate
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.finding import Severity
from netra.db.models.scan import ScanStatus
from netra.scanner.tools.base import ToolResult

# ---------------------------------------------------------------------------
# Shared fakes and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_tiktoken(monkeypatch):
    """Force the chars/4 heuristic so no tokenizer vocabulary is fetched."""
    monkeypatch.setattr(token_budget, "_encoder", lambda: None)


class FakeBrain:
    """Brain exposing query_structured (returns a canned dict or JSON string)."""

    def __init__(self, response):
        self.response = response
        self.prompts: list[str] = []

    async def query_structured(self, *, system_prompt, user_prompt, provider=None, model=None):
        del system_prompt, provider, model
        self.prompts.append(user_prompt)
        if isinstance(self.response, Exception):
            raise self.response
        if isinstance(self.response, str):
            return json.loads(self.response)
        return self.response


class OllamaOnlyBrain:
    """Brain without query_structured: exercises the _query_ollama fallback path."""

    def __init__(self, response):
        self.response = response

    async def _query_ollama(self, _prompt):
        return self.response


class FakeCoordinator:
    def __init__(self, metadata=None):
        self.metadata = metadata or {
            "agents": [],
            "focus_areas": ["idor"],
            "recommended_tools": [],
            "corpus_hits": [],
        }
        self.suggest_plan_metadata = AsyncMock(return_value=self.metadata)


class FakeRouter:
    def __init__(self, choices):
        self.choices = list(choices)
        self.calls: list[dict] = []

    async def next_tool(self, **kwargs):
        self.calls.append(kwargs)
        return self.choices.pop(0)


def _db(status=ScanStatus.RUNNING):
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.get = AsyncMock(return_value=SimpleNamespace(status=status))
    return db


def _scan():
    import uuid

    return SimpleNamespace(id=uuid.uuid4())


def _step(tool="httpx", vuln_class="generic", target="api.shopify.com"):
    return PlannedStep(
        vuln_class=vuln_class,
        target=target,
        hypothesis="hypothesis",
        suggested_tool=tool,
        max_attempts=1,
        expected_signal="signal",
    )


def _plan(*steps):
    return AgenticPlan(steps=list(steps) or [_step()], rationale="test")


def _choice(tool="httpx", target="api.shopify.com", flags=None):
    return ToolChoice(tool=tool, target=target, flags=dict(flags or {}), raw_response="{}")


def _program(approved=None):
    return BBProgram(
        platform=BBPlatform.HACKERONE,
        handle="shopify",
        name="Shopify",
        currency="USD",
        active_classes_approved=approved if approved is not None else ["generic"],
    )


def _validator():
    return ScopeValidator(
        [ScopeRule(rule_type=RuleType.IN, asset_type=AssetType.DOMAIN, pattern="api.shopify.com")]
    )


def _record_tool(monkeypatch, class_name, tool_name, findings=None):
    """Replace a tool wrapper inside the executor module with a recorder."""
    calls: list[tuple[str, dict]] = []

    class Fake:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def run(self, target, **kwargs):
            calls.append((target, kwargs))
            return ToolResult(
                tool_name=tool_name,
                success=True,
                target=target,
                findings=[dict(f) for f in (findings or [])],
            )

    monkeypatch.setattr(f"netra.bugbounty.agentic.executor.{class_name}", Fake)
    return calls


def _patch_finding_service(monkeypatch, *, created=True):
    service = MagicMock()
    if created:
        service.create_finding_from_tool = AsyncMock(return_value=SimpleNamespace(severity=None))
    else:
        service.create_finding_from_tool = AsyncMock(return_value=None)
    service._normalize_severity = MagicMock(return_value=Severity.HIGH)
    factory = MagicMock(return_value=service)
    monkeypatch.setattr("netra.services.finding_service.FindingService", factory)
    return service


# ---------------------------------------------------------------------------
# executor.py
# ---------------------------------------------------------------------------


async def test_run_plan_confirms_step_and_creates_findings(monkeypatch) -> None:
    _record_tool(
        monkeypatch,
        "HttpxTool",
        "httpx",
        findings=[{"severity": "high", "title": "exposed"}],
    )
    service = _patch_finding_service(monkeypatch)
    db = _db()
    router = FakeRouter([_choice("httpx")])

    result = await AgenticExecutor(db, router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert result["created_findings"] == 1
    assert len(result["observations"]) == 1
    assert result["observations"][0]["tool_name"] == "httpx"
    service.create_finding_from_tool.assert_awaited_once()
    step_row = db.add.call_args_list[2].args[0]
    assert step_row.status == "confirmed"
    assert step_row.decision_rationale == "hypothesis"
    plan_row = db.add.call_args_list[0].args[0]
    assert plan_row.status == "completed"
    assert plan_row.completed_at is not None


async def test_run_plan_marks_step_exhausted_when_no_findings(monkeypatch) -> None:
    _record_tool(monkeypatch, "HttpxTool", "httpx", findings=[])
    _patch_finding_service(monkeypatch)
    db = _db()

    result = await AgenticExecutor(db, router=FakeRouter([_choice("httpx")])).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert result["created_findings"] == 0
    assert db.add.call_args_list[2].args[0].status == "exhausted"


async def test_run_plan_skips_persisting_finding_when_service_returns_none(monkeypatch) -> None:
    _record_tool(monkeypatch, "HttpxTool", "httpx", findings=[{"severity": "low", "title": "x"}])
    service = _patch_finding_service(monkeypatch, created=False)

    result = await AgenticExecutor(_db(), router=FakeRouter([_choice("httpx")])).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert result["created_findings"] == 1
    service._normalize_severity.assert_not_called()


async def test_run_plan_dry_run_never_executes_tools(monkeypatch) -> None:
    calls = _record_tool(monkeypatch, "HttpxTool", "httpx")
    db = _db()
    router = FakeRouter([_choice("httpx")])

    result = await AgenticExecutor(db, router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
        dry_run=True,
    )

    assert calls == []
    assert result["observations"] == []
    assert db.add.call_args_list[0].args[0].status == "dry_run"
    assert db.add.call_args_list[2].args[0].status == "skipped"


async def test_run_plan_blocks_active_step_for_unapproved_vuln_class(monkeypatch) -> None:
    calls = _record_tool(monkeypatch, "NucleiTool", "nuclei")
    db = _db()

    result = await AgenticExecutor(db, router=FakeRouter([_choice("nuclei")])).run_plan(
        scan=_scan(),
        program=_program(approved=[]),
        plan=_plan(_step("nuclei", vuln_class="xss")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert calls == []
    assert result["observations"] == []
    step_row = db.add.call_args_list[2].args[0]
    assert step_row.status == "blocked"
    assert "xss" in step_row.decision_rationale


async def test_run_plan_stops_when_tool_budget_exhausted(monkeypatch) -> None:
    calls = _record_tool(monkeypatch, "HttpxTool", "httpx")
    _patch_finding_service(monkeypatch)
    router = FakeRouter([_choice("httpx"), _choice("httpx")])
    budget = HuntBudget(max_tools=1)

    result = await AgenticExecutor(_db(), router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx"), _step("httpx")),
        validator=_validator(),
        budget=budget,
    )

    assert len(calls) == 1
    assert len(router.calls) == 1
    assert len(result["observations"]) == 1


async def test_run_plan_stops_when_token_budget_exhausted(monkeypatch) -> None:
    _record_tool(monkeypatch, "HttpxTool", "httpx")
    _patch_finding_service(monkeypatch)
    router = FakeRouter([_choice("httpx"), _choice("httpx")])
    budget = HuntBudget(max_tokens=1)

    await AgenticExecutor(_db(), router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx"), _step("httpx")),
        validator=_validator(),
        budget=budget,
    )

    assert len(router.calls) == 1
    assert budget.tokens_used > 0


async def test_run_plan_returns_cancelled_when_scan_cancelled(monkeypatch) -> None:
    calls = _record_tool(monkeypatch, "HttpxTool", "httpx")
    db = _db(status=ScanStatus.CANCELLED)
    router = FakeRouter([_choice("httpx")])

    result = await AgenticExecutor(db, router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert result["cancelled"] is True
    assert calls == []
    assert db.add.call_args_list[0].args[0].status == "cancelled"


async def test_is_cancelled_treats_missing_scan_as_cancelled() -> None:
    db = _db()
    db.get = AsyncMock(return_value=None)
    assert await AgenticExecutor(db, router=FakeRouter([]))._is_cancelled(_scan().id) is True


async def test_is_cancelled_false_for_running_scan() -> None:
    assert await AgenticExecutor(_db(), router=FakeRouter([]))._is_cancelled(_scan().id) is False


async def test_program_allows_step_rules(monkeypatch) -> None:
    executor = AgenticExecutor(_db(), router=FakeRouter([]))
    approved = _program(approved=["  XSS  ", ""])

    # Unknown tools are never allowed.
    assert executor._program_allows_step(approved, _step("bogus"), "bogus") is False  # noqa: SLF001
    # Passive tools never need vuln-class approval.
    assert executor._program_allows_step(_program(), _step("subfinder"), "subfinder") is True  # noqa: SLF001
    # Active tools need the (case-insensitive) vuln class approved.
    assert executor._program_allows_step(approved, _step(vuln_class="xss"), "nuclei") is True  # noqa: SLF001
    assert executor._program_allows_step(approved, _step(vuln_class="sqli"), "nuclei") is False  # noqa: SLF001
    # None approvals are treated as empty.
    none_program = _program()
    none_program.active_classes_approved = None
    assert (
        executor._program_allows_step(none_program, _step(vuln_class="xss"), "nuclei") is False  # noqa: SLF001
    )


@pytest.mark.parametrize(
    ("tool", "class_name", "expected_kwargs"),
    [
        ("subfinder", "SubfinderTool", {"passive_only": True}),
        ("httpx", "HttpxTool", {"head": True, "tech_detect": True}),
        (
            "nuclei",
            "NucleiTool",
            {"tags": "cve,exposure,misconfig", "severity": "critical,high,medium"},
        ),
        ("ffuf", "FfufTool", {}),
    ],
)
async def test_execute_choice_dispatches_each_supported_tool(
    monkeypatch, tool, class_name, expected_kwargs
) -> None:
    calls = _record_tool(monkeypatch, class_name, tool)
    executor = AgenticExecutor(_db(), router=FakeRouter([]))

    result = await executor._execute_choice(  # noqa: SLF001
        _choice(tool, target="api.shopify.com", flags={"extra": 1})
    )

    assert result.tool_name == tool
    assert calls == [("api.shopify.com", {**expected_kwargs, "extra": 1})]


@pytest.mark.parametrize("tool", ["amass", "gitleaks", "not-a-real-tool"])
async def test_execute_choice_rejects_unsupported_tools(tool) -> None:
    executor = AgenticExecutor(_db(), router=FakeRouter([]))
    with pytest.raises(ValueError, match="Unsupported tool choice"):
        await executor._execute_choice(_choice(tool))  # noqa: SLF001


async def test_run_plan_scope_is_enforced_by_executor_not_only_router(monkeypatch) -> None:
    """Intended: an out-of-scope target never reaches a tool, even if the router returns it."""
    calls = _record_tool(monkeypatch, "HttpxTool", "httpx")
    _patch_finding_service(monkeypatch)
    db = _db()
    router = FakeRouter([_choice("httpx", target="evil.example.com")])

    result = await AgenticExecutor(db, router=router).run_plan(
        scan=_scan(),
        program=_program(),
        plan=_plan(_step("httpx")),
        validator=_validator(),
        budget=HuntBudget(),
    )

    assert calls == []
    assert result["observations"] == []
    step_row = db.add.call_args_list[2].args[0]
    assert step_row.status == "blocked"
    assert "out of scope" in step_row.decision_rationale


async def test_execute_choice_nuclei_rejects_flags_that_override_defaults(monkeypatch) -> None:
    # Regression for the crash: a 'tags' or 'severity' flag used to raise a bare TypeError
    # (duplicate keyword). Now it is refused with a clear error and no tool runs.
    from netra.scanner.tools.nuclei import NucleiTool

    calls: list[object] = []

    async def fake_exec(self, args, stdin=None, timeout=300):  # noqa: ANN001
        del self, stdin, timeout
        calls.append(args)
        return ToolResult(tool_name="nuclei", success=True, target="x", raw_output="")

    monkeypatch.setattr(NucleiTool, "_exec", fake_exec)
    executor = AgenticExecutor(_db(), router=FakeRouter([]))
    with pytest.raises(ValueError, match="cannot override executor defaults: \\['tags'\\]"):
        await executor._execute_choice(  # noqa: SLF001
            _choice("nuclei", flags={"tags": "panel"})
        )
    assert calls == []


async def test_execute_choice_nuclei_passes_non_conflicting_flags(monkeypatch) -> None:
    from netra.scanner.tools.nuclei import NucleiTool

    async def fake_exec(self, args, stdin=None, timeout=300):  # noqa: ANN001
        del self, args, stdin, timeout
        return ToolResult(tool_name="nuclei", success=True, target="x", raw_output="")

    monkeypatch.setattr(NucleiTool, "_exec", fake_exec)
    executor = AgenticExecutor(_db(), router=FakeRouter([]))
    result = await executor._execute_choice(  # noqa: SLF001
        _choice("nuclei", flags={"rate_limit": 10})
    )
    assert result.tool_name == "nuclei"


# ---------------------------------------------------------------------------
# observation.py
# ---------------------------------------------------------------------------


def test_observation_to_dict_serialises_timestamp() -> None:
    ts = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    obs = Observation(tool_name="t", target="x", ts=ts, kind="generic")
    row = obs.to_dict()
    assert row["ts"] == ts.isoformat()
    assert row["payload"] == {}
    assert row["derived_facts"] == {}


def test_observation_uses_now_when_completed_at_missing() -> None:
    result = ToolResult(tool_name="unknown", success=False, target="t", completed_at=None)
    obs = observation_from_tool_result(result)
    assert obs.ts.tzinfo is not None
    assert obs.kind == "generic"
    assert obs.payload == {"success": False, "metadata": {}, "error": None}


def test_observation_hosts_dedupes_and_skips_blank_entries() -> None:
    result = ToolResult(
        tool_name="amass",
        success=True,
        target="example.com",
        findings=[
            {"hostname": "A.example.com"},
            {"url": "a.example.com"},
            {"hostname": "   "},
            {"other": "ignored"},
            {"hostname": "b.example.com"},
        ],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "hosts"
    assert obs.derived_facts["hosts"] == ["A.example.com", "b.example.com"]


def test_observation_httpx_collects_tech_titles_and_status_codes() -> None:
    result = ToolResult(
        tool_name="httpx",
        success=True,
        target="https://x",
        findings=[
            {"tech": ["React", "react"], "title": "Home", "status_code": 200},
            {"tech": [], "title": "home", "status_code": None},
            {"tech": ["Next.js"], "title": None, "status_code": 301},
        ],
    )
    facts = observation_from_tool_result(result).derived_facts
    assert facts["tech"] == ["React", "Next.js"]
    assert facts["titles"] == ["Home"]
    assert facts["status_codes"] == [200, 301]


def test_observation_nuclei_falls_back_to_host_and_url_keys() -> None:
    result = ToolResult(
        tool_name="nuclei",
        success=True,
        target="t",
        findings=[
            {"template_id": "a", "title": "T", "host": "h.example", "tags": ["cve"]},
            {"template_id": "b", "url": "https://u.example", "name": "N"},
        ],
    )
    findings = observation_from_tool_result(result).derived_facts["findings"]
    assert findings[0]["name"] == "T"
    assert findings[0]["matched_at"] == "h.example"
    assert findings[1]["matched_at"] == "https://u.example"
    assert findings[1]["tags"] == []
    assert observation_from_tool_result(result).derived_facts["vuln_classes"] == ["cve"]


def test_observation_dalfox_style_findings_normalise_fields() -> None:
    result = ToolResult(
        tool_name="dalfox",
        success=True,
        target="t",
        findings=[{"name": "XSS", "severity": "high", "url": "u", "parameter": "q"}],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "findings"
    assert obs.derived_facts["findings"] == [
        {"title": "XSS", "severity": "high", "url": "u", "parameter": "q"}
    ]


def test_observation_semgrep_uses_nested_start_line_fallback() -> None:
    result = ToolResult(
        tool_name="semgrep",
        success=True,
        target="repo",
        findings=[
            {"check_id": "rule.a", "start": {"line": 7}, "file": "a.py"},
            {"rule_id": "rule.b", "line": 3, "path": "b.py", "severity": "low"},
        ],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "code_findings"
    assert obs.derived_facts["code_findings"] == [
        {"rule_id": "rule.a", "severity": None, "path": "a.py", "line": 7},
        {"rule_id": "rule.b", "severity": "low", "path": "b.py", "line": 3},
    ]


def test_observation_ffuf_collects_paths_and_interesting_statuses() -> None:
    result = ToolResult(
        tool_name="ffuf",
        success=True,
        target="https://api.example.com/FUZZ",
        findings=[
            {"path": "/admin", "status_code": 403},
            {"url": "https://api.example.com/admin", "status_code": None},
            {"path": "/admin", "status_code": 200},
            {"path": "", "url": "", "status_code": 500},
        ],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "paths"
    assert obs.derived_facts["paths"] == ["/admin", "https://api.example.com/admin"]
    assert obs.derived_facts["interesting_statuses"] == [403, 200, 500]


def test_observation_gitleaks_maps_secret_hits() -> None:
    result = ToolResult(
        tool_name="gitleaks",
        success=True,
        target="repo",
        findings=[{"rule": "aws-key", "path": "cfg.env", "title": "AWS key"}],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "secrets"
    assert obs.derived_facts["secret_hits"] == [
        {"rule_id": "aws-key", "file": "cfg.env", "description": "AWS key"}
    ]


@pytest.mark.parametrize("tool", ["pip-audit", "trivy", "checkov", "prowler"])
def test_observation_risk_tools_share_risk_findings_shape(tool) -> None:
    result = ToolResult(
        tool_name=tool,
        success=True,
        target="t",
        findings=[{"check_id": "CKV_1", "resource": "bucket", "name": "Open bucket"}],
    )
    obs = observation_from_tool_result(result)
    assert obs.kind == "risk_findings"
    assert obs.derived_facts["risk_findings"] == [
        {"id": "CKV_1", "severity": None, "target": "bucket", "title": "Open bucket"}
    ]


# ---------------------------------------------------------------------------
# planner.py
# ---------------------------------------------------------------------------


@pytest.fixture
def no_priors(monkeypatch):
    monkeypatch.setattr("netra.bugbounty.agentic.planner.load_priors", lambda: {"tech_priors": {}})


async def test_planner_no_tech_fallback_uses_scope_seed_when_target_missing(no_priors) -> None:
    coordinator = FakeCoordinator({"agents": [], "corpus_hits": ["c-hit"]})
    plan = await Planner(brain=FakeBrain({}), coordinator=coordinator).make_plan(
        asset_facts={"tech": []},
        scope=["seed.example.com"],
        corpus_hits=["c-hit", "other"],
    )
    assert plan.rationale == "fallback plan"
    assert plan.steps[0].target == "seed.example.com"
    assert plan.coordination["corpus_hits"] == ["c-hit"]
    coordinator.suggest_plan_metadata.assert_awaited_once()


async def test_planner_no_tech_and_no_scope_gives_empty_target(no_priors) -> None:
    plan = await Planner(brain=FakeBrain({}), coordinator=FakeCoordinator()).make_plan(
        asset_facts={}, scope=[], corpus_hits=None
    )
    assert plan.steps[0].target == ""
    assert plan.steps[0].suggested_tool == "nuclei"


async def test_planner_structured_plan_caps_steps_and_attempts(no_priors) -> None:
    steps = [
        {
            "vuln_class": f"class{i}",
            "target": "api.shopify.com",
            "hypothesis": "h",
            "suggested_tool": "httpx",
            "max_attempts": 9,
            "expected_signal": "s",
        }
        for i in range(12)
    ]
    brain = FakeBrain({"steps": steps, "rationale": "ranked"})
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"target": "api.shopify.com", "tech": ["react"]},
        scope=["api.shopify.com"],
    )
    assert len(plan.steps) == 10
    assert all(step.max_attempts == 3 for step in plan.steps)
    assert plan.rationale == "ranked"
    assert "Tech facts" in brain.prompts[0]


async def test_planner_default_max_attempts_is_one(no_priors) -> None:
    brain = FakeBrain(
        {
            "steps": [
                {
                    "vuln_class": "idor",
                    "target": "t",
                    "hypothesis": "h",
                    "suggested_tool": "httpx",
                    "expected_signal": "s",
                }
            ]
        }
    )
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"tech": ["react"]}, scope=[]
    )
    assert plan.steps[0].max_attempts == 1
    assert plan.rationale == ""


async def test_planner_malformed_payload_falls_back_to_recommended_tool(no_priors) -> None:
    coordinator = FakeCoordinator({"recommended_tools": ["ffuf", "httpx"], "corpus_hits": []})
    brain = FakeBrain({"steps": [{"vuln_class": "idor"}]})  # missing required keys
    plan = await Planner(brain=brain, coordinator=coordinator).make_plan(
        asset_facts={"target": "api.shopify.com", "tech": ["next.js", "stripe", "a", "b", "c"]},
        scope=["api.shopify.com"],
    )
    assert plan.rationale == "deterministic fallback"
    assert plan.steps[0].vuln_class == "fingerprint_followup"
    assert plan.steps[0].suggested_tool == "ffuf"
    assert plan.steps[0].hypothesis.startswith("Observed tech stack next.js, stripe, a, b")


async def test_planner_empty_steps_fall_back_to_httpx(no_priors) -> None:
    brain = FakeBrain({"steps": [], "rationale": "nothing"})
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"target": "t", "tech": ["react"]}, scope=["t"]
    )
    assert plan.steps[0].suggested_tool == "httpx"
    assert plan.steps[0].target == "t"


async def test_planner_non_list_steps_fall_back(no_priors) -> None:
    brain = FakeBrain({"steps": "not-a-list"})
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"tech": ["react"]}, scope=[]
    )
    assert plan.rationale == "deterministic fallback"


async def test_planner_query_failure_propagates(no_priors) -> None:
    brain = FakeBrain(RuntimeError("llm unavailable"))
    with pytest.raises(RuntimeError, match="llm unavailable"):
        await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
            asset_facts={"tech": ["react"]}, scope=[]
        )


async def test_planner_uses_ollama_fallback_when_no_structured_query(no_priors) -> None:
    brain = OllamaOnlyBrain(json.dumps({"steps": [], "rationale": "x"}))
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"tech": ["react"]}, scope=[]
    )
    assert plan.rationale == "deterministic fallback"


async def test_planner_ollama_fallback_accepts_dict_response(no_priors) -> None:
    brain = OllamaOnlyBrain(
        {
            "steps": [
                {
                    "vuln_class": "ssrf",
                    "target": "t",
                    "hypothesis": "h",
                    "suggested_tool": "nuclei",
                    "max_attempts": 2,
                    "expected_signal": "s",
                }
            ],
            "rationale": "dict path",
        }
    )
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"tech": ["react"]}, scope=[]
    )
    assert plan.steps[0].vuln_class == "ssrf"
    assert plan.rationale == "dict path"


async def test_planner_fallback_defaults_to_httpx_without_recommendations(no_priors) -> None:
    brain = FakeBrain({"steps": []})
    plan = await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"target": "t", "tech": ["react"]}, scope=[]
    )
    assert plan.steps[0].suggested_tool == "httpx"


async def test_planner_loads_priors_into_prompt(monkeypatch) -> None:
    monkeypatch.setattr(
        "netra.bugbounty.agentic.planner.load_priors",
        lambda: {"tech_priors": {"react": [{"vuln_class": "xss"}]}},
    )
    brain = FakeBrain({"steps": []})
    await Planner(brain=brain, coordinator=FakeCoordinator()).make_plan(
        asset_facts={"tech": ["react"]}, scope=[]
    )
    assert "react" in brain.prompts[0]
    assert "xss" in brain.prompts[0]


def test_test_plan_to_dict_round_trips_steps() -> None:
    plan = AgenticPlan(steps=[_step("httpx")], rationale="r", coordination={"k": 1})
    data = plan.to_dict()
    assert data["steps"][0]["suggested_tool"] == "httpx"
    assert data["rationale"] == "r"
    assert data["coordination"] == {"k": 1}


# ---------------------------------------------------------------------------
# priors.py
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_priors_cache():
    priors_mod.load_priors.cache_clear()
    yield
    priors_mod.load_priors.cache_clear()


def test_load_priors_returns_empty_when_file_missing(monkeypatch, tmp_path, clean_priors_cache):
    monkeypatch.setattr(priors_mod, "PRIORS_PATH", tmp_path / "absent.yaml")
    assert priors_mod.load_priors() == {}


def test_load_priors_parses_file_and_caches_result(monkeypatch, tmp_path, clean_priors_cache):
    path = tmp_path / "priors.yaml"
    path.write_text(json.dumps({"tech_priors": {"react": []}}), encoding="utf-8")
    monkeypatch.setattr(priors_mod, "PRIORS_PATH", path)

    first = priors_mod.load_priors()
    path.write_text(json.dumps({"tech_priors": {"changed": []}}), encoding="utf-8")
    second = priors_mod.load_priors()

    assert first == {"tech_priors": {"react": []}}
    assert second is first


def test_reload_priors_picks_up_changed_file(monkeypatch, tmp_path, clean_priors_cache):
    path = tmp_path / "priors.yaml"
    path.write_text(json.dumps({"v": 1}), encoding="utf-8")
    monkeypatch.setattr(priors_mod, "PRIORS_PATH", path)
    assert priors_mod.load_priors() == {"v": 1}

    path.write_text(json.dumps({"v": 2}), encoding="utf-8")
    assert priors_mod.reload_priors() == {"v": 2}


def test_shipped_priors_file_is_valid_json_with_tech_priors(clean_priors_cache) -> None:
    data = priors_mod.load_priors()
    assert isinstance(data, dict)
    assert "tech_priors" in data


# ---------------------------------------------------------------------------
# knowledge.py
# ---------------------------------------------------------------------------


async def test_base_retriever_is_abstract() -> None:
    with pytest.raises(NotImplementedError):
        await KnowledgeRetriever().retrieve("anything")


async def test_null_retriever_returns_no_hits() -> None:
    assert await NullKnowledgeRetriever().retrieve("idor") == []


async def test_composite_dedupes_by_source_and_title_keeping_best_score() -> None:
    class Static(KnowledgeRetriever):
        def __init__(self, hits):
            self.hits = hits

        async def retrieve(self, query, *, limit=5):
            del query, limit
            return list(self.hits)

    low = RetrievalHit(source="a", title="T", snippet="low", score=1.0)
    high = RetrievalHit(source="a", title="T", snippet="high", score=5.0)
    other = RetrievalHit(source="b", title="U", snippet="u", score=3.0)
    composite = CompositeKnowledgeRetriever([Static([low, other]), Static([high])])

    hits = await composite.retrieve("q", limit=5)

    assert [hit.snippet for hit in hits] == ["high", "u"]


async def test_composite_respects_limit() -> None:
    class Static(KnowledgeRetriever):
        async def retrieve(self, query, *, limit=5):
            del query, limit
            return [
                RetrievalHit(source="s", title=f"t{i}", snippet="", score=float(i))
                for i in range(4)
            ]

    hits = await CompositeKnowledgeRetriever([Static()]).retrieve("q", limit=2)
    assert [hit.title for hit in hits] == ["t3", "t2"]


def _graph_file(tmp_path: Path, payload) -> Path:
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


async def test_graphify_retriever_missing_graph_returns_nothing(tmp_path: Path) -> None:
    retriever = GraphifyKnowledgeRetriever(graph_path=tmp_path / "nope.json")
    assert await retriever.retrieve("planner router") == []
    assert await retriever.retrieve_attack_paths("planner router") == []


async def test_graphify_retriever_invalid_json_is_treated_as_missing(tmp_path: Path) -> None:
    path = tmp_path / "graph.json"
    path.write_text("{not json", encoding="utf-8")
    retriever = GraphifyKnowledgeRetriever(graph_path=path)
    assert await retriever.retrieve("planner router") == []
    assert retriever._graph is None  # noqa: SLF001


async def test_graphify_retriever_short_terms_return_nothing(tmp_path: Path) -> None:
    path = _graph_file(tmp_path, {"nodes": [{"id": "a", "label": "ab"}], "links": []})
    retriever = GraphifyKnowledgeRetriever(graph_path=path)
    assert await retriever.retrieve("a b") == []
    assert await retriever.retrieve_attack_paths("a b") == []


async def test_graphify_retriever_no_matching_node_returns_nothing(tmp_path: Path) -> None:
    path = _graph_file(tmp_path, {"nodes": [{"id": "a", "label": "Planner"}], "links": []})
    assert await GraphifyKnowledgeRetriever(graph_path=path).retrieve("kubernetes") == []


async def test_graphify_retriever_snippet_for_isolated_node_and_truncation(tmp_path: Path) -> None:
    long_label = "Planner " + ("x" * 400)
    path = _graph_file(
        tmp_path,
        {
            "nodes": [{"id": "p", "label": long_label, "source": "planner.py"}],
            "links": [],
        },
    )
    hits = await GraphifyKnowledgeRetriever(graph_path=path).retrieve("planner")
    assert hits[0].snippet == long_label[:280]
    assert hits[0].source == "planner.py"
    assert hits[0].title == long_label


async def test_graphify_retriever_edge_where_node_is_target(tmp_path: Path) -> None:
    path = _graph_file(
        tmp_path,
        {
            "nodes": [
                {"id": "router", "label": "Tool Router", "source_file": "router.py"},
                {"id": "planner", "label": "Planner", "source_file": "planner.py"},
            ],
            "links": [{"source": "planner", "target": "router", "label": "hands_off_to"}],
        },
    )
    hits = await GraphifyKnowledgeRetriever(graph_path=path).retrieve("router")
    assert hits[0].snippet == "Tool Router -[hands_off_to]-> Planner"


async def test_graphify_retriever_caches_loaded_graph(tmp_path: Path) -> None:
    path = _graph_file(tmp_path, {"nodes": [{"id": "p", "label": "Planner"}], "links": []})
    retriever = GraphifyKnowledgeRetriever(graph_path=path)
    await retriever.retrieve("planner")
    path.unlink()
    assert await retriever.retrieve("planner")


async def test_graphify_attack_paths_from_links_and_hyperedge_defaults(tmp_path: Path) -> None:
    path = _graph_file(
        tmp_path,
        {
            "graph": {
                "hyperedges": [
                    {"label": "", "nodes": ["planner", "router"], "relation": "r"},
                    {"label": "Other", "nodes": ["zzz"], "relation": "r"},
                ]
            },
            "nodes": [
                {"id": "planner", "label": "Planner", "source_file": "p.py"},
                {"id": "router", "label": "Tool Router", "source_file": "r.py"},
            ],
            "links": [
                {"source": "planner", "target": "router", "label": "hands_off_to"},
                {"source": "x", "target": "y", "label": "unrelated"},
            ],
        },
    )
    paths = await GraphifyKnowledgeRetriever(graph_path=path).retrieve_attack_paths(
        "planner", limit=5
    )
    names = {item["name"] for item in paths}
    assert "graphify_hyperedge" in names
    assert "Planner to Tool Router" in names
    assert all(item["name"] != "x to y" for item in paths)
    hyper = next(item for item in paths if item["name"] == "graphify_hyperedge")
    assert hyper["score"] == 0.5
    assert hyper["steps"] == "Planner -> Tool Router"


async def test_graphify_attack_paths_dedupe_keeps_highest_score(tmp_path: Path) -> None:
    path = _graph_file(
        tmp_path,
        {
            "graph": {
                "hyperedges": [
                    {"label": "Same", "nodes": ["a"], "relation": "r", "confidence_score": 0.2},
                    {"label": "Same", "nodes": ["a"], "relation": "r", "confidence_score": 0.9},
                ]
            },
            "nodes": [{"id": "a", "label": "Alpha"}],
            "links": [],
        },
    )
    paths = await GraphifyKnowledgeRetriever(graph_path=path).retrieve_attack_paths("alpha")
    assert len(paths) == 1
    assert paths[0]["score"] == 0.9


async def test_graphify_attack_paths_no_terms_or_graph(tmp_path: Path) -> None:
    path = _graph_file(tmp_path, {"nodes": [], "links": []})
    retriever = GraphifyKnowledgeRetriever(graph_path=path)
    assert await retriever.retrieve_attack_paths("ab") == []
    assert await retriever.retrieve_attack_paths("nothing-matches") == []


def test_graphify_default_path_points_at_repo_graph() -> None:
    retriever = GraphifyKnowledgeRetriever()
    assert retriever.graph_path.parts[-2:] == ("graphify-out", "graph.json")


async def test_filesystem_retriever_skips_missing_roots_and_short_terms(tmp_path: Path) -> None:
    retriever = FileSystemKnowledgeRetriever(roots=[tmp_path / "missing"])
    assert await retriever.retrieve("planner router") == []
    assert await FileSystemKnowledgeRetriever(roots=[tmp_path]).retrieve("a b") == []


async def test_filesystem_retriever_ignores_unreadable_candidates(tmp_path: Path) -> None:
    (tmp_path / "dir.md").mkdir()  # matches the *.md glob but cannot be read as text
    (tmp_path / "good.txt").write_text("planner notes about routing", encoding="utf-8")
    hits = await FileSystemKnowledgeRetriever(roots=[tmp_path]).retrieve("planner routing")
    assert [hit.title for hit in hits] == ["good.txt"]
    assert "planner" in hits[0].snippet


async def test_filesystem_retriever_no_match_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("nothing relevant", encoding="utf-8")
    assert await FileSystemKnowledgeRetriever(roots=[tmp_path]).retrieve("kubernetes") == []


def test_filesystem_extract_snippet_handles_missing_term_and_radius() -> None:
    retriever = FileSystemKnowledgeRetriever(roots=[])
    assert retriever._extract_snippet("short text", "zzz") == "short text"  # noqa: SLF001
    long_text = "a" * 50 + "needle" + "b" * 500
    snippet = retriever._extract_snippet(long_text, "needle", radius=40)  # noqa: SLF001
    assert "needle" in snippet
    assert len(snippet) <= 40


def test_default_retriever_without_graph_uses_filesystem_only(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        knowledge_mod,
        "GraphifyKnowledgeRetriever",
        lambda: GraphifyKnowledgeRetriever(graph_path=tmp_path / "absent.json"),
    )
    assert isinstance(default_retriever(), FileSystemKnowledgeRetriever)


def test_default_retriever_with_graph_composes_both(monkeypatch, tmp_path: Path) -> None:
    graph = _graph_file(tmp_path, {"nodes": [], "links": []})
    monkeypatch.setattr(
        knowledge_mod,
        "GraphifyKnowledgeRetriever",
        lambda: GraphifyKnowledgeRetriever(graph_path=graph),
    )
    retriever = default_retriever()
    assert isinstance(retriever, CompositeKnowledgeRetriever)
    assert isinstance(retriever.retrievers[0], GraphifyKnowledgeRetriever)
    assert isinstance(retriever.retrievers[1], FileSystemKnowledgeRetriever)


# ---------------------------------------------------------------------------
# Router/sanitiser safety findings (tool dispatch boundary feeding the executor)
# ---------------------------------------------------------------------------


async def test_router_llm_choice_is_limited_to_available_tools() -> None:
    """Intended: the LLM may only pick from available_tools, as the prompt states."""
    router = ToolRouter(
        brain=FakeBrain(
            '{"tool":"nuclei","target":"api.shopify.com","flags":{},"rationale":"scan"}'
        )
    )
    choice = await router.next_tool(
        plan={"steps": [{"suggested_tool": "subfinder", "target": "api.shopify.com"}]},
        observations=[],
        validator=_validator(),
        available_tools=["subfinder"],
    )
    assert choice.tool == "subfinder"


async def test_sanitiser_rejects_non_mapping_flags() -> None:
    with pytest.raises(SanitiserError, match="flags must be a mapping"):
        validate(
            {"tool": "httpx", "target": "api.shopify.com", "flags": ["--x"]},
            _validator(),
        )


async def test_sanitiser_drops_path_flag_outside_approved_wordlists() -> None:
    # Regression for the safety fix: a wordlist path outside the approved directory is
    # dropped before it reaches the tool, instead of being forwarded into **kwargs.
    result = validate(
        {
            "tool": "ffuf",
            "target": "https://api.shopify.com/FUZZ",
            "flags": {"wordlist": "/etc/passwd"},
        },
        _validator(),
    )
    assert "wordlist" not in result["flags"]
