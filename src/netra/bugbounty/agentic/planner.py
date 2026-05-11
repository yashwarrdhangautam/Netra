"""Hypothesis-driven plan generator."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from netra.ai.brain import AIBrain
from netra.bugbounty.agentic.multi_agent import MultiAgentCoordinator, format_assessment_for_prompt
from netra.bugbounty.agentic.priors import load_priors


@dataclass
class PlannedStep:
    vuln_class: str
    target: str
    hypothesis: str
    suggested_tool: str
    max_attempts: int
    expected_signal: str


@dataclass
class TestPlan:
    steps: list[PlannedStep]
    rationale: str = ""
    coordination: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [asdict(step) for step in self.steps],
            "rationale": self.rationale,
            "coordination": self.coordination,
        }


class Planner:
    """Create a bounded test plan from current asset facts."""

    def __init__(
        self,
        brain: AIBrain | None = None,
        coordinator: MultiAgentCoordinator | None = None,
    ) -> None:
        self.brain = brain or AIBrain()
        self.coordinator = coordinator or MultiAgentCoordinator(brain=self.brain)

    async def make_plan(
        self,
        asset_facts: dict[str, Any],
        scope: list[str],
        corpus_hits: list[str] | None = None,
    ) -> TestPlan:
        tech = asset_facts.get("tech", []) or []
        target = asset_facts.get("target") or (scope[0] if scope else "")
        priors = load_priors()
        coordination = await self.coordinator.suggest_plan_metadata(
            asset_facts=asset_facts,
            scope=scope,
            corpus_hits=corpus_hits,
        )
        merged_corpus_hits = list(dict.fromkeys([*(corpus_hits or []), *coordination.get("corpus_hits", [])]))

        if not tech:
            return TestPlan(
                steps=[
                    PlannedStep(
                        vuln_class="generic_exposure",
                        target=target,
                        hypothesis="No strong fingerprint yet; run generic exposure templates first.",
                        suggested_tool="nuclei",
                        max_attempts=1,
                        expected_signal="safe template hit or no finding",
                    )
                ],
                rationale="fallback plan",
                coordination=coordination,
            )

        system_prompt = (
            "You are NETRA's bug bounty hunt orchestrator. Produce JSON only with keys steps and rationale. "
            "Each step must have vuln_class,target,hypothesis,suggested_tool,max_attempts,expected_signal. "
            "Prefer passive or active_readonly tools. Cap steps at 10."
        )
        user_prompt = (
            f"Tech facts: {json.dumps(asset_facts, default=str)}. "
            f"Scope seeds: {json.dumps(scope)}. "
            f"Corpus hits: {json.dumps(merged_corpus_hits)}. "
            f"Priors: {json.dumps(priors.get('tech_priors', {}), default=str)}. "
            f"Specialist coordination: {format_assessment_for_prompt(coordination)}."
        )
        payload = await self._query_structured(system_prompt=system_prompt, user_prompt=user_prompt)
        try:
            steps = [
                PlannedStep(
                    vuln_class=item["vuln_class"],
                    target=item["target"],
                    hypothesis=item["hypothesis"],
                    suggested_tool=item["suggested_tool"],
                    max_attempts=min(int(item.get("max_attempts", 1)), 3),
                    expected_signal=item["expected_signal"],
                )
                for item in payload.get("steps", [])[:10]
            ]
            if steps:
                return TestPlan(
                    steps=steps,
                    rationale=str(payload.get("rationale", "")),
                    coordination=coordination,
                )
        except Exception:
            pass

        recommended_tools = coordination.get("recommended_tools") or []
        fallback_tool = str(recommended_tools[0] if recommended_tools else ("httpx" if tech else "nuclei"))
        return TestPlan(
            steps=[
                PlannedStep(
                    vuln_class="fingerprint_followup",
                    target=target,
                    hypothesis=f"Observed tech stack {', '.join(tech[:4])}; verify stack and collect more signals.",
                    suggested_tool=fallback_tool,
                    max_attempts=1,
                    expected_signal="tech or finding facts",
                )
            ],
            rationale="deterministic fallback",
            coordination=coordination,
        )

    async def _query_structured(self, *, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        if hasattr(self.brain, "query_structured"):
            return await self.brain.query_structured(system_prompt=system_prompt, user_prompt=user_prompt)
        raw = await self.brain._query_ollama(user_prompt)  # type: ignore[attr-defined]  # pragma: no cover
        if isinstance(raw, dict):
            return raw
        return json.loads(raw)
