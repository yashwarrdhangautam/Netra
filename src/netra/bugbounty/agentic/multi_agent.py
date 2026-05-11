"""Named-agent coordination layer for NETRA-BB."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from netra.ai.brain import AIBrain
from netra.bugbounty.agentic.knowledge import (
    KnowledgeRetriever,
    RetrievalHit,
    default_retriever,
)
from netra.bugbounty.agentic.model_routing import AgentModelRouter, AgentRole


@dataclass
class AgentOutput:
    """Normalised output from a specialist agent."""

    role: str
    summary: str
    facts: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""


@dataclass
class MultiAgentAssessment:
    """Merged coordination output used by the planner and operator surfaces."""

    summary: str
    focus_areas: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    corpus_hits: list[str] = field(default_factory=list)
    retrieval_hits: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    report_focus: list[str] = field(default_factory=list)
    agents: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseSpecialistAgent:
    """Base helper for deterministic and LLM-backed specialist agents."""

    def __init__(self, brain: AIBrain, model_router: AgentModelRouter) -> None:
        self.brain = brain
        self.model_router = model_router

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        raise NotImplementedError


class ReconAgent(BaseSpecialistAgent):
    """Summarise what we already know about scope and assets."""

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        known_hosts = list(context.get("known_hosts") or [])
        seed_domains = list(context.get("seed_domains") or [])
        return AgentOutput(
            role=AgentRole.RECON,
            summary=f"{len(seed_domains)} seed domains and {len(known_hosts)} known hosts available for planning.",
            facts={
                "seed_domains": seed_domains[:10],
                "known_hosts": known_hosts[:20],
                "approved_active_classes": list(context.get("active_classes_approved") or []),
            },
            recommendations=["subfinder" if not known_hosts else "httpx"],
        )


class ServiceAnalystAgent(BaseSpecialistAgent):
    """Turn asset facts into concrete focus areas."""

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        tech = [str(item).strip() for item in (context.get("tech") or []) if str(item).strip()]
        focus: list[str] = []
        if any("next" in item.lower() for item in tech):
            focus.append("nextjs_routes_and_api_handlers")
        if any("stripe" in item.lower() for item in tech):
            focus.append("webhook_validation_and_idor")
        if any("cloudflare" in item.lower() for item in tech):
            focus.append("origin_exposure_and_cache_behaviour")
        if not focus:
            focus.append("generic_exposure_review")
        route = self.model_router.route(AgentRole.SERVICE_ANALYST)
        return AgentOutput(
            role=AgentRole.SERVICE_ANALYST,
            summary=f"Primary stack cues: {', '.join(tech[:5]) or 'none yet'}.",
            facts={"tech": tech[:20], "focus_areas": focus},
            recommendations=["httpx", "nuclei"],
            model=route.model,
            provider=route.provider,
        )


class SecurityExpertAgent(BaseSpecialistAgent):
    """Bring in corpus evidence and likely vuln classes."""

    def __init__(
        self,
        brain: AIBrain,
        model_router: AgentModelRouter,
        retriever: KnowledgeRetriever,
    ) -> None:
        super().__init__(brain, model_router)
        self.retriever = retriever

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        tech = list(context.get("tech") or [])
        priors = list(context.get("prior_vuln_classes") or [])
        query = " ".join([*tech[:5], *priors[:5], str(context.get("program_handle") or "")]).strip()
        retrieval_hits = await self.retriever.retrieve(query, limit=5)
        route = self.model_router.route(AgentRole.SECURITY_EXPERT)
        likely_classes = self._likely_classes(tech, priors, retrieval_hits)
        return AgentOutput(
            role=AgentRole.SECURITY_EXPERT,
            summary=f"Retrieved {len(retrieval_hits)} local knowledge hits for {query or 'current target'}.",
            facts={
                "likely_vuln_classes": likely_classes,
                "retrieval_hits": [asdict(hit) for hit in retrieval_hits],
            },
            recommendations=["nuclei", "httpx"] if likely_classes else ["nuclei"],
            model=route.model,
            provider=route.provider,
        )

    def _likely_classes(
        self,
        tech: list[Any],
        priors: list[Any],
        retrieval_hits: list[RetrievalHit],
    ) -> list[str]:
        classes: list[str] = [str(item).strip().lower() for item in priors if str(item).strip()]
        joined = " ".join(
            [
                *[str(item) for item in tech],
                *[hit.title for hit in retrieval_hits],
                *[hit.snippet for hit in retrieval_hits],
            ]
        ).lower()
        mapping = {
            "ssrf": ["ssrf", "metadata service", "webhook"],
            "idor": ["idor", "object reference", "orders", "account"],
            "xss": ["xss", "javascript", "reflection"],
            "sqli": ["sql", "database", "injection"],
            "exposure": ["exposure", "misconfig", "public bucket"],
        }
        for vuln_class, needles in mapping.items():
            if vuln_class in classes:
                continue
            if any(needle in joined for needle in needles):
                classes.append(vuln_class)
        return classes[:8]


class AttackPathAgent(BaseSpecialistAgent):
    """Generate deterministic chain hypotheses from current facts."""

    def __init__(
        self,
        brain: AIBrain,
        model_router: AgentModelRouter,
        retriever: KnowledgeRetriever,
    ) -> None:
        super().__init__(brain, model_router)
        self.retriever = retriever

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        likely = list(context.get("likely_vuln_classes") or [])
        attack_paths: list[dict[str, Any]] = []
        if "idor" in likely and "ssrf" in likely:
            attack_paths.append(
                {
                    "name": "idor_to_internal_data_exposure",
                    "steps": ["idor", "ssrf"],
                    "narrative": "An exposed object reference could feed internal-facing resource discovery.",
                }
            )
        if "xss" in likely and "idor" in likely:
            attack_paths.append(
                {
                    "name": "xss_to_account_takeover_signal",
                    "steps": ["xss", "idor"],
                    "narrative": "Browser-side execution combined with weak object controls may widen account-impact scope.",
                }
            )
        query = " ".join(
            [
                *[str(item) for item in context.get("tech", [])[:5]],
                *[str(item) for item in likely[:5]],
                str(context.get("program_handle") or ""),
            ]
        ).strip()
        if hasattr(self.retriever, "retrieve_attack_paths"):
            graph_paths = await self.retriever.retrieve_attack_paths(query, limit=5)  # type: ignore[attr-defined]
            for item in graph_paths:
                attack_paths.append(
                    {
                        "name": item.get("name"),
                        "steps": str(item.get("steps", "")).split(" -> ") if item.get("steps") else [],
                        "narrative": item.get("narrative"),
                        "source": "graphify",
                        "score": item.get("score"),
                    }
                )
        route = self.model_router.route(AgentRole.ATTACK_PATH)
        return AgentOutput(
            role=AgentRole.ATTACK_PATH,
            summary=f"Built {len(attack_paths)} candidate attack paths.",
            facts={"attack_paths": attack_paths},
            recommendations=["nuclei" if attack_paths else "httpx"],
            model=route.model,
            provider=route.provider,
        )


class ReportSynthAgent(BaseSpecialistAgent):
    """Describe what evidence will matter if a finding lands."""

    async def run(self, context: dict[str, Any]) -> AgentOutput:
        likely = list(context.get("likely_vuln_classes") or [])
        report_focus = ["clear reproduction", "scope proof", "impact narrative"]
        if "idor" in likely:
            report_focus.append("object identifier comparison")
        if "ssrf" in likely:
            report_focus.append("request/response diff and internal target proof")
        route = self.model_router.route(AgentRole.REPORT_SYNTH)
        return AgentOutput(
            role=AgentRole.REPORT_SYNTH,
            summary="Prepared reporting priorities for any confirmed finding.",
            facts={"report_focus": report_focus[:6]},
            recommendations=[],
            model=route.model,
            provider=route.provider,
        )


class MultiAgentCoordinator:
    """Coordinate named specialist agents and merge their outputs."""

    def __init__(
        self,
        *,
        brain: AIBrain | None = None,
        retriever: KnowledgeRetriever | None = None,
        model_router: AgentModelRouter | None = None,
    ) -> None:
        self.brain = brain or AIBrain()
        self.retriever = retriever or default_retriever()
        self.model_router = model_router or AgentModelRouter()
        self.agents = [
            ReconAgent(self.brain, self.model_router),
            ServiceAnalystAgent(self.brain, self.model_router),
            SecurityExpertAgent(self.brain, self.model_router, self.retriever),
            AttackPathAgent(self.brain, self.model_router, self.retriever),
            ReportSynthAgent(self.brain, self.model_router),
        ]

    async def assess(
        self,
        *,
        asset_facts: dict[str, Any],
        scope: list[str],
        corpus_hits: list[str] | None = None,
    ) -> MultiAgentAssessment:
        merged_context = {**asset_facts, "scope": scope}
        agent_outputs: list[AgentOutput] = []
        aggregated_hits = list(corpus_hits or [])

        for agent in self.agents:
            output = await agent.run(merged_context)
            agent_outputs.append(output)
            merged_context.update(output.facts)
            if output.role == AgentRole.SECURITY_EXPERT:
                aggregated_hits.extend(
                    [
                        hit.get("title", "")
                        for hit in output.facts.get("retrieval_hits", [])
                        if hit.get("title")
                    ]
                )

        focus_areas = self._dedupe(
            [
                *merged_context.get("focus_areas", []),
                *merged_context.get("likely_vuln_classes", []),
            ]
        )
        recommended_tools = self._dedupe(
            recommendation
            for output in agent_outputs
            for recommendation in output.recommendations
        )
        summary = " | ".join(output.summary for output in agent_outputs if output.summary)

        return MultiAgentAssessment(
            summary=summary,
            focus_areas=focus_areas[:10],
            recommended_tools=recommended_tools[:10],
            corpus_hits=self._dedupe(aggregated_hits)[:10],
            retrieval_hits=merged_context.get("retrieval_hits", []),
            attack_paths=merged_context.get("attack_paths", [])[:5],
            report_focus=merged_context.get("report_focus", [])[:8],
            agents=[
                {
                    "role": str(output.role),
                    "summary": output.summary,
                    "facts": output.facts,
                    "recommendations": output.recommendations,
                    "provider": output.provider,
                    "model": output.model,
                }
                for output in agent_outputs
            ],
        )

    async def suggest_plan_metadata(
        self,
        *,
        asset_facts: dict[str, Any],
        scope: list[str],
        corpus_hits: list[str] | None = None,
    ) -> dict[str, Any]:
        """Produce orchestration context for the planner prompt."""
        assessment = await self.assess(asset_facts=asset_facts, scope=scope, corpus_hits=corpus_hits)
        route = self.model_router.route(AgentRole.ORCHESTRATOR)
        payload = assessment.to_dict()
        payload["orchestrator_model"] = route.model
        payload["orchestrator_provider"] = route.provider
        payload["orchestrator_reason"] = route.reason
        return payload

    def _dedupe(self, values: Any) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for item in values:
            value = str(item).strip()
            if not value:
                continue
            lowered = value.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            output.append(value)
        return output


def format_assessment_for_prompt(assessment: dict[str, Any]) -> str:
    """Compact JSON string for planner prompts."""
    return json.dumps(assessment, default=str)
