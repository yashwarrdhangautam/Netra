"""LLM-assisted next-tool routing."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from netra.ai.brain import AIBrain
from netra.bugbounty.agentic.sanitiser import SanitiserError, validate
from netra.bugbounty.agentic.tool_registry import registered_tool_names
from netra.bugbounty.scope import ScopeValidator


@dataclass
class ToolChoice:
    tool: str
    target: str
    flags: dict[str, Any]
    rationale: str = ""
    raw_response: str = ""


class ToolRouter:
    """Pick the next safe tool from a bounded allowlist."""

    def __init__(self, brain: AIBrain | None = None) -> None:
        self.brain = brain or AIBrain()

    async def next_tool(
        self,
        plan: dict[str, Any],
        observations: list[dict[str, Any]],
        validator: ScopeValidator,
        available_tools: list[str] | None = None,
    ) -> ToolChoice:
        allow = sorted(set(available_tools or registered_tool_names()))
        prompt = (
            "Choose the next tool as JSON with keys tool,target,flags,rationale. "
            f"Allowed tools: {json.dumps(allow)}. "
            f"Plan: {json.dumps(plan, default=str)}. "
            f"Observations: {json.dumps(observations[-5:], default=str)}. "
            "Only choose passive or active_readonly actions."
        )
        payload = await self._query_structured(prompt)
        try:
            safe = validate(payload, validator)
            return ToolChoice(
                tool=safe["tool"],
                target=safe["target"],
                flags=safe["flags"],
                rationale=str(payload.get("rationale", "")),
                raw_response=json.dumps(payload),
            )
        except (json.JSONDecodeError, SanitiserError, KeyError, TypeError, ValueError):
            step = (plan.get("steps") or [{}])[0]
            fallback_tool = str(step.get("suggested_tool") or "nuclei")
            if fallback_tool not in {"subfinder", "httpx", "nuclei", "ffuf"}:
                fallback_tool = "nuclei"
            fallback_target = str(step.get("target") or "")
            safe = validate({"tool": fallback_tool, "target": fallback_target, "flags": {}}, validator)
            return ToolChoice(
                tool=safe["tool"],
                target=safe["target"],
                flags=safe["flags"],
                rationale="deterministic fallback",
                raw_response=json.dumps(payload),
            )

    async def _query_structured(self, prompt: str) -> dict[str, Any]:
        if hasattr(self.brain, "query_structured"):
            return await self.brain.query_structured(
                system_prompt="You are NETRA's safe tool router. Return JSON only.",
                user_prompt=prompt,
            )
        raw = await self.brain._query_ollama(prompt)  # type: ignore[attr-defined]  # pragma: no cover
        if isinstance(raw, dict):
            return raw
        return json.loads(raw)
