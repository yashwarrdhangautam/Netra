"""Generate conservative PoC text for high-value findings."""
from __future__ import annotations

from netra.ai.brain import AIBrain
from netra.bugbounty.agentic.poc_static_check import is_safe_poc


class PocBuilder:
    def __init__(self, brain: AIBrain | None = None) -> None:
        self.brain = brain or AIBrain()

    async def build(self, finding: dict, evidence: dict, vuln_class: str) -> str:
        prompt = (
            "Return only one fenced code block in http, bash, or python. "
            "Default to GET/HEAD only and keep it read-only. "
            f"Vuln class: {vuln_class}. Finding: {finding}. Evidence: {evidence}."
        )
        text = await self.brain._query_ollama(prompt)  # noqa: SLF001
        if is_safe_poc(text, allow_post=vuln_class == "csrf"):
            return text
        return "```http\nGET / HTTP/1.1\nHost: example.invalid\n\n```"
