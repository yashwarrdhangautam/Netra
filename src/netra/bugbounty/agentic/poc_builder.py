"""Generate conservative PoC text for high-value findings."""

from __future__ import annotations

from netra.ai.brain import AIBrain
from netra.bugbounty.agentic.poc_static_check import is_safe_poc


FALLBACK_POC = "```http\nGET / HTTP/1.1\nHost: example.invalid\n\n```"

_SYSTEM_PROMPT = (
    "You write one read-only proof-of-concept for a bug bounty finding. "
    'Respond with a JSON object: {"poc": "<exactly one fenced code block in http, bash, or python>"}. '
    "Default to GET/HEAD only."
)


class PocBuilder:
    def __init__(self, brain: AIBrain | None = None) -> None:
        self.brain = brain or AIBrain()

    async def build(self, finding: dict, evidence: dict, vuln_class: str) -> str:
        user_prompt = f"Vuln class: {vuln_class}. Finding: {finding}. Evidence: {evidence}."
        # The generic query forces JSON output and returns the parsed object.
        result = await self.brain._query_ollama_generic(_SYSTEM_PROMPT, user_prompt)  # noqa: SLF001
        text = result.get("poc") if isinstance(result, dict) else None
        # Missing, empty, or unsafe output fails closed to the static fallback.
        if isinstance(text, str) and text.strip() and is_safe_poc(text, allow_post=vuln_class == "csrf"):
            return text
        return FALLBACK_POC
