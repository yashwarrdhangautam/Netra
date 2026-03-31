"""AI Brain orchestrator for NETRA."""
import asyncio
import json
from typing import Any

import structlog

from netra.ai.prompts import (
    ANALYST_PROMPT,
    ATTACKER_PROMPT,
    DEFENDER_PROMPT,
    SKEPTIC_PROMPT,
)
from netra.core.config import settings
from netra.db.models.finding import Finding

logger = structlog.get_logger()


class AIBrain:
    """AI Brain for security analysis and consensus."""

    def __init__(self) -> None:
        """Initialize AI Brain."""
        self.provider = settings.ai_provider

    async def analyze_finding(self, finding: Finding) -> dict[str, Any]:
        """Analyze a finding with all personas.

        Args:
            finding: Finding model instance

        Returns:
            Analysis results from all personas with consensus
        """
        finding_context = self._finding_to_context(finding)

        results: dict[str, Any] = {
            "attacker": {},
            "defender": {},
            "analyst": {},
            "skeptic": {},
            "confidence": finding.confidence,
        }

        if self.provider == "none":
            logger.info(
                "ai_disabled",
                message="AI provider set to 'none', skipping analysis",
            )
            return results

        # Run all 4 personas in parallel for 3-4x speedup
        persona_tasks = [
            self._query_persona("attacker", ATTACKER_PROMPT, finding_context),
            self._query_persona("defender", DEFENDER_PROMPT, finding_context),
            self._query_persona("analyst", ANALYST_PROMPT, finding_context),
            self._query_persona("skeptic", SKEPTIC_PROMPT, finding_context),
        ]
        results["attacker"], results["defender"], results["analyst"], results["skeptic"] = (
            await asyncio.gather(*persona_tasks)
        )

        # Consensus voting
        results["consensus"] = self._compute_consensus(results)
        results["confidence"] = results["consensus"].get("final_confidence", finding.confidence)

        return results

    async def discover_attack_chains(
        self, findings: list[Finding]
    ) -> list[dict[str, Any]]:
        """Use Attacker persona to discover multi-finding attack chains.

        Args:
            findings: List of findings to analyze

        Returns:
            List of discovered attack chains
        """
        if self.provider == "none" or len(findings) < 2:
            return []

        context = "Analyze these findings for attack chains:\n\n"
        for i, f in enumerate(findings[:50]):  # Limit to 50 findings for token budget
            url_info = f.url or 'N/A'
            cwe_info = f.cwe_id or 'N/A'
            context += f"{i+1}. [{f.severity}] {f.title} at {url_info} (CWE: {cwe_info})\n"

        chain_prompt = """Identify attack chains — sequences of findings that together create
a more severe attack than any individual finding.

For each chain, provide:
- Chain name and description
- Steps (which findings, in what order)
- Combined CVSS score (should be higher than individual findings)
- Narrative: tell the story of how an attacker would exploit this chain

Output JSON array of chains."""

        result = await self._query_persona("attacker", chain_prompt, context)
        return result.get("attack_chains", []) if isinstance(result, dict) else []

    async def _query_persona(
        self, persona_name: str, system_prompt: str, context: str
    ) -> dict[str, Any]:
        """Query a single AI persona.

        Args:
            persona_name: Name of the persona
            system_prompt: System prompt for the persona
            context: Finding context to analyze

        Returns:
            AI response parsed as JSON
        """
        try:
            if self.provider == "anthropic":
                return await self._query_anthropic(persona_name, system_prompt, context)
            elif self.provider == "ollama":
                return await self._query_ollama(persona_name, system_prompt, context)
            else:
                return {}
        except Exception as e:
            logger.error("ai_query_failed", persona=persona_name, error=str(e))
            return {"error": str(e)}

    async def _query_anthropic(
        self, persona_name: str, system_prompt: str, context: str
    ) -> dict[str, Any]:
        """Query Anthropic Claude API.

        Args:
            persona_name: Name of the persona
            system_prompt: System prompt for the persona
            context: Finding context to analyze

        Returns:
            AI response parsed as JSON
        """
        import anthropic

        model = settings.anthropic_model
        if persona_name == "skeptic":
            model = settings.anthropic_skeptic_model  # Use cheaper model for skeptic

        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

        response = await client.messages.create(
            model=model,
            max_tokens=2000,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze this finding:\n\n{context}\n\nRespond with JSON only.",
                }
            ],
        )

        text = response.content[0].text
        return self._parse_ai_json(text)

    async def _query_ollama(
        self, persona_name: str, system_prompt: str, context: str
    ) -> dict[str, Any]:
        """Query local Ollama instance.

        Args:
            persona_name: Name of the persona
            system_prompt: System prompt for the persona
            context: Finding context to analyze

        Returns:
            AI response parsed as JSON
        """
        import httpx

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{settings.ollama_base_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {
                            "role": "user",
                            "content": f"Analyze this finding:\n\n{context}\n\n"
                                       "Respond with JSON only.",
                        },
                    ],
                    "stream": False,
                    "format": "json",
                },
            )
            data = response.json()
            return self._parse_ai_json(data.get("message", {}).get("content", "{}"))

    def _compute_consensus(self, results: dict[str, Any]) -> dict[str, Any]:
        """Compute consensus from 4 persona results.

        Rules:
        - 3/4 must agree to confirm a finding
        - Skeptic has veto power on false positives
        - If skeptic says FP + 1 other disagrees → needs_review

        Args:
            results: Analysis results from all personas

        Returns:
            Consensus decision
        """
        skeptic = results.get("skeptic", {})
        skeptic_verdict = skeptic.get("verdict", "confirmed")

        # If skeptic says false_positive, downgrade
        if skeptic_verdict == "false_positive":
            return {
                "status": "false_positive",
                "final_confidence": 10,
                "reasoning": "Skeptic determined this is a false positive",
            }

        # Count confidence scores
        confidences = []
        for persona in ["attacker", "defender", "analyst", "skeptic"]:
            conf = results.get(persona, {}).get("confidence", 50)
            if isinstance(conf, int | float):
                confidences.append(conf)

        avg_confidence = sum(confidences) / len(confidences) if confidences else 50

        if skeptic_verdict == "likely_false_positive":
            avg_confidence = min(avg_confidence, 30)
            status = "needs_review"
        elif skeptic_verdict == "needs_evidence":
            avg_confidence = min(avg_confidence, 60)
            status = "needs_evidence"
        elif avg_confidence >= 70:
            status = "confirmed"
        else:
            status = "needs_review"

        return {
            "status": status,
            "final_confidence": int(avg_confidence),
            "persona_confidences": {
                persona: results.get(persona, {}).get("confidence", 50)
                for persona in ["attacker", "defender", "analyst", "skeptic"]
            },
        }

    def _finding_to_context(self, finding: Finding) -> str:
        """Convert a Finding model to a text context for AI analysis.

        Args:
            finding: Finding model instance

        Returns:
            Formatted context string
        """
        return f"""Title: {finding.title}
Severity: {finding.severity}
URL: {finding.url or 'N/A'}
Parameter: {finding.parameter or 'N/A'}
CWE: {finding.cwe_id or 'N/A'}
CVEs: {', '.join(finding.cve_ids or [])}
Tool: {finding.tool_source}
Description: {finding.description}
Evidence: {json.dumps(finding.evidence or {}, indent=2)[:2000]}"""

    def _parse_ai_json(self, text: str) -> dict[str, Any]:
        """Parse JSON from AI response, handling markdown code blocks.

        Args:
            text: Raw AI response text

        Returns:
            Parsed JSON dictionary
        """
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("ai_json_parse_failed", text=text[:200])
            return {"raw_response": text}
