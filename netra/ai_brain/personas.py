"""
netra/ai_brain/personas.py
AI persona definitions for the NETRA multi-agent consensus system.
Three specialist personas + one skeptic reviewer for false positive filtering.

Models (Open-Source, Ollama-based):
  Personas  → qwen:14b (default) or llama2, mistral, neural-chat
  Skeptic   → qwen:14b (compact but effective)
  Backend   → Local Ollama (no API keys needed)
"""

from typing import Any, Dict, Optional
import json
import asyncio

# ── Model identifiers ─────────────────────────────────────────────────
MODEL_PERSONA  = "qwen:14b"        # open-source, no API key needed
MODEL_SKEPTIC  = "qwen:14b"        # same model for skeptic

# ── Persona definitions (Ollama/Qwen-optimized) ────────────────────────
PERSONAS: Dict[str, Dict[str, str]] = {
    "bug_bounty_hunter": {
        "model": MODEL_PERSONA,
        "system": (
            "You are a bug bounty hunter analyzing a security finding.\n"
            "Assess: Is it exploitable? Real-world impact? Chain potential?\n"
            "Respond in JSON: {\"verdict\": \"confirm|reject|needs_more_info\", "
            "\"confidence\": 0-100, \"narrative\": \"brief analysis\"}"
        ),
    },
    "code_auditor": {
        "model": MODEL_PERSONA,
        "system": (
            "You are a code security engineer analyzing a finding.\n"
            "Assess: Root cause? CWE? Systemic risk? Fix recommendation?\n"
            "Respond in JSON: {\"verdict\": \"confirm|reject|needs_more_info\", "
            "\"confidence\": 0-100, \"narrative\": \"brief analysis\", \"cwe\": \"CWE-XXX\"}"
        ),
    },
    "pentester": {
        "model": MODEL_PERSONA,
        "system": (
            "You are a penetration tester analyzing a finding.\n"
            "Assess: Attack narrative? Business impact? Remediation urgency?\n"
            "Respond in JSON: {\"verdict\": \"confirm|reject|needs_more_info\", "
            "\"confidence\": 0-100, \"narrative\": \"brief analysis\", "
            "\"urgency\": \"immediate|high|medium|low\"}"
        ),
    },
    "skeptic": {
        "model": MODEL_SKEPTIC,
        "system": (
            "You are a false positive filter for security findings.\n"
            "Identify: Scanner artifacts? Test data? Benign configs? Detection errors?\n"
            "Reject if not confident this is a real exploitable issue.\n"
            "Respond in JSON: {\"verdict\": \"confirm|reject\", "
            "\"confidence\": 0-100, \"fp_reason\": \"reason if rejecting\"}"
        ),
    },
}

# Skeptic veto threshold — if skeptic confidence >= this, it can override
# the other personas and reject the finding
SKEPTIC_VETO_THRESHOLD = 0.80  # 80% confidence FP → veto

# Consensus threshold — fraction of confirming personas required
CONSENSUS_THRESHOLD = 0.75     # 3 out of 4 personas must confirm


def build_finding_prompt(finding: dict) -> str:
    """
    Build a structured prompt describing a finding for persona analysis.

    Args:
        finding: Finding dict from FindingsDB.

    Returns:
        Formatted prompt string.
    """
    lines = [
        f"FINDING ANALYSIS REQUEST",
        f"========================",
        f"Title:       {finding.get('title', 'N/A')}",
        f"Severity:    {finding.get('severity', 'N/A').upper()}",
        f"CVSS:        {finding.get('cvss_score', 'N/A')}",
        f"CVE:         {finding.get('cve_id', 'N/A')}",
        f"CWE:         {finding.get('cwe_id', 'N/A')}",
        f"Host:        {finding.get('host', 'N/A')}",
        f"URL:         {finding.get('url', 'N/A')}",
        f"Category:    {finding.get('category', 'N/A')}",
        f"OWASP Web:   {finding.get('owasp_web', 'N/A')}",
        f"MITRE:       {finding.get('mitre_technique', 'N/A')}",
        f"",
        f"Description:",
        f"{finding.get('description', 'N/A')[:600]}",
    ]

    if finding.get("evidence"):
        lines += ["", "Evidence (truncated):", finding["evidence"][:400]]

    if finding.get("request"):
        lines += ["", "HTTP Request (truncated):", finding["request"][:300]]

    if finding.get("poc_command"):
        lines += ["", "PoC Command:", finding["poc_command"]]

    return "\n".join(lines)


class PersonaClient:
    """
    Ollama-based persona client for NETRA AI brain.
    No API keys required — runs fully locally.

    Usage:
        client = PersonaClient()
        result = await client.analyse_async(persona_name, finding)
    """

    def __init__(self) -> None:
        """Initialize Ollama client."""
        self._ollama_available: bool = False
        self._init_backends()

    def _init_backends(self) -> None:
        """Detect Ollama availability."""
        from netra.core.config import CONFIG

        try:
            import httpx
            resp = httpx.get(
                CONFIG.get("ollama_url", "http://localhost:11434") + "/api/tags",
                timeout=2.0
            )
            if resp.status_code == 200:
                self._ollama_available = True
        except Exception:
            pass

    async def analyse_async(self, persona_name: str, finding: dict) -> dict:
        """
        Run a single persona analysis asynchronously via Ollama.

        Args:
            persona_name: One of: bug_bounty_hunter, code_auditor, pentester, skeptic
            finding:      Finding dict to analyse.

        Returns:
            dict with verdict, confidence, narrative, and persona metadata.
        """
        from netra.core.config import CONFIG

        persona = PERSONAS.get(persona_name)
        if not persona:
            return {"verdict": "needs_more_info", "confidence": 0,
                    "narrative": f"Unknown persona: {persona_name}"}

        prompt = build_finding_prompt(finding)

        # Use Ollama (no Anthropic fallback)
        if self._ollama_available:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self._call_ollama, persona, prompt, CONFIG
                )
                result["persona"] = persona_name
                return result
            except Exception as e:
                pass  # fall through to manual fallback

        # Final fallback: neutral response if Ollama unavailable
        return {
            "persona":    persona_name,
            "verdict":    "needs_more_info",
            "confidence": 50,
            "narrative":  "Ollama not running. Start with: ollama run qwen:14b",
        }

    def _call_ollama(self, persona: dict, prompt: str, config: dict) -> dict:
        """
        Synchronous Ollama API call for a persona.

        Args:
            persona: Persona definition dict.
            prompt:  Finding prompt string.
            config:  NETRA config dict.

        Returns:
            Parsed response dict.
        """
        import httpx
        url  = config.get("ollama_url", "http://localhost:11434") + "/api/generate"
        body = {
            "model":  config.get("ollama_model", MODEL_OLLAMA),
            "prompt": f"{persona['system']}\n\n{prompt}",
            "stream": False,
        }
        resp = httpx.post(url, json=body, timeout=60.0)
        resp.raise_for_status()
        raw  = resp.json().get("response", "").strip()
        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> dict:
        """
        Parse a JSON response from a persona, with fallback extraction.

        Args:
            raw: Raw text response from the model.

        Returns:
            Parsed dict with at minimum: verdict, confidence, narrative.
        """
        # Strip markdown code fences if present
        if "```" in raw:
            import re
            raw = re.sub(r"```(?:json)?", "", raw).strip("`").strip()

        try:
            data = json.loads(raw)
            # Ensure required keys
            return {
                "verdict":    data.get("verdict", "needs_more_info"),
                "confidence": int(data.get("confidence", 50)),
                "narrative":  data.get("narrative", ""),
                **{k: v for k, v in data.items()
                   if k not in ("verdict", "confidence", "narrative")},
            }
        except json.JSONDecodeError:
            # Best-effort extraction
            verdict    = "confirm" if "confirm" in raw.lower() else "reject"
            confidence = 50
            return {
                "verdict":   verdict,
                "confidence": confidence,
                "narrative":  raw[:300],
            }
