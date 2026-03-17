"""
netra/ai_brain/narrative.py
Ollama-powered narrative generation for findings and executive summaries.
Uses Qwen/Llama models to write clear, professional prose (no API keys needed).

Two main functions:
  generate_finding_narrative()   — writes a 2-3 paragraph finding description
  generate_executive_summary()   — writes the exec summary for a full scan
"""

import logging
from typing import Optional

logger = logging.getLogger("netra.ai_brain.narrative")


def _ollama_generate(prompt: str, system: str) -> str:
    """
    Generate text via local Ollama (primary backend).

    Args:
        prompt: User prompt.
        system: System instruction.

    Returns:
        Generated text string, or empty if unavailable.
    """
    try:
        from netra.core.config import CONFIG
        import httpx

        url  = CONFIG.get("ollama_url", "http://localhost:11434") + "/api/generate"
        body = {
            "model":  CONFIG.get("ollama_model", "qwen:14b"),
            "prompt": f"{system}\n\n{prompt}",
            "stream": False,
        }
        resp = httpx.post(url, json=body, timeout=60.0)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        logger.warning(f"Ollama generation failed: {e}")
        return ""


def generate_finding_narrative(finding: dict) -> str:
    """
    Generate a professional pentest-style narrative for a single finding.

    The narrative explains:
      - What was discovered and where
      - How an attacker could exploit it
      - What the real-world business impact is
      - A brief remediation recommendation

    Args:
        finding: Finding dict from FindingsDB.

    Returns:
        Markdown-formatted narrative string (2-3 paragraphs).
        Returns empty string if AI is unavailable.
    """
    system = (
        "You are a senior penetration tester writing a client security report. "
        "Write clear, professional prose that both technical and non-technical "
        "readers can understand. Do NOT use bullet points. Write in flowing paragraphs. "
        "Keep it concise — 2-3 paragraphs total. Do not repeat the title."
    )

    prompt = f"""Write a professional pentest finding narrative for the following vulnerability.

Title: {finding.get('title', 'N/A')}
Severity: {finding.get('severity', 'N/A').upper()}
CVSS: {finding.get('cvss_score', 'N/A')}
Host: {finding.get('host', 'N/A')}
URL: {finding.get('url', 'N/A')}
Category: {finding.get('category', 'N/A')}
CVE: {finding.get('cve_id', 'N/A')}
MITRE: {finding.get('mitre_technique', 'N/A')}

Description:
{finding.get('description', 'N/A')[:500]}

Evidence:
{finding.get('evidence', 'N/A')[:300]}

Impact:
{finding.get('impact', 'Assess based on the vulnerability type and context.')}

Remediation hint:
{finding.get('remediation', 'Provide general remediation guidance.')}

Write a narrative covering: (1) what was found and where, (2) how an attacker could exploit it \
and the business risk, (3) recommended remediation steps."""

    # Use Ollama (no Anthropic)
    result = _ollama_generate(prompt, system)
    return result if result else _fallback_narrative(finding)


def generate_executive_summary(ctx: dict) -> str:
    """
    Generate a Claude-powered executive summary for a complete scan.

    The summary covers:
      - Overall risk posture and grade
      - Top 3 most critical findings
      - Attack chain highlights
      - Business impact overview
      - Recommended immediate actions

    Args:
        ctx: Report context dict with keys:
             scan_id, findings, stats, chains, risk_score, risk_grade,
             client, engagement, operator

    Returns:
        Markdown-formatted executive summary (4-6 paragraphs).
    """
    stats      = ctx.get("stats", {})
    risk_score = ctx.get("risk_score", 0)
    risk_grade = ctx.get("risk_grade", "?")
    findings   = ctx.get("findings", [])
    chains     = ctx.get("chains", [])
    client     = ctx.get("client", "")
    engagement = ctx.get("engagement", "")

    top_findings = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
    top_chain    = chains[0] if chains else None

    system = (
        "You are a senior security consultant writing an executive summary for a "
        "penetration test report. Write for a C-suite audience — no technical jargon, "
        "focus on business risk and recommended actions. Use professional, authoritative prose. "
        "No bullet points. Structure as paragraphs with clear transitions. 4-6 paragraphs."
    )

    top_findings_text = "\n".join(
        f"  - {f.get('title')} [{f.get('severity').upper()}] on {f.get('host')}"
        for f in top_findings
    ) or "  - No critical or high severity findings."

    chain_text = (
        f"  Attack chain: {top_chain.get('mitre_sequence', 'N/A')} "
        f"(Combined CVSS: {top_chain.get('combined_cvss', 'N/A')})"
        if top_chain else "  No multi-step attack chains discovered."
    )

    prompt = f"""Write an executive summary for a security assessment with these findings:

CLIENT: {client or 'Confidential'}
ENGAGEMENT: {engagement or 'Security Assessment'}
RISK SCORE: {risk_score}/100  (Grade: {risk_grade})

FINDING COUNTS:
  Critical: {stats.get('critical', 0)}
  High:     {stats.get('high', 0)}
  Medium:   {stats.get('medium', 0)}
  Low:      {stats.get('low', 0)}
  Total:    {sum(stats.values())}

TOP CRITICAL/HIGH FINDINGS:
{top_findings_text}

ATTACK CHAIN HIGHLIGHT:
{chain_text}

Write a professional executive summary covering:
1. Opening: Overall security posture and risk grade
2. Critical findings overview and their business impact
3. Attack chain risk (if applicable)
4. Pattern analysis (are issues systemic or isolated?)
5. Recommended immediate actions (top 3)
6. Closing: Path to remediation"""

    # Use Ollama (no Anthropic)
    result = _ollama_generate(prompt, system)
    return result if result else _fallback_executive_summary(ctx)


def generate_chain_narrative(chain: dict, findings: list) -> str:
    """
    Generate a narrative description for a multi-step attack chain.

    Args:
        chain:    Attack chain dict with nodes, combined_cvss, mitre_sequence.
        findings: List of finding dicts that form the chain nodes.

    Returns:
        Narrative string describing the attack progression.
    """
    if not findings:
        return "No findings available for chain narrative."

    system = (
        "You are an offensive security analyst explaining a multi-step attack to a client. "
        "Write 1-2 paragraphs describing the attack path as a story — from initial access "
        "to final impact. Be specific about what an attacker would do at each step."
    )

    steps_text = "\n".join(
        f"  Step {i+1}: {f.get('title')} [{f.get('severity')}] on {f.get('host')} "
        f"(CVSS: {f.get('cvss_score')})"
        for i, f in enumerate(findings)
    )

    prompt = f"""Describe this multi-step attack chain:

MITRE Sequence: {chain.get('mitre_sequence', 'N/A')}
Combined CVSS: {chain.get('combined_cvss', 'N/A')}

Attack Steps:
{steps_text}

Write a 1-2 paragraph narrative describing how an attacker would exploit this chain \
from initial access to final impact."""

    # Use Ollama (no Anthropic)
    result = _ollama_generate(prompt, system)
    return result if result else (
        f"Multi-step attack chain with {len(findings)} steps. "
        f"MITRE sequence: {chain.get('mitre_sequence', 'N/A')}. "
        f"Combined CVSS: {chain.get('combined_cvss', 'N/A')}."
    )


# ── Fallback narratives (no AI available) ────────────────────────────

def _fallback_narrative(finding: dict) -> str:
    """Generate a template narrative when AI is unavailable."""
    sev  = finding.get("severity", "medium").lower()
    urgency = {
        "critical": "immediate attention and emergency remediation",
        "high":     "prompt remediation within 24-48 hours",
        "medium":   "remediation within the current sprint",
        "low":      "remediation in the next maintenance window",
    }.get(sev, "scheduled remediation")

    return (
        f"A {sev} severity vulnerability was identified in the assessment of "
        f"{finding.get('host', 'the target system')}. "
        f"The issue, classified as {finding.get('category', 'a security weakness')}, "
        f"presents a real risk to the confidentiality, integrity, or availability of the "
        f"affected system.\n\n"
        f"This finding requires {urgency}. "
        f"The remediation guidance provided should be implemented in consultation with the "
        f"development and operations teams to ensure the fix is both complete and does not "
        f"introduce regressions."
    )


def _fallback_executive_summary(ctx: dict) -> str:
    """Generate a template executive summary when AI is unavailable."""
    stats      = ctx.get("stats", {})
    risk_grade = ctx.get("risk_grade", "?")
    risk_score = ctx.get("risk_score", 0)
    total      = sum(stats.values())
    critical   = stats.get("critical", 0)
    high       = stats.get("high", 0)

    grade_desc = {
        "A": "low", "B": "moderate", "C": "significant", "D": "critical"
    }.get(risk_grade, "unknown")

    return (
        f"This security assessment identified {total} findings across the assessed scope, "
        f"resulting in an overall risk grade of {risk_grade} ({risk_score}/100), "
        f"indicating a {grade_desc} level of security risk.\n\n"
        f"The assessment identified {critical} critical and {high} high severity findings "
        f"that require immediate attention. These findings represent the most significant "
        f"risks to the organisation and should be prioritised for remediation.\n\n"
        f"It is recommended that all critical and high severity findings be addressed "
        f"immediately, followed by medium severity issues within the next development cycle. "
        f"A follow-up assessment should be conducted after remediation to verify effectiveness."
    )
