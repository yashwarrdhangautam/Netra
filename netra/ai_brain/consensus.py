"""
netra/ai_brain/consensus.py
Multi-persona consensus voting engine.

For each finding:
  1. All 4 personas (bug_bounty_hunter, code_auditor, pentester, skeptic) run in parallel
  2. Skeptic can veto at >= 80% FP confidence
  3. 3/4 of remaining personas must confirm to validate the finding
  4. Results persisted to ai_analysis table in FindingsDB

Consensus rule summary:
  - Skeptic confidence >= 0.80 → finding rejected (false positive)
  - Otherwise: require CONSENSUS_THRESHOLD fraction of confirm votes
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any

from netra.core.database import FindingsDB
from netra.ai_brain.personas import (
    PersonaClient,
    PERSONAS,
    SKEPTIC_VETO_THRESHOLD,
    CONSENSUS_THRESHOLD,
)

logger = logging.getLogger("netra.ai_brain.consensus")


def run_consensus_analysis(
    scan_id: str,
    db: FindingsDB,
    finding_ids: Optional[List[int]] = None,
    severity_filter: str = "critical,high,medium",
) -> List[dict]:
    """
    Run multi-persona consensus on all findings for a scan.
    Entry point called from the main scan pipeline and MCP tools.

    Args:
        scan_id:        Scan to analyse.
        db:             FindingsDB instance.
        finding_ids:    Optional list of specific finding IDs to analyse.
                        If None, analyses all findings matching severity_filter.
        severity_filter: Comma-separated severity levels to include.

    Returns:
        List of consensus result dicts, one per finding.
    """
    from netra.core.utils import banner, status

    banner("AI BRAIN", "Multi-persona consensus analysis")

    if finding_ids:
        findings = [f for f in db.get_findings(scan_id=scan_id)
                    if f["id"] in finding_ids]
    else:
        findings = db.get_findings(scan_id=scan_id, severity=severity_filter)

    if not findings:
        status("No findings to analyse", "info")
        return []

    status(f"Analysing {len(findings)} findings with {len(PERSONAS)} personas", "ai")

    client  = PersonaClient()
    results = asyncio.run(_run_all_async(findings, client, db))

    confirmed = sum(1 for r in results if r.get("consensus") == "confirmed")
    rejected  = sum(1 for r in results if r.get("consensus") == "rejected")
    status(f"Consensus complete — confirmed: {confirmed}, rejected: {rejected}", "ok")

    return results


async def _run_all_async(
    findings: List[dict],
    client: PersonaClient,
    db: FindingsDB,
) -> List[dict]:
    """
    Run consensus analysis on all findings concurrently.
    Semaphore limits concurrency to avoid hammering the API.

    Args:
        findings: List of finding dicts to analyse.
        client:   PersonaClient instance.
        db:       FindingsDB instance.

    Returns:
        List of consensus result dicts.
    """
    sem  = asyncio.Semaphore(3)   # max 3 findings in parallel
    tasks = [
        _analyse_finding_with_sem(finding, client, db, sem)
        for finding in findings
    ]
    return await asyncio.gather(*tasks, return_exceptions=False)


async def _analyse_finding_with_sem(
    finding: dict,
    client: PersonaClient,
    db: FindingsDB,
    sem: asyncio.Semaphore,
) -> dict:
    """Wrapper that acquires semaphore before analysing."""
    async with sem:
        return await analyse_finding(finding, client, db)


async def analyse_finding(
    finding: dict,
    client: PersonaClient,
    db: FindingsDB,
) -> dict:
    """
    Run all personas in parallel on a single finding and compute consensus.

    Pipeline:
      1. Run all 4 personas concurrently via asyncio.gather
      2. Check skeptic veto
      3. Compute majority vote from non-skeptic personas
      4. Persist results to DB
      5. Update finding status if rejected as FP

    Args:
        finding: Finding dict from FindingsDB.
        client:  PersonaClient for API calls.
        db:      FindingsDB for persisting results.

    Returns:
        Consensus result dict.
    """
    finding_id = finding["id"]
    persona_names = list(PERSONAS.keys())

    # ── Run all personas in parallel ──────────────────────────────────
    tasks   = [client.analyse_async(name, finding) for name in persona_names]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    persona_results: Dict[str, dict] = {}
    for name, result in zip(persona_names, results):
        if isinstance(result, Exception):
            logger.warning(f"Persona {name} error for finding {finding_id}: {result}")
            persona_results[name] = {
                "persona":    name,
                "verdict":    "needs_more_info",
                "confidence": 50,
                "narrative":  f"Error: {result}",
            }
        else:
            persona_results[name] = result

    # ── Skeptic veto check ────────────────────────────────────────────
    skeptic     = persona_results.get("skeptic", {})
    skeptic_conf = skeptic.get("confidence", 0) / 100.0
    skeptic_veto = (
        skeptic.get("verdict") == "reject" and
        skeptic_conf >= SKEPTIC_VETO_THRESHOLD
    )

    # ── Majority vote (non-skeptic personas) ─────────────────────────
    specialist_names = [n for n in persona_names if n != "skeptic"]
    specialist_votes = [
        persona_results[n] for n in specialist_names
        if persona_results[n].get("verdict") == "confirm"
    ]
    specialist_total  = len(specialist_names)
    confirm_fraction  = len(specialist_votes) / specialist_total if specialist_total else 0

    # ── Consensus decision ────────────────────────────────────────────
    if skeptic_veto:
        consensus = "rejected"
        reason    = skeptic.get("fp_reason") or "Skeptic veto — likely false positive"
        # Auto-mark as FP
        try:
            db.mark_fp(finding_id, f"[AI Skeptic] {reason}", operator="netra-ai")
        except Exception:
            pass
    elif confirm_fraction >= CONSENSUS_THRESHOLD:
        consensus = "confirmed"
        reason    = None
    else:
        consensus = "unconfirmed"
        reason    = "Insufficient consensus among specialist personas"

    # ── Average confidence across confirming specialists ──────────────
    if specialist_votes:
        avg_confidence = int(
            sum(v.get("confidence", 50) for v in specialist_votes) / len(specialist_votes)
        )
    else:
        avg_confidence = 30

    # ── Build combined narrative ──────────────────────────────────────
    narratives = [
        f"[{n.replace('_', ' ').title()}] {persona_results[n].get('narrative', '')}"
        for n in specialist_names
        if persona_results[n].get("narrative")
    ]
    combined_narrative = "\n\n".join(narratives)

    # Update AI narrative on the finding
    if consensus == "confirmed" and combined_narrative:
        try:
            db.update_ai_narrative(finding_id, combined_narrative)
        except Exception:
            pass

    # ── Persist each persona analysis ────────────────────────────────
    for name, pres in persona_results.items():
        try:
            db.save_ai_analysis(
                finding_id  = finding_id,
                persona     = name,
                verdict     = pres.get("verdict", "needs_more_info"),
                confidence  = pres.get("confidence", 50),
                narrative   = pres.get("narrative", ""),
                raw_response= str(pres),
            )
        except Exception as e:
            logger.warning(f"Failed to save analysis for persona {name}: {e}")

    result = {
        "finding_id":        finding_id,
        "finding_title":     finding.get("title"),
        "finding_severity":  finding.get("severity"),
        "consensus":         consensus,
        "avg_confidence":    avg_confidence,
        "confirm_fraction":  round(confirm_fraction, 2),
        "skeptic_veto":      skeptic_veto,
        "fp_reason":         reason,
        "personas":          {
            name: {
                "verdict":    v.get("verdict"),
                "confidence": v.get("confidence"),
            }
            for name, v in persona_results.items()
        },
    }

    logger.debug(
        f"Finding {finding_id} ({finding.get('severity')}) → {consensus} "
        f"(conf: {avg_confidence}%, fraction: {confirm_fraction:.0%})"
    )

    return result


def get_consensus_summary(scan_id: str, db: FindingsDB) -> dict:
    """
    Build a summary of AI consensus results for a scan.

    Args:
        scan_id: Scan to summarise.
        db:      FindingsDB instance.

    Returns:
        dict with confirmed/rejected/unconfirmed counts per severity.
    """
    findings = db.get_findings(scan_id)
    summary: dict = {
        "total":       len(findings),
        "confirmed":   0,
        "rejected":    0,
        "unconfirmed": 0,
        "by_severity": {},
    }

    for f in findings:
        analyses = db.get_ai_analyses(f["id"])
        if not analyses:
            summary["unconfirmed"] += 1
            continue

        # Count verdicts
        verdicts = [a["verdict"] for a in analyses if a["persona"] != "skeptic"]
        confirms = sum(1 for v in verdicts if v == "confirm")
        fraction = confirms / len(verdicts) if verdicts else 0

        skeptic_analyses = [a for a in analyses if a["persona"] == "skeptic"]
        skeptic_veto = any(
            a["verdict"] == "reject" and (a["confidence"] / 100.0) >= SKEPTIC_VETO_THRESHOLD
            for a in skeptic_analyses
        )

        if skeptic_veto:
            cat = "rejected"
        elif fraction >= CONSENSUS_THRESHOLD:
            cat = "confirmed"
        else:
            cat = "unconfirmed"

        summary[cat] += 1
        sev = f.get("severity", "unknown")
        summary["by_severity"].setdefault(sev, {"confirmed": 0, "rejected": 0, "unconfirmed": 0})
        summary["by_severity"][sev][cat] += 1

    return summary
