"""AI consensus logic for NETRA — multi-persona agreement system."""
from typing import Any


def calculate_consensus(analyses: dict[str, Any]) -> dict[str, Any]:
    """Calculate consensus from multiple AI persona analyses.

    Rules:
    - 3/4 must agree to confirm a finding
    - Skeptic has veto power on false positives
    - If skeptic says FP + 1 other disagrees → needs_review

    Args:
        analyses: Analysis results from all personas (attacker, defender, analyst, skeptic)

    Returns:
        Consensus decision with confidence score
    """
    skeptic = analyses.get("skeptic", {})
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
        conf = analyses.get(persona, {}).get("confidence", 50)
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
            persona: analyses.get(persona, {}).get("confidence", 50)
            for persona in ["attacker", "defender", "analyst", "skeptic"]
        },
        "reasoning": f"Consensus based on {len(confidences)} persona analyses",
    }


def resolve_disagreement(
    analyses: dict[str, Any],
    threshold: float = 0.7,
) -> dict[str, Any]:
    """Resolve disagreements between personas.

    Args:
        analyses: Analysis results from all personas
        threshold: Agreement threshold (0.0 to 1.0)

    Returns:
        Resolution decision
    """
    # Get all persona opinions
    opinions = []
    for persona in ["attacker", "defender", "analyst"]:
        persona_data = analyses.get(persona, {})
        if isinstance(persona_data, dict):
            opinions.append(persona_data.get("confidence", 50))

    if not opinions:
        return {
            "status": "unresolved",
            "resolved": False,
            "reason": "No persona opinions available",
        }

    # Calculate agreement level
    avg_opinion = sum(opinions) / len(opinions)
    agreement_level = avg_opinion / 100.0

    if agreement_level >= threshold:
        return {
            "status": "resolved",
            "resolved": True,
            "reason": f"Agreement level {agreement_level:.2f} meets threshold {threshold}",
            "confidence": int(avg_opinion),
        }
    else:
        return {
            "status": "needs_human_review",
            "resolved": False,
            "reason": f"Agreement level {agreement_level:.2f} below threshold {threshold}",
            "confidence": int(avg_opinion),
        }
