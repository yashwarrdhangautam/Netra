"""BountyHunter — the 5th AI persona, added to NETRA's existing consensus.

The existing personas in netra/ai/prompts.py are Attacker, Defender, Analyst, Skeptic.
BountyHunter scores findings on three dimensions specific to bug bounty work:

    1. impact     — how bad is it if exploited (1-10)
    2. novelty    — how likely it is to be NOT a duplicate (1-10)
    3. payout     — expected $ value relative to program brackets (1-10)

The score is impact * 0.5 + novelty * 0.3 + payout * 0.2. Skeptic veto still applies
at the consensus layer — BountyHunter cannot override Skeptic.
"""
from __future__ import annotations

from dataclasses import dataclass


BOUNTY_HUNTER_PROMPT = """You are BountyHunter, a senior bug bounty researcher reviewing
a finding for submission to a public bug bounty program.

Your job is to score the finding on three dimensions, each 1-10:

  1. IMPACT — How bad is real-world exploitation?
     1 = informational only; 10 = full account / data takeover.

  2. NOVELTY — How likely is this NOT a duplicate of a prior submission on this program?
     1 = textbook duplicate; 10 = new attack class for this program.

  3. PAYOUT — Expected $ value relative to the program's bracket.
     1 = bottom of low bracket or N/A; 10 = top of critical bracket.

You MUST consider the program's policy (in particular, common N/A categories like:
self-XSS, missing security headers, rate limiting, low-impact disclosure, social
engineering vectors).

Return strict JSON with these keys: impact, novelty, payout, rationale_short.
The rationale_short field is at most 280 characters and explains the score in plain
English.

Finding under review:
{finding_context}

Program info:
{program_context}

Comparable disclosed reports and prior art:
{comparable_reports}

Respond with JSON only.
"""


@dataclass(frozen=True)
class BountyScore:
    """Output of one BountyHunter call."""

    impact: int
    novelty: int
    payout: int
    rationale: str

    @property
    def composite(self) -> float:
        """Weighted composite. Higher is better. Range 1.0-10.0."""
        return (self.impact * 0.5) + (self.novelty * 0.3) + (self.payout * 0.2)

    @property
    def tier(self) -> str:
        """Bucketed label for the operator's quick scan."""
        c = self.composite
        if c >= 8.0:
            return "must_submit"
        if c >= 6.0:
            return "submit"
        if c >= 4.0:
            return "consider"
        return "skip"


def parse_response(raw: str) -> BountyScore:
    """Parse a BountyHunter LLM response into a BountyScore.

    Defensive: tolerates extra whitespace, code fences, leading prose. Raises
    ValueError if the response is unrecoverable.
    """
    import json
    import re

    text = raw.strip()
    # Strip markdown code fences if present.
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$", "", text)
    # If there's leading prose, find the first '{' and parse from there.
    brace = text.find("{")
    if brace > 0:
        text = text[brace:]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"BountyHunter response was not valid JSON: {exc}") from exc

    try:
        return BountyScore(
            impact=int(data["impact"]),
            novelty=int(data["novelty"]),
            payout=int(data["payout"]),
            rationale=str(data.get("rationale_short", ""))[:280],
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError(f"BountyHunter response missing/invalid fields: {exc}") from exc
