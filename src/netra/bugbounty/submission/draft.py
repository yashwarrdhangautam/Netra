"""H1-style submission report drafter.

Produces a Markdown body in the standard HackerOne / Bugcrowd shape:

    # Title
    ## Summary
    ## Steps to Reproduce
    ## Impact
    ## Suggested Fix
    ## Supporting Material / References

The draft is committed to bb_submissions.draft_md. The operator reviews and pastes
it into the platform UI. NETRA-BB never auto-submits.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class DraftSections:
    """Inputs to the drafter — caller fills these in from the Finding + AI analysis."""

    title: str
    summary: str
    steps_to_reproduce: list[str]
    impact: str
    suggested_fix: str | None = None
    references: list[str] | None = None
    proof_of_concept: str | None = None
    comparable_reports: list[str] | None = None


def render_markdown(sections: DraftSections) -> str:
    """Render sections to a Markdown string suitable for H1's report body field."""
    lines = []
    lines.append(f"# {sections.title.strip()}")
    lines.append("")
    lines.append("## Summary")
    lines.append(sections.summary.strip())
    lines.append("")

    lines.append("## Steps to Reproduce")
    for i, step in enumerate(sections.steps_to_reproduce, start=1):
        lines.append(f"{i}. {step.strip()}")
    lines.append("")

    lines.append("## Impact")
    lines.append(sections.impact.strip())
    lines.append("")

    if sections.suggested_fix:
        lines.append("## Suggested Fix")
        lines.append(sections.suggested_fix.strip())
        lines.append("")

    if sections.references:
        lines.append("## References")
        for ref in sections.references:
            lines.append(f"- {ref.strip()}")
        lines.append("")

    if sections.proof_of_concept:
        lines.append("## Proof of Concept")
        lines.append(sections.proof_of_concept.rstrip())
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def title_from_class(vuln_class: str, asset: str) -> str:
    """Generate a default title — operator can override.

    Example: title_from_class('xss', 'api.shopify.com/v1/orders')
        → 'Reflected XSS in api.shopify.com/v1/orders'
    """
    label_map = {
        "xss": "Reflected XSS",
        "stored_xss": "Stored XSS",
        "sqli": "SQL Injection",
        "ssrf": "SSRF",
        "idor": "IDOR",
        "rce": "Remote Code Execution",
        "auth_bypass": "Authentication Bypass",
        "info_disc": "Information Disclosure",
        "open_redirect": "Open Redirect",
        "csrf": "CSRF",
    }
    label = label_map.get(vuln_class.strip().lower(), vuln_class.replace("_", " ").title())
    return f"{label} in {asset}"


def detect_verbatim_overlap(
    candidate: str,
    references: list[str],
    *,
    ngram_size: int = 8,
    threshold: float = 0.5,
) -> str | None:
    """Return the first reference that overlaps too heavily with the candidate.

    We intentionally use a coarse word-ngram check instead of semantic similarity.
    This catches copy-paste style leakage from public writeups before it lands in a
    user-facing draft.
    """

    candidate_tokens = _tokenize(candidate)
    candidate_ngrams = _ngrams(candidate_tokens, ngram_size)
    if not candidate_ngrams:
        return None
    for reference in references:
        reference_tokens = _tokenize(reference)
        reference_ngrams = _ngrams(reference_tokens, ngram_size)
        if not reference_ngrams:
            continue
        overlap = len(candidate_ngrams & reference_ngrams) / len(reference_ngrams)
        if overlap >= threshold:
            return reference
    return None


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9_:/.-]+", text.lower()) if token]


def _ngrams(tokens: list[str], size: int) -> set[tuple[str, ...]]:
    if len(tokens) < size:
        return set()
    return {tuple(tokens[index : index + size]) for index in range(len(tokens) - size + 1)}
