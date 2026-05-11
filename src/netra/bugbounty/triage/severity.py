"""Severity mapping — combine CVSS with program-specific severity caps.

The program's scope rules can declare a severity cap (e.g. *.myshopify.com is in scope
but capped at 'high'). This module merges that cap with the AI-suggested severity to
arrive at the final reportable severity.
"""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Numerical severity for ordering. Matches netra.db.models.finding.Severity values."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        return cls[s.upper()]

    def to_string(self) -> str:
        return self.name.lower()


def cap_severity(suggested: str, cap: str | None) -> str:
    """Return the lower of suggested vs cap. cap=None means no cap."""
    sug = Severity.from_string(suggested)
    if cap is None:
        return sug.to_string()
    capped = Severity.from_string(cap)
    return min(sug, capped).to_string()


def cvss_to_severity(cvss_score: float) -> str:
    """Map CVSS 3.1 base score to a severity bucket.

    Buckets follow the FIRST.org / NVD convention:
        0.0       → none/info
        0.1-3.9   → low
        4.0-6.9   → medium
        7.0-8.9   → high
        9.0-10.0  → critical
    """
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    if cvss_score > 0.0:
        return "low"
    return "info"
