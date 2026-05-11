"""Expected-payout estimator.

A simple linear interpolation between program min/max payouts, weighted by severity.
Conservative — there is no machine learning here. Operators see this as an estimate,
not a promise.
"""
from __future__ import annotations

from dataclasses import dataclass


# Severity → fraction of (max - min) to add to min.
SEVERITY_WEIGHTS = {
    "info": 0.0,
    "low": 0.1,
    "medium": 0.35,
    "high": 0.65,
    "critical": 1.0,
}


@dataclass(frozen=True)
class PayoutEstimate:
    """Estimated payout, with a conservative range."""

    estimate: int
    low: int
    high: int
    currency: str

    def __str__(self) -> str:
        return f"~{self.estimate} {self.currency} (range {self.low}-{self.high})"


def estimate_payout(
    severity: str,
    program_min: int | None,
    program_max: int | None,
    currency: str = "USD",
) -> PayoutEstimate | None:
    """Return a PayoutEstimate or None if the program has no bracket info.

    The estimate is the weighted point in the program's range. Low and high apply
    a ±20% confidence band, clamped to the program's min/max.
    """
    if program_min is None or program_max is None:
        return None
    if program_max < program_min:
        return None  # bad data — refuse to extrapolate

    weight = SEVERITY_WEIGHTS.get(severity.strip().lower(), 0.0)
    estimate = int(program_min + (program_max - program_min) * weight)

    # ±20% confidence band, clamped to program range.
    band = max(1, int((program_max - program_min) * 0.2))
    low = max(program_min, estimate - band)
    high = min(program_max, estimate + band)

    return PayoutEstimate(estimate=estimate, low=low, high=high, currency=currency)
