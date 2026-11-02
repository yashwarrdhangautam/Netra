"""Per-hunt token and cost telemetry.

Accumulates input/output tokens and a USD estimate per hunt, broken down by
model, so cost per hunt is measurable (the Measure-First prerequisite for the
benchmark) and can be surfaced in the GUI. Prices are editable estimates keyed
by model tier; they move over time, so treat them as defaults, not truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# USD per 1,000,000 tokens, as (input, output). Representative defaults; override
# per deployment. Tiers map NETRA's 80/18/2 Haiku/Sonnet/Opus routing.
_PRICES: dict[str, tuple[float, float]] = {
    "haiku": (0.80, 4.00),
    "sonnet": (3.00, 15.00),
    "opus": (15.00, 75.00),
}
_DEFAULT_PRICE = (3.00, 15.00)


def _tier(model: str) -> str:
    m = (model or "").lower()
    for tier in _PRICES:
        if tier in m:
            return tier
    return ""


def price_for(model: str) -> tuple[float, float]:
    """(input, output) USD per 1M tokens for a model (default when unknown)."""
    return _PRICES.get(_tier(model), _DEFAULT_PRICE)


@dataclass
class HuntCost:
    """Running token + USD totals for one hunt, with a per-model breakdown."""

    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    by_model: dict[str, dict[str, float]] = field(default_factory=dict)

    def record(self, model: str, *, input_tokens: int = 0, output_tokens: int = 0) -> float:
        """Record one model call; returns the USD cost of this call."""
        in_t = max(0, input_tokens)
        out_t = max(0, output_tokens)
        price_in, price_out = price_for(model)
        cost = in_t / 1_000_000 * price_in + out_t / 1_000_000 * price_out
        self.input_tokens += in_t
        self.output_tokens += out_t
        self.usd += cost
        agg = self.by_model.setdefault(model, {"input_tokens": 0, "output_tokens": 0, "usd": 0.0})
        agg["input_tokens"] += in_t
        agg["output_tokens"] += out_t
        agg["usd"] += cost
        return cost

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "usd": round(self.usd, 6),
            "by_model": {m: {**v, "usd": round(v["usd"], 6)} for m, v in self.by_model.items()},
        }
