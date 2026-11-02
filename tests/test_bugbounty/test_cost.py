"""Tests for per-hunt cost telemetry (Sprint 3)."""

from netra.bugbounty.agentic.cost import HuntCost, price_for


def test_price_tiers_and_default():
    assert price_for("claude-haiku-4-5-20251001") == (0.80, 4.00)
    assert price_for("claude-sonnet-4-20250514") == (3.00, 15.00)
    assert price_for("claude-opus-4") == (15.00, 75.00)
    assert price_for("some-unknown-model") == (3.00, 15.00)


def test_record_computes_cost():
    c = HuntCost()
    # 1M input + 1M output on haiku = 0.80 + 4.00
    cost = c.record("claude-haiku-4-5", input_tokens=1_000_000, output_tokens=1_000_000)
    assert round(cost, 2) == 4.80
    assert round(c.usd, 2) == 4.80
    assert c.total_tokens == 2_000_000


def test_accumulates_and_breaks_down_by_model():
    c = HuntCost()
    c.record("haiku-x", input_tokens=500_000)
    c.record("sonnet-x", output_tokens=1_000_000)
    assert set(c.by_model) == {"haiku-x", "sonnet-x"}
    assert round(c.by_model["haiku-x"]["usd"], 3) == round(0.5 * 0.80, 3)
    assert round(c.by_model["sonnet-x"]["usd"], 3) == 15.0
    assert c.input_tokens == 500_000 and c.output_tokens == 1_000_000


def test_negative_tokens_clamped():
    c = HuntCost()
    c.record("haiku", input_tokens=-10, output_tokens=-5)
    assert c.input_tokens == 0 and c.output_tokens == 0 and c.usd == 0.0


def test_to_dict_shape():
    c = HuntCost()
    c.record("haiku", input_tokens=1000, output_tokens=2000)
    d = c.to_dict()
    assert d["total_tokens"] == 3000
    assert "by_model" in d and "haiku" in d["by_model"]
