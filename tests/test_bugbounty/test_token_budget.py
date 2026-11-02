"""Tests for the token-budget spine (Sprint 1)."""

from netra.bugbounty.agentic.budget import HuntBudget
from netra.bugbounty.agentic.token_budget import context_window, count_tokens, output_limit


def test_count_tokens_empty():
    assert count_tokens("") == 0


def test_count_tokens_nonempty_positive():
    assert count_tokens("hello world, this is a token count test") > 0


def test_count_tokens_scales_with_length():
    assert count_tokens("a" * 4000) > count_tokens("a" * 40)


def test_context_window_known_and_fallback():
    assert context_window("claude-sonnet-4-20250514") == 200_000
    assert context_window("totally-unknown-model", fallback=12345) == 12345


def test_output_limit_positive():
    assert output_limit("claude-sonnet-4-20250514") > 0


def test_hunt_budget_token_ceiling():
    b = HuntBudget(max_tools=30, max_tokens=1000)
    assert b.exhausted() is False
    b.record_tokens(400)
    b.record_tokens(400)
    assert b.tokens_used == 800
    assert b.tokens_remaining() == 200
    assert b.exhausted() is False
    b.record_tokens(300)
    assert b.exhausted() is True
    assert b.exhaustion_reason() == "max_tokens"


def test_hunt_budget_tool_ceiling_still_works():
    b = HuntBudget(max_tools=2, max_tokens=10_000)
    b.record_tool()
    b.record_tool()
    assert b.exhausted() is True
    assert b.exhaustion_reason() == "max_tools"


def test_record_tokens_ignores_nonpositive():
    b = HuntBudget(max_tokens=100)
    b.record_tokens(0)
    b.record_tokens(-5)
    assert b.tokens_used == 0
