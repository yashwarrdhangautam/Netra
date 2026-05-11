"""Tests for AI prompts."""

from netra.ai.prompts import BOUNTY_HUNTER_PROMPT, get_system_prompt


def test_bounty_hunter_prompt_contract() -> None:
    prompt = BOUNTY_HUNTER_PROMPT.lower()
    assert "{finding_context}" in BOUNTY_HUNTER_PROMPT
    assert "{program_context}" in BOUNTY_HUNTER_PROMPT
    assert "impact" in prompt
    assert "novelty" in prompt
    assert "payout" in prompt
    assert BOUNTY_HUNTER_PROMPT.strip().endswith("Respond with JSON only.")
    assert get_system_prompt("bounty_hunter") == BOUNTY_HUNTER_PROMPT

