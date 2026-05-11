"""Tests for passive bug bounty recon."""

import pytest

from netra.bugbounty.recon import passive
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator


@pytest.mark.asyncio
async def test_passive_recon_dedupes_and_scope_filters(monkeypatch) -> None:
    async def source(seed: str) -> list[str]:
        return ["api.example.com", "API.example.com", "evil.com"]

    monkeypatch.setitem(passive.SOURCES, "unit", source)
    validator = ScopeValidator(
        [ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.com")]
    )

    result = await passive.run_passive_recon(
        ["example.com"], validator, "example", sources=["unit"]
    )

    assert result.in_scope_hosts == ["api.example.com"]
    assert result.out_of_scope_hosts == ["evil.com"]
    assert result.sources["unit"] == 2

