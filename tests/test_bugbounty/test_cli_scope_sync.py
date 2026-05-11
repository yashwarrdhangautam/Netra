"""Tests for `netra-bb scope --sync` and the scope-diff rendering helper.

The renderer is a pure function — we exercise it without a DB by constructing a
ScopeDiff manually. The platform-fetch + DB-write path is exercised end-to-end in
contract / integration tests; here we keep the unit tests fast and isolated.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from netra.bugbounty.cli import _render_scope_diff
from netra.bugbounty.programs import ScopeDiff, ScopeRuleInput
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType


def _added(asset_type, pattern, *, severity_cap=None):
    return ScopeRuleInput(
        rule_type=ScopeRuleType.IN,
        asset_type=asset_type,
        pattern=pattern,
        severity_cap=severity_cap,
    )


def _removed(asset_type, pattern, *, severity_cap=None):
    rule = MagicMock()
    rule.rule_type = "in"
    rule.asset_type = asset_type
    rule.pattern = pattern
    rule.severity_cap = severity_cap
    return rule


class TestRenderScopeDiff:
    def test_no_changes_renders_up_to_date(self, capsys):
        diff = ScopeDiff(added=[], removed=[], unchanged_count=42)
        _render_scope_diff(diff, "hackerone", "shopify")
        out = capsys.readouterr().out
        assert "up to date" in out
        assert "hackerone/shopify" in out
        assert "42" in out

    def test_renders_added_rules_with_plus_marker(self, capsys):
        diff = ScopeDiff(
            added=[_added(ScopeAssetType.WILDCARD, "*.shopify.com")],
            removed=[],
            unchanged_count=10,
        )
        _render_scope_diff(diff, "hackerone", "shopify")
        out = capsys.readouterr().out
        assert "*.shopify.com" in out
        assert "+ 1 added" in out
        assert "10 unchanged" in out

    def test_renders_removed_rules_with_minus_marker(self, capsys):
        diff = ScopeDiff(
            added=[],
            removed=[_removed("domain", "old-asset.shopify.com")],
            unchanged_count=5,
        )
        _render_scope_diff(diff, "hackerone", "shopify")
        out = capsys.readouterr().out
        assert "old-asset.shopify.com" in out
        assert "- 1 deactivated" in out

    def test_renders_severity_cap_in_added_rule(self, capsys):
        diff = ScopeDiff(
            added=[_added(ScopeAssetType.WILDCARD, "*.myshopify.com", severity_cap="high")],
            removed=[],
            unchanged_count=0,
        )
        _render_scope_diff(diff, "hackerone", "shopify")
        out = capsys.readouterr().out
        assert "*.myshopify.com" in out
        assert "high" in out

    def test_renders_mixed_added_and_removed(self, capsys):
        diff = ScopeDiff(
            added=[
                _added(ScopeAssetType.DOMAIN, "new-asset.shopify.com"),
                _added(ScopeAssetType.WILDCARD, "*.new.shopify.com"),
            ],
            removed=[_removed("domain", "removed.shopify.com")],
            unchanged_count=15,
        )
        _render_scope_diff(diff, "hackerone", "shopify")
        out = capsys.readouterr().out
        assert "new-asset.shopify.com" in out
        assert "*.new.shopify.com" in out
        assert "removed.shopify.com" in out
        assert "+ 2 added" in out
        assert "- 1 deactivated" in out
        assert "15 unchanged" in out

    def test_has_changes_detection(self):
        empty = ScopeDiff(added=[], removed=[], unchanged_count=10)
        with_added = ScopeDiff(
            added=[_added(ScopeAssetType.DOMAIN, "x.com")],
            removed=[],
            unchanged_count=0,
        )
        with_removed = ScopeDiff(
            added=[],
            removed=[_removed("domain", "x.com")],
            unchanged_count=0,
        )
        assert empty.has_changes is False
        assert with_added.has_changes is True
        assert with_removed.has_changes is True


class TestSyncProgramScopeGuards:
    """Path-selection logic; full integration tested in test_hackerone."""

    @pytest.mark.asyncio
    async def test_unsupported_platform_returns_none(self, capsys):
        from netra.bugbounty.cli import _sync_program_scope
        from netra.db.models.bb_program import BBPlatform

        diff = await _sync_program_scope(BBPlatform.BUGCROWD, "anything")
        assert diff is None
        out = capsys.readouterr().out
        assert "not implemented" in out
        assert "bugcrowd" in out

    @pytest.mark.asyncio
    async def test_h1_without_credentials_returns_none(self, monkeypatch, capsys):
        # Stub HackerOneClient so we never touch httpx (sandbox proxy env breaks it).
        from netra.bugbounty import cli as bb_cli
        from netra.db.models.bb_program import BBPlatform
        import netra.integrations.hackerone as h1mod

        class _UnconfiguredClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def is_configured(self):
                return False

            async def get_structured_scopes(self, handle):
                raise AssertionError("must not be called when unconfigured")

        monkeypatch.setattr(h1mod, "HackerOneClient", _UnconfiguredClient)

        diff = await bb_cli._sync_program_scope(BBPlatform.HACKERONE, "shopify")
        assert diff is None
        out = capsys.readouterr().out
        assert "credentials" in out.lower()
