"""Tests for the HackerOne integration.

Uses a custom httpx MockTransport so we don't need pytest-httpx as a dep.
"""
from __future__ import annotations

import pytest

# pytest-asyncio mode is configured in the project's existing pytest.ini / pyproject.

httpx = pytest.importorskip("httpx")

from netra.bugbounty.programs import ScopeRuleInput
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType
from netra.integrations.hackerone import (
    H1HacktivityItem,
    H1_ASSET_TYPE_MAP,
    HackerOneClient,
    fetch_and_convert_program,
    to_program_input,
)


# ── Fixtures ────────────────────────────────────────────────────────────────────
PROGRAM_RESP = {
    "id": "1",
    "type": "program",
    "attributes": {
        "name": "Shopify",
        "handle": "shopify",
        "policy": "https://hackerone.com/shopify",
        "offers_bounties": True,
        "bounty_min": 500,
        "bounty_max": 30000,
        "currency": "USD",
    },
}

SCOPES_PAGE_1 = {
    "data": [
        {
            "id": "1",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.shopify.com",
                "eligible_for_submission": True,
                "max_severity": None,
                "instruction": None,
            },
        },
        {
            "id": "2",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "shopify.com",
                "eligible_for_submission": True,
                "max_severity": None,
                "instruction": None,
            },
        },
        {
            "id": "3",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "internal.shopify.com",
                "eligible_for_submission": False,
                "max_severity": None,
                "instruction": "Internal infra — out of scope.",
            },
        },
        {
            "id": "4",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.myshopify.com",
                "eligible_for_submission": True,
                "max_severity": "high",
                "instruction": None,
            },
        },
        {
            "id": "5",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "GOOGLE_PLAY_APP_ID",
                "asset_identifier": "com.shopify.mobile",
                "eligible_for_submission": True,
                "max_severity": None,
                "instruction": None,
            },
        },
        {
            "id": "6",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "UNSUPPORTED_TYPE",
                "asset_identifier": "weird-thing",
                "eligible_for_submission": True,
                "max_severity": None,
                "instruction": None,
            },
        },
    ],
    "links": {
        "next": "https://api.hackerone.com/v1/hackers/programs/shopify/structured_scopes?page%5Bnumber%5D=2",
    },
}

SCOPES_PAGE_2 = {
    "data": [
        {
            "id": "7",
            "type": "structured-scope",
            "attributes": {
                "asset_type": "CIDR",
                "asset_identifier": "203.0.113.0/24",
                "eligible_for_submission": True,
                "max_severity": None,
                "instruction": None,
            },
        },
    ],
    "links": {},  # last page
}

HACKTIVITY_PAGE = {
    "data": [
        {
            "id": "evt-1",
            "type": "hacktivity-item",
            "attributes": {
                "latest_disclosable_activity_at": "2026-05-09T10:00:00Z",
                "message": "Report disclosed publicly",
            },
            "relationships": {
                "report": {"data": {"type": "report", "id": "r1"}},
                "program": {"data": {"type": "program", "id": "p1"}},
                "hacker": {"data": {"type": "hacker", "id": "h1"}},
                "weakness": {"data": {"type": "weakness", "id": "w1"}},
            },
        }
    ],
    "included": [
        {
            "id": "r1",
            "type": "report",
            "attributes": {
                "title": "Shopify reflected XSS",
                "url": "https://hackerone.com/reports/1",
                "severity_rating": "medium",
                "description": "Reflected XSS in Shopify dashboard.",
                "disclosed_at": "2026-05-09T10:00:00Z",
            },
        },
        {"id": "p1", "type": "program", "attributes": {"handle": "shopify"}},
        {"id": "h1", "type": "hacker", "attributes": {"username": "alice"}},
        {"id": "w1", "type": "weakness", "attributes": {"name": "Cross-Site Scripting (XSS)"}},
    ],
    "links": {},
}


def _build_mock_transport():
    """Return an httpx MockTransport that serves our canned responses."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "401" in url:
            return httpx.Response(401, json={"errors": ["unauthorized"]})
        if url.endswith("/hackers/programs/shopify"):
            return httpx.Response(200, json=PROGRAM_RESP)
        if "/structured_scopes" in url and "page%5Bnumber%5D=2" in url:
            return httpx.Response(200, json=SCOPES_PAGE_2)
        if url.endswith("/hackers/programs/shopify/structured_scopes") or "structured_scopes?page%5Bsize%5D=100" in url:
            return httpx.Response(200, json=SCOPES_PAGE_1)
        if "/hackers/hacktivity" in url:
            return httpx.Response(200, json=HACKTIVITY_PAGE)
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


# Patch HackerOneClient's context manager to use the mock transport.
class MockedClient(HackerOneClient):
    """Test variant that mounts a MockTransport instead of real network."""

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            auth=(self.api_username, self.api_token),
            timeout=self._timeout,
            transport=_build_mock_transport(),
            headers={"Accept": "application/json"},
        )
        return self


# ── Configuration / safety ──────────────────────────────────────────────────────
class TestConfig:
    def test_unconfigured_client_returns_false(self, monkeypatch):
        monkeypatch.delenv("H1_API_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)
        client = HackerOneClient()
        assert client.is_configured() is False

    def test_explicit_creds_override_env(self, monkeypatch):
        monkeypatch.setenv("H1_API_USERNAME", "env_user")
        client = HackerOneClient(api_username="explicit", api_token="t")
        assert client.api_username == "explicit"
        assert client.is_configured() is True

    def test_env_creds_picked_up(self, monkeypatch):
        monkeypatch.setenv("H1_API_USERNAME", "env_user")
        monkeypatch.setenv("H1_API_TOKEN", "env_token")
        client = HackerOneClient()
        assert client.is_configured() is True


# ── Asset type map ──────────────────────────────────────────────────────────────
class TestAssetTypeMap:
    def test_known_h1_types_map(self):
        assert H1_ASSET_TYPE_MAP["URL"] is ScopeAssetType.URL
        assert H1_ASSET_TYPE_MAP["WILDCARD"] is ScopeAssetType.WILDCARD
        assert H1_ASSET_TYPE_MAP["GOOGLE_PLAY_APP_ID"] is ScopeAssetType.MOBILE
        assert H1_ASSET_TYPE_MAP["SOURCE_CODE"] is ScopeAssetType.REPO
        assert H1_ASSET_TYPE_MAP["CIDR"] is ScopeAssetType.CIDR

    def test_unknown_h1_type_returns_none_via_converter(self):
        # _scope_item_to_rule should drop unknown types rather than guess.
        from netra.integrations.hackerone import HackerOneClient
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "BIZARRE_NEW_TYPE",
                "asset_identifier": "x",
                "eligible_for_submission": True,
            }
        })
        assert rule is None


# ── Scope item → rule conversion ────────────────────────────────────────────────
class TestScopeItemToRule:
    def test_eligible_becomes_in(self):
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "shopify.com",
                "eligible_for_submission": True,
            }
        })
        assert isinstance(rule, ScopeRuleInput)
        assert rule.rule_type == ScopeRuleType.IN
        assert rule.asset_type == ScopeAssetType.DOMAIN
        assert rule.pattern == "shopify.com"

    def test_ineligible_becomes_out(self):
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "internal.shopify.com",
                "eligible_for_submission": False,
            }
        })
        assert rule is not None
        assert rule.rule_type == ScopeRuleType.OUT

    def test_severity_cap_propagates(self):
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.myshopify.com",
                "eligible_for_submission": True,
                "max_severity": "high",
            }
        })
        assert rule is not None
        assert rule.severity_cap == "high"

    def test_instruction_kept_as_notes(self):
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "x.com",
                "eligible_for_submission": True,
                "instruction": "Hello operator.",
            }
        })
        assert rule is not None
        assert rule.notes == "Hello operator."

    def test_missing_identifier_returned_as_none(self):
        rule = HackerOneClient._scope_item_to_rule({
            "attributes": {
                "asset_type": "DOMAIN",
                "asset_identifier": "",
                "eligible_for_submission": True,
            }
        })
        assert rule is None


# ── End-to-end with mocked HTTP ────────────────────────────────────────────────
class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_get_program(self):
        async with MockedClient(api_username="x", api_token="y") as client:
            prog = await client.get_program("shopify")
        assert prog.handle == "shopify"
        assert prog.name == "Shopify"
        assert prog.payout_min == 500
        assert prog.payout_max == 30000
        assert prog.policy_url is not None

    @pytest.mark.asyncio
    async def test_get_structured_scopes_paginates(self):
        async with MockedClient(api_username="x", api_token="y") as client:
            rules = await client.get_structured_scopes("shopify")

        # 6 from page 1, but UNSUPPORTED_TYPE is dropped → 5; +1 from page 2 → 6 total.
        assert len(rules) == 6
        types = {(r.rule_type.value, r.asset_type.value) for r in rules}
        assert ("in", "wildcard") in types
        assert ("in", "domain") in types
        assert ("out", "domain") in types
        assert ("in", "mobile") in types
        assert ("in", "cidr") in types

    @pytest.mark.asyncio
    async def test_get_program_unauthorized(self, monkeypatch):
        # Build a client where the URL is forced to include "401".
        client = MockedClient(api_username="x", api_token="y")
        # Override BASE_URL on the instance so the mock returns 401.
        client.BASE_URL = "https://api.hackerone.com/v1/401"
        async with client as c:
            with pytest.raises(PermissionError):
                await c.get_program("shopify")

    @pytest.mark.asyncio
    async def test_get_hacktivity_parses_disclosed_reports(self):
        async with MockedClient(api_username="x", api_token="y") as client:
            items = await client.get_hacktivity()
        assert len(items) == 1
        item = items[0]
        assert isinstance(item, H1HacktivityItem)
        assert item.program_handle == "shopify"
        assert item.author_handle == "alice"
        assert item.weakness == "Cross-Site Scripting (XSS)"
        assert item.source_url == "https://hackerone.com/reports/1"


# ── Helpers ────────────────────────────────────────────────────────────────────
class TestHelpers:
    def test_to_program_input(self):
        from netra.integrations.hackerone import H1Program
        p = H1Program(
            handle="shopify",
            name="Shopify",
            policy_url="https://hackerone.com/shopify",
            payout_min=500,
            payout_max=30000,
            currency="USD",
            raw={},
        )
        pi = to_program_input(p)
        assert pi.handle == "shopify"
        assert pi.platform.value == "hackerone"
        assert pi.payout_min == 500

    @pytest.mark.asyncio
    async def test_fetch_and_convert_program(self, monkeypatch):
        # Patch HackerOneClient to be MockedClient for the duration of this test.
        from netra.integrations import hackerone as h1mod
        monkeypatch.setattr(h1mod, "HackerOneClient", MockedClient)
        # Set creds via env so MockedClient.is_configured() returns True.
        monkeypatch.setenv("H1_API_USERNAME", "x")
        monkeypatch.setenv("H1_API_TOKEN", "y")

        prog_input, rules = await fetch_and_convert_program("shopify")
        assert prog_input.handle == "shopify"
        assert len(rules) == 6
