"""HackerOne API integration — pulls program metadata and scope rules.

HackerOne's public API: https://api.hackerone.com/v1/

Auth uses HTTP Basic with (api_username, api_token). The credentials live in env vars
H1_API_USERNAME and H1_API_TOKEN — they are NEVER read from the chat or stored in
the DB. NETRA-BB only READS via this client. Submission is always manual through the
H1 UI; no write methods are exposed.

Scope mapping (HackerOne 'structured_scopes' → NETRA-BB scope rules):
    asset_type       → ScopeAssetType
    URL              → url     (with optional path prefix)
    DOMAIN           → domain
    WILDCARD         → wildcard
    APPLE_STORE_APP_ID, GOOGLE_PLAY_APP_ID, OTHER_APK → mobile
    SOURCE_CODE      → repo
    CIDR             → cidr
    IP_ADDRESS       → ip
    eligible_for_submission=True  → ScopeRuleType.IN
    eligible_for_submission=False → ScopeRuleType.OUT
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import structlog

from netra.bugbounty.programs import ProgramInput, ScopeRuleInput
from netra.db.models.bb_program import BBPlatform
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType

logger = structlog.get_logger()


# ── HackerOne asset type → NETRA-BB asset type ──────────────────────────────────
H1_ASSET_TYPE_MAP: dict[str, ScopeAssetType] = {
    "URL": ScopeAssetType.URL,
    "DOMAIN": ScopeAssetType.DOMAIN,
    "WILDCARD": ScopeAssetType.WILDCARD,
    "APPLE_STORE_APP_ID": ScopeAssetType.MOBILE,
    "GOOGLE_PLAY_APP_ID": ScopeAssetType.MOBILE,
    "OTHER_APK": ScopeAssetType.MOBILE,
    "SOURCE_CODE": ScopeAssetType.REPO,
    "CIDR": ScopeAssetType.CIDR,
    "IP_ADDRESS": ScopeAssetType.IP,
}


@dataclass(frozen=True)
class H1Program:
    """A program as fetched from HackerOne."""

    handle: str
    name: str
    policy_url: str | None
    payout_min: int | None
    payout_max: int | None
    currency: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class H1HacktivityItem:
    """Normalized disclosed hacktivity item."""

    source_url: str
    title: str
    body: str
    severity: str | None
    program_handle: str | None
    author_handle: str | None
    weakness: str | None
    disclosed_at: datetime | None
    raw: dict[str, Any]


class HackerOneClient:
    """Read-only HackerOne API client.

    Submission is intentionally NOT supported. Operators submit through the H1 UI,
    never through this client.
    """

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(
        self,
        api_username: str | None = None,
        api_token: str | None = None,
        timeout: float = 30.0,
        before_request: Any | None = None,
        after_response: Any | None = None,
    ):
        """Initialise. Falls back to env vars H1_API_USERNAME / H1_API_TOKEN."""
        self.api_username = api_username or os.environ.get("H1_API_USERNAME", "")
        self.api_token = api_token or os.environ.get("H1_API_TOKEN", "")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._before_request = before_request
        self._after_response = after_response

    def is_configured(self) -> bool:
        """Return True if the client has credentials."""
        return bool(self.api_username and self.api_token)

    async def __aenter__(self) -> "HackerOneClient":
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            auth=(self.api_username, self.api_token),
            timeout=self._timeout,
            headers={"Accept": "application/json"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("HackerOneClient must be used as an async context manager")
        if not self.is_configured():
            raise RuntimeError(
                "HackerOne credentials missing. Set H1_API_USERNAME and H1_API_TOKEN."
            )
        full_url = f"{self.BASE_URL}{path}"
        if self._before_request is not None:
            await self._before_request(full_url)
        resp = await self._client.get(path, params=params)
        if self._after_response is not None:
            await self._after_response(full_url, resp)
        if resp.status_code == 401:
            raise PermissionError("HackerOne API: invalid credentials.")
        if resp.status_code == 429:
            raise RuntimeError("HackerOne API: rate limited (429). Back off and retry.")
        resp.raise_for_status()
        return resp.json()

    # ── Programs ────────────────────────────────────────────────────────────────
    async def get_program(self, handle: str) -> H1Program:
        """Fetch a single program by handle (e.g. 'shopify')."""
        data = await self._get(f"/hackers/programs/{handle}")
        attrs = data.get("attributes", {}) or {}
        bracket = attrs.get("offers_bounties", False)
        # H1 doesn't always expose the explicit min/max in this endpoint — caller
        # may supplement from the program's policy page.
        return H1Program(
            handle=handle,
            name=attrs.get("name", handle),
            policy_url=attrs.get("policy") or f"https://hackerone.com/{handle}",
            payout_min=attrs.get("bounty_min") if bracket else None,
            payout_max=attrs.get("bounty_max") if bracket else None,
            currency=attrs.get("currency", "USD") or "USD",
            raw=data,
        )

    async def get_structured_scopes(self, handle: str) -> list[ScopeRuleInput]:
        """Pull structured_scopes for a program and convert to ScopeRuleInput rows.

        HackerOne's structured_scopes endpoint returns paginated results. We follow
        page links until exhausted.
        """
        rules: list[ScopeRuleInput] = []
        next_path: str | None = f"/hackers/programs/{handle}/structured_scopes"
        params: dict[str, Any] | None = {"page[size]": 100}

        while next_path:
            data = await self._get(next_path, params=params)
            for item in data.get("data", []) or []:
                rule = self._scope_item_to_rule(item)
                if rule is not None:
                    rules.append(rule)
            # H1 follows JSON:API pagination conventions.
            links = data.get("links") or {}
            next_url = links.get("next")
            if next_url:
                # Strip the base URL to get the path.
                next_path = next_url.replace(self.BASE_URL, "") or None
                params = None  # already encoded in the next URL
            else:
                next_path = None
        return rules

    async def get_hacktivity(
        self,
        *,
        disclosed: bool = True,
        since: str | None = None,
        page_size: int = 100,
    ) -> list[H1HacktivityItem]:
        """Fetch disclosed hacktivity items using HackerOne's JSON:API pagination."""
        items: list[H1HacktivityItem] = []
        next_path: str | None = "/hackers/hacktivity"
        params: dict[str, Any] | None = {
            "queryString": f"disclosed:{str(disclosed).lower()}",
            "sortField": "latest_disclosable_activity_at",
            "page[size]": page_size,
        }
        if since:
            params["filter[since]"] = since

        while next_path:
            data = await self._get(next_path, params=params)
            included = data.get("included") or []
            items.extend(self._parse_hacktivity_page(data.get("data", []) or [], included))
            links = data.get("links") or {}
            next_url = links.get("next")
            if next_url:
                next_path = next_url.replace(self.BASE_URL, "") or None
                params = None
            else:
                next_path = None
        return items

    @staticmethod
    def _parse_hacktivity_page(data: list[dict[str, Any]], included: list[dict[str, Any]]) -> list[H1HacktivityItem]:
        included_map = {
            (item.get("type"), item.get("id")): item for item in included
        }
        output: list[H1HacktivityItem] = []
        for item in data:
            attrs = item.get("attributes") or {}
            relationships = item.get("relationships") or {}
            report_ref = ((relationships.get("report") or {}).get("data") or {})
            report = included_map.get((report_ref.get("type"), report_ref.get("id")), {})
            report_attrs = report.get("attributes") or {}

            program_ref = ((relationships.get("program") or {}).get("data") or {})
            program = included_map.get((program_ref.get("type"), program_ref.get("id")), {})
            program_attrs = program.get("attributes") or {}

            hacker_ref = ((relationships.get("hacker") or {}).get("data") or {})
            hacker = included_map.get((hacker_ref.get("type"), hacker_ref.get("id")), {})
            hacker_attrs = hacker.get("attributes") or {}

            weakness_ref = ((relationships.get("weakness") or {}).get("data") or {})
            weakness = included_map.get((weakness_ref.get("type"), weakness_ref.get("id")), {})
            weakness_attrs = weakness.get("attributes") or {}

            latest_activity = attrs.get("latest_disclosable_activity_at") or report_attrs.get("disclosed_at")
            disclosed_at = None
            if latest_activity:
                try:
                    disclosed_at = datetime.fromisoformat(str(latest_activity).replace("Z", "+00:00"))
                except ValueError:
                    disclosed_at = None

            output.append(
                H1HacktivityItem(
                    source_url=report_attrs.get("url")
                    or attrs.get("url")
                    or f"https://hackerone.com/reports/{report_ref.get('id')}",
                    title=report_attrs.get("title") or attrs.get("title") or "HackerOne disclosed report",
                    body=report_attrs.get("substate") or report_attrs.get("description") or attrs.get("message") or "",
                    severity=report_attrs.get("severity_rating") or attrs.get("severity_rating"),
                    program_handle=program_attrs.get("handle"),
                    author_handle=hacker_attrs.get("username") or hacker_attrs.get("name"),
                    weakness=weakness_attrs.get("name"),
                    disclosed_at=disclosed_at,
                    raw={"event": item, "report": report, "program": program, "hacker": hacker, "weakness": weakness},
                )
            )
        return output

    @staticmethod
    def _scope_item_to_rule(item: dict[str, Any]) -> ScopeRuleInput | None:
        """Convert a single HackerOne structured_scope object → ScopeRuleInput.

        Returns None if the asset type isn't representable in NETRA-BB (we'd rather
        skip it than guess).
        """
        attrs = (item or {}).get("attributes") or {}
        h1_asset_type = (attrs.get("asset_type") or "").upper()
        identifier = attrs.get("asset_identifier") or ""
        eligible = bool(attrs.get("eligible_for_submission", False))

        ba = H1_ASSET_TYPE_MAP.get(h1_asset_type)
        if ba is None or not identifier:
            return None

        return ScopeRuleInput(
            rule_type=ScopeRuleType.IN if eligible else ScopeRuleType.OUT,
            asset_type=ba,
            pattern=identifier.strip(),
            severity_cap=attrs.get("max_severity"),
            notes=attrs.get("instruction"),
        )


# ── Convenience: program input from H1 program ─────────────────────────────────
def to_program_input(program: H1Program) -> ProgramInput:
    """Convert an H1Program to a NETRA-BB ProgramInput."""
    return ProgramInput(
        platform=BBPlatform.HACKERONE,
        handle=program.handle,
        name=program.name,
        policy_url=program.policy_url,
        payout_min=program.payout_min,
        payout_max=program.payout_max,
        currency=program.currency,
    )


async def fetch_and_convert_program(handle: str) -> tuple[ProgramInput, list[ScopeRuleInput]]:
    """One-shot helper: fetch a program + its scope, return ready-to-persist DTOs."""
    async with HackerOneClient() as client:
        prog = await client.get_program(handle)
        rules = await client.get_structured_scopes(handle)
    return to_program_input(prog), rules
