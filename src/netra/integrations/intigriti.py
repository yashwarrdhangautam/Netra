"""Read-only Intigriti researcher API client for NETRA-BB.

Endpoints checked against the live researcher API with a researcher token (GET only):
  GET /external/researcher/v1/programs          -> {"maxCount", "records": [{"id", "handle", "name", ...}]}
  GET /external/researcher/v1/programs/{id}     -> {"domains": {"content": [{"endpoint", "type": {"value"}, "tier": {"value"}, ...}]}, ...}
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from netra.bugbounty.programs import ProgramInput, ScopeRuleInput
from netra.core.config import settings
from netra.db.models.bb_program import BBPlatform
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType

OUT_OF_SCOPE_TIER = "out of scope"


class IntigritiClient:
    """Read-only client for the Intigriti researcher API. Makes GET requests only."""

    BASE_URL = "https://api.intigriti.com/external/researcher/v1"

    def __init__(self, token: str | None = None, timeout: float = 30.0) -> None:
        self.token = token or settings.intigriti_token or os.getenv("INTIGRITI_TOKEN", "")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> IntigritiClient:
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=self.timeout,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client:
            await self._client.aclose()

    def _require(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("IntigritiClient must be used as an async context manager")
        return self._client

    async def list_programs(
        self, page_size: int = 100, max_pages: int = 50
    ) -> list[dict[str, Any]]:
        """Every program visible to the token. Pages with offset until maxCount is reached."""
        records: list[dict[str, Any]] = []
        for page in range(max_pages):
            resp = await self._require().get(
                "/programs", params={"limit": page_size, "offset": page * page_size}
            )
            resp.raise_for_status()
            body = resp.json()
            batch = list(body.get("records", []))
            records.extend(batch)
            if not batch or len(records) >= int(body.get("maxCount", 0)):
                break
        return records

    async def resolve_id(self, handle_or_id: str) -> str:
        """Accept a program id or a handle; return the id the API needs."""
        for record in await self.list_programs():
            if handle_or_id in (str(record.get("id")), str(record.get("handle"))):
                return str(record["id"])
        return handle_or_id

    async def get_program(self, handle_or_id: str) -> dict[str, Any]:
        program_id = await self.resolve_id(handle_or_id)
        resp = await self._require().get(f"/programs/{program_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_scope(self, program_id: str) -> list[ScopeRuleInput]:
        data = await self.get_program(program_id)
        domains = data.get("domains") or {}
        items = domains.get("content", []) if isinstance(domains, dict) else []
        return self.scope_to_rules(items)

    def to_program_input(self, data: dict[str, Any]) -> ProgramInput:
        return ProgramInput(
            platform=BBPlatform.INTIGRITI,
            handle=str(data.get("handle") or data.get("id")),
            name=data.get("name") or str(data.get("handle")),
            policy_url=None,
            payout_min=None,
            payout_max=None,
            currency="EUR",
        )

    @staticmethod
    def scope_to_rules(targets: list[dict[str, Any]]) -> list[ScopeRuleInput]:
        rules: list[ScopeRuleInput] = []
        for target in targets or []:
            value = target.get("endpoint") or target.get("value") or target.get("target")
            if not value:
                continue
            tier = (
                (target.get("tier") or {}).get("value", "")
                if isinstance(target.get("tier"), dict)
                else ""
            )
            out = bool(target.get("outOfScope") or target.get("out_of_scope"))
            out = out or tier.lower() == OUT_OF_SCOPE_TIER
            type_value = (
                (target.get("type") or {}).get("value", "")
                if isinstance(target.get("type"), dict)
                else str(target.get("type", ""))
            )
            rules.append(
                ScopeRuleInput(
                    rule_type=ScopeRuleType.OUT if out else ScopeRuleType.IN,
                    asset_type=_asset_type(str(value), type_value),
                    pattern=str(value),
                    severity_cap=None,
                    notes=target.get("description"),
                )
            )
        return rules


def _asset_type(value: str, type_hint: str = "") -> ScopeAssetType:
    v = f"{value} {type_hint}".lower()
    if value.startswith(("http://", "https://")):
        return ScopeAssetType.URL
    if "*" in value or "wildcard" in v:
        return ScopeAssetType.WILDCARD
    if "cidr" in v:
        return ScopeAssetType.CIDR
    if "ip" in v:
        return ScopeAssetType.IP
    if "mobile" in v or "app" in v:
        return ScopeAssetType.MOBILE
    return ScopeAssetType.DOMAIN
