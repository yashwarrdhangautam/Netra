"""Read-only Intigriti API/client mapping for NETRA-BB."""
from __future__ import annotations

import os
from typing import Any

import httpx

from netra.bugbounty.programs import ProgramInput, ScopeRuleInput
from netra.db.models.bb_program import BBPlatform
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType


class IntigritiClient:
    """Small read-only client mirroring the HackerOne integration shape."""

    BASE_URL = "https://api.intigriti.com/core"

    def __init__(self, token: str | None = None, timeout: float = 30.0) -> None:
        self.token = token or os.getenv("INTIGRITI_TOKEN", "")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "IntigritiClient":
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=self.timeout,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client:
            await self._client.aclose()

    async def get_program(self, handle: str) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("IntigritiClient must be used as an async context manager")
        resp = await self._client.get(f"/programs/{handle}")
        resp.raise_for_status()
        return resp.json()

    async def get_scope(self, handle: str) -> list[ScopeRuleInput]:
        data = await self.get_program(handle)
        return self.scope_to_rules(data.get("domains", []) + data.get("targets", []))

    def to_program_input(self, handle: str, data: dict[str, Any]) -> ProgramInput:
        return ProgramInput(
            platform=BBPlatform.INTIGRITI,
            handle=handle,
            name=data.get("name", handle),
            policy_url=data.get("programUrl") or data.get("url"),
            payout_min=data.get("minimumBounty"),
            payout_max=data.get("maximumBounty"),
            currency=data.get("currency", "EUR"),
        )

    @staticmethod
    def scope_to_rules(targets: list[dict[str, Any]]) -> list[ScopeRuleInput]:
        rules: list[ScopeRuleInput] = []
        for target in targets or []:
            value = target.get("endpoint") or target.get("value") or target.get("target")
            if not value:
                continue
            out = bool(target.get("outOfScope") or target.get("out_of_scope"))
            rules.append(
                ScopeRuleInput(
                    rule_type=ScopeRuleType.OUT if out else ScopeRuleType.IN,
                    asset_type=_asset_type(str(value), target.get("type", "")),
                    pattern=str(value),
                    severity_cap=target.get("maxSeverity"),
                    notes=target.get("description"),
                )
            )
        return rules


def _asset_type(value: str, type_hint: str = "") -> ScopeAssetType:
    v = f"{value} {type_hint}".lower()
    if value.startswith(("http://", "https://")):
        return ScopeAssetType.URL
    if "*" in value:
        return ScopeAssetType.WILDCARD
    if "cidr" in v:
        return ScopeAssetType.CIDR
    if "ip" in v:
        return ScopeAssetType.IP
    if "mobile" in v or "app" in v:
        return ScopeAssetType.MOBILE
    return ScopeAssetType.DOMAIN
