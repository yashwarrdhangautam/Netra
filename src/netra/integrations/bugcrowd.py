"""Read-only Bugcrowd API/client mapping for NETRA-BB."""
from __future__ import annotations

import os
from typing import Any

import httpx

from netra.bugbounty.programs import ProgramInput, ScopeRuleInput
from netra.db.models.bb_program import BBPlatform
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType


class BugcrowdClient:
    """Small read-only client mirroring the HackerOne integration shape."""

    BASE_URL = "https://api.bugcrowd.com"

    def __init__(self, token: str | None = None, timeout: float = 30.0) -> None:
        self.token = token or os.getenv("BUGCROWD_TOKEN", "")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BugcrowdClient":
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=self.timeout,
            headers={"Accept": "application/json", "Authorization": f"Token {self.token}"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client:
            await self._client.aclose()

    async def get_program(self, handle: str) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("BugcrowdClient must be used as an async context manager")
        resp = await self._client.get(f"/programs/{handle}")
        resp.raise_for_status()
        return resp.json()

    async def get_scope(self, handle: str) -> list[ScopeRuleInput]:
        data = await self.get_program(handle)
        return self.scope_to_rules(data.get("target_groups", data.get("targets", [])))

    def to_program_input(self, handle: str, data: dict[str, Any]) -> ProgramInput:
        return ProgramInput(
            platform=BBPlatform.BUGCROWD,
            handle=handle,
            name=data.get("name", handle),
            policy_url=data.get("program_url") or data.get("url"),
            payout_min=data.get("payout_min"),
            payout_max=data.get("payout_max"),
            currency=data.get("currency", "USD"),
        )

    @staticmethod
    def scope_to_rules(groups: list[dict[str, Any]]) -> list[ScopeRuleInput]:
        rules: list[ScopeRuleInput] = []
        for group in groups or []:
            in_scope = not bool(group.get("out_of_scope"))
            targets = group.get("targets") if "targets" in group else [group]
            for target in targets or []:
                value = target.get("target") or target.get("name") or target.get("uri")
                if not value:
                    continue
                rules.append(
                    ScopeRuleInput(
                        rule_type=ScopeRuleType.IN if in_scope else ScopeRuleType.OUT,
                        asset_type=_asset_type(target.get("type") or target.get("category") or value),
                        pattern=str(value),
                        notes=target.get("description") or group.get("description"),
                    )
                )
        return rules


def _asset_type(value: str) -> ScopeAssetType:
    v = value.lower()
    if "/" in v and ("http" in v or "." in v):
        return ScopeAssetType.URL
    if "*" in v:
        return ScopeAssetType.WILDCARD
    if "cidr" in v or "/" in v and any(ch.isdigit() for ch in v):
        return ScopeAssetType.CIDR
    if "ip" in v:
        return ScopeAssetType.IP
    if "mobile" in v or "app" in v:
        return ScopeAssetType.MOBILE
    return ScopeAssetType.DOMAIN

