"""Threat-intelligence lookups for analysts: exploitation status for CVE identifiers."""

from typing import Annotated

from fastapi import APIRouter, Query

from netra.intel.cve_intel import CveIntelClient, rank_key

router = APIRouter(prefix="/intel", tags=["Intel"])
MAX_IDS = 50


@router.get("/cve")
async def cve_intel(
    ids: Annotated[
        str, Query(min_length=1, max_length=2000, description="Comma-separated CVE ids")
    ],
) -> dict[str, object]:
    """Return KEV status and EPSS likelihood, exploited first, for up to 50 CVE ids."""
    raw = [part for part in ids.split(",")][:MAX_IDS]
    results = await CveIntelClient().lookup(raw)
    ordered = sorted(results, key=rank_key)
    return {
        "items": [
            {
                "cve": r.cve,
                "known_exploited": r.known_exploited,
                "epss": r.epss,
                "priority": r.priority,
            }
            for r in ordered
        ],
        "count": len(ordered),
    }
