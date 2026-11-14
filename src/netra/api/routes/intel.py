"""Threat-intelligence lookups for analysts: CVE exploitation status, payloads and bypass checks."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from netra.core.config import settings
from netra.intel.cve_intel import CveIntelClient, rank_key
from netra.intel.payloads import checkout_dir, load_payloads, search

router = APIRouter(prefix="/intel", tags=["Intel"])
MAX_IDS = 50
MAX_RESULTS = 100


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


@router.get("/payloads")
async def payloads(
    q: Annotated[str, Query(max_length=200)] = "",
    topic: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_RESULTS)] = 25,
) -> dict[str, object]:
    """Search the pinned payload library. Each passage carries its source file and commit."""
    root = checkout_dir(settings.tools_dir)
    if not root.is_dir():
        raise HTTPException(
            status_code=503,
            detail="Payload library is not synced. Run the payload sync on the worker host.",
        )
    hits = search(load_payloads(root), query=q, topic=topic, limit=limit)
    return {"items": [p.as_dict() for p in hits], "count": len(hits)}
