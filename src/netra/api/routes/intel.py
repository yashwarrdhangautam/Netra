"""Threat-intelligence lookups for analysts: CVE exploitation status, payloads and bypass checks."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.api.scope import can_see_scan
from netra.core.config import settings
from netra.db.models.scan import Scan
from netra.db.models.user import User
from netra.intel.cve_intel import CveIntelClient, rank_key
from netra.intel.manifest import build_manifest, render_arsenal
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


@router.get("/scans/{scan_id}/manifest", response_model=None)
async def scan_manifest(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_active_user)],
    output: Annotated[str, Query(alias="format", pattern="^(json|markdown)$")] = "json",
    db: AsyncSession = Depends(get_db_session),
):
    """Recon manifest (schema 1.0) for a scan, built from the hosts its recon phase found.

    Returns JSON by default, or the arsenal map as markdown with ?format=markdown.
    """
    scan = await db.get(Scan, scan_id)
    if not scan or not await can_see_scan(db, current_user, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    hosts = (scan.checkpoint_data or {}).get("http_hosts")
    if hosts is None:
        raise HTTPException(status_code=409, detail="Recon has not recorded hosts for this scan")
    target = str(getattr(scan, "name", None) or scan_id)
    manifest = build_manifest(target, hosts)
    if output == "markdown":
        return PlainTextResponse(render_arsenal(manifest), media_type="text/markdown")
    return manifest
