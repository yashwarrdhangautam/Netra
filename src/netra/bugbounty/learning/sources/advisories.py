"""GHSA and NVD advisory ingestion."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.fetcher import LearningFetcher
from netra.bugbounty.learning.ingest import log_ingest, upsert_advisory
from netra.core.config import settings

GHSA_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_nvd_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        metrics = cve.get("metrics") or {}
        cvss_block = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                cvss_block = values[0]
                break
        descriptions = cve.get("descriptions") or []
        summary = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), "") or ""
        references = cve.get("references") or []
        items.append(
            {
                "source_url": (references[0].get("url") if references else None),
                "cve_id": cve.get("id"),
                "ghsa_id": None,
                "severity": ((cvss_block or {}).get("cvssData") or {}).get("baseSeverity"),
                "cvss_vector": ((cvss_block or {}).get("cvssData") or {}).get("vectorString"),
                "affected_packages": [
                    item.get("criteria")
                    for node in (cve.get("configurations") or [])
                    for subgroup in (node.get("nodes") or [])
                    for item in (subgroup.get("cpeMatch") or [])
                    if item.get("criteria")
                ][:20],
                "summary": summary,
                "metadata": {"source": "nvd"},
            }
        )
    return items


def _extract_ghsa_items(payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in payload:
        vulnerabilities = row.get("vulnerabilities") or []
        items.append(
            {
                "source_url": row.get("html_url"),
                "cve_id": row.get("cve_id"),
                "ghsa_id": row.get("ghsa_id"),
                "severity": row.get("severity"),
                "cvss_vector": ((row.get("cvss") or {}).get("vector_string")),
                "affected_packages": [
                    vuln.get("package", {}).get("name")
                    for vuln in vulnerabilities
                    if vuln.get("package", {}).get("name")
                ][:20],
                "summary": row.get("summary") or row.get("description") or "",
                "metadata": {"source": "ghsa"},
            }
        )
    return items


async def ingest_advisories(
    session: AsyncSession,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, int]:
    started = datetime.now(timezone.utc)
    added = 0
    updated = 0
    if not settings.corpus_source_advisories:
        await log_ingest(
            session,
            source_name="public_advisories",
            items_added=0,
            items_updated=0,
            notes="disabled_by_config",
            started_at=started,
        )
        await session.commit()
        return {"added": 0, "updated": 0}
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=60, headers={"Accept": "application/json", "User-Agent": "NETRA-BB/1.0"})
        close_client = True
    fetcher = LearningFetcher(client=client)
    try:
        items = _extract_ghsa_items(await fetcher.get_json(GHSA_URL)) + _extract_nvd_items(await fetcher.get_json(NVD_URL))
        for item in items:
            _row, created = await upsert_advisory(
                session,
                source_url=item["source_url"],
                cve_id=item["cve_id"],
                ghsa_id=item["ghsa_id"],
                severity=item["severity"],
                cvss_vector=item["cvss_vector"],
                affected_packages=item["affected_packages"],
                summary=item["summary"],
                metadata=item["metadata"],
                ingested_at=started,
            )
            if created:
                added += 1
            else:
                updated += 1
        await log_ingest(
            session,
            source_name="public_advisories",
            items_added=added,
            items_updated=updated,
            started_at=started,
        )
        await session.commit()
        return {"added": added, "updated": updated}
    finally:
        if close_client:
            await client.aclose()
