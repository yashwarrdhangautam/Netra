"""Bugcrowd public disclosure feed (Crowdstream, disclosed only) for the learning corpus.

Endpoint and field names come from a third-party scraper's documentation, not from Bugcrowd.
They are unverified against the live site and must be confirmed before relying on this source:

- ``GET https://bugcrowd.com/crowdstream.json?filter_by=disclosures&page=N``

Only metadata is stored: program name, researcher handle, priority, title and the link to the
public disclosure page. Full write-ups are not fetched or stored, so no third-party report text
enters the corpus. Each stored row is checked against the right-to-be-forgotten blocklist by
``upsert_report``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.fetcher import LearningFetcher
from netra.bugbounty.learning.ingest import log_ingest, upsert_report
from netra.core.config import settings

CROWDSTREAM_URL = "https://bugcrowd.com/crowdstream.json"
SOURCE_NAME = "bugcrowd_disclosures"
_SEVERITY = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P5"}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%d %b %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _report_url(entry: dict[str, Any]) -> str | None:
    """The live feed gives a relative path (/disclosures/...). Keep only bugcrowd.com links."""
    raw = entry.get("disclosure_report_url") or entry.get("disclosureReportUrl")
    if not isinstance(raw, str) or not raw:
        return None
    url = f"https://bugcrowd.com{raw}" if raw.startswith("/") else raw
    return url[:1000] if url.startswith("https://bugcrowd.com/") else None


def extract_rows(payload: Any) -> list[dict[str, Any]]:
    """Return only well-formed disclosed rows; ignore anything else in the feed.

    Field names follow the live feed: a top-level ``results`` list, ``engagement_name``,
    ``researcher_username``, ``disclosed_at`` as "6 Nov 2026", and a ``disclosed`` flag.
    """
    items = payload
    if isinstance(payload, dict):
        items = payload.get("results") or payload.get("items") or []
    if not isinstance(items, list):
        return []
    rows: list[dict[str, Any]] = []
    for entry in items:
        if not isinstance(entry, dict) or entry.get("disclosed") is False:
            continue
        url = _report_url(entry)
        if url is None:
            continue  # not a publicly disclosed submission with a report page
        priority = entry.get("priority")
        rows.append(
            {
                "source_url": url,
                "title": str(entry.get("title") or "")[:500] or None,
                "program": str(entry.get("engagement_name") or entry.get("engagementName") or "")[
                    :255
                ]
                or None,
                "author": str(
                    entry.get("researcher_username") or entry.get("researcherUsername") or ""
                )[:255]
                or None,
                "severity": _SEVERITY.get(priority) if isinstance(priority, int) else None,
                "disclosed_at": _parse_time(entry.get("disclosed_at") or entry.get("disclosedAt")),
                "target": str(entry.get("target") or "")[:500] or None,
            }
        )
    return rows


async def ingest_bugcrowd_disclosures(
    session: AsyncSession,
    *,
    max_pages: int = 3,
    client: httpx.AsyncClient | None = None,
) -> dict[str, int]:
    started = datetime.now(UTC)
    if not settings.corpus_source_bugcrowd:
        await log_ingest(
            session,
            source_name=SOURCE_NAME,
            items_added=0,
            items_updated=0,
            notes="disabled_by_config",
            started_at=started,
        )
        await session.commit()
        return {"added": 0, "updated": 0}

    fetcher = LearningFetcher(client=client)
    added = 0
    updated = 0
    errors: list[str] = []
    for page in range(1, max_pages + 1):
        try:
            payload = await fetcher.get_json(
                CROWDSTREAM_URL, params={"filter_by": "disclosures", "page": page}
            )
        except Exception as exc:  # network, robots or parse failure: record and stop
            errors.append(f"page {page}: {type(exc).__name__}")
            break
        rows = extract_rows(payload)
        if not rows:
            break
        for row in rows:
            report, created = await upsert_report(
                session,
                source_platform="bugcrowd",
                source_url=row["source_url"],
                author_handle=row["author"],
                program_handle=row["program"],
                vuln_class=None,
                severity=row["severity"],
                title=row["title"],
                body_summary=row["title"] or "",
                tech_stack=[],
                metadata={"target": row["target"]},
                ingested_at=row["disclosed_at"] or started,
            )
            if report is None:
                continue  # forgotten (right-to-be-forgotten blocklist): not counted
            if created:
                added += 1
            else:
                updated += 1

    await log_ingest(
        session,
        source_name=SOURCE_NAME,
        items_added=added,
        items_updated=updated,
        errors=errors or None,
        started_at=started,
    )
    await session.commit()
    return {"added": added, "updated": updated}
