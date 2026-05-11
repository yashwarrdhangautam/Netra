"""HackerOne hacktivity ingestion for the local learning corpus."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.fetcher import LearningFetcher
from netra.bugbounty.learning.ingest import log_ingest, upsert_report
from netra.core.config import settings
from netra.integrations.hackerone import H1HacktivityItem, HackerOneClient


def _infer_vuln_class(item: H1HacktivityItem) -> str | None:
    weakness = (item.weakness or "").lower()
    mapping = {
        "xss": "xss",
        "cross-site scripting": "xss",
        "idor": "idor",
        "sql injection": "sqli",
        "server-side request forgery": "ssrf",
        "csrf": "csrf",
    }
    for needle, vuln_class in mapping.items():
        if needle in weakness:
            return vuln_class
    return weakness or None


async def ingest_hacktivity(
    session: AsyncSession,
    *,
    since_days: int = 1,
    client_cls: type[HackerOneClient] = HackerOneClient,
) -> dict[str, int]:
    started = datetime.now(timezone.utc)
    added = 0
    updated = 0
    if not settings.corpus_source_hackerone:
        await log_ingest(
            session,
            source_name="hackerone_hacktivity",
            items_added=0,
            items_updated=0,
            notes="disabled_by_config",
            started_at=started,
        )
        await session.commit()
        return {"added": 0, "updated": 0}
    since = (started - timedelta(days=since_days)).isoformat()
    fetcher = LearningFetcher()
    async with client_cls(before_request=fetcher.before_request, after_response=fetcher.after_response) as client:
        if not client.is_configured():
            await log_ingest(
                session,
                source_name="hackerone_hacktivity",
                items_added=0,
                items_updated=0,
                errors=["credentials_missing"],
                started_at=started,
            )
            await session.commit()
            return {"added": 0, "updated": 0}
        items = await client.get_hacktivity(disclosed=True, since=since)
    for item in items:
        _row, created = await upsert_report(
            session,
            source_platform="hackerone",
            source_url=item.source_url,
            author_handle=item.author_handle,
            program_handle=item.program_handle,
            vuln_class=_infer_vuln_class(item),
            severity=item.severity,
            title=item.title,
            body_summary=item.body,
            tech_stack=[],
            metadata={"weakness": item.weakness},
            ingested_at=item.disclosed_at or started,
        )
        if created:
            added += 1
        else:
            updated += 1
    await log_ingest(
        session,
        source_name="hackerone_hacktivity",
        items_added=added,
        items_updated=updated,
        started_at=started,
    )
    await session.commit()
    return {"added": added, "updated": updated}


async def bootstrap_program(
    session: AsyncSession,
    *,
    handle: str,
    since_days: int = 90,
    client_cls: type[HackerOneClient] = HackerOneClient,
) -> dict[str, int]:
    """Preload disclosed history for a single program when first registering it."""
    started = datetime.now(timezone.utc)
    added = 0
    updated = 0
    if not settings.corpus_source_hackerone:
        return {"added": 0, "updated": 0}
    since = (started - timedelta(days=since_days)).isoformat()
    fetcher = LearningFetcher()
    async with client_cls(before_request=fetcher.before_request, after_response=fetcher.after_response) as client:
        if not client.is_configured():
            return {"added": 0, "updated": 0}
        items = await client.get_hacktivity(disclosed=True, since=since)
    for item in items:
        if (item.program_handle or "").lower() != handle.lower():
            continue
        _row, created = await upsert_report(
            session,
            source_platform="hackerone",
            source_url=item.source_url,
            author_handle=item.author_handle,
            program_handle=item.program_handle,
            vuln_class=_infer_vuln_class(item),
            severity=item.severity,
            title=item.title,
            body_summary=item.body,
            tech_stack=[],
            metadata={"weakness": item.weakness, "bootstrap": True},
            ingested_at=item.disclosed_at or started,
        )
        if created:
            added += 1
        else:
            updated += 1
    await session.commit()
    return {"added": added, "updated": updated}
