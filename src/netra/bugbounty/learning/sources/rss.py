"""Public RSS writeup ingestion for the learning corpus."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree import ElementTree as ET

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.fetcher import LearningFetcher
from netra.bugbounty.learning.ingest import log_ingest, upsert_writeup
from netra.core.config import settings

DEFAULT_FEEDS = [
    "https://medium.com/feed/tag/bug-bounty",
    "https://portswigger.net/research/rss",
]


def _infer_vuln_class(text: str) -> str | None:
    lowered = text.lower()
    mapping = {
        "ssrf": "ssrf",
        "idor": "idor",
        "xss": "xss",
        "sql injection": "sqli",
        "csrf": "csrf",
        "s3 bucket": "exposure",
    }
    for needle, vuln_class in mapping.items():
        if needle in lowered:
            return vuln_class
    return None


def _parse_feed(xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    items: list[dict[str, Any]] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        author = (item.findtext("author") or item.findtext("{http://purl.org/dc/elements/1.1/}creator") or "").strip()
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        pub_date = None
        if pub_date_raw:
            try:
                pub_date = parsedate_to_datetime(pub_date_raw)
            except (TypeError, ValueError):
                pub_date = None
        items.append(
            {
                "title": title,
                "source_url": link,
                "body_summary": description,
                "author": author or None,
                "published_at": pub_date,
                "vuln_class": _infer_vuln_class(" ".join([title, description])),
            }
        )
    return items


async def ingest_public_writeups(
    session: AsyncSession,
    *,
    feeds: list[str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, int]:
    started = datetime.now(timezone.utc)
    added = 0
    updated = 0
    if not settings.corpus_source_writeups:
        await log_ingest(
            session,
            source_name="public_rss_writeups",
            items_added=0,
            items_updated=0,
            notes="disabled_by_config",
            started_at=started,
        )
        await session.commit()
        return {"added": 0, "updated": 0}
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=60, headers={"User-Agent": "NETRA-BB/1.0"})
        close_client = True
    fetcher = LearningFetcher(client=client)
    try:
        for feed in feeds or DEFAULT_FEEDS:
            for item in _parse_feed(await fetcher.get_text(feed)):
                if not item["source_url"] or not item["title"]:
                    continue
                _row, created = await upsert_writeup(
                    session,
                    source_url=item["source_url"],
                    author=item["author"],
                    title=item["title"],
                    vuln_class=item["vuln_class"],
                    tech_stack=[],
                    body_summary=item["body_summary"],
                    metadata={"feed": feed},
                    ingested_at=item["published_at"] or started,
                )
                if created:
                    added += 1
                else:
                    updated += 1
        await log_ingest(
            session,
            source_name="public_rss_writeups",
            items_added=added,
            items_updated=updated,
            started_at=started,
        )
        await session.commit()
        return {"added": added, "updated": updated}
    finally:
        if close_client:
            await client.aclose()
