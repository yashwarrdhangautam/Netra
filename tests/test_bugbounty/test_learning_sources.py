"""Tests for learning source adapters and ingesters."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup
from netra.integrations.hackerone import H1HacktivityItem


class FakeHacktivityClient:
    def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        pass

    def is_configured(self) -> bool:
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get_hacktivity(self, **kwargs):  # noqa: ANN003
        return [
            H1HacktivityItem(
                source_url="https://hackerone.com/reports/123",
                title="Shopify XSS",
                body="Reflected XSS with alice@example.com and key AKIAIOSFODNN7EXAMPLE",
                severity="medium",
                program_handle="shopify",
                author_handle="alice",
                weakness="Cross-Site Scripting (XSS)",
                disclosed_at=datetime.now(timezone.utc),
                raw={},
            )
        ]


@pytest.mark.asyncio
async def test_hacktivity_ingest_redacts_and_upserts(db_session) -> None:
    from netra.bugbounty.learning.sources.hackerone import ingest_hacktivity
    from netra.bugbounty.learning.sources import hackerone as h1_source

    original = h1_source.settings.corpus_obey_robots
    h1_source.settings.corpus_obey_robots = False

    try:
        result = await ingest_hacktivity(db_session, client_cls=FakeHacktivityClient)
        assert result["added"] == 1

        rows = (await db_session.execute(BBCorpusReport.__table__.select())).all()
        assert len(rows) == 1
        row = rows[0]
        assert "[REDACTED:email:0]" in row.body_summary
        assert row.redaction_count >= 1
        assert row.embedding_model_version
    finally:
        h1_source.settings.corpus_obey_robots = original


@pytest.mark.asyncio
async def test_advisory_ingest_stores_ghsa_and_nvd(db_session) -> None:
    from netra.bugbounty.learning.sources.advisories import ingest_advisories
    from netra.bugbounty.learning.sources import advisories as advisories_source

    def handler(request: httpx.Request) -> httpx.Response:
        if "api.github.com/advisories" in str(request.url):
            return httpx.Response(
                200,
                json=[
                    {
                        "ghsa_id": "GHSA-abcd-1234",
                        "cve_id": "CVE-2026-9999",
                        "severity": "high",
                        "summary": "Next.js SSRF in webhook handler",
                        "html_url": "https://github.com/advisories/GHSA-abcd-1234",
                        "vulnerabilities": [{"package": {"name": "next"}}],
                        "cvss": {"vector_string": "CVSS:3.1/..."},
                    }
                ],
            )
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-1111",
                            "descriptions": [{"lang": "en", "value": "Webhook SSRF issue"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "vectorString": "CVSS:3.1/..."}}]},
                            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"}],
                            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vercel:next.js"}]}]}],
                        }
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    original = advisories_source.settings.corpus_obey_robots
    advisories_source.settings.corpus_obey_robots = False
    try:
        result = await ingest_advisories(db_session, client=client)
    finally:
        advisories_source.settings.corpus_obey_robots = original
        await client.aclose()
    assert result["added"] == 2
    rows = (await db_session.execute(BBCorpusAdvisory.__table__.select())).all()
    assert len(rows) == 2
    assert all(row.embedding_model_version for row in rows)


@pytest.mark.asyncio
async def test_rss_ingest_stores_writeups(db_session) -> None:
    from netra.bugbounty.learning.sources.rss import ingest_public_writeups
    from netra.bugbounty.learning.sources import rss as rss_source

    xml = """
    <rss><channel>
      <item>
        <title>Shopify IDOR writeup</title>
        <link>https://example.com/shopify-idor</link>
        <description>IDOR in order APIs with exposed identifiers.</description>
        <author>Alice</author>
        <pubDate>Fri, 09 May 2026 10:00:00 GMT</pubDate>
      </item>
    </channel></rss>
    """

    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text=xml)))
    original = rss_source.settings.corpus_obey_robots
    rss_source.settings.corpus_obey_robots = False
    try:
        result = await ingest_public_writeups(db_session, feeds=["https://example.com/feed"], client=client)
    finally:
        rss_source.settings.corpus_obey_robots = original
        await client.aclose()
    assert result["added"] == 1
    rows = (await db_session.execute(BBCorpusWriteup.__table__.select())).all()
    assert len(rows) == 1
    assert rows[0].title == "Shopify IDOR writeup"
    assert rows[0].embedding_model_version


@pytest.mark.asyncio
async def test_forget_corpus_entries_deletes_matching_author(db_session) -> None:
    from netra.bugbounty.learning.ingest import forget_corpus_entries

    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/report-forget",
            author_handle="alice",
            program_handle="shopify",
            vuln_class="xss",
            severity="medium",
            title="Forget me",
            body_summary="summary",
            tech_stack=[],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            ingested_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    deleted = await forget_corpus_entries(db_session, author="alice")
    await db_session.commit()
    assert deleted["reports"] == 1
    rows = (await db_session.execute(BBCorpusReport.__table__.select())).all()
    assert rows == []
