"""Tests for learning-corpus trend summaries and API surface."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup


@pytest.mark.asyncio
async def test_summarize_trends_aggregates_corpus(db_session) -> None:
    from netra.bugbounty.learning.trends import summarize_trends

    now = datetime.now(timezone.utc)
    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/report-1",
            author_handle="alice",
            program_handle="shopify",
            vuln_class="xss",
            severity="high",
            title="Shopify XSS",
            body_summary="Reflected XSS report",
            tech_stack=["next.js"],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            ingested_at=now,
        )
    )
    db_session.add(
        BBCorpusWriteup(
            source_url="https://example.com/writeup-1",
            author="bob",
            title="IDOR writeup",
            vuln_class="idor",
            tech_stack=["rails"],
            body_summary="IDOR against order APIs",
            metadata_={},
            redaction_count=0,
            embedding=[0.0, 1.0, 0.0],
            ingested_at=now,
        )
    )
    db_session.add(
        BBCorpusAdvisory(
            cve_id="CVE-2026-5555",
            ghsa_id=None,
            severity="high",
            cvss_vector="CVSS:3.1/...",
            affected_packages=["next.js"],
            summary="Webhook SSRF issue",
            source_url="https://example.com/cve-2026-5555",
            metadata_={},
            embedding=[0.0, 0.0, 1.0],
            ingested_at=now,
        )
    )
    await db_session.commit()

    summary = await summarize_trends(db_session, days=7)
    assert summary["total_reports"] == 1
    assert summary["total_writeups"] == 1
    assert summary["total_advisories"] == 1
    assert summary["top_vuln_classes"][0]["name"] in {"xss", "idor"}
    assert any(bucket["name"] == "shopify" for bucket in summary["top_programs"])


@pytest.mark.asyncio
async def test_trends_api_returns_summary(client, db_session) -> None:
    now = datetime.now(timezone.utc)
    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/report-api",
            author_handle="alice",
            program_handle="shopify",
            vuln_class="xss",
            severity="high",
            title="Shopify XSS",
            body_summary="Reflected XSS report",
            tech_stack=["next.js"],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            ingested_at=now,
        )
    )
    await db_session.commit()

    response = await client.get("/api/v1/bb/trends?days=7")
    assert response.status_code == 200
    payload = response.json()
    assert payload["window_days"] == 7
    assert payload["total_reports"] == 1
