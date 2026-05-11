"""Tests for learning corpus similarity search."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netra.bugbounty.learning.embeddings import embed
from netra.bugbounty.learning.search import build_corpus_context, find_similar
from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup


@pytest.mark.asyncio
async def test_find_similar_prefers_matching_report(db_session, monkeypatch) -> None:
    async def fake_embed_with_version(text: str) -> tuple[list[float], str]:
        embedding = [1.0, 0.0, 0.0] if "shopify" in text.lower() else [0.0, 1.0, 0.0]
        return embedding, "test-model-v1"

    monkeypatch.setattr("netra.bugbounty.learning.search.embed_with_version", fake_embed_with_version)

    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/report-1",
            author_handle="alice",
            program_handle="shopify",
            vuln_class="idor",
            severity="high",
            title="Shopify order IDOR",
            body_summary="Order API exposed predictable identifiers.",
            tech_stack=["rails"],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            embedding_model_version="test-model-v1",
            ingested_at=datetime.now(timezone.utc),
        )
    )
    db_session.add(
        BBCorpusWriteup(
            source_url="https://example.com/writeup-1",
            author="bob",
            title="Generic XSS writeup",
            vuln_class="xss",
            tech_stack=["next.js"],
            body_summary="Reflected XSS against a search parameter.",
            metadata_={},
            redaction_count=0,
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="test-model-v1",
            ingested_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    hits = await find_similar(
        db_session,
        "shopify order idor",
        top_k=2,
        filters={"program_handle": "shopify"},
    )
    assert hits
    assert hits[0].kind == "reports"
    assert hits[0].title == "Shopify order IDOR"


@pytest.mark.asyncio
async def test_build_corpus_context_formats_hits(db_session, monkeypatch) -> None:
    async def fake_embed_with_version(text: str) -> tuple[list[float], str]:
        embedding = [0.0, 1.0, 0.0] if "cve" in text.lower() else [1.0, 0.0, 0.0]
        return embedding, "test-model-v1"

    monkeypatch.setattr("netra.bugbounty.learning.search.embed_with_version", fake_embed_with_version)

    db_session.add(
        BBCorpusAdvisory(
            cve_id="CVE-2026-1234",
            ghsa_id=None,
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            affected_packages=["next"],
            summary="Next.js advisory affecting webhook handlers.",
            source_url="https://example.com/cve-2026-1234",
            metadata_={},
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="test-model-v1",
            ingested_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    context = await build_corpus_context(db_session, "cve next webhook", top_k=1)
    assert context
    assert "CVE-2026-1234" in context[0]
    assert "advisories" in context[0]


@pytest.mark.asyncio
async def test_find_similar_skips_mismatched_embedding_versions(db_session, monkeypatch) -> None:
    async def fake_embed_with_version(text: str) -> tuple[list[float], str]:
        return [1.0, 0.0, 0.0], "query-model-v2"

    monkeypatch.setattr("netra.bugbounty.learning.search.embed_with_version", fake_embed_with_version)

    db_session.add(
        BBCorpusReport(
            source_platform="hackerone",
            source_url="https://example.com/report-old",
            author_handle="alice",
            program_handle="shopify",
            vuln_class="idor",
            severity="high",
            title="Old embedding report",
            body_summary="Order API exposed predictable identifiers.",
            tech_stack=["rails"],
            metadata_={},
            redaction_count=0,
            embedding=[1.0, 0.0, 0.0],
            embedding_model_version="legacy-model-v1",
            ingested_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    hits = await find_similar(db_session, "shopify order idor", top_k=3)
    assert hits == []
