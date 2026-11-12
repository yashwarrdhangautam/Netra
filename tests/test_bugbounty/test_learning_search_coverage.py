"""Coverage-focused tests for learning search, ingest and embeddings.

Complements test_learning_search.py / test_learning_embeddings.py / test_learning_sources.py.
No real embedding model, pgvector server, network or database beyond the in-memory SQLite
fixture is used: Ollama HTTP calls are faked with httpx, and PostgreSQL behaviour is
simulated with a fake session that reports a ``postgresql`` dialect.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from netra.bugbounty.learning import pgvector as pgv
from netra.bugbounty.learning.embeddings import (
    EMBEDDING_DIM,
    current_embedding_model_version,
    embed,
    embed_with_version,
)
from netra.bugbounty.learning.ingest import (
    forget_corpus_entries,
    log_ingest,
    reembed_corpus,
    upsert_advisory,
    upsert_report,
    upsert_writeup,
)
from netra.bugbounty.learning.pgvector import sync_embedding_vector
from netra.bugbounty.learning.search import (
    _cosine_similarity,
    _find_similar_pgvector,
    _row_to_hit,
    build_corpus_context,
    find_similar,
)
from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup, CorpusIngestLog

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)


class _FakeBind:
    def __init__(self, dialect_name: str) -> None:
        self.dialect = SimpleNamespace(name=dialect_name)


class _FakePgSession:
    """Stands in for AsyncSession on PostgreSQL; records every executed statement."""

    def __init__(self, rows_by_table: dict[str, list[Any]] | None = None) -> None:
        self.rows_by_table = rows_by_table or {}
        self.statements: list[tuple[str, dict[str, Any]]] = []

    def get_bind(self) -> _FakeBind:
        return _FakeBind("postgresql")

    async def execute(self, statement: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        sql = str(statement)
        self.statements.append((sql, dict(params or {})))
        for table, rows in self.rows_by_table.items():
            if f"FROM {table}" in sql or f"UPDATE {table}" in sql:
                return _FakeResult(rows)
        return _FakeResult([])


class _NoBindSession:
    def get_bind(self) -> None:
        return None


def _patch_search_embed(monkeypatch, vector: list[float], version: str = "v1") -> list[str]:
    seen: list[str] = []

    async def fake_embed(text: str) -> tuple[list[float], str]:
        seen.append(text)
        return vector, version

    monkeypatch.setattr("netra.bugbounty.learning.search.embed_with_version", fake_embed)
    return seen


def _patch_ingest_embed(monkeypatch, vector: list[float], version: str = "v1") -> list[str]:
    seen: list[str] = []

    async def fake_embed(text: str) -> tuple[list[float], str]:
        seen.append(text)
        return vector, version

    monkeypatch.setattr("netra.bugbounty.learning.ingest.embed_with_version", fake_embed)
    return seen


def _pg_report_row(**overrides: Any) -> SimpleNamespace:
    data: dict[str, Any] = {
        "title": "Shopify order IDOR",
        "source_url": "https://example.com/pg-report",
        "snippet": "Order API leaks ids",
        "program_handle": "shopify",
        "vuln_class": "idor",
        "severity": "high",
        "source_platform": "hackerone",
        "score": 0.9,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _pg_writeup_row(**overrides: Any) -> SimpleNamespace:
    data: dict[str, Any] = {
        "title": "Writeup",
        "source_url": "https://example.com/pg-writeup",
        "snippet": "Reflected XSS",
        "author": "bob",
        "vuln_class": "xss",
        "tech_stack": ["next.js"],
        "score": 0.5,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _pg_advisory_row(**overrides: Any) -> SimpleNamespace:
    data: dict[str, Any] = {
        "cve_id": "CVE-2026-0001",
        "ghsa_id": None,
        "source_url": "https://example.com/adv",
        "snippet": "Advisory summary",
        "severity": "medium",
        "affected_packages": ["next"],
        "score": 0.4,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _report(**overrides: Any) -> BBCorpusReport:
    data: dict[str, Any] = {
        "source_platform": "hackerone",
        "source_url": "https://example.com/report",
        "author_handle": "alice",
        "program_handle": "shopify",
        "vuln_class": "idor",
        "severity": "high",
        "title": "Report",
        "body_summary": "summary",
        "tech_stack": [],
        "metadata_": {},
        "redaction_count": 0,
        "ingested_at": datetime.now(UTC),
    }
    data.update(overrides)
    return BBCorpusReport(**data)


def _writeup(**overrides: Any) -> BBCorpusWriteup:
    data: dict[str, Any] = {
        "source_url": "https://example.com/writeup",
        "author": "bob",
        "title": "Writeup",
        "vuln_class": "xss",
        "tech_stack": [],
        "body_summary": "summary",
        "metadata_": {},
        "redaction_count": 0,
        "ingested_at": datetime.now(UTC),
    }
    data.update(overrides)
    return BBCorpusWriteup(**data)


def _advisory(**overrides: Any) -> BBCorpusAdvisory:
    data: dict[str, Any] = {
        "cve_id": None,
        "ghsa_id": None,
        "severity": "low",
        "cvss_vector": None,
        "affected_packages": [],
        "summary": "advisory summary",
        "source_url": None,
        "metadata_": {},
        "ingested_at": datetime.now(UTC),
    }
    data.update(overrides)
    return BBCorpusAdvisory(**data)


# ---------------------------------------------------------------------------
# search.py: pure helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ([1.0, 0.0], [1.0, 0.0], 1.0),
        ([1.0, 0.0], [0.0, 1.0], 0.0),
        ([1.0, 0.0], [-1.0, 0.0], -1.0),
        ([], [1.0, 0.0], 0.0),
        ([1.0, 0.0], [], 0.0),
        ([0.0, 0.0], [1.0, 1.0], 0.0),
    ],
)
def test_cosine_similarity_edge_cases(left, right, expected) -> None:
    assert _cosine_similarity(left, right) == pytest.approx(expected)


def test_cosine_similarity_truncates_to_shorter_vector() -> None:
    # Only the first two components participate; the trailing 5.0 is ignored.
    assert _cosine_similarity([1.0, 1.0, 5.0], [1.0, 1.0]) == pytest.approx(1.0)


def test_cosine_similarity_accepts_generators() -> None:
    value = _cosine_similarity((x for x in [3.0, 4.0]), (x for x in [3.0, 4.0]))
    assert math.isclose(value, 1.0)


def test_row_to_hit_report_falls_back_to_platform_and_program_title() -> None:
    row = SimpleNamespace(
        title=None,
        body_summary="x" * 400,
        source_url="https://example.com/r",
        program_handle=None,
        vuln_class="xss",
        severity="low",
        source_platform="bugcrowd",
    )
    hit = _row_to_hit("reports", row, 0.7)
    assert hit.title == "bugcrowd:report"
    assert len(hit.snippet) == 280
    assert hit.metadata["source_platform"] == "bugcrowd"


def test_row_to_hit_writeup_metadata_lists_tech_stack() -> None:
    row = SimpleNamespace(
        title="W",
        body_summary="body",
        source_url="https://example.com/w",
        author="bob",
        vuln_class="xss",
        tech_stack=None,
    )
    hit = _row_to_hit("writeups", row, 0.3)
    assert hit.kind == "writeups"
    assert hit.metadata == {"author": "bob", "vuln_class": "xss", "tech_stack": []}


def test_row_to_hit_advisory_title_precedence_and_empty_url() -> None:
    by_ghsa = _row_to_hit(
        "advisories",
        SimpleNamespace(
            cve_id=None,
            ghsa_id="GHSA-xxxx-yyyy-zzzz",
            source_url=None,
            summary="s",
            severity="high",
            affected_packages=None,
        ),
        0.1,
    )
    assert by_ghsa.title == "GHSA-xxxx-yyyy-zzzz"
    assert by_ghsa.source_url == ""
    assert by_ghsa.metadata["affected_packages"] == []

    anonymous = _row_to_hit(
        "advisories",
        SimpleNamespace(
            cve_id=None,
            ghsa_id=None,
            source_url="https://example.com/a",
            summary="s",
            severity=None,
            affected_packages=["lodash"],
        ),
        0.1,
    )
    assert anonymous.title == "advisory"


# ---------------------------------------------------------------------------
# search.py: SQLite (non-pgvector) path with real rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_similar_applies_report_filters(db_session, monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0])
    base = {
        "source_platform": "hackerone",
        "author_handle": "alice",
        "program_handle": "shopify",
        "vuln_class": "idor",
        "severity": "high",
        "title": "match",
        "body_summary": "summary",
        "tech_stack": [],
        "metadata_": {},
        "redaction_count": 0,
        "embedding": [1.0, 0.0, 0.0],
        "embedding_model_version": "v1",
        "ingested_at": datetime.now(UTC),
    }
    db_session.add(BBCorpusReport(source_url="https://example.com/keep", **base))
    db_session.add(
        BBCorpusReport(
            source_url="https://example.com/other-program",
            **{**base, "program_handle": "github", "title": "other program"},
        )
    )
    db_session.add(
        BBCorpusReport(
            source_url="https://example.com/other-class",
            **{**base, "vuln_class": "xss", "title": "other class"},
        )
    )
    db_session.add(
        BBCorpusReport(
            source_url="https://example.com/other-platform",
            **{**base, "source_platform": "bugcrowd", "title": "other platform"},
        )
    )
    db_session.add(
        BBCorpusReport(
            source_url="https://example.com/deleted",
            **{**base, "title": "deleted", "deleted_at": datetime.now(UTC)},
        )
    )
    await db_session.commit()

    hits = await find_similar(
        db_session,
        "anything",
        top_k=10,
        kinds=["reports"],
        filters={
            "program_handle": "shopify",
            "vuln_class": "idor",
            "source_platform": "hackerone",
        },
    )
    assert [hit.title for hit in hits] == ["match"]


@pytest.mark.asyncio
async def test_find_similar_writeup_and_advisory_vuln_class_filters(
    db_session, monkeypatch
) -> None:
    _patch_search_embed(monkeypatch, [0.0, 1.0, 0.0])
    now = datetime.now(UTC)
    db_session.add(
        _writeup(
            source_url="https://example.com/w-xss",
            vuln_class="xss",
            title="XSS writeup",
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="v1",
        )
    )
    db_session.add(
        _writeup(
            source_url="https://example.com/w-idor",
            vuln_class="idor",
            title="IDOR writeup",
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="v1",
        )
    )
    db_session.add(
        _advisory(
            source_url="https://example.com/a-xss",
            cve_id="CVE-2026-7001",
            metadata_={"vuln_class": "xss"},
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="v1",
            ingested_at=now,
        )
    )
    db_session.add(
        _advisory(
            source_url="https://example.com/a-idor",
            cve_id="CVE-2026-7002",
            metadata_={"vuln_class": "idor"},
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="v1",
            ingested_at=now,
        )
    )
    await db_session.commit()

    writeup_hits = await find_similar(
        db_session, "q", top_k=5, kinds=["writeups"], filters={"vuln_class": "xss"}
    )
    assert [hit.title for hit in writeup_hits] == ["XSS writeup"]

    advisory_hits = await find_similar(
        db_session, "q", top_k=5, kinds=["advisories"], filters={"vuln_class": "xss"}
    )
    assert [hit.title for hit in advisory_hits] == ["CVE-2026-7001"]


@pytest.mark.asyncio
async def test_find_similar_skips_unknown_kinds_and_unembedded_rows(
    db_session, monkeypatch
) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0])
    db_session.add(
        _writeup(
            source_url="https://example.com/no-embedding",
            title="No embedding",
            embedding=None,
            embedding_model_version="v1",
        )
    )
    db_session.add(
        _writeup(
            source_url="https://example.com/orthogonal",
            title="Orthogonal",
            embedding=[0.0, 1.0, 0.0],
            embedding_model_version="v1",
        )
    )
    db_session.add(
        _writeup(
            source_url="https://example.com/match",
            title="Match",
            embedding=[1.0, 0.0, 0.0],
            embedding_model_version="v1",
        )
    )
    await db_session.commit()

    hits = await find_similar(db_session, "q", top_k=5, kinds=["bogus", "writeups"])
    assert [hit.title for hit in hits] == ["Match"]


@pytest.mark.asyncio
async def test_find_similar_sorts_and_truncates_to_top_k(db_session, monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0])
    for index, vector in enumerate([[0.2, 1.0], [1.0, 0.1], [1.0, 0.0]]):
        db_session.add(
            _writeup(
                source_url=f"https://example.com/rank-{index}",
                title=f"rank-{index}",
                embedding=vector,
                embedding_model_version="v1",
            )
        )
    await db_session.commit()

    hits = await find_similar(db_session, "q", top_k=2, kinds=["writeups"])
    assert len(hits) == 2
    assert hits[0].title == "rank-2"
    assert hits[0].score >= hits[1].score


@pytest.mark.asyncio
async def test_find_similar_keeps_rows_with_unset_model_version(db_session, monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0], version="query-v9")
    db_session.add(
        _writeup(
            source_url="https://example.com/legacy-no-version",
            title="Legacy",
            embedding=[1.0, 0.0, 0.0],
            embedding_model_version=None,
        )
    )
    await db_session.commit()

    hits = await find_similar(db_session, "q", top_k=3, kinds=["writeups"])
    assert [hit.title for hit in hits] == ["Legacy"]


@pytest.mark.asyncio
async def test_build_corpus_context_uses_kind_when_source_url_missing(
    db_session, monkeypatch
) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0])
    db_session.add(
        _advisory(
            cve_id="CVE-2026-8888",
            summary="x" * 300,
            source_url=None,
            embedding=[1.0, 0.0, 0.0],
            embedding_model_version="v1",
        )
    )
    await db_session.commit()

    context = await build_corpus_context(db_session, "q", top_k=1)
    assert len(context) == 1
    assert context[0].startswith("[advisories] CVE-2026-8888 :: ")
    assert context[0].endswith("(advisories)")
    snippet = context[0].split(" :: ", 1)[1].rsplit(" (", 1)[0]
    assert len(snippet) == 280


# ---------------------------------------------------------------------------
# search.py: PostgreSQL / pgvector path (fake session, no server)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pgvector_path_merges_kinds_and_sorts(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0], version="v1")
    session = _FakePgSession(
        {
            "bb_corpus_reports": [_pg_report_row(score=0.9)],
            "bb_corpus_writeups": [_pg_writeup_row(score=0.95)],
            "bb_corpus_advisories": [_pg_advisory_row(score=0.4)],
        }
    )

    hits = await find_similar(session, "q", top_k=2)

    assert [hit.kind for hit in hits] == ["writeups", "reports"]
    assert hits[0].score == pytest.approx(0.95)
    assert len(session.statements) == 3


@pytest.mark.asyncio
async def test_pgvector_path_report_filters_are_bound(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0, 0.0], version="v7")
    session = _FakePgSession({"bb_corpus_reports": [_pg_report_row()]})

    await find_similar(
        session,
        "q",
        top_k=4,
        kinds=["reports"],
        filters={
            "program_handle": "shopify",
            "vuln_class": "idor",
            "source_platform": "hackerone",
        },
    )

    sql, params = session.statements[0]
    assert "program_handle = :program_handle" in sql
    assert "vuln_class = :vuln_class" in sql
    assert "source_platform = :source_platform" in sql
    assert "embedding_model_version = :query_version" in sql
    assert "deleted_at IS NULL" in sql
    assert params["program_handle"] == "shopify"
    assert params["vuln_class"] == "idor"
    assert params["source_platform"] == "hackerone"
    assert params["query_version"] == "v7"
    assert params["limit"] == 4
    assert params["embedding"].startswith("[1,0,0")


@pytest.mark.asyncio
async def test_pgvector_path_writeup_and_advisory_filters_are_bound(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [0.0, 1.0], version="v2")
    session = _FakePgSession(
        {
            "bb_corpus_writeups": [_pg_writeup_row()],
            "bb_corpus_advisories": [_pg_advisory_row()],
        }
    )

    hits = await find_similar(
        session, "q", top_k=5, kinds=["writeups", "advisories"], filters={"vuln_class": "xss"}
    )

    writeup_sql, writeup_params = session.statements[0]
    advisory_sql, advisory_params = session.statements[1]
    assert "vuln_class = :vuln_class" in writeup_sql
    assert writeup_params["vuln_class"] == "xss"
    assert "metadata_->>'vuln_class' = :vuln_class" in advisory_sql
    assert advisory_params["vuln_class"] == "xss"
    assert {hit.kind for hit in hits} == {"writeups", "advisories"}


@pytest.mark.asyncio
async def test_pgvector_path_applies_fallbacks_for_missing_fields(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0])
    session = _FakePgSession(
        {
            "bb_corpus_reports": [
                _pg_report_row(
                    title=None,
                    program_handle=None,
                    source_platform="bugcrowd",
                    snippet=None,
                    score=0.25,
                )
            ],
            "bb_corpus_writeups": [_pg_writeup_row(tech_stack=None, snippet="y" * 500)],
            "bb_corpus_advisories": [
                _pg_advisory_row(cve_id=None, ghsa_id=None, source_url=None, affected_packages=None)
            ],
        }
    )

    hits = await find_similar(session, "q", top_k=10, kinds=["reports", "writeups", "advisories"])
    by_kind = {hit.kind: hit for hit in hits}

    assert by_kind["reports"].title == "bugcrowd:report"
    assert by_kind["reports"].snippet == ""
    assert by_kind["reports"].score == pytest.approx(0.25)
    assert by_kind["writeups"].metadata["tech_stack"] == []
    assert len(by_kind["writeups"].snippet) == 280
    assert by_kind["advisories"].title == "advisory"
    assert by_kind["advisories"].source_url == ""
    assert by_kind["advisories"].metadata["affected_packages"] == []


@pytest.mark.asyncio
async def test_pgvector_path_unknown_kind_runs_no_sql(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0])
    session = _FakePgSession()

    hits = await find_similar(session, "q", kinds=["mystery"])

    assert hits == []
    assert session.statements == []


@pytest.mark.asyncio
async def test_find_similar_pgvector_returns_none_without_postgres_bind() -> None:
    assert (
        await _find_similar_pgvector(
            _NoBindSession(),
            ["reports"],
            query_embedding=[1.0],
            query_version="v1",
            top_k=1,
            filters=None,
        )
        is None
    )


@pytest.mark.asyncio
async def test_find_similar_pgvector_direct_respects_top_k() -> None:
    session = _FakePgSession(
        {
            "bb_corpus_reports": [
                _pg_report_row(score=0.3),
                _pg_report_row(score=0.8, title="best"),
            ],
        }
    )

    hits = await _find_similar_pgvector(
        session,
        ["reports"],
        query_embedding=[1.0, 0.0],
        query_version="v1",
        top_k=1,
        filters=None,
    )

    assert hits is not None
    assert [hit.title for hit in hits] == ["best"]


@pytest.mark.asyncio
async def test_pgvector_path_drops_non_positive_scores_like_fallback(monkeypatch) -> None:
    _patch_search_embed(monkeypatch, [1.0, 0.0])
    session = _FakePgSession(
        {
            "bb_corpus_reports": [
                _pg_report_row(title="opposed", score=-0.25),
                _pg_report_row(title="orthogonal", score=0.0),
            ]
        }
    )

    hits = await find_similar(session, "q", top_k=5, kinds=["reports"])

    assert hits == []


# ---------------------------------------------------------------------------
# ingest.py
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_report_updates_existing_row_and_redacts(db_session, monkeypatch) -> None:
    embed_inputs = _patch_ingest_embed(monkeypatch, [1.0, 0.0, 0.0], version="v1")
    created_row, created = await upsert_report(
        db_session,
        source_platform="hackerone",
        source_url="https://example.com/upsert-report",
        author_handle="alice",
        program_handle="shopify",
        vuln_class="idor",
        severity="high",
        title="First",
        body_summary="Contact bob@example.com for details",
    )
    await db_session.commit()
    assert created is True
    assert created_row.redaction_count == 1
    assert "[REDACTED:email:0]" in created_row.body_summary
    assert created_row.tech_stack == []
    assert created_row.metadata_ == {}
    assert "First" in embed_inputs[0]
    assert "[REDACTED:email:0]" in embed_inputs[0]

    _patch_ingest_embed(monkeypatch, [0.0, 1.0, 0.0], version="v2")
    updated_at = datetime(2026, 1, 2, tzinfo=UTC)
    updated_row, created_again = await upsert_report(
        db_session,
        source_platform="hackerone",
        source_url="https://example.com/upsert-report",
        author_handle="alice",
        program_handle="shopify",
        vuln_class="idor",
        severity="critical",
        title="Second",
        body_summary="No contact info here",
        tech_stack=["rails"],
        metadata={"k": "v"},
        ingested_at=updated_at,
    )
    await db_session.commit()

    assert created_again is False
    assert updated_row.id == created_row.id
    assert updated_row.title == "Second"
    assert updated_row.severity == "critical"
    assert updated_row.redaction_count == 0
    assert updated_row.tech_stack == ["rails"]
    assert updated_row.metadata_ == {"k": "v"}
    assert updated_row.embedding_model_version == "v2"
    assert updated_row.embedding == [0.0, 1.0, 0.0]
    assert updated_row.ingested_at.replace(tzinfo=None) == updated_at.replace(tzinfo=None)


@pytest.mark.asyncio
async def test_upsert_report_syncs_pgvector_mirror(db_session, monkeypatch) -> None:
    _patch_ingest_embed(monkeypatch, [1.0, 0.0])
    synced: list[tuple[str, Any, list[float]]] = []

    async def fake_sync(session, *, table_name, row_id, embedding):  # noqa: ANN001, ANN003
        synced.append((table_name, row_id, embedding))

    monkeypatch.setattr("netra.bugbounty.learning.ingest.sync_embedding_vector", fake_sync)
    row, _ = await upsert_report(
        db_session,
        source_platform="hackerone",
        source_url="https://example.com/synced-report",
        author_handle=None,
        program_handle=None,
        vuln_class=None,
        severity=None,
        title=None,
        body_summary="plain summary",
    )
    assert synced == [("bb_corpus_reports", row.id, [1.0, 0.0])]


@pytest.mark.asyncio
async def test_upsert_writeup_create_then_update(db_session, monkeypatch) -> None:
    embed_inputs = _patch_ingest_embed(monkeypatch, [1.0, 0.0, 0.0], version="v1")
    synced: list[str] = []

    async def fake_sync(session, *, table_name, row_id, embedding):  # noqa: ANN001, ANN003
        synced.append(table_name)

    monkeypatch.setattr("netra.bugbounty.learning.ingest.sync_embedding_vector", fake_sync)

    row, created = await upsert_writeup(
        db_session,
        source_url="https://example.com/upsert-writeup",
        author="bob",
        title="Original",
        vuln_class="xss",
        tech_stack=["next.js"],
        body_summary="Token leak at bob@example.com",
        metadata={"lang": "en"},
    )
    await db_session.commit()
    assert created is True
    assert row.redaction_count == 1
    assert row.metadata_ == {"lang": "en"}
    assert "Original xss" in embed_inputs[0]

    _patch_ingest_embed(monkeypatch, [0.0, 0.0, 1.0], version="v2")
    updated, created_again = await upsert_writeup(
        db_session,
        source_url="https://example.com/upsert-writeup",
        author=None,
        title="Revised",
        vuln_class=None,
        tech_stack=None,
        body_summary="Clean body",
    )
    await db_session.commit()
    assert created_again is False
    assert updated.id == row.id
    assert updated.title == "Revised"
    assert updated.tech_stack == []
    assert updated.embedding_model_version == "v2"
    assert synced == ["bb_corpus_writeups", "bb_corpus_writeups"]


@pytest.mark.asyncio
async def test_upsert_advisory_update_by_source_url(db_session, monkeypatch) -> None:
    _patch_ingest_embed(monkeypatch, [1.0, 0.0])
    first, created = await upsert_advisory(
        db_session,
        source_url="https://example.com/adv-1",
        cve_id="CVE-2026-1111",
        ghsa_id=None,
        severity="low",
        cvss_vector=None,
        affected_packages=["pkg-a"],
        summary="first summary",
    )
    await db_session.commit()
    assert created is True
    assert first.affected_packages == ["pkg-a"]

    second, created_again = await upsert_advisory(
        db_session,
        source_url="https://example.com/adv-1",
        cve_id="CVE-2026-1111",
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        severity="high",
        cvss_vector="CVSS:3.1/AV:N",
        affected_packages=None,
        summary="second summary",
        metadata={"vuln_class": "xss"},
    )
    await db_session.commit()
    assert created_again is False
    assert second.id == first.id
    assert second.severity == "high"
    assert second.ghsa_id == "GHSA-aaaa-bbbb-cccc"
    assert second.affected_packages == []
    assert second.summary == "second summary"


@pytest.mark.asyncio
async def test_upsert_advisory_lookup_by_cve_and_ghsa_without_url(db_session, monkeypatch) -> None:
    _patch_ingest_embed(monkeypatch, [1.0, 0.0])
    cve_row, _ = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id="CVE-2026-2222",
        ghsa_id=None,
        severity="low",
        cvss_vector=None,
        affected_packages=None,
        summary="cve only",
    )
    ghsa_row, _ = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id="GHSA-dddd-eeee-ffff",
        severity="low",
        cvss_vector=None,
        affected_packages=None,
        summary="ghsa only",
    )
    await db_session.commit()

    cve_again, created_cve = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id="CVE-2026-2222",
        ghsa_id=None,
        severity="medium",
        cvss_vector=None,
        affected_packages=None,
        summary="cve updated",
    )
    ghsa_again, created_ghsa = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id="GHSA-dddd-eeee-ffff",
        severity="medium",
        cvss_vector=None,
        affected_packages=None,
        summary="ghsa updated",
    )
    await db_session.commit()

    assert created_cve is False and cve_again.id == cve_row.id
    assert created_ghsa is False and ghsa_again.id == ghsa_row.id
    assert cve_again.summary == "cve updated"
    assert ghsa_again.summary == "ghsa updated"


@pytest.mark.asyncio
async def test_upsert_advisory_without_identifiers_does_not_overwrite_other_rows(
    db_session, monkeypatch
) -> None:
    _patch_ingest_embed(monkeypatch, [1.0, 0.0])
    existing, _ = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id="CVE-2026-3333",
        ghsa_id=None,
        severity="low",
        cvss_vector=None,
        affected_packages=None,
        summary="untouched summary",
    )
    await db_session.commit()

    _row, created = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id=None,
        severity="high",
        cvss_vector=None,
        affected_packages=None,
        summary="anonymous advisory",
    )
    await db_session.commit()

    assert created is True
    await db_session.refresh(existing)
    assert existing.summary == "untouched summary"


@pytest.mark.asyncio
async def test_upsert_advisory_identity_less_rows_with_different_titles_stay_separate(
    db_session, monkeypatch
) -> None:
    _patch_ingest_embed(monkeypatch, [1.0, 0.0])
    first, created_first = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id=None,
        severity="low",
        cvss_vector=None,
        affected_packages=None,
        summary="first advisory",
        source="vendor-feed",
        title="Alpha advisory",
        published_at="2026-03-01",
    )
    second, created_second = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id=None,
        severity="high",
        cvss_vector=None,
        affected_packages=None,
        summary="second advisory",
        source="vendor-feed",
        title="Beta advisory",
        published_at="2026-03-01",
    )
    await db_session.commit()

    assert created_first is True
    assert created_second is True
    assert first.id != second.id
    await db_session.refresh(first)
    assert first.summary == "first advisory"
    assert first.severity == "low"

    # Same identity (source, title, published date) does update the matching row only.
    again, created_again = await upsert_advisory(
        db_session,
        source_url=None,
        cve_id=None,
        ghsa_id=None,
        severity="medium",
        cvss_vector=None,
        affected_packages=None,
        summary="first advisory updated",
        source="vendor-feed",
        title="Alpha advisory",
        published_at="2026-03-01",
    )
    await db_session.commit()
    assert created_again is False
    assert again.id == first.id
    await db_session.refresh(second)
    assert second.summary == "second advisory"


@pytest.mark.asyncio
async def test_forget_corpus_entries_by_author_removes_writeups(db_session) -> None:
    db_session.add(_writeup(source_url="https://example.com/fw-1", author="mallory"))
    db_session.add(_writeup(source_url="https://example.com/fw-2", author="eve"))
    await db_session.commit()

    deleted = await forget_corpus_entries(db_session, author="mallory")
    await db_session.commit()

    assert deleted == {"reports": 0, "writeups": 1, "advisories": 0}
    remaining = (await db_session.execute(select(BBCorpusWriteup.author))).scalars().all()
    assert remaining == ["eve"]


@pytest.mark.asyncio
async def test_forget_corpus_entries_by_source_url_removes_all_kinds(db_session) -> None:
    url = "https://example.com/shared-url"
    db_session.add(_report(source_url=url))
    db_session.add(_writeup(source_url=url))
    db_session.add(_advisory(source_url=url, summary="shared"))
    db_session.add(_advisory(source_url="https://example.com/other", summary="keep"))
    await db_session.commit()

    deleted = await forget_corpus_entries(db_session, source_url=url)
    await db_session.commit()

    assert deleted == {"reports": 1, "writeups": 1, "advisories": 1}
    summaries = (await db_session.execute(select(BBCorpusAdvisory.summary))).scalars().all()
    assert summaries == ["keep"]


@pytest.mark.asyncio
async def test_forget_corpus_entries_without_filters_is_noop(db_session) -> None:
    db_session.add(_report(source_url="https://example.com/still-here"))
    await db_session.commit()

    deleted = await forget_corpus_entries(db_session)

    assert deleted == {"reports": 0, "writeups": 0, "advisories": 0}
    rows = (await db_session.execute(select(BBCorpusReport.source_url))).scalars().all()
    assert rows == ["https://example.com/still-here"]


@pytest.mark.asyncio
async def test_reembed_corpus_refreshes_active_rows_only(db_session, monkeypatch) -> None:
    texts: list[str] = []

    async def fake_embed(text: str) -> tuple[list[float], str]:
        texts.append(text)
        return [0.5, 0.5], "reembed-v3"

    monkeypatch.setattr("netra.bugbounty.learning.ingest.embed_with_version", fake_embed)
    synced: list[tuple[str, Any]] = []

    async def fake_sync(session, *, table_name, row_id, embedding):  # noqa: ANN001, ANN003
        synced.append((table_name, embedding))

    monkeypatch.setattr("netra.bugbounty.learning.ingest.sync_embedding_vector", fake_sync)

    db_session.add(
        _report(source_url="https://example.com/re-report", title="R", body_summary="rb")
    )
    db_session.add(
        _report(
            source_url="https://example.com/re-report-deleted",
            deleted_at=datetime.now(UTC),
        )
    )
    db_session.add(
        _writeup(source_url="https://example.com/re-writeup", title="W", vuln_class=None)
    )
    db_session.add(
        _advisory(source_url="https://example.com/re-adv", cve_id="CVE-2026-4444", summary="as")
    )
    await db_session.commit()

    refreshed = await reembed_corpus(db_session)
    await db_session.commit()

    assert refreshed == {"reports": 1, "writeups": 1, "advisories": 1}
    assert len(texts) == 3
    assert any("CVE-2026-4444" in text for text in texts)
    assert {table for table, _ in synced} == {
        "bb_corpus_reports",
        "bb_corpus_writeups",
        "bb_corpus_advisories",
    }
    report = (
        await db_session.execute(
            select(BBCorpusReport).where(
                BBCorpusReport.source_url == "https://example.com/re-report"
            )
        )
    ).scalar_one()
    assert report.embedding == [0.5, 0.5]
    assert report.embedding_model_version == "reembed-v3"


@pytest.mark.asyncio
async def test_log_ingest_defaults_errors_and_persists(db_session) -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    row = await log_ingest(
        db_session,
        source_name="unit-test",
        items_added=3,
        items_updated=1,
        started_at=started,
    )
    await db_session.commit()

    assert isinstance(row, CorpusIngestLog)
    assert row.errors == []
    assert row.notes is None
    assert row.completed_at is not None
    stored = (await db_session.execute(select(CorpusIngestLog))).scalar_one()
    assert stored.source_name == "unit-test"
    assert stored.items_added == 3


# ---------------------------------------------------------------------------
# pgvector.py: best-effort sync
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_embedding_vector_executes_update_on_postgres() -> None:
    session = _FakePgSession()

    await sync_embedding_vector(
        session,
        table_name="bb_corpus_reports",
        row_id=7,
        embedding=[1.0, -0.5],
    )

    sql, params = session.statements[0]
    assert "UPDATE bb_corpus_reports SET embedding_vector" in sql
    assert params == {"embedding": "[1,-0.5]", "row_id": 7}


@pytest.mark.asyncio
async def test_sync_embedding_vector_is_noop_on_other_dialects() -> None:
    class _SqliteSession:
        def __init__(self) -> None:
            self.executed = 0

        def get_bind(self) -> _FakeBind:
            return _FakeBind("sqlite")

        async def execute(self, *args: Any, **kwargs: Any) -> None:
            self.executed += 1

    session = _SqliteSession()
    await sync_embedding_vector(session, table_name="bb_corpus_writeups", row_id=1, embedding=[1.0])
    assert session.executed == 0
    assert pgv.pgvector_literal([2.0]) == "[2]"


# ---------------------------------------------------------------------------
# embeddings.py: Ollama branches (HTTP faked via httpx)
# ---------------------------------------------------------------------------


def _fake_ollama(
    monkeypatch, *, payload: Any = None, status: int = 200, raises: bool = False
) -> None:
    async def fake_post(self, url, **kwargs):  # noqa: ANN001, ANN003
        if raises:
            raise httpx.ConnectError("ollama is down")
        return httpx.Response(status, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr("httpx.AsyncClient.post", fake_post)


@pytest.mark.asyncio
async def test_embed_empty_text_returns_zero_vector_without_http(monkeypatch) -> None:
    async def should_not_post(self, url, **kwargs):  # noqa: ANN001, ANN003
        raise AssertionError("HTTP must not be called for empty text")

    monkeypatch.setattr("httpx.AsyncClient.post", should_not_post)

    vector, version = await embed_with_version("   ")

    assert vector == [0.0] * EMBEDDING_DIM
    assert version == current_embedding_model_version()


@pytest.mark.asyncio
async def test_embed_uses_ollama_embedding_and_pads_short_vectors(monkeypatch) -> None:
    _fake_ollama(monkeypatch, payload={"embedding": [3.0, 4.0]})

    vector, version = await embed_with_version("shopify idor")

    assert len(vector) == EMBEDDING_DIM
    assert vector[0] == pytest.approx(0.6)
    assert vector[1] == pytest.approx(0.8)
    assert all(value == 0.0 for value in vector[2:])
    assert version == current_embedding_model_version()


@pytest.mark.asyncio
async def test_embed_accepts_batch_style_embeddings_key(monkeypatch) -> None:
    _fake_ollama(monkeypatch, payload={"embeddings": [[0.0, 2.0]]})

    vector, version = await embed_with_version("batch style")

    assert vector[1] == pytest.approx(1.0)
    assert version.startswith("ollama:")


@pytest.mark.asyncio
async def test_embed_truncates_oversized_ollama_vectors(monkeypatch) -> None:
    oversized = [1.0] * (EMBEDDING_DIM + 50)
    _fake_ollama(monkeypatch, payload={"embedding": oversized})

    vector, _version = await embed_with_version("big vector")

    assert len(vector) == EMBEDDING_DIM
    assert math.isclose(sum(value * value for value in vector), 1.0, rel_tol=1e-9)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"embeddings": []},
        {"embedding": "not-a-list"},
        {"unrelated": True},
    ],
)
async def test_embed_falls_back_when_ollama_payload_is_unusable(monkeypatch, payload) -> None:
    _fake_ollama(monkeypatch, payload=payload)

    vector, version = await embed_with_version("fallback payload")

    assert len(vector) == EMBEDDING_DIM
    assert version == f"local:hashed-token-v1:{EMBEDDING_DIM}"


@pytest.mark.asyncio
async def test_embed_falls_back_on_http_error_status(monkeypatch) -> None:
    _fake_ollama(monkeypatch, payload={"error": "model missing"}, status=500)

    vector, version = await embed_with_version("status error")

    assert version.startswith("local:")
    assert any(value != 0 for value in vector)


@pytest.mark.asyncio
async def test_embed_falls_back_on_transport_error(monkeypatch) -> None:
    _fake_ollama(monkeypatch, raises=True)

    vector = await embed("transport error")

    assert len(vector) == EMBEDDING_DIM
    assert any(value != 0 for value in vector)
