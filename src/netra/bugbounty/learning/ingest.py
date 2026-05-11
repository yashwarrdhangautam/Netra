"""Shared ingestion helpers for the NETRA-BB learning corpus."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.evidence.redactor import redact_text
from netra.bugbounty.learning.embeddings import embed_with_version
from netra.bugbounty.learning.pgvector import sync_embedding_vector
from netra.db.models import (
    BBCorpusAdvisory,
    BBCorpusReport,
    BBCorpusWriteup,
    CorpusIngestLog,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def log_ingest(
    session: AsyncSession,
    *,
    source_name: str,
    items_added: int,
    items_updated: int,
    errors: list[str] | None = None,
    notes: str | None = None,
    started_at: datetime | None = None,
) -> CorpusIngestLog:
    row = CorpusIngestLog(
        source_name=source_name,
        items_added=items_added,
        items_updated=items_updated,
        errors=errors or [],
        notes=notes,
        started_at=started_at or _now(),
        completed_at=_now(),
    )
    session.add(row)
    await session.flush()
    return row


async def upsert_report(
    session: AsyncSession,
    *,
    source_platform: str,
    source_url: str,
    author_handle: str | None,
    program_handle: str | None,
    vuln_class: str | None,
    severity: str | None,
    title: str | None,
    body_summary: str,
    tech_stack: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    ingested_at: datetime | None = None,
) -> tuple[BBCorpusReport, bool]:
    result = await session.execute(
        select(BBCorpusReport).where(BBCorpusReport.source_url == source_url)
    )
    row = result.scalar_one_or_none()
    redacted_summary, hits = redact_text(body_summary[:2048])
    embedding, embedding_model_version = await embed_with_version(
        " ".join(filter(None, [title or "", vuln_class or "", redacted_summary]))
    )
    payload = {
        "source_platform": source_platform,
        "author_handle": author_handle,
        "program_handle": program_handle,
        "vuln_class": vuln_class,
        "severity": severity,
        "title": title,
        "body_summary": redacted_summary,
        "tech_stack": list(tech_stack or []),
        "metadata_": metadata or {},
        "redaction_count": len(hits),
        "embedding": embedding,
        "embedding_model_version": embedding_model_version,
        "ingested_at": ingested_at or _now(),
        "deleted_at": None,
    }
    created = row is None
    if row is None:
        row = BBCorpusReport(source_url=source_url, **payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    await sync_embedding_vector(
        session,
        table_name="bb_corpus_reports",
        row_id=row.id,
        embedding=embedding,
    )
    return row, created


async def upsert_writeup(
    session: AsyncSession,
    *,
    source_url: str,
    author: str | None,
    title: str,
    vuln_class: str | None,
    tech_stack: list[str] | None,
    body_summary: str,
    metadata: dict[str, Any] | None = None,
    ingested_at: datetime | None = None,
) -> tuple[BBCorpusWriteup, bool]:
    result = await session.execute(
        select(BBCorpusWriteup).where(BBCorpusWriteup.source_url == source_url)
    )
    row = result.scalar_one_or_none()
    redacted_summary, hits = redact_text(body_summary[:2048])
    embedding, embedding_model_version = await embed_with_version(
        " ".join(filter(None, [title, vuln_class or "", redacted_summary]))
    )
    payload = {
        "author": author,
        "title": title,
        "vuln_class": vuln_class,
        "tech_stack": list(tech_stack or []),
        "body_summary": redacted_summary,
        "metadata_": metadata or {},
        "redaction_count": len(hits),
        "embedding": embedding,
        "embedding_model_version": embedding_model_version,
        "ingested_at": ingested_at or _now(),
        "deleted_at": None,
    }
    created = row is None
    if row is None:
        row = BBCorpusWriteup(source_url=source_url, **payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    await sync_embedding_vector(
        session,
        table_name="bb_corpus_writeups",
        row_id=row.id,
        embedding=embedding,
    )
    return row, created


async def upsert_advisory(
    session: AsyncSession,
    *,
    source_url: str | None,
    cve_id: str | None,
    ghsa_id: str | None,
    severity: str | None,
    cvss_vector: str | None,
    affected_packages: list[str] | None,
    summary: str,
    metadata: dict[str, Any] | None = None,
    ingested_at: datetime | None = None,
) -> tuple[BBCorpusAdvisory, bool]:
    stmt = select(BBCorpusAdvisory)
    if source_url:
        stmt = stmt.where(BBCorpusAdvisory.source_url == source_url)
    elif cve_id:
        stmt = stmt.where(BBCorpusAdvisory.cve_id == cve_id)
    else:
        stmt = stmt.where(BBCorpusAdvisory.ghsa_id == ghsa_id)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    redacted_summary, _hits = redact_text(summary[:2048])
    embedding, embedding_model_version = await embed_with_version(
        " ".join(filter(None, [cve_id or "", ghsa_id or "", redacted_summary]))
    )
    payload = {
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "severity": severity,
        "cvss_vector": cvss_vector,
        "affected_packages": list(affected_packages or []),
        "summary": redacted_summary,
        "source_url": source_url,
        "metadata_": metadata or {},
        "embedding": embedding,
        "embedding_model_version": embedding_model_version,
        "ingested_at": ingested_at or _now(),
        "deleted_at": None,
    }
    created = row is None
    if row is None:
        row = BBCorpusAdvisory(**payload)
        session.add(row)
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    await session.flush()
    await sync_embedding_vector(
        session,
        table_name="bb_corpus_advisories",
        row_id=row.id,
        embedding=embedding,
    )
    return row, created


async def forget_corpus_entries(
    session: AsyncSession,
    *,
    author: str | None = None,
    source_url: str | None = None,
) -> dict[str, int]:
    """Hard-delete matching public corpus entries."""
    deleted: dict[str, int] = {"reports": 0, "writeups": 0, "advisories": 0}
    if author:
        reports_result = await session.execute(
            delete(BBCorpusReport).where(BBCorpusReport.author_handle == author)
        )
        writeups_result = await session.execute(
            delete(BBCorpusWriteup).where(BBCorpusWriteup.author == author)
        )
        deleted["reports"] += reports_result.rowcount or 0
        deleted["writeups"] += writeups_result.rowcount or 0
    if source_url:
        reports_result = await session.execute(
            delete(BBCorpusReport).where(BBCorpusReport.source_url == source_url)
        )
        writeups_result = await session.execute(
            delete(BBCorpusWriteup).where(BBCorpusWriteup.source_url == source_url)
        )
        advisories_result = await session.execute(
            delete(BBCorpusAdvisory).where(BBCorpusAdvisory.source_url == source_url)
        )
        deleted["reports"] += reports_result.rowcount or 0
        deleted["writeups"] += writeups_result.rowcount or 0
        deleted["advisories"] += advisories_result.rowcount or 0
    await session.flush()
    return deleted


async def reembed_corpus(session: AsyncSession) -> dict[str, int]:
    """Refresh stored embeddings and model versions for all active corpus rows."""
    refreshed = {"reports": 0, "writeups": 0, "advisories": 0}
    for model, kind, text_builder in (
        (
            BBCorpusReport,
            "reports",
            lambda row: " ".join(filter(None, [row.title or "", row.vuln_class or "", row.body_summary])),
        ),
        (
            BBCorpusWriteup,
            "writeups",
            lambda row: " ".join(filter(None, [row.title, row.vuln_class or "", row.body_summary])),
        ),
        (
            BBCorpusAdvisory,
            "advisories",
            lambda row: " ".join(filter(None, [row.cve_id or "", row.ghsa_id or "", row.summary])),
        ),
    ):
        result = await session.execute(select(model).where(model.deleted_at.is_(None)))
        for row in result.scalars().all():
            row.embedding, row.embedding_model_version = await embed_with_version(text_builder(row))
            await sync_embedding_vector(
                session,
                table_name=model.__tablename__,
                row_id=row.id,
                embedding=row.embedding,
            )
            refreshed[kind] += 1
    await session.flush()
    return refreshed
