"""Similarity search helpers for the local bug bounty learning corpus."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import Select, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from netra.bugbounty.learning.embeddings import embed_with_version
from netra.bugbounty.learning.pgvector import pgvector_literal
from netra.db.models import BBCorpusAdvisory, BBCorpusReport, BBCorpusWriteup


@dataclass(frozen=True)
class CorpusSearchHit:
    """Uniform retrieval result across corpus tables."""

    kind: str
    title: str
    source_url: str
    snippet: str
    score: float
    metadata: dict[str, Any]


def _cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    left_values = [float(value) for value in left]
    right_values = [float(value) for value in right]
    if not left_values or not right_values:
        return 0.0
    size = min(len(left_values), len(right_values))
    numerator = sum(left_values[i] * right_values[i] for i in range(size))
    left_norm = math.sqrt(sum(value * value for value in left_values[:size]))
    right_norm = math.sqrt(sum(value * value for value in right_values[:size]))
    denominator = left_norm * right_norm
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _report_query(filters: dict[str, Any] | None) -> Select[Any]:
    query = select(BBCorpusReport).where(BBCorpusReport.deleted_at.is_(None))
    if not filters:
        return query
    if program_handle := filters.get("program_handle"):
        query = query.where(BBCorpusReport.program_handle == str(program_handle))
    if vuln_class := filters.get("vuln_class"):
        query = query.where(BBCorpusReport.vuln_class == str(vuln_class))
    if source_platform := filters.get("source_platform"):
        query = query.where(BBCorpusReport.source_platform == str(source_platform))
    return query


def _writeup_query(filters: dict[str, Any] | None) -> Select[Any]:
    query = select(BBCorpusWriteup).where(BBCorpusWriteup.deleted_at.is_(None))
    if not filters:
        return query
    if vuln_class := filters.get("vuln_class"):
        query = query.where(BBCorpusWriteup.vuln_class == str(vuln_class))
    return query


def _advisory_query(filters: dict[str, Any] | None) -> Select[Any]:
    query = select(BBCorpusAdvisory).where(BBCorpusAdvisory.deleted_at.is_(None))
    if not filters:
        return query
    if vuln_class := filters.get("vuln_class"):
        query = query.where(BBCorpusAdvisory.metadata_["vuln_class"].as_string() == str(vuln_class))
    return query


def _row_to_hit(kind: str, row: Any, score: float) -> CorpusSearchHit:
    if kind == "reports":
        title = row.title or f"{row.source_platform}:{row.program_handle or 'report'}"
        snippet = row.body_summary
        source_url = row.source_url
        metadata = {
            "program_handle": row.program_handle,
            "vuln_class": row.vuln_class,
            "severity": row.severity,
            "source_platform": row.source_platform,
        }
    elif kind == "writeups":
        title = row.title
        snippet = row.body_summary
        source_url = row.source_url
        metadata = {
            "author": row.author,
            "vuln_class": row.vuln_class,
            "tech_stack": list(row.tech_stack or []),
        }
    else:
        title = row.cve_id or row.ghsa_id or "advisory"
        snippet = row.summary
        source_url = row.source_url or ""
        metadata = {
            "cve_id": row.cve_id,
            "ghsa_id": row.ghsa_id,
            "severity": row.severity,
            "affected_packages": list(row.affected_packages or []),
        }
    return CorpusSearchHit(
        kind=kind,
        title=title,
        snippet=snippet[:280],
        source_url=source_url,
        score=score,
        metadata=metadata,
    )


async def find_similar(
    session: AsyncSession,
    query: str,
    *,
    top_k: int = 5,
    kinds: Iterable[str] | None = None,
    filters: dict[str, Any] | None = None,
) -> list[CorpusSearchHit]:
    """Search the local corpus using local embeddings and cosine similarity."""
    requested_kinds = list(kinds or ("reports", "writeups", "advisories"))
    query_embedding, query_version = await embed_with_version(query)
    accelerated = await _find_similar_pgvector(
        session,
        requested_kinds,
        query_embedding=query_embedding,
        query_version=query_version,
        top_k=top_k,
        filters=filters,
    )
    if accelerated is not None:
        return accelerated
    hits: list[CorpusSearchHit] = []
    query_builders = {
        "reports": _report_query,
        "writeups": _writeup_query,
        "advisories": _advisory_query,
    }
    for kind in requested_kinds:
        builder = query_builders.get(kind)
        if builder is None:
            continue
        result = await session.execute(builder(filters))
        for row in result.scalars().all():
            if not row.embedding:
                continue
            row_version = getattr(row, "embedding_model_version", None)
            if row_version and row_version != query_version:
                continue
            score = _cosine_similarity(query_embedding, row.embedding)
            if score <= 0:
                continue
            hits.append(_row_to_hit(kind, row, score))
    hits.sort(key=lambda item: item.score, reverse=True)
    return hits[:top_k]


async def _find_similar_pgvector(
    session: AsyncSession,
    requested_kinds: list[str],
    *,
    query_embedding: list[float],
    query_version: str,
    top_k: int,
    filters: dict[str, Any] | None,
) -> list[CorpusSearchHit] | None:
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return None
    literal = pgvector_literal(query_embedding)
    hits: list[CorpusSearchHit] = []
    for kind in requested_kinds:
        rows = await _pgvector_rows_for_kind(
            session,
            kind,
            literal=literal,
            query_version=query_version,
            top_k=top_k,
            filters=filters,
        )
        hits.extend(rows)
    hits.sort(key=lambda item: item.score, reverse=True)
    return hits[:top_k]


async def _pgvector_rows_for_kind(
    session: AsyncSession,
    kind: str,
    *,
    literal: str,
    query_version: str,
    top_k: int,
    filters: dict[str, Any] | None,
) -> list[CorpusSearchHit]:
    if kind == "reports":
        where = ["deleted_at IS NULL", "embedding_vector IS NOT NULL", "embedding_model_version = :query_version"]
        params: dict[str, Any] = {"embedding": literal, "query_version": query_version, "limit": top_k}
        if filters and filters.get("program_handle"):
            where.append("program_handle = :program_handle")
            params["program_handle"] = str(filters["program_handle"])
        if filters and filters.get("vuln_class"):
            where.append("vuln_class = :vuln_class")
            params["vuln_class"] = str(filters["vuln_class"])
        if filters and filters.get("source_platform"):
            where.append("source_platform = :source_platform")
            params["source_platform"] = str(filters["source_platform"])
        sql = f"""
            SELECT title, source_url, body_summary AS snippet, program_handle, vuln_class, severity, source_platform,
                   1 - (embedding_vector <=> CAST(:embedding AS vector)) AS score
            FROM bb_corpus_reports
            WHERE {' AND '.join(where)}
            ORDER BY embedding_vector <=> CAST(:embedding AS vector)
            LIMIT :limit
        """
        result = await session.execute(text(sql), params)
        return [
            CorpusSearchHit(
                kind="reports",
                title=row.title or f"{row.source_platform}:{row.program_handle or 'report'}",
                source_url=row.source_url,
                snippet=(row.snippet or "")[:280],
                score=float(row.score or 0.0),
                metadata={
                    "program_handle": row.program_handle,
                    "vuln_class": row.vuln_class,
                    "severity": row.severity,
                    "source_platform": row.source_platform,
                },
            )
            for row in result.mappings().all()
        ]
    if kind == "writeups":
        where = ["deleted_at IS NULL", "embedding_vector IS NOT NULL", "embedding_model_version = :query_version"]
        params = {"embedding": literal, "query_version": query_version, "limit": top_k}
        if filters and filters.get("vuln_class"):
            where.append("vuln_class = :vuln_class")
            params["vuln_class"] = str(filters["vuln_class"])
        sql = f"""
            SELECT title, source_url, body_summary AS snippet, author, vuln_class, tech_stack,
                   1 - (embedding_vector <=> CAST(:embedding AS vector)) AS score
            FROM bb_corpus_writeups
            WHERE {' AND '.join(where)}
            ORDER BY embedding_vector <=> CAST(:embedding AS vector)
            LIMIT :limit
        """
        result = await session.execute(text(sql), params)
        return [
            CorpusSearchHit(
                kind="writeups",
                title=row.title,
                source_url=row.source_url,
                snippet=(row.snippet or "")[:280],
                score=float(row.score or 0.0),
                metadata={
                    "author": row.author,
                    "vuln_class": row.vuln_class,
                    "tech_stack": list(row.tech_stack or []),
                },
            )
            for row in result.mappings().all()
        ]
    if kind == "advisories":
        where = ["deleted_at IS NULL", "embedding_vector IS NOT NULL", "embedding_model_version = :query_version"]
        params = {"embedding": literal, "query_version": query_version, "limit": top_k}
        if filters and filters.get("vuln_class"):
            where.append("metadata_->>'vuln_class' = :vuln_class")
            params["vuln_class"] = str(filters["vuln_class"])
        sql = f"""
            SELECT cve_id, ghsa_id, source_url, summary AS snippet, severity, affected_packages,
                   1 - (embedding_vector <=> CAST(:embedding AS vector)) AS score
            FROM bb_corpus_advisories
            WHERE {' AND '.join(where)}
            ORDER BY embedding_vector <=> CAST(:embedding AS vector)
            LIMIT :limit
        """
        result = await session.execute(text(sql), params)
        return [
            CorpusSearchHit(
                kind="advisories",
                title=row.cve_id or row.ghsa_id or "advisory",
                source_url=row.source_url or "",
                snippet=(row.snippet or "")[:280],
                score=float(row.score or 0.0),
                metadata={
                    "cve_id": row.cve_id,
                    "ghsa_id": row.ghsa_id,
                    "severity": row.severity,
                    "affected_packages": list(row.affected_packages or []),
                },
            )
            for row in result.mappings().all()
        ]
    return []


async def build_corpus_context(
    session: AsyncSession,
    query: str,
    *,
    top_k: int = 5,
    filters: dict[str, Any] | None = None,
) -> list[str]:
    """Return compact strings suitable for planner/report prompts."""
    hits = await find_similar(session, query, top_k=top_k, filters=filters)
    output: list[str] = []
    for hit in hits:
        source = hit.source_url or hit.kind
        output.append(f"[{hit.kind}] {hit.title} :: {hit.snippet} ({source})")
    return output
