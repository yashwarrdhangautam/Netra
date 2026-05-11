"""Corpus models for disclosed bug bounty reports."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBCorpusReport(Base):
    """Public disclosed report stored for local retrieval."""

    __tablename__ = "bb_corpus_reports"

    source_platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_url: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    author_handle: Mapped[str | None] = mapped_column(String(255))
    program_handle: Mapped[str | None] = mapped_column(String(255), index=True)
    vuln_class: Mapped[str | None] = mapped_column(String(128), index=True)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    body_summary: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    tech_stack: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
    redaction_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    embedding: Mapped[list[float] | None] = mapped_column(JSONB)
    embedding_model_version: Mapped[str | None] = mapped_column(String(128))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
