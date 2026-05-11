"""Corpus models for advisories and CVE/GHSA records."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBCorpusAdvisory(Base):
    """Advisory record stored for retrieval and correlation."""

    __tablename__ = "bb_corpus_advisories"

    cve_id: Mapped[str | None] = mapped_column(String(64), index=True)
    ghsa_id: Mapped[str | None] = mapped_column(String(64), index=True)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    affected_packages: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024), unique=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
    embedding: Mapped[list[float] | None] = mapped_column(JSONB)
    embedding_model_version: Mapped[str | None] = mapped_column(String(128))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
