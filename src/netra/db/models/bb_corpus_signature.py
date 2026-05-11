"""Corpus models for external signature sets used by learning and recon."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBCorpusSignature(Base):
    """Versioned signature payload from sources like Wappalyzer or nuclei templates."""

    __tablename__ = "bb_corpus_signatures"

    source_repo: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tag: Mapped[str | None] = mapped_column(String(255), index=True)
    signature_blob: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
    updated_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
