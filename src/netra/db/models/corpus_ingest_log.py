"""Audit log for learning corpus ingests."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class CorpusIngestLog(Base):
    """Track source ingests and failures without mixing them into scan logs."""

    __tablename__ = "corpus_ingest_log"

    source_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    items_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
