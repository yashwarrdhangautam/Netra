"""Corpus models for weekly learning trends."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Integer, String
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBCorpusTrend(Base):
    """Weekly aggregate of vulnerability and technology trends."""

    __tablename__ = "bb_corpus_trends"

    week_starting: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    vuln_class: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delta_vs_prior: Mapped[int | None] = mapped_column(Integer)
    top_assets: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    top_tech: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
