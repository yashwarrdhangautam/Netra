"""Bug bounty hunt budget model."""
import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class BBHuntBudget(Base):
    """Budget policy and counters for an agentic hunt."""

    __tablename__ = "bb_hunt_budgets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    max_tools: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    wallclock_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    per_tool_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    tools_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

    scan: Mapped["Scan"] = relationship()
