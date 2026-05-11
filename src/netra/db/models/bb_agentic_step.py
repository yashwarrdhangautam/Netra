"""Telemetry rows for agentic hunt decisions."""
import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class BBAgenticStep(Base):
    """Single persisted execution step from the agentic loop."""

    __tablename__ = "bb_agentic_steps"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bb_hunt_plans.id", ondelete="SET NULL")
    )
    step_n: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    tool_chosen: Mapped[str | None] = mapped_column(String(80))
    llm_prompt: Mapped[str | None] = mapped_column(Text)
    llm_response: Mapped[str | None] = mapped_column(Text)
    observations_in: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    observations_out: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    decision_rationale: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

    scan: Mapped["Scan"] = relationship()
    plan: Mapped["BBHuntPlan | None"] = relationship()
