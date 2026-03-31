"""Scan model for storing security scan information."""
import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.finding import Finding
    from netra.db.models.report import Report
    from netra.db.models.scan_phase import ScanPhase
    from netra.db.models.target import Target


class ScanStatus(StrEnum):
    """Enumeration of possible scan statuses."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(StrEnum):
    """Enumeration of scan profile types."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    API_ONLY = "api_only"
    CLOUD = "cloud"
    MOBILE = "mobile"
    CONTAINER = "container"
    AI_LLM = "ai_llm"
    CUSTOM = "custom"


class Scan(Base):
    """Model representing a security scan."""

    __tablename__ = "scans"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        String(20), default=ScanStatus.PENDING, nullable=False
    )
    profile: Mapped[ScanProfile] = mapped_column(
        String(20), default=ScanProfile.STANDARD, nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    checkpoint_data: Mapped[dict | None] = mapped_column(JSONB, default=dict)

    # Relationships
    target: Mapped["Target"] = relationship(back_populates="scans")
    phases: Mapped[list["ScanPhase"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
