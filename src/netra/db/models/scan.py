"""Scan model for storing security scan information."""
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


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
    BUGBOUNTY_PASSIVE = "bugbounty_passive"
    BUGBOUNTY_ACTIVE = "bugbounty_active"
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
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    checkpoint_data: Mapped[dict | None] = mapped_column(JSONB, default=dict)

    # Relationships
    user: Mapped["User | None"] = relationship(back_populates="scans")
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
