"""ScanPhase model for tracking scan phase progress."""
import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.scan import Scan


class PhaseType(StrEnum):
    """Enumeration of scan phase types."""

    # Phase 1 phases
    SCOPE = "scope"
    RECON_OSINT = "recon_osint"
    RECON_SUBDOMAINS = "recon_subdomains"
    RECON_DISCOVERY = "recon_discovery"
    RECON_PORTS = "recon_ports"
    VULN_SCAN = "vuln_scan"
    PENTEST = "pentest"
    AUTH_TEST = "auth_test"
    AI_ANALYSIS = "ai_analysis"
    REPORTING = "reporting"

    # Phase 2 phases
    SAST = "sast"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    CSPM = "cspm"
    CONTAINER = "container"
    IAC = "iac"
    AI_LLM = "ai_llm"


class PhaseStatus(StrEnum):
    """Enumeration of phase statuses."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanPhase(Base):
    """Model representing a phase within a security scan."""

    __tablename__ = "scan_phases"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    phase_type: Mapped[PhaseType] = mapped_column(String(30), nullable=False)
    status: Mapped[PhaseStatus] = mapped_column(
        String(20), default=PhaseStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    tool_outputs: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="phases")
