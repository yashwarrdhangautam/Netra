"""Report model for storing generated reports."""
import uuid
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.scan import Scan


class ReportType(StrEnum):
    """Enumeration of report types."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    PENTEST = "pentest"
    COMPLIANCE = "compliance"
    HTML = "html"
    EXCEL = "excel"
    EVIDENCE = "evidence"
    DELTA = "delta"
    API = "api"
    CLOUD = "cloud"
    FULL = "full"


class ReportStatus(StrEnum):
    """Enumeration of report statuses."""

    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class Report(Base):
    """Model representing a generated security report."""

    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    report_type: Mapped[ReportType] = mapped_column(String(20), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        String(20), default=ReportStatus.PENDING, nullable=False
    )
    file_path: Mapped[str | None] = mapped_column(Text)
    file_size: Mapped[int | None] = mapped_column()
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="reports")
