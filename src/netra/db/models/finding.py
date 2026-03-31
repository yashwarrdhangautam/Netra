"""Finding model for storing security vulnerability findings."""
import uuid
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.compliance import ComplianceMapping
    from netra.db.models.scan import Scan


class Severity(StrEnum):
    """Enumeration of severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Enumeration of finding statuses."""

    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Finding(Base):
    """Model representing a security finding/vulnerability."""

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(String(20), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        String(20), default=FindingStatus.NEW, nullable=False
    )
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    cve_ids: Mapped[dict | None] = mapped_column(JSONB, default=list)
    url: Mapped[str | None] = mapped_column(Text)
    parameter: Mapped[str | None] = mapped_column(String(255))
    evidence: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    tool_source: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    remediation: Mapped[str | None] = mapped_column(Text)
    ai_analysis: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    tags: Mapped[dict | None] = mapped_column(JSONB, default=list)
    assignee: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    dedup_hash: Mapped[str | None] = mapped_column(String(64), index=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings")
    compliance_mappings: Mapped[list["ComplianceMapping"]] = relationship(
        back_populates="finding"
    )
