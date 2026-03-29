"""ComplianceMapping model for mapping findings to compliance frameworks."""
import uuid

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class ComplianceMapping(Base):
    """Model representing mapping between findings and compliance controls."""

    __tablename__ = "compliance_mappings"

    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True
    )
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    control_name: Mapped[str] = mapped_column(String(500), nullable=False)
    control_description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="not_assessed")
    is_mapped: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    finding: Mapped["Finding | None"] = relationship(
        back_populates="compliance_mappings"
    )
