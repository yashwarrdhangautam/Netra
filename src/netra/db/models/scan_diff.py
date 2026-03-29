"""ScanDiff model for comparing two scans."""
import uuid

from sqlalchemy import ForeignKey, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class ScanDiff(Base):
    """Model representing a comparison/diff between two scans."""

    __tablename__ = "scan_diffs"

    scan_a_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    scan_b_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    resolved_findings: Mapped[int] = mapped_column(Integer, default=0)
    changed_findings: Mapped[int] = mapped_column(Integer, default=0)
    unchanged_findings: Mapped[int] = mapped_column(Integer, default=0)
    diff_data: Mapped[dict | None] = mapped_column(JSONB, default=dict)
