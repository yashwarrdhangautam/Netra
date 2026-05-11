"""Bug bounty evidence and replay models."""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class BBEvidence(Base):
    """Redacted, encrypted evidence attached to a finding."""

    __tablename__ = "bb_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_programs.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False, default="application/octet-stream")
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redaction_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

    redactions: Mapped[list["BBEvidenceRedaction"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    replays: Mapped[list["BBEvidenceReplay"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )


class BBEvidenceRedaction(Base):
    """A redaction hit recorded without storing the secret value."""

    __tablename__ = "bb_evidence_redactions"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_evidence.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False)
    replacement: Mapped[str] = mapped_column(String(120), nullable=False)
    start_offset: Mapped[int | None] = mapped_column(Integer)
    end_offset: Mapped[int | None] = mapped_column(Integer)

    evidence: Mapped["BBEvidence"] = relationship(back_populates="redactions")


class BBEvidenceReplay(Base):
    """Replay/verification result for a piece of evidence."""

    __tablename__ = "bb_evidence_replays"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_evidence.id", ondelete="CASCADE"), nullable=False
    )
    verifier_id: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    diff: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)

    evidence: Mapped["BBEvidence"] = relationship(back_populates="replays")

