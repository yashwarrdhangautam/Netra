"""Bug bounty deduplication signature model."""
import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBDedupSignature(Base):
    """A deterministic fingerprint of a finding, used for dup detection.

    The signature_hash is sha256 of a normalised tuple: (vuln_class, normalised_path, param_name).
    This lets the deduper answer 'have we submitted something equivalent to this before' without
    invoking AI.
    """

    __tablename__ = "bb_dedup_signatures"
    __table_args__ = (
        Index("ix_bb_dedup_signatures_program_hash", "program_id", "signature_hash"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_programs.id", ondelete="CASCADE"), nullable=False
    )
    signature_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(40), nullable=False)
    vuln_class: Mapped[str] = mapped_column(String(80), nullable=False)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
