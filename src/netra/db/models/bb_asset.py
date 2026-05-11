"""Bug bounty asset model."""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class BBAsset(Base):
    """A discovered asset belonging to a program."""

    __tablename__ = "bb_assets"
    __table_args__ = (
        UniqueConstraint("program_id", "host", name="uq_bb_assets_program_host"),
    )

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_programs.id", ondelete="CASCADE"), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    ports: Mapped[list | None] = mapped_column(JSONB, default=list)
    tech: Mapped[list | None] = mapped_column(JSONB, default=list)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(512))
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    program: Mapped["BBProgram"] = relationship(back_populates="assets")
