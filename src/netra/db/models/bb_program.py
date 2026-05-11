"""Bug bounty program model."""
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class BBPlatform(StrEnum):
    """Supported bug bounty platforms."""

    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    PRIVATE = "private"


class BBProgram(Base):
    """A bug bounty program (e.g. shopify on HackerOne).

    A snapshot of the program registry at scope-sync time. The raw policy URL is kept so
    operators can re-check intent. payout_min/max are advisory, used by the BountyHunter
    persona to prioritise findings.
    """

    __tablename__ = "bb_programs"
    __table_args__ = (
        UniqueConstraint("platform", "handle", name="uq_bb_programs_platform_handle"),
    )

    platform: Mapped[BBPlatform] = mapped_column(String(20), nullable=False)
    handle: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_url: Mapped[str | None] = mapped_column(String(512))
    payout_min: Mapped[int | None] = mapped_column(Integer)
    payout_max: Mapped[int | None] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    scope_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active_classes_approved: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    scope_rules: Mapped[list["BBScopeRule"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    assets: Mapped[list["BBAsset"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    submissions: Mapped[list["BBSubmission"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
