"""Bug bounty scope rule model."""
import uuid
from enum import StrEnum

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base


class ScopeRuleType(StrEnum):
    """In-scope (allow) or out-of-scope (deny)."""

    IN = "in"
    OUT = "out"


class ScopeAssetType(StrEnum):
    """Type of asset the scope rule covers."""

    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    MOBILE = "mobile"
    REPO = "repo"
    OTHER = "other"


class BBScopeRule(Base):
    """A single scope rule snapshot for a program.

    Match order at validation time is: deny rules first (ScopeRuleType.OUT), then allow
    rules (ScopeRuleType.IN). A miss is always treated as deny.
    """

    __tablename__ = "bb_scope_rules"

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bb_programs.id", ondelete="CASCADE"), nullable=False
    )
    rule_type: Mapped[ScopeRuleType] = mapped_column(String(10), nullable=False)
    asset_type: Mapped[ScopeAssetType] = mapped_column(String(20), nullable=False)
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    severity_cap: Mapped[str | None] = mapped_column(String(20))
    notes: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    synced_from_platform: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # Relationships
    program: Mapped["BBProgram"] = relationship(back_populates="scope_rules")
