"""Target model for storing scan targets."""

import uuid
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models._types import JSONB
from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.scan import Scan


class TargetType(StrEnum):
    """Enumeration of target types."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    IP_RANGE = "ip_range"
    DOMAIN_LIST = "domain_list"


class Target(Base):
    """Model representing a scan target."""

    __tablename__ = "targets"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # The client user this target is assigned to. Clients see only their assigned targets.
    client_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    target_type: Mapped[TargetType] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    group_name: Mapped[str | None] = mapped_column(String(100))
    scope_includes: Mapped[dict | None] = mapped_column(JSONB, default=list)
    scope_excludes: Mapped[dict | None] = mapped_column(JSONB, default=list)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, default=dict)

    # Relationships
    scans: Mapped[list["Scan"]] = relationship(back_populates="target")
