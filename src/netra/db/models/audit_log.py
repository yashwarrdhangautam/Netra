"""General audit trail for account, scan, finding and target changes."""

import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models._types import JSONB
from netra.db.models.base import Base


class AuditLog(Base):
    """One row per state-changing action: who did what to which object, and when."""

    __tablename__ = "audit_logs"

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(60), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120))
    detail: Mapped[dict | None] = mapped_column(JSONB, default=dict)
