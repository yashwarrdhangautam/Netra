"""Audit rows for state-changing GUI/API actions."""
import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class AuditUIAction(Base):
    """Audit trail for mutating BB API calls."""

    __tablename__ = "audit_ui_actions"

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(80))
    target_id: Mapped[str | None] = mapped_column(String(120))
    payload_hash: Mapped[str | None] = mapped_column(String(64))
    result_code: Mapped[int] = mapped_column(nullable=False, default=200)
    trace_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(80))
    user_agent: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, default=dict)

