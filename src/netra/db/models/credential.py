"""Credential model for storing authentication credentials."""
import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class Credential(Base):
    """Model representing stored credentials for authenticated scanning."""

    __tablename__ = "credentials"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    login_url: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str | None] = mapped_column(String(255))
    password_encrypted: Mapped[str | None] = mapped_column(Text)
    token: Mapped[str | None] = mapped_column(Text)
    headers: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    cookies: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    auth_flow: Mapped[dict | None] = mapped_column(JSONB, default=dict)
