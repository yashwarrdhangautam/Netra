"""Credential model for storing authentication credentials."""

import re
import uuid

from sqlalchemy import ForeignKey, String, Text, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models._types import JSONB
from netra.db.models.base import Base

# Writes to the credentials table are refused at the driver layer, so ORM flushes,
# bulk statements and raw Core execution are all covered. Stage 1 has no secure
# secret store; that arrives with Stage 5a (spec S7).
_CREDENTIAL_WRITE = re.compile(
    r"^\s*(INSERT\s+INTO|UPDATE|MERGE\s+INTO|REPLACE\s+INTO)\s+\"?credentials\"?\b",
    re.IGNORECASE,
)


@event.listens_for(Engine, "before_cursor_execute")
def _refuse_plaintext_credential_writes(conn, cursor, statement, parameters, context, executemany):
    if _CREDENTIAL_WRITE.match(statement):
        raise ValueError("credential_storage_unavailable")


class Credential(Base):
    """Model representing stored credentials for authenticated scanning."""

    __tablename__ = "credentials"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    login_url: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str | None] = mapped_column(String(255))
    password_encrypted: Mapped[str | None] = mapped_column(Text)
    token: Mapped[str | None] = mapped_column(Text)
    headers: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    cookies: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    auth_flow: Mapped[dict | None] = mapped_column(JSONB, default=dict)
