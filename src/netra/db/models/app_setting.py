"""Encrypted application settings (integration keys set from the GUI)."""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class AppSetting(Base):
    """One encrypted value per setting name. Values are never returned in full."""

    __tablename__ = "app_settings"

    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    value_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by_email: Mapped[str | None] = mapped_column(String(255))
