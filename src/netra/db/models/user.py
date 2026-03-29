"""User model for authentication and authorization."""
from enum import StrEnum

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class UserRole(StrEnum):
    """Enumeration of user roles."""

    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class User(Base):
    """Model representing a system user."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        String(20), default=UserRole.USER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    api_key_hash: Mapped[str | None] = mapped_column(String(255))
