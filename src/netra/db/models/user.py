"""User model for authentication and authorization with MFA support."""
from datetime import UTC
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra.db.models.base import Base

if TYPE_CHECKING:
    from netra.db.models.scan import Scan


class UserRole(StrEnum):
    """Enumeration of user roles with RBAC permissions.

    Roles hierarchy:
    - ADMIN: Full system access, user management
    - ANALYST: Create/edit scans, manage findings
    - VIEWER: Read-only access to all scans
    - CLIENT: Read-only access to assigned targets only
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    CLIENT = "client"


class User(Base):
    """Model representing a system user with RBAC and MFA support."""

    __tablename__ = "users"

    # Authentication
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile
    full_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        String(20), default=UserRole.VIEWER, nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # API Access
    api_key_hash: Mapped[str | None] = mapped_column(String(255))

    # Client-specific (for CLIENT role)
    organization: Mapped[str | None] = mapped_column(String(255))

    # Security
    last_login_at: Mapped[DateTime | None] = mapped_column(DateTime)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[DateTime | None] = mapped_column(DateTime)

    # MFA / 2FA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(255))  # Encrypted at rest
    backup_codes_hash: Mapped[list[str] | None] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )  # List of hashed backup codes

    # Notification preferences
    notify_email_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email_high: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_slack_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_slack_high: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_sla_breach: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="user")

    # Methods
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    def requires_mfa(self) -> bool:
        """Check if user has MFA enabled."""
        return self.mfa_enabled

    def is_account_locked(self) -> bool:
        """Check if account is currently locked."""
        if not self.locked_until:
            return False
        from datetime import datetime
        return self.locked_until > datetime.now(UTC)
