"""Pydantic schemas for authentication operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from netra.db.models.user import UserRole


class UserLogin(BaseModel):
    """Schema for user login request."""

    email: EmailStr
    password: str


class UserRegister(BaseModel):
    """Schema for user registration request."""

    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str | None = None


class UserResponse(BaseModel):
    """Schema for user response."""

    id: uuid.UUID
    email: str
    full_name: str | None
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """Schema for token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Schema for token refresh request."""

    refresh_token: str


class ChangePassword(BaseModel):
    """Schema for password change request."""

    current_password: str
    new_password: str = Field(min_length=8)
