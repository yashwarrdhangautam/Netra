"""Authentication routes with refresh tokens, MFA, and password reset."""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.core.security import (
    TokenBlacklist,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_access_token,
    decode_password_reset_token,
    decode_refresh_token,
    generate_backup_codes,
    generate_mfa_secret,
    get_mfa_provisioning_uri,
    get_password_hash,
    hash_api_key,
    hash_backup_code,
    token_blacklist,
    verify_api_key,
    verify_backup_code,
    verify_mfa_code,
    verify_password,
)
from netra.db.models.user import User, UserRole
from netra.db.session import get_db

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Authentication"])

# HTTP Bearer token security
http_bearer = HTTPBearer(auto_error=False)


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    """Login response schema."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str
    mfa_required: bool = False


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""

    refresh_token: str


class RefreshTokenResponse(BaseModel):
    """Refresh token response schema."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    """User registration request schema."""

    email: EmailStr
    password: str = Field(..., min_length=12, description="Minimum 12 characters")
    full_name: str = Field(..., min_length=1, max_length=255)

    @validator("password")
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        return v


class RegisterResponse(BaseModel):
    """User registration response schema."""

    user_id: str
    email: str
    full_name: str
    message: str


class MFASetupResponse(BaseModel):
    """MFA setup response with QR code URI."""

    secret: str
    provisioning_uri: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""

    code: str = Field(..., min_length=6, max_length=6)


class MFAEnableRequest(BaseModel):
    """Enable MFA request."""

    code: str = Field(..., min_length=6, max_length=6)
    secret: str


class PasswordResetRequest(BaseModel):
    """Password reset request (initiate)."""

    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation request."""

    token: str
    new_password: str = Field(..., min_length=12)


class ChangePasswordRequest(BaseModel):
    """Change password request (authenticated user)."""

    current_password: str
    new_password: str = Field(..., min_length=12)


class APIKeyResponse(BaseModel):
    """API key generation response."""

    api_key: str
    message: str


# ── Helper Functions ──────────────────────────────────────────────────────────


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Get current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer credentials
        db: Database session

    Returns:
        The authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Check blacklist
    if await token_blacklist.is_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Decode token
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = uuid.UUID(payload["sub"])

    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get current active user (with is_active check).

    Args:
        current_user: The authenticated user

    Returns:
        The active user

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return user


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get current admin user.

    Args:
        current_user: The authenticated user

    Returns:
        The admin user

    Raises:
        HTTPException: If user is not admin
    """
    if not current_user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# ── Authentication Routes ─────────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """Authenticate user and issue JWT tokens.

    Args:
        request: Login credentials
        db: Database session

    Returns:
        Access and refresh tokens

    Raises:
        HTTPException: If credentials are invalid or account is locked
    """
    # Get user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user:
        # Increment failed login attempts for non-existent email (prevent enumeration)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account locked until {user.locked_until.isoformat()}",
        )

    # Verify password
    if not verify_password(request.password, user.hashed_password):
        # Increment failed login attempts
        user.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            user.failed_login_attempts = 0
            logger.warning(
                "account_locked",
                user_id=str(user.id),
                email=user.email,
            )

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    logger.info("user_logged_in", user_id=str(user.id), email=user.email)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_expire_minutes * 60,
        user_id=str(user.id),
        email=user.email,
        mfa_required=user.requires_mfa(),
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RefreshTokenResponse:
    """Refresh access token using refresh token.

    Implements refresh token rotation for enhanced security.

    Args:
        request: Refresh token
        db: Database session

    Returns:
        New access token

    Raises:
        HTTPException: If refresh token is invalid or revoked
    """
    # Check blacklist
    if await token_blacklist.is_blacklisted(request.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Decode refresh token
    payload = decode_refresh_token(request.refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = uuid.UUID(payload["sub"])

    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new access token
    new_access_token = create_access_token(user.id)

    logger.info("token_refreshed", user_id=str(user.id))

    return RefreshTokenResponse(
        access_token=new_access_token,
        expires_in=settings.jwt_expire_minutes * 60,
    )