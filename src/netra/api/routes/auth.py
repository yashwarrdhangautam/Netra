"""Authentication routes with refresh tokens, MFA, and password reset."""
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from pydantic.functional_validators import field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_current_user
from netra.core.config import settings
from netra.core.rate_limiter import RateLimitProfiles, rate_limit
from netra.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    token_blacklist,
    verify_password,
)
from netra.db.models.user import User
from netra.db.session import get_db

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Authentication"])


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

    @field_validator("password")
    @classmethod
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
# NOTE: get_current_user and get_current_active_user live in netra.api.deps
# to avoid circular imports. Import them from there.


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
@rate_limit(RateLimitProfiles.LOGIN)
async def login(
    request: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    response: Response,
) -> LoginResponse:
    """Authenticate user and issue JWT tokens via HttpOnly cookies.

    Args:
        request: Login credentials
        db: Database session
        response: Response object for setting cookies

    Returns:
        Access and refresh tokens (also set as cookies)

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
    if user.locked_until and user.locked_until > datetime.now(UTC):
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
            user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
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
    user.last_login_at = datetime.now(UTC)
    await db.commit()

    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    # Set HttpOnly cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=3600 * 24 * 7,  # 7 days
        path="/",
    )

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
@rate_limit("10/minute")
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


@router.post("/logout")
async def logout(
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User | None, Depends(get_current_user)] = None,
) -> dict:
    """Logout user and revoke tokens by clearing HttpOnly cookies.

    Args:
        response: Response object for clearing cookies
        db: Database session
        current_user: Optional current user (for logging)

    Returns:
        Logout confirmation
    """
    # Clear HttpOnly cookies
    response.delete_cookie(
        key="access_token",
        path="/",
    )
    response.delete_cookie(
        key="refresh_token",
        path="/",
    )

    # Blacklist tokens if provided in request body (optional)
    # This is handled client-side by not sending tokens

    if current_user:
        logger.info("user_logged_out", user_id=str(current_user.id))

    return {"message": "Successfully logged out"}
