"""Authentication routes with refresh tokens, MFA, and password reset."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.core.config import settings
from netra.core.rate_limiter import rate_limit
from netra.core.secretbox import decrypt_value
from netra.core.security import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_access_token,
    decode_password_reset_token,
    decode_refresh_token,
    get_password_hash,
    password_fingerprint,
    token_blacklist,
    verify_api_key,
    verify_backup_code,
    verify_mfa_code,
    verify_password,
)
from netra.db.models.user import User, UserRole
from netra.db.session import get_db
from netra.notifications.email import EmailNotifier

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Authentication"])

# HTTP Bearer token security
http_bearer = HTTPBearer(auto_error=False)

# Personal API keys look like ntr_<hex> and are stored hashed on the user row.
API_KEY_PREFIX = "ntr_"


def _consume_backup_code(user: User, code: str) -> bool:
    """Accept a one-time backup code and remove it so it cannot be reused."""
    hashes = list(user.backup_codes_hash or [])
    for stored in hashes:
        if verify_backup_code(code, stored):
            user.backup_codes_hash = [h for h in hashes if h != stored]
            return True
    return False


async def _user_for_api_key(api_key: str, db: AsyncSession) -> User:
    """Resolve a personal API key to its active user, or raise 401."""
    result = await db.execute(select(User).where(User.api_key_hash.is_not(None)))
    for candidate in result.scalars().all():
        if candidate.api_key_hash and verify_api_key(api_key, candidate.api_key_hash):
            if not candidate.is_active:
                break
            return candidate
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Pydantic Schemas ──────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr
    password: str = Field(..., min_length=1)
    mfa_code: str | None = Field(default=None, max_length=32)


class LoginResponse(BaseModel):
    """Login response schema."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type label
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
    token_type: str = "bearer"  # noqa: S105 - OAuth token type label
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

    # API keys (nk_...) are checked against the stored hash of each user's key.
    if token.startswith(API_KEY_PREFIX):
        return await _user_for_api_key(token, db)

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
    return current_user


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

    # Second factor: TOTP code, or a single-use backup code.
    if user.requires_mfa():
        if not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="mfa_required",
            )
        code = request.mfa_code.strip()
        mfa_plain = decrypt_value(user.mfa_secret) if user.mfa_secret else None
        if not (mfa_plain and verify_mfa_code(mfa_plain, code)):
            used = _consume_backup_code(user, code)
            if not used:
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code",
                )

    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(UTC)
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


_RESET_INVALID = "Reset link is invalid or has expired"


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
@rate_limit("3/hour")
async def request_password_reset(
    request: Request,
    body: PasswordResetRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Email a one-hour reset link. The answer is the same whether or not the email exists."""
    answer = {"detail": "If that account exists, a reset link has been sent."}
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        return answer

    token = create_password_reset_token(user.id, password_hash=user.hashed_password)
    link = f"{settings.public_app_url.rstrip('/')}/reset-password?token={token}"
    sent = EmailNotifier().send(
        to=user.email,
        subject="Reset your NETRA password",
        body=(
            "Use this link within one hour to choose a new password:\n\n"
            f"{link}\n\n"
            "If you did not ask for this, ignore this email."
        ),
    )
    # The link itself is never logged. If SMTP is not configured, nothing is sent.
    logger.info("password_reset_requested", user_id=str(user.id), email_sent=sent)
    return answer


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    body: PasswordResetConfirmRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Set a new password from a reset link. The link works once: changing the password voids it."""
    payload = decode_password_reset_token(body.token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_RESET_INVALID)
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_RESET_INVALID) from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_RESET_INVALID)
    if payload.get("pwh") != password_fingerprint(user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_RESET_INVALID)

    user.hashed_password = get_password_hash(body.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    logger.info("password_reset_completed", user_id=str(user.id))
    return {"detail": "Password updated. You can sign in now."}


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


@router.get("/me")
async def read_current_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> dict[str, object]:
    """Return the signed-in user's profile for the GUI."""
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": str(current_user.role),
        "is_active": bool(current_user.is_active),
        "is_verified": bool(current_user.is_verified),
    }


# ── Role checks (PRD 5.3.2) ───────────────────────────────────────────────────
# Defined here, next to get_current_active_user, so route modules can import them
# without a circular import. netra.api.rbac re-exports these names.

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
WRITER_ROLES = frozenset({UserRole.ADMIN, UserRole.ANALYST})


async def require_access(
    request: Request,
    user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """Allow reads for any active user. Writes need the analyst or admin role."""
    if request.method in WRITE_METHODS and user.role not in WRITER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role is read-only. Ask an analyst or admin to make changes.",
        )
    return user


async def require_writer(
    user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """Allow analysts and admins. Viewers and clients cannot read sensitive drafts."""
    if user.role not in WRITER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot read submission drafts.",
        )
    return user


async def require_admin(
    user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """Allow only admins."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return user
