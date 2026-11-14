"""Account endpoints: sign-out, self sign-up, password change, MFA, personal API keys."""

from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.routes.auth import (
    get_current_active_user,
    http_bearer,
)
from netra.core.config import settings
from netra.core.passwords import validate_password
from netra.core.secretbox import decrypt_value, encrypt_value
from netra.core.security import (
    create_api_key,
    decode_access_token,
    generate_backup_codes,
    generate_mfa_secret,
    get_mfa_provisioning_uri,
    get_password_hash,
    hash_api_key,
    hash_backup_code,
    token_blacklist,
    verify_mfa_code,
    verify_password,
)
from netra.db.models.user import User, UserRole
from netra.services.audit import record_audit

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Account"])


def _mfa_matches(user: User, code: str) -> bool:
    """Check a TOTP code against the stored (encrypted) secret. Fails closed."""
    plain = decrypt_value(user.mfa_secret) if user.mfa_secret else None
    return bool(plain) and verify_mfa_code(plain, code.strip())


# ── Schemas ───────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)
    full_name: str | None = Field(default=None, max_length=255)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1, max_length=256)


class MfaCodeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaEnableResponse(BaseModel):
    enabled: bool
    backup_codes: list[str]


class MfaStatusResponse(BaseModel):
    enabled: bool
    backup_codes_remaining: int


class ApiKeyResponse(BaseModel):
    api_key: str
    note: str


class ApiKeyStatusResponse(BaseModel):
    has_key: bool


def _check_password(password: str) -> None:
    problem = validate_password(password)
    if problem:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=problem)


# ── Sign-out and sign-up ──────────────────────────────────────────────────────


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)],
    user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Revoke the current access token so it cannot be used again."""
    if credentials is None:
        return
    token = credentials.credentials
    if token.startswith("ntr_"):
        # API keys are revoked from the Account page, not by signing out.
        return
    payload = decode_access_token(token)
    expires = (
        datetime.fromtimestamp(payload["exp"], tz=UTC)
        if payload and payload.get("exp")
        else datetime.now(UTC)
    )
    await token_blacklist.add(token, expires)
    logger.info("user_logged_out", user_id=str(user.id))


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> dict[str, str]:
    """Create a viewer account. Only available when NETRA_ALLOW_SELF_SIGNUP is enabled."""
    if not settings.allow_self_signup:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self sign-up is disabled. Ask an admin to create your account.",
        )
    _check_password(body.password)
    email = body.email.lower()
    existing = await db.execute(select(User.id).where(User.email == email))
    if existing.first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    user = User(
        email=email,
        full_name=body.full_name,
        hashed_password=get_password_hash(body.password),
        role=UserRole.VIEWER,
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    await db.commit()
    return {"id": str(user.id), "email": user.email, "status": "created"}


# ── Password ──────────────────────────────────────────────────────────────────


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> None:
    """Change the signed-in user's own password."""
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is wrong"
        )
    _check_password(body.new_password)
    user.hashed_password = get_password_hash(body.new_password)
    await record_audit(
        db,
        actor=user,
        action="account.password_change",
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()


# ── MFA (TOTP with backup codes) ──────────────────────────────────────────────


@router.get("/mfa", response_model=MfaStatusResponse)
async def mfa_status(
    user: Annotated[User, Depends(get_current_active_user)],
) -> MfaStatusResponse:
    return MfaStatusResponse(
        enabled=bool(user.mfa_enabled),
        backup_codes_remaining=len(user.backup_codes_hash or []),
    )


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> MfaSetupResponse:
    """Create a new TOTP secret. MFA is not active until /mfa/enable confirms a code."""
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    secret = generate_mfa_secret()
    user.mfa_secret = encrypt_value(secret)
    await db.commit()
    return MfaSetupResponse(
        secret=secret,
        provisioning_uri=get_mfa_provisioning_uri(secret, user.email),
    )


@router.post("/mfa/enable", response_model=MfaEnableResponse)
async def mfa_enable(
    body: MfaCodeRequest,
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> MfaEnableResponse:
    """Confirm the authenticator app with a code, then turn MFA on and issue backup codes."""
    if not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Run MFA setup first")
    if not _mfa_matches(user, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
    codes = generate_backup_codes()
    user.mfa_enabled = True
    user.backup_codes_hash = [hash_backup_code(c) for c in codes]
    await record_audit(
        db, actor=user, action="account.mfa_enable", resource_type="user", resource_id=str(user.id)
    )
    await db.commit()
    return MfaEnableResponse(enabled=True, backup_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaCodeRequest,
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> None:
    """Turn MFA off. Requires a current code so a stolen session cannot disable it."""
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    if not _mfa_matches(user, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.backup_codes_hash = []
    await record_audit(
        db, actor=user, action="account.mfa_disable", resource_type="user", resource_id=str(user.id)
    )
    await db.commit()


# ── Personal API key (for scripts and MCP clients) ────────────────────────────


@router.get("/api-key", response_model=ApiKeyStatusResponse)
async def api_key_status(
    user: Annotated[User, Depends(get_current_active_user)],
) -> ApiKeyStatusResponse:
    return ApiKeyStatusResponse(has_key=bool(user.api_key_hash))


@router.post("/api-key", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def api_key_create(
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> ApiKeyResponse:
    """Create a new personal API key. Replaces any existing key. Shown once."""
    key = create_api_key()
    user.api_key_hash = hash_api_key(key)
    await record_audit(
        db,
        actor=user,
        action="account.api_key_create",
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()
    return ApiKeyResponse(
        api_key=key,
        note="Store this key now. It is not shown again. Send it as 'Authorization: Bearer <key>'.",
    )


@router.delete("/api-key", status_code=status.HTTP_204_NO_CONTENT)
async def api_key_revoke(
    user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> None:
    user.api_key_hash = None
    await record_audit(
        db,
        actor=user,
        action="account.api_key_revoke",
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()
