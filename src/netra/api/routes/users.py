"""Admin user management: list, create, change role or status, reset password, deactivate."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.api.rbac import require_admin
from netra.core.passwords import validate_password
from netra.core.security import get_password_hash
from netra.db.models.user import User, UserRole
from netra.services.audit import record_audit

router = APIRouter(prefix="/auth/users", tags=["Users"])


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login_at: str | None


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=255)


class PasswordReset(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


def _out(user: User) -> UserOut:
    return UserOut(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=str(user.role),
        is_active=bool(user.is_active),
        is_verified=bool(user.is_verified),
        mfa_enabled=bool(user.mfa_enabled),
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )


async def _get_user(db: AsyncSession, user_id: str) -> User:
    try:
        parsed = uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc
    result = await db.execute(select(User).where(User.id == parsed))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=list[UserOut])
async def list_users(
    _admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> list[UserOut]:
    result = await db.execute(select(User).order_by(User.email))
    return [_out(u) for u in result.scalars().all()]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    _admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> UserOut:
    problem = validate_password(body.password)
    if problem:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=problem)
    email = body.email.lower()
    existing = await db.execute(select(User.id).where(User.email == email))
    if existing.first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
    user = User(
        email=email,
        full_name=body.full_name,
        hashed_password=get_password_hash(body.password),
        role=body.role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await record_audit(
        db,
        actor=_admin,
        action="user.create",
        resource_type="user",
        resource_id=email,
        detail={"role": str(body.role)},
    )
    await db.commit()
    await db.refresh(user)
    return _out(user)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    body: UserUpdate,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> UserOut:
    user = await _get_user(db, user_id)
    is_self = str(user.id) == str(admin.id)
    if body.role is not None:
        if is_self and body.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="You cannot demote yourself"
            )
        user.role = body.role
    if body.is_active is not None:
        if is_self and not body.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="You cannot deactivate yourself"
            )
        user.is_active = body.is_active
    if body.full_name is not None:
        user.full_name = body.full_name
    await record_audit(
        db,
        actor=admin,
        action="user.update",
        resource_type="user",
        resource_id=str(user.id),
        detail=body.model_dump(exclude_none=True, mode="json"),
    )
    await db.commit()
    await db.refresh(user)
    return _out(user)


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: str,
    body: PasswordReset,
    _admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> None:
    problem = validate_password(body.password)
    if problem:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=problem)
    user = await _get_user(db, user_id)
    user.hashed_password = get_password_hash(body.password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await record_audit(
        db,
        actor=_admin,
        action="user.password_reset",
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> None:
    """Deactivate a user. Their scans and targets are kept for the audit trail."""
    user = await _get_user(db, user_id)
    if str(user.id) == str(admin.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="You cannot delete yourself"
        )
    user.is_active = False
    await record_audit(
        db,
        actor=admin,
        action="user.deactivate",
        resource_type="user",
        resource_id=str(user.id),
        detail={"email": user.email},
    )
    await db.commit()
