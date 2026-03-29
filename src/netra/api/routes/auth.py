"""Authentication routes for user management."""
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_current_user, get_db_session
from netra.core.security import (
    create_access_token,
    get_password_hash,
    verify_password,
)
from netra.db.models.user import User, UserRole
from netra.schemas.auth import (
    ChangePassword,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: UserLogin,
    db: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """Authenticate user and return JWT token.

    Args:
        payload: Login credentials
        db: Database session

    Returns:
        Access token
    """
    from sqlalchemy.future import select

    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        from netra.core.exceptions import AuthenticationError
        raise AuthenticationError("Invalid email or password")

    if not user.is_active:
        from netra.core.exceptions import AuthorizationError
        raise AuthorizationError("Account is disabled")

    token = create_access_token(subject=user.id)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=3600,
    )


@router.post("/register", response_model=UserResponse)
async def register(
    payload: UserRegister,
    db: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Register a new user.

    Args:
        payload: Registration data
        db: Database session

    Returns:
        Created user details
    """
    from sqlalchemy.future import select

    # Check if user already exists
    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    existing = result.scalar_one_or_none()

    if existing:
        from netra.core.exceptions import ConflictError
        raise ConflictError("User with this email already exists")

    # Create new user
    user = User(
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        full_name=payload.full_name,
        role=UserRole.USER,
    )

    db.add(user)
    await db.flush()
    await db.refresh(user)

    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Get current authenticated user information.

    Args:
        current_user: Authenticated user from dependency

    Returns:
        User details
    """
    return UserResponse.model_validate(current_user)


@router.post("/change-password")
async def change_password(
    payload: ChangePassword,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Change current user's password.

    Args:
        payload: Password change data
        current_user: Authenticated user
        db: Database session

    Returns:
        Success message
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        from netra.core.exceptions import ValidationError
        raise ValidationError("Current password is incorrect")

    current_user.hashed_password = get_password_hash(payload.new_password)
    await db.merge(current_user)

    return {"message": "Password changed successfully"}
