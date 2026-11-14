"""FastAPI dependency injection utilities."""

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.user import User
from netra.db.session import get_db


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session from dependency.

    Yields:
        Async SQLAlchemy session
    """
    async for session in get_db():
        yield session


_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """Authenticate a request. One implementation for every route.

    Delegates to the auth module, which also accepts personal API keys (ntr_...) and rejects
    tokens revoked by logout. Keeping a second copy here let revoked tokens work on scan and
    finding routes.
    """
    # Imported here: the auth routes import the API package, which imports this module.
    from netra.api.routes.auth import get_current_user as verify

    return await verify(credentials=credentials, db=db)


async def get_admin_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Get current user and verify admin role.

    Args:
        current_user: The authenticated user

    Returns:
        The admin user

    Raises:
        HTTPException: If user is not an admin
    """
    from netra.db.models.user import UserRole

    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# Type aliases for common dependencies
DBSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(get_admin_user)]
