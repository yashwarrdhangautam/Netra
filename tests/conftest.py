"""Shared test fixtures."""

import asyncio
import sys
import uuid
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from netra.api.app import create_app
from netra.api.deps import get_db_session
from netra.api.routes.auth import get_current_active_user
from netra.db.models import Base
from netra.db.models.user import User, UserRole

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use the selector policy on Windows to avoid Proactor teardown crashes in tests."""
    if sys.platform.startswith("win") and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        return asyncio.WindowsSelectorEventLoopPolicy()
    return asyncio.get_event_loop_policy()


@pytest.fixture
async def db_engine():
    """Create a test database engine."""
    engine = create_async_engine(TEST_DB_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def async_db_session(db_session: AsyncSession) -> AsyncSession:
    """Backward-compatible alias for older phase tests."""
    return db_session


def _test_admin() -> User:
    """Signed-in admin used by the authenticated test client (not persisted)."""
    return User(
        id=uuid.UUID("00000000-0000-0000-0000-00000000a0a0"),
        email="test-admin@example.com",
        hashed_password="not-used",  # noqa: S106 - never used for login in tests
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )


@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated test HTTP client (every data route needs a signed-in user)."""
    app = create_app()

    async def override_db():
        yield db_session

    async def override_user():
        return _test_admin()

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_current_active_user] = override_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def anon_client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated test client, used to prove protected routes reject anonymous calls."""
    app = create_app()

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
