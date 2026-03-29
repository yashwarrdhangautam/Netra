"""Database engine factory for dual-mode SQLite/PostgreSQL support."""
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from netra.core.config import settings


def get_engine() -> AsyncEngine:
    """Create database engine based on configuration.

    SQLite for CLI/development, PostgreSQL for Docker/production.
    Determined by DATABASE_URL env var.

    Returns:
        An async SQLAlchemy engine instance
    """
    url = settings.database_url

    if url.startswith("sqlite"):
        # SQLite async requires aiosqlite
        connect_args = {"check_same_thread": False}
        engine = create_async_engine(
            url,
            connect_args=connect_args,
            echo=settings.db_echo,
        )
    else:
        # PostgreSQL async requires asyncpg
        engine = create_async_engine(
            url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
        )
    return engine
