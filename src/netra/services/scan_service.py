"""Scan service for business logic."""
from sqlalchemy.ext.asyncio import AsyncSession


class ScanService:
    """Service for scan-related business logic."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize scan service.

        Args:
            db: Async database session
        """
        self.db = db

    # Phase 1: implement real service methods
