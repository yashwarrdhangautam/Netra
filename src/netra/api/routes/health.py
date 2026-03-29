"""Health check route."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.core.config import settings
from netra.schemas.common import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> HealthResponse:
    """Check API health status.

    Returns:
        Health status with version and database connection status
    """
    db_status = "connected"
    try:
        await db.execute("SELECT 1")
    except Exception:
        db_status = "disconnected"

    return HealthResponse(
        status="ok",
        version=settings.app_version,
        db=db_status,
    )
