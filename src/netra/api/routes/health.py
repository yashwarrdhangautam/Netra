"""Health check route."""
from fastapi import APIRouter, Depends
from sqlalchemy import text
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
        Health status with version, database, and AI provider connection status
    """
    import httpx

    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    # Check AI provider connectivity
    ai_status = "unknown"
    ai_provider = settings.ai_provider

    if ai_provider == "none":
        ai_status = "disabled"
    elif ai_provider == "anthropic":
        # Check Anthropic API key is set
        if settings.anthropic_api_key:
            ai_status = "configured"
        else:
            ai_status = "missing_key"
    elif ai_provider == "ollama":
        # Check Ollama server is reachable
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.ollama_base_url}/api/tags")
                if response.status_code == 200:
                    ai_status = "connected"
                else:
                    ai_status = "unreachable"
        except Exception:
            ai_status = "unreachable"

    return HealthResponse(
        status="ok",
        version=settings.app_version,
        db=db_status,
        ai_provider=ai_provider,
        ai_status=ai_status,
    )
