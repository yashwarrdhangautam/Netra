"""FastAPI application factory with rate limiting and SSRF protection."""
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netra.api.middleware import add_bugbounty_audit_middleware, add_error_handlers
from netra.api.routes import (
    agent,
    auth,
    bugbounty,
    compliance,
    findings,
    health,
    reports,
    scans,
    targets,
    websocket,
    schedules,
)
from netra.core.config import settings
from netra.core.logging import setup_logging
from netra.core.rate_limiter import setup_rate_limiting, limiter


async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown.

    Args:
        app: FastAPI application instance
    """
    # Startup
    setup_logging(
        log_format=settings.log_format,
        log_level=settings.log_level,
    )
    
    yield
    # Shutdown
    # Cleanup resources if needed


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI-augmented unified cybersecurity platform with SSRF protection and rate limiting",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Middleware
    setup_rate_limiting(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Error handlers
    add_error_handlers(app)
    add_bugbounty_audit_middleware(app)

    # Routes
    app.include_router(health, tags=["Health"])
    app.include_router(health, prefix="/api/v1", tags=["Health"])
    app.include_router(auth, prefix="/api/v1", tags=["Auth"])
    app.include_router(bugbounty, prefix="/api/v1/bb", tags=["Bug Bounty"])
    app.include_router(scans, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(findings, prefix="/api/v1/findings", tags=["Findings"])
    app.include_router(targets, prefix="/api/v1", tags=["Targets"])
    app.include_router(reports, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(compliance, prefix="/api/v1/compliance", tags=["Compliance"])
    app.include_router(agent, prefix="/api/v1/agent", tags=["Agent"])
    app.include_router(schedules, prefix="/api/v1/schedules", tags=["Schedules"])
    app.include_router(websocket, tags=["WebSocket"])

    return app
