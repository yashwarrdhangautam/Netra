"""FastAPI application factory."""
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netra.api.middleware import add_error_handlers, add_rate_limiting
from netra.api.routes import (
    agent,
    auth,
    compliance,
    findings,
    health,
    reports,
    scans,
    targets,
    websocket,
)
from netra.core.config import settings
from netra.core.logging import setup_logging


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


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI-augmented unified cybersecurity platform",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    add_rate_limiting(app)
    add_error_handlers(app)

    # Routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
    app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(
        compliance.router, prefix="/api/v1/compliance", tags=["Compliance"]
    )
    app.include_router(agent.router, tags=["Agent"])
    app.include_router(websocket.router)

    return app
