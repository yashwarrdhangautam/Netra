"""FastAPI application factory with rate limiting and SSRF protection."""
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netra.api.middleware import add_error_handlers
from netra.api.routes import (
    agent,
    auth,
    compliance,
    findings,
    health,
    reports,
    scans,
    schedules,
    targets,
    websocket,
)
from netra.api.routes import (
    settings as settings_router,
)
from netra.core.config import settings
from netra.core.csrf import setup_csrf_protection
from netra.core.logging import setup_logging
from netra.core.rate_limiter import setup_rate_limiting
from netra.core.security_headers import setup_security_headers


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

    # Setup rate limiting
    setup_rate_limiting(app)

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
        description="AI-augmented unified cybersecurity platform with SSRF "
                    "protection and rate limiting",
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
        expose_headers=["X-CSRF-Token"],  # Expose CSRF token header to frontend
    )

    # CSRF Protection (after CORS)
    setup_csrf_protection(app)

    # Security Headers (CSP, X-Frame-Options, etc.)
    setup_security_headers(app)

    # Error handlers
    add_error_handlers(app)

    # Routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
    app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
    app.include_router(agent.router, prefix="/api/v1/agent", tags=["Agent"])
    app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"])
    app.include_router(settings_router.router, prefix="/api/v1/settings", tags=["Settings"])
    app.include_router(websocket.router, tags=["WebSocket"])

    return app
