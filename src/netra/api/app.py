"""FastAPI application factory with rate limiting and SSRF protection."""

from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netra.api.middleware import add_bugbounty_audit_middleware, add_error_handlers
from netra.api.rbac import require_access
from netra.api.routes import (
    account,
    agent,
    audit,
    auth,
    bugbounty,
    compliance,
    findings,
    health,
    intel,
    reports,
    scanner_tools,
    scans,
    schedules,
    search,
    targets,
    users,
    websocket,
)
from netra.api.routes import (
    settings as settings_routes,
)
from netra.core.config import settings
from netra.core.logging import setup_logging
from netra.core.rate_limiter import setup_rate_limiting


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
    app.include_router(account.router, prefix="/api/v1", tags=["Account"])
    app.include_router(users.router, prefix="/api/v1", tags=["Users"])
    # Every data route requires a signed-in user; writes need analyst or admin.
    # Health, login and register stay public. The WebSocket routes check their own token.
    authed = [Depends(require_access)]

    # Feature switches the GUI reads. Public: it holds no data.
    @app.get("/api/v1/features", tags=["Health"])
    async def features() -> dict[str, bool]:
        return {"bugbounty": settings.bb_enabled}

    if settings.bb_enabled:
        app.include_router(bugbounty, prefix="/api/v1/bb", tags=["Bug Bounty"], dependencies=authed)
    app.include_router(scans, prefix="/api/v1/scans", tags=["Scans"], dependencies=authed)
    app.include_router(findings, prefix="/api/v1/findings", tags=["Findings"], dependencies=authed)
    app.include_router(targets, prefix="/api/v1", tags=["Targets"], dependencies=authed)
    app.include_router(reports, prefix="/api/v1/reports", tags=["Reports"], dependencies=authed)
    app.include_router(
        compliance, prefix="/api/v1/compliance", tags=["Compliance"], dependencies=authed
    )
    app.include_router(agent, prefix="/api/v1/agent", tags=["Agent"], dependencies=authed)
    app.include_router(
        schedules, prefix="/api/v1/schedules", tags=["Schedules"], dependencies=authed
    )
    app.include_router(search.router, prefix="/api/v1", tags=["Search"], dependencies=authed)
    app.include_router(
        settings_routes.router, prefix="/api/v1", tags=["Settings"], dependencies=authed
    )
    app.include_router(audit.router, prefix="/api/v1", tags=["Audit"], dependencies=authed)
    app.include_router(scanner_tools.router, prefix="/api/v1", dependencies=authed)
    app.include_router(intel.router, prefix="/api/v1", dependencies=authed)
    app.include_router(websocket, tags=["WebSocket"])

    return app
