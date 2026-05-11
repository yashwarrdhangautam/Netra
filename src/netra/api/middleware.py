"""FastAPI middleware configuration."""
from collections.abc import Callable
import uuid

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from netra.core.config import settings
from netra.core.exceptions import NetraException
from netra.core.logging import get_logger

logger = get_logger(__name__)

# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)


def add_rate_limiting(app: FastAPI) -> None:
    """Add rate limiting middleware to the application.

    Args:
        app: The FastAPI application instance
    """
    app.state.limiter = limiter
    app.add_exception_handler(429, _rate_limit_exceeded_handler)


def add_error_handlers(app: FastAPI) -> None:
    """Add global error handlers to the application.

    Args:
        app: The FastAPI application instance
    """

    @app.exception_handler(NetraException)
    async def netra_exception_handler(
        request: Request,
        exc: NetraException,
    ) -> JSONResponse:
        """Handle custom NETRA exceptions.

        Args:
            request: The HTTP request
            exc: The NETRA exception

        Returns:
            JSON response with error details
        """
        logger.error(
            "netra_exception",
            status_code=exc.status_code,
            message=exc.message,
            details=exc.details,
        )


def add_bugbounty_audit_middleware(app: FastAPI) -> None:
    """Guard and audit mutating NETRA-BB API requests.

    Development deployments stay usable without a login. In production, BB routes
    require Bearer auth; mutating calls require operator-capable roles and CSRF.
    """

    @app.middleware("http")
    async def bugbounty_audit_middleware(request: Request, call_next: Callable):
        is_bb = request.url.path.startswith("/api/v1/bb")
        is_mutating = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        if is_bb and settings.environment == "production":
            auth = request.headers.get("authorization", "")
            if not auth.lower().startswith("bearer "):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"error": {"code": "auth.unauthorized", "message": "Login required"}},
                )
            try:
                from netra.core.security import decode_access_token
                from netra.db.models.user import User, UserRole
                from netra.db.session import async_session_factory
                from sqlalchemy import select

                token = auth.split(None, 1)[1]
                payload = decode_access_token(token)
                if not payload:
                    raise ValueError("invalid token")
                async with async_session_factory() as session:
                    user = (
                        await session.execute(select(User).where(User.id == uuid.UUID(payload["sub"])))
                    ).scalar_one_or_none()
                    if not user or not user.is_active:
                        raise ValueError("inactive user")
                    if is_mutating and user.role not in {UserRole.ADMIN, UserRole.ANALYST}:
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={"error": {"code": "auth.forbidden", "message": "Operator role required"}},
                        )
            except Exception:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"error": {"code": "auth.unauthorized", "message": "Invalid token"}},
                )
            if is_mutating:
                csrf_cookie = request.cookies.get("netra_csrf")
                csrf_header = request.headers.get("x-csrf-token")
                if not csrf_header or (csrf_cookie and csrf_header != csrf_cookie):
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"error": {"code": "auth.csrf", "message": "CSRF token required"}},
                    )

        response = await call_next(request)
        if is_bb and is_mutating:
            try:
                from netra.db.models.audit_ui_action import AuditUIAction
                from netra.db.session import async_session_factory

                parts = [p for p in request.url.path.split("/") if p]
                target_type = parts[3] if len(parts) > 3 else None
                target_id = parts[4] if len(parts) > 4 else None
                trace_id = request.headers.get("x-trace-id") or uuid.uuid4().hex
                async with async_session_factory() as session:
                    session.add(
                        AuditUIAction(
                            action=f"{request.method} {request.url.path}",
                            target_type=target_type,
                            target_id=target_id,
                            result_code=response.status_code,
                            trace_id=trace_id,
                            ip=request.client.host if request.client else None,
                            user_agent=request.headers.get("user-agent"),
                            metadata_={"query": str(request.url.query or "")},
                        )
                    )
                    await session.commit()
                response.headers["x-trace-id"] = trace_id
            except Exception as exc:
                logger.warning("bb_audit_write_failed", error=str(exc))
        return response
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": exc.__class__.__name__,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Handle uncaught exceptions.

        Args:
            request: The HTTP request
            exc: The uncaught exception

        Returns:
            JSON response with error details
        """
        logger.exception("uncaught_exception", error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "type": "InternalServerError",
                    "message": "An unexpected error occurred",
                }
            },
        )
