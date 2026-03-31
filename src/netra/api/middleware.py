"""FastAPI middleware configuration."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

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
