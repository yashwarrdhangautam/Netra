"""Rate limiting middleware using slowapi (limits).

Provides rate limiting for API endpoints to prevent abuse.
"""
from collections.abc import Callable

import structlog
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

logger = structlog.get_logger()


# Create limiter instance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/minute", "1000/hour"],
    storage_uri="memory://",
)


def setup_rate_limiting(app: FastAPI) -> None:
    """Setup rate limiting middleware for the FastAPI app.

    Args:
        app: FastAPI application instance
    """
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    logger.info("rate_limiting_enabled", default_limits="100/minute, 1000/hour")


# ── Rate Limit Decorators ─────────────────────────────────────────────────────


def rate_limit(limit: str):
    """Decorator for applying rate limits to specific endpoints.

    Args:
        limit: Rate limit string (e.g., "10/minute", "100/hour")

    Returns:
        Decorator function

    Example:
        @router.post("/scans")
        @rate_limit("5/minute")
        async def create_scan(...):
            pass
    """
    def decorator(func: Callable):
        return limiter.limit(limit)(func)
    return decorator


# ── Custom Rate Limit Exceeded Handler ────────────────────────────────────────


async def custom_rate_limit_handler(
    request: Request,
    exc: RateLimitExceeded,
) -> JSONResponse:
    """Custom handler for rate limit exceeded errors.

    Args:
        request: The incoming request
        exc: RateLimitExceeded exception

    Returns:
        JSON response with rate limit error details
    """
    logger.warning(
        "rate_limit_exceeded",
        path=request.url.path,
        method=request.method,
        client_ip=get_remote_address(request),
        limit=str(exc.detail),
    )

    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded",
            "error": "Too many requests. Please slow down.",
            "limit": str(exc.detail),
            "retry_after": _get_retry_after_seconds(exc.detail),
        },
    )


def _get_retry_after_seconds(limit_detail: str) -> int:
    """Extract retry-after seconds from limit detail string.

    Args:
        limit_detail: Rate limit detail (e.g., "10 per minute")

    Returns:
        Seconds to wait before retrying
    """
    # Simple parsing - in production, use proper parsing
    if "minute" in limit_detail.lower():
        return 60
    elif "hour" in limit_detail.lower():
        return 3600
    elif "second" in limit_detail.lower():
        return 1
    else:
        return 60  # Default to 1 minute


# ── Rate Limit Profiles ───────────────────────────────────────────────────────


class RateLimitProfiles:
    """Predefined rate limit profiles for different endpoint types."""

    # Authentication endpoints (strict limits)
    AUTH = "5/minute"
    LOGIN = "3/minute"
    REGISTER = "2/minute"
    PASSWORD_RESET = "2/hour"

    # Scan endpoints (moderate limits)
    SCAN_CREATE = "10/minute"
    SCAN_LIST = "30/minute"
    SCAN_DELETE = "5/minute"

    # Finding endpoints (higher limits for browsing)
    FINDING_LIST = "60/minute"
    FINDING_DETAIL = "120/minute"

    # Report endpoints (resource-intensive)
    REPORT_GENERATE = "5/minute"
    REPORT_DOWNLOAD = "20/minute"

    # General API
    GENERAL = "100/minute"
    HEALTH = "300/minute"  # Health checks need higher limits

    # Admin endpoints (strict)
    ADMIN = "20/minute"
    USER_MANAGEMENT = "10/minute"


# ── API Key Based Rate Limiting ──────────────────────────────────────────────


def get_rate_limit_key(request: Request) -> str:
    """Get rate limit key based on API key or IP address.

    API keys get higher limits than IP-based limiting.

    Args:
        request: The incoming request

    Returns:
        Rate limit key string
    """
    # Check for API key in headers
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"api_key:{api_key}"

    # Check for Bearer token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return f"token:{token[:32]}"  # Use first 32 chars of token

    # Fall back to IP address
    return get_remote_address(request)


# ── Dynamic Rate Limiting ─────────────────────────────────────────────────────


class DynamicRateLimiter:
    """Dynamic rate limiter that adjusts based on user role.

    Higher roles (admin, analyst) get higher rate limits.
    """

    ROLE_LIMITS = {
        "admin": "1000/minute",
        "analyst": "500/minute",
        "viewer": "100/minute",
        "client": "50/minute",
        "default": "100/minute",
    }

    @staticmethod
    def get_limit_for_role(role: str) -> str:
        """Get rate limit for a user role.

        Args:
            role: User role string

        Returns:
            Rate limit string
        """
        return DynamicRateLimiter.ROLE_LIMITS.get(
            role.lower(),
            DynamicRateLimiter.ROLE_LIMITS["default"],
        )

    @staticmethod
    def limiter_for_role(role: str) -> Callable:
        """Create a rate limiter decorator for a specific role.

        Args:
            role: User role string

        Returns:
            Rate limit decorator
        """
        limit = DynamicRateLimiter.get_limit_for_role(role)
        return rate_limit(limit)
