"""CSRF Protection Middleware for FastAPI.

Implements Double Submit Cookie pattern for CSRF protection.
"""
import hmac
import secrets
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from netra.core.config import settings


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF Protection Middleware.

    Implements the Double Submit Cookie pattern:
    1. Server sets a CSRF token in a cookie (httponly=False, so JS can read it)
    2. Client must send the token in a custom header (X-CSRF-Token)
    3. Server validates that cookie token matches header token

    Safe methods (GET, HEAD, OPTIONS) are exempt from CSRF checks.
    """

    CSRF_COOKIE_NAME = "csrf_token"
    CSRF_HEADER_NAME = "x-csrf-token"

    def __init__(self, app: FastAPI):
        """Initialize CSRF middleware.

        Args:
            app: FastAPI application instance
        """
        super().__init__(app)
        self.secret_key = settings.csrf_secret_key.encode()

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        """Process request and add CSRF protection.

        Args:
            request: The incoming request
            call_next: Next middleware/handler in chain

        Returns:
            Response with CSRF cookie set
        """
        # Generate CSRF token if not present
        csrf_token = request.cookies.get(self.CSRF_COOKIE_NAME)
        if not csrf_token:
            csrf_token = self._generate_token()

        # Check if request requires CSRF validation
        if request.method not in ["GET", "HEAD", "OPTIONS"]:
            # Validate CSRF token
            header_token = request.headers.get(self.CSRF_HEADER_NAME)

            if not header_token or not self._validate_tokens(csrf_token, header_token):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "CSRF token missing or invalid"},
                )

        # Process request
        response = await call_next(request)

        # Set CSRF token in cookie (httponly=False so JS can read it)
        response.set_cookie(
            key=self.CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=False,  # Must be readable by JavaScript
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
            max_age=3600 * 24 * 30,  # 30 days
        )

        return response

    def _generate_token(self) -> str:
        """Generate a new CSRF token.

        Returns:
            Random CSRF token string
        """
        return secrets.token_urlsafe(32)

    def _validate_tokens(self, cookie_token: str, header_token: str) -> bool:
        """Validate that cookie and header tokens match.

        Args:
            cookie_token: Token from cookie
            header_token: Token from request header

        Returns:
            True if tokens match, False otherwise
        """
        if not cookie_token or not header_token:
            return False

        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(cookie_token, header_token)


def setup_csrf_protection(app: FastAPI) -> None:
    """Add CSRF protection middleware to FastAPI app.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(CSRFMiddleware)
