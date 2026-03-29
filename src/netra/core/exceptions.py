"""Custom exception hierarchy for NETRA."""
from typing import Any


class NetraException(Exception):
    """Base exception for all NETRA exceptions."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: dict | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(NetraException):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, status_code=401, details=details)


class AuthorizationError(NetraException):
    """Raised when authorization fails."""

    def __init__(
        self,
        message: str = "Not authorized",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, status_code=403, details=details)


class NotFoundError(NetraException):
    """Raised when a resource is not found."""

    def __init__(
        self,
        resource: str,
        identifier: Any,
        details: dict | None = None,
    ) -> None:
        message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(message, status_code=404, details=details)


class ValidationError(NetraException):
    """Raised when validation fails."""

    def __init__(
        self,
        message: str,
        field: str | None = None,
        details: dict | None = None,
    ) -> None:
        if field:
            details = details or {}
            details["field"] = field
        super().__init__(message, status_code=422, details=details)


class ConflictError(NetraException):
    """Raised when a resource conflict occurs."""

    def __init__(
        self,
        message: str = "Resource conflict",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, status_code=409, details=details)


class ScanError(NetraException):
    """Raised when a scan operation fails."""

    def __init__(
        self,
        message: str,
        scan_id: str | None = None,
        details: dict | None = None,
    ) -> None:
        if scan_id:
            details = details or {}
            details["scan_id"] = scan_id
        super().__init__(message, status_code=500, details=details)


class ToolError(NetraException):
    """Raised when a security tool fails."""

    def __init__(
        self,
        tool_name: str,
        message: str,
        details: dict | None = None,
    ) -> None:
        details = details or {}
        details["tool"] = tool_name
        super().__init__(message, status_code=500, details=details)


class ConfigurationError(NetraException):
    """Raised when configuration is invalid."""

    def __init__(
        self,
        message: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, status_code=500, details=details)
