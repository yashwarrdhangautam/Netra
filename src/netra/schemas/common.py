"""Common Pydantic schemas for pagination and shared types."""
from datetime import datetime
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    per_page: int
    pages: int


class SeverityLevel(StrEnum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditMixin(BaseModel):
    """Mixin for audit fields."""

    created_at: datetime
    updated_at: datetime


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    db: str
