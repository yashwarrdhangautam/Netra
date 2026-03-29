"""Pydantic schemas for target operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from netra.db.models.target import TargetType


class TargetCreate(BaseModel):
    """Schema for creating a new target."""

    name: str = Field(min_length=1, max_length=255)
    target_type: TargetType
    value: str
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None
    metadata_: dict | None = Field(None, alias="metadata")


class TargetUpdate(BaseModel):
    """Schema for updating a target."""

    name: str | None = Field(None, min_length=1, max_length=255)
    value: str | None = None
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None
    metadata_: dict | None = Field(None, alias="metadata")


class TargetResponse(BaseModel):
    """Schema for target response."""

    id: uuid.UUID
    name: str
    target_type: TargetType
    value: str
    scope_includes: list[str] | None
    scope_excludes: list[str] | None
    metadata_: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    """Schema for target list items."""

    id: uuid.UUID
    name: str
    target_type: TargetType
    value: str
    created_at: datetime

    model_config = {"from_attributes": True}
