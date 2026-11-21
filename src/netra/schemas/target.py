"""Pydantic schemas for target operations."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from netra.db.models.target import TargetType


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """Schema for creating a new target."""

    name: str = Field(min_length=1, max_length=255)
    target_type: TargetType
    value: str
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None


class TargetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """Schema for updating a target."""

    name: str | None = Field(None, min_length=1, max_length=255)
    value: str | None = None
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None
    # Assign to a client user, or send null to unassign. Analysts and admins only.
    client_id: uuid.UUID | None = None


class TargetResponse(BaseModel):
    """Schema for target response."""

    id: uuid.UUID
    name: str
    target_type: TargetType
    value: str
    scope_includes: list[str] | None
    scope_excludes: list[str] | None
    metadata_: dict | None
    client_id: uuid.UUID | None = None
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
