"""Pydantic schemas for scan operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from netra.db.models.scan import ScanProfile, ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""

    target_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    profile: ScanProfile = ScanProfile.STANDARD
    config: dict | None = None


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    status: ScanStatus | None = None
    name: str | None = Field(None, min_length=1, max_length=255)


class ScanResponse(BaseModel):
    """Schema for scan response."""

    id: uuid.UUID
    name: str
    status: ScanStatus
    profile: ScanProfile
    target_id: uuid.UUID
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Schema for scan list items."""

    id: uuid.UUID
    name: str
    status: ScanStatus
    profile: ScanProfile
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanPhaseResponse(BaseModel):
    """Schema for scan phase response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    phase_type: str
    status: str
    progress: float
    findings_count: int
    started_at: datetime | None
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanDiffRequest(BaseModel):
    """Schema for scan comparison request."""

    scan_a_id: uuid.UUID
    scan_b_id: uuid.UUID


class ScanDiffResponse(BaseModel):
    """Schema for scan comparison response."""

    scan_a_id: uuid.UUID
    scan_b_id: uuid.UUID
    new_findings: int
    resolved_findings: int
    changed_findings: int
    unchanged_findings: int
    diff_data: dict
