"""Pydantic schemas for scan operations."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from netra.db.models.scan import ScanProfile, ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""

    target_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    profile: ScanProfile = ScanProfile.STANDARD
    config: dict | None = None

    @model_validator(mode="after")
    def validate_profile_config(self) -> "ScanCreate":
        from netra.schemas.scan_config import validate_scan_config

        self.config = validate_scan_config(str(self.profile), self.config)
        return self


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    status: ScanStatus | None = None
    name: str | None = Field(None, min_length=1, max_length=255)


# "pending": the scan is still running and the tool has not reached its turn yet.
ToolRunState = Literal["completed", "skipped", "unavailable", "failed", "parse_error", "pending"]


class ToolCoverage(BaseModel):
    phase: str
    tool: str
    state: ToolRunState
    required: bool
    reason_code: str | None = None
    findings_count: int | None = None


class ScanCoverage(BaseModel):
    outcome: Literal["complete", "incomplete"] = "incomplete"
    coverage_reason: str | None = "coverage_unknown"
    coverage: list[ToolCoverage] = Field(default_factory=list)


class ScanResponse(ScanCoverage):
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


class ScanListResponse(ScanCoverage):
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
    # Why a phase failed or was skipped, or its warnings (e.g. active_test_not_authorized).
    error_message: str | None = None

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
