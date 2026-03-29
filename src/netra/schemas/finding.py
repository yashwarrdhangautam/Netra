"""Pydantic schemas for finding operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from netra.db.models.finding import FindingStatus, Severity


class FindingCreate(BaseModel):
    """Schema for creating a new finding."""

    scan_id: uuid.UUID
    title: str = Field(min_length=1, max_length=500)
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.NEW
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    cve_ids: list[str] | None = None
    url: str | None = None
    parameter: str | None = None
    evidence: dict | None = None
    tool_source: str
    confidence: int = Field(50, ge=0, le=100)
    remediation: str | None = None
    tags: list[str] | None = None


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""

    status: FindingStatus | None = None
    severity: Severity | None = None
    assignee: str | None = None
    notes: str | None = None
    remediation: str | None = None
    tags: list[str] | None = None


class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    cvss_score: float | None
    cvss_vector: str | None
    cwe_id: str | None
    cve_ids: list[str] | None
    url: str | None
    parameter: str | None
    evidence: dict | None
    tool_source: str
    confidence: int
    remediation: str | None
    ai_analysis: dict | None
    tags: list[str] | None
    assignee: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    """Schema for finding list items."""

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: Severity
    status: FindingStatus
    tool_source: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingBulkUpdate(BaseModel):
    """Schema for bulk updating findings."""

    finding_ids: list[uuid.UUID]
    status: FindingStatus | None = None
    severity: Severity | None = None
    assignee: str | None = None
    tags: list[str] | None = None
