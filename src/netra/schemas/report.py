"""Pydantic schemas for report operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel

from netra.db.models.report import ReportStatus, ReportType


class ReportCreate(BaseModel):
    """Schema for creating a new report."""

    scan_id: uuid.UUID
    report_type: ReportType
    config: dict | None = None


class ReportResponse(BaseModel):
    """Schema for report response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: ReportType
    status: ReportStatus
    file_path: str | None
    file_size: int | None
    config: dict | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    """Schema for report list items."""

    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: ReportType
    status: ReportStatus
    file_path: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportGenerateRequest(BaseModel):
    """Schema for report generation request."""

    scan_id: uuid.UUID
    report_type: ReportType
    config: dict | None = None


class ReportDownloadResponse(BaseModel):
    """Schema for report download response."""

    file_name: str
    content_type: str
    file_size: int
