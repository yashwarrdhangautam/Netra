"""Pydantic schemas for compliance operations."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ComplianceMapRequest(BaseModel):
    """Schema for requesting compliance mapping."""

    scan_id: uuid.UUID
    frameworks: list[str] | None = None


class ComplianceMappingCreate(BaseModel):
    """Schema for creating a compliance mapping."""

    finding_id: uuid.UUID | None = None
    framework: str
    control_id: str
    control_name: str
    control_description: str | None = None


class ComplianceMappingResponse(BaseModel):
    """Schema for compliance mapping response."""

    id: uuid.UUID
    finding_id: uuid.UUID | None
    framework: str
    control_id: str
    control_name: str
    control_description: str | None
    status: str
    is_mapped: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ComplianceScoreResponse(BaseModel):
    """Schema for compliance score response."""

    scan_id: uuid.UUID
    framework: str
    score: float = Field(..., description="Compliance score 0-100")
    total_controls: int
    passed: int
    failed: int
    failed_controls: list[dict]


class ComplianceFrameworkResponse(BaseModel):
    """Schema for compliance framework response."""

    scan_id: uuid.UUID
    framework: str
    score: float = Field(..., description="Compliance score 0-100")
    total_controls: int
    passed: int
    failed: int
    status: str  # "pass" or "fail"


class ComplianceGapAnalysisResponse(BaseModel):
    """Schema for compliance gap analysis response."""

    scan_id: uuid.UUID
    framework: str
    total_gaps: int
    gaps_by_severity: dict[str, int]
    gaps: list[dict]


class ComplianceFrameworkListResponse(BaseModel):
    """Schema for listing available compliance frameworks."""

    frameworks: list[dict] = Field(
        default=[
            {"id": "iso27001", "name": "ISO 27001", "description": "Information Security Management"},
            {"id": "pci_dss", "name": "PCI DSS", "description": "Payment Card Industry Data Security Standard"},
            {"id": "soc2", "name": "SOC 2", "description": "Service Organization Control 2"},
            {"id": "hipaa", "name": "HIPAA", "description": "Health Insurance Portability and Accountability Act"},
            {"id": "nist_csf", "name": "NIST CSF", "description": "NIST Cybersecurity Framework"},
            {"id": "cis_controls", "name": "CIS Controls", "description": "Center for Internet Security Controls"},
        ]
    )
