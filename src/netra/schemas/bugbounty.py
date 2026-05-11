"""Pydantic schemas for NETRA-BB API routes."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from netra.db.models.bb_program import BBPlatform
from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType


class BBCounters(BaseModel):
    """Counts displayed beside a bug bounty program."""

    scope_rules: int = 0
    assets: int = 0
    findings_open: int = 0
    submissions_draft: int = 0


class BBProgramCreate(BaseModel):
    """Create a bug bounty program."""

    platform: BBPlatform = BBPlatform.PRIVATE
    handle: str = Field(min_length=1, max_length=120)
    name: str | None = Field(default=None, max_length=255)
    policy_url: str | None = None
    payout_min: int | None = Field(default=None, ge=0)
    payout_max: int | None = Field(default=None, ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    auto_sync_scope: bool = True


class BBProgramResponse(BaseModel):
    """Bug bounty program response."""

    id: uuid.UUID
    platform: str
    handle: str
    name: str
    policy_url: str | None
    payout_min: int | None
    payout_max: int | None
    currency: str
    scope_synced_at: datetime | None
    active: bool
    created_at: datetime
    updated_at: datetime
    counts: BBCounters = Field(default_factory=BBCounters)


class BBScopeRuleCreate(BaseModel):
    """Create a manual scope rule."""

    program_id: uuid.UUID
    rule_type: ScopeRuleType
    asset_type: ScopeAssetType
    pattern: str = Field(min_length=1, max_length=512)
    severity_cap: str | None = None
    notes: str | None = None


class BBScopeRuleResponse(BaseModel):
    """Scope rule response."""

    id: uuid.UUID
    program_id: uuid.UUID
    rule_type: str
    asset_type: str
    pattern: str
    severity_cap: str | None
    notes: str | None
    active: bool
    synced_from_platform: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScopeCheckRequest(BaseModel):
    """Request a scope decision."""

    program_id: uuid.UUID
    target: str = Field(min_length=1, max_length=2048)


class ScopeDiffResponse(BaseModel):
    """Scope sync diff returned to the UI."""

    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    unchanged_count: int
    has_changes: bool
    warning: str | None = None


class HuntCreate(BaseModel):
    """Create a bug bounty hunt scan."""

    program_id: uuid.UUID
    profile: Literal["passive", "active"] = "passive"
    options: dict[str, Any] = Field(default_factory=dict)


class PlanPreviewRequest(BaseModel):
    """Preview an agentic hunt plan for a program/asset."""

    program_id: uuid.UUID
    asset: str | None = None


class PlanPreviewResponse(BaseModel):
    """Planner preview response."""

    rationale: str
    coordination: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(default_factory=list)


class HuntResponse(BaseModel):
    """Bug bounty hunt response."""

    id: uuid.UUID
    name: str
    status: str
    profile: str
    program_id: uuid.UUID | None
    target_id: uuid.UUID
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    mode: Literal["fixed", "agentic"] = "fixed"
    dry_run: bool = False
    phases: list[dict[str, Any]] = Field(default_factory=list)
    assets_discovered: int = 0
    blocked_count: int = 0
    findings_count: int = 0


class HuntExplainStepResponse(BaseModel):
    """Single persisted agentic step row."""

    step_n: int
    status: str
    tool_chosen: str | None = None
    decision_rationale: str | None = None
    observations_in: dict[str, Any] = Field(default_factory=dict)
    observations_out: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class HuntExplainResponse(BaseModel):
    """Persisted hunt explanation with coordination context."""

    scan_id: uuid.UUID
    summary: str | None = None
    focus_areas: list[str] = Field(default_factory=list)
    recommended_tools: list[str] = Field(default_factory=list)
    corpus_hits: list[str] = Field(default_factory=list)
    retrieval_hits: list[dict[str, Any]] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    report_focus: list[str] = Field(default_factory=list)
    steps: list[HuntExplainStepResponse] = Field(default_factory=list)


class DoctorCheckResponse(BaseModel):
    """Single doctor check result."""

    name: str
    status: Literal["ok", "warn", "error"]
    detail: str


class DashboardResponse(BaseModel):
    """Single aggregate for the BB dashboard."""

    active_programs: int
    scope_rules: int
    assets: int
    open_findings: int
    submissions_draft: int
    out_of_scope_blocks_24h: int
    recent_hunts: list[HuntResponse]
    doctor: list[DoctorCheckResponse]


class TrendBucketResponse(BaseModel):
    """Single aggregated trend bucket."""

    name: str
    count: int


class TrendSummaryResponse(BaseModel):
    """Learning-corpus trend summary for operator prioritization."""

    window_days: int
    total_reports: int
    total_writeups: int
    total_advisories: int
    top_vuln_classes: list[TrendBucketResponse] = Field(default_factory=list)
    top_tech: list[TrendBucketResponse] = Field(default_factory=list)
    top_programs: list[TrendBucketResponse] = Field(default_factory=list)


class FindingCorpusContextResponse(BaseModel):
    """Comparable public prior art for an operator reviewing a finding."""

    finding_id: uuid.UUID
    similar_reports: list[str] = Field(default_factory=list)


class TriageRowResponse(BaseModel):
    """Finding row shaped for the triage queue."""

    id: uuid.UUID
    title: str
    asset: str | None
    vuln_class: str
    severity: str
    status: str
    cvss: float | None
    bounty_hunter: dict[str, Any]
    skeptic_vetoed: bool
    dedup: dict[str, Any]
    created_at: datetime


class SubmissionResponse(BaseModel):
    """Submission row response."""

    id: uuid.UUID
    finding_id: uuid.UUID
    program_id: uuid.UUID
    title: str
    status: str
    severity: str
    payout_expected: int | None
    payout_actual: int | None
    currency: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SubmissionDetailResponse(SubmissionResponse):
    """Submission detail with markdown body."""

    draft_md: str | None
    cvss_vector: str | None
    platform_report_id: str | None
    submitted_at: datetime | None
    verdict_at: datetime | None
    verdict_notes: str | None
    metadata_: dict | None


class SubmissionCreateRequest(BaseModel):
    """Create a draft submission from a finding."""

    finding_id: uuid.UUID
    force: bool = False
    include_poc: bool = False
    formats: list[str] = Field(default_factory=lambda: ["md", "docx"])


class SubmissionUpdateRequest(BaseModel):
    """Update editable submission fields."""

    title: str | None = Field(default=None, max_length=512)
    draft_md: str | None = None
    platform_report_id: str | None = Field(default=None, max_length=64)
    verdict_notes: str | None = None


class SubmissionTransitionRequest(BaseModel):
    """Submission state transition request."""

    to_status: str
    notes: str | None = None


class SubmissionRenderRequest(BaseModel):
    """Render a submission artifact."""

    format: Literal["md", "docx", "pdf"] = "md"


class SubmissionRenderResponse(BaseModel):
    """Rendered artifact result."""

    format: str
    path: str
    download_url: str | None = None


class SubmissionVerdictRequest(BaseModel):
    """Verdict ingestion request."""

    verdict: Literal["paid", "dup", "na", "info"]
    payout_actual: int | None = Field(default=None, ge=0)
    notes: str | None = None


class EvidenceResponse(BaseModel):
    """Evidence item response."""

    id: uuid.UUID
    finding_id: uuid.UUID
    program_id: uuid.UUID
    filename: str
    mime_type: str
    sha256: str
    size_bytes: int
    redaction_count: int
    encrypted: bool
    metadata_: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ReplayRequest(BaseModel):
    """Replay/verify request."""

    verifier_id: str = Field(min_length=1, max_length=120)
    typed_confirm: str | None = None


class ReplayResponse(BaseModel):
    """Replay result."""

    id: uuid.UUID
    evidence_id: uuid.UUID
    verifier_id: str
    status: str
    status_code: int | None
    latency_ms: int | None
    diff: dict | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
