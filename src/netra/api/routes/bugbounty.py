"""NETRA-BB API routes for the operator console."""
from __future__ import annotations

import uuid
import inspect
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.api.deps import get_db_session
from netra.bugbounty.programs import (
    ProgramInput,
    ScopeRuleInput,
    create_program,
    get_active_scope_rules,
    replace_scope_rules,
)
from netra.bugbounty.scope import ScopeValidator
from netra.bugbounty.triage.deduper import find_graph_similar, fingerprint, is_duplicate
from netra.db.models.audit_ui_action import AuditUIAction
from netra.db.models.bb_agentic_step import BBAgenticStep
from netra.db.models.bb_asset import BBAsset
from netra.db.models.bb_evidence import BBEvidence, BBEvidenceReplay
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.bb_scope_rule import BBScopeRule
from netra.db.models.bb_submission import BBSubmission, SubmissionStatus
from netra.db.models.finding import Finding, FindingStatus
from netra.db.models.scan import Scan, ScanProfile, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, ScanPhase
from netra.db.models.target import Target, TargetType
from netra.schemas.bugbounty import (
    BBCounters,
    BBProgramCreate,
    BBProgramResponse,
    BBScopeRuleCreate,
    BBScopeRuleResponse,
    DashboardResponse,
    DoctorCheckResponse,
    EvidenceResponse,
    FindingCorpusContextResponse,
    PlanPreviewRequest,
    PlanPreviewResponse,
    HuntCreate,
    HuntExplainResponse,
    HuntResponse,
    ReplayRequest,
    ReplayResponse,
    ScopeCheckRequest,
    ScopeDiffResponse,
    SubmissionCreateRequest,
    SubmissionDetailResponse,
    SubmissionRenderRequest,
    SubmissionRenderResponse,
    SubmissionResponse,
    SubmissionTransitionRequest,
    SubmissionUpdateRequest,
    SubmissionVerdictRequest,
    TrendSummaryResponse,
    TriageRowResponse,
)

router = APIRouter()

SUBMISSION_OUTPUT_DIR = Path.home() / "netra_output" / "bb" / "submissions"


def _value(value: Any) -> Any:
    """Return enum values as strings without caring if the ORM gave us str or enum."""
    return getattr(value, "value", value)


def _program_id_from_scan(scan: Scan) -> uuid.UUID | None:
    raw = (scan.config or {}).get("program_id")
    if not raw:
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        return None


def _scope_rule_input_to_dict(rule: ScopeRuleInput) -> dict[str, Any]:
    return {
        "rule_type": _value(rule.rule_type),
        "asset_type": _value(rule.asset_type),
        "pattern": rule.pattern,
        "severity_cap": rule.severity_cap,
        "notes": rule.notes,
    }


def _scope_rule_to_dict(rule: BBScopeRule) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "rule_type": _value(rule.rule_type),
        "asset_type": _value(rule.asset_type),
        "pattern": rule.pattern,
        "severity_cap": rule.severity_cap,
        "notes": rule.notes,
        "active": rule.active,
    }


async def _submission_artifact_path(
    db: AsyncSession,
    submission: BBSubmission,
    artifact_format: str,
) -> Path:
    """Build the only permitted local path for a rendered submission artifact."""
    program = await db.get(BBProgram, submission.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    stem = f"{program.handle}-{str(submission.finding_id)[:8]}"
    return SUBMISSION_OUTPUT_DIR / f"{stem}.{artifact_format}"


async def _program_counts(db: AsyncSession, program: BBProgram) -> BBCounters:
    scope_rules = await db.scalar(
        select(func.count(BBScopeRule.id)).where(
            BBScopeRule.program_id == program.id,
            BBScopeRule.active.is_(True),
        )
    )
    assets = await db.scalar(
        select(func.count(BBAsset.id)).where(BBAsset.program_id == program.id)
    )
    submissions_draft = await db.scalar(
        select(func.count(BBSubmission.id)).where(
            BBSubmission.program_id == program.id,
            BBSubmission.status == "draft",
        )
    )

    findings_open = 0
    rows = await db.execute(select(Finding, Scan).join(Scan, Finding.scan_id == Scan.id))
    for finding, scan in rows.all():
        if _program_id_from_scan(scan) != program.id:
            continue
        if str(_value(finding.status)) not in {
            FindingStatus.RESOLVED.value,
            FindingStatus.FALSE_POSITIVE.value,
            FindingStatus.ACCEPTED_RISK.value,
        }:
            findings_open += 1

    return BBCounters(
        scope_rules=scope_rules or 0,
        assets=assets or 0,
        findings_open=findings_open,
        submissions_draft=submissions_draft or 0,
    )


async def _program_response(db: AsyncSession, program: BBProgram) -> BBProgramResponse:
    return BBProgramResponse(
        id=program.id,
        platform=str(_value(program.platform)),
        handle=program.handle,
        name=program.name,
        policy_url=program.policy_url,
        payout_min=program.payout_min,
        payout_max=program.payout_max,
        currency=program.currency,
        scope_synced_at=program.scope_synced_at,
        active=program.active,
        created_at=program.created_at,
        updated_at=program.updated_at,
        counts=await _program_counts(db, program),
    )


def _phase_to_dict(phase: ScanPhase) -> dict[str, Any]:
    return {
        "id": str(phase.id),
        "phase_type": str(_value(phase.phase_type)),
        "status": str(_value(phase.status)),
        "progress": phase.progress,
        "findings_count": phase.findings_count,
        "started_at": phase.started_at.isoformat() if phase.started_at else None,
        "completed_at": phase.completed_at.isoformat() if phase.completed_at else None,
        "error_message": phase.error_message,
        "tool_outputs": phase.tool_outputs or {},
    }


async def _hunt_response(db: AsyncSession, scan: Scan) -> HuntResponse:
    phases_result = await db.execute(
        select(ScanPhase).where(ScanPhase.scan_id == scan.id).order_by(ScanPhase.created_at)
    )
    phases = list(phases_result.scalars().all())
    program_id = _program_id_from_scan(scan)
    assets_discovered = 0
    if program_id:
        assets_discovered = await db.scalar(
            select(func.count(BBAsset.id)).where(BBAsset.program_id == program_id)
        ) or 0
    findings_count = await db.scalar(
        select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
    ) or 0
    blocked_count = sum(1 for phase in phases if str(_value(phase.status)) == "blocked")
    return HuntResponse(
        id=scan.id,
        name=scan.name,
        status=str(_value(scan.status)),
        profile=str(_value(scan.profile)),
        program_id=program_id,
        target_id=scan.target_id,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        mode="agentic" if bool((scan.config or {}).get("agentic")) else "fixed",
        dry_run=bool((scan.config or {}).get("dry_run")),
        phases=[_phase_to_dict(phase) for phase in phases],
        assets_discovered=assets_discovered,
        blocked_count=blocked_count,
        findings_count=findings_count,
    )


async def _platform_scope_rules(program: BBProgram) -> tuple[list[ScopeRuleInput], str | None]:
    """Pull scope rules when credentials are configured; return warning otherwise."""
    if program.platform == BBPlatform.HACKERONE:
        from netra.integrations.hackerone import HackerOneClient

        async with HackerOneClient() as client:
            if not client.is_configured():
                return [], "HackerOne credentials are not configured. Set H1_API_USERNAME and H1_API_TOKEN."
            return await client.get_structured_scopes(program.handle), None

    if program.platform == BBPlatform.BUGCROWD:
        from netra.integrations.bugcrowd import BugcrowdClient

        async with BugcrowdClient() as client:
            if not client.token:
                return [], "Bugcrowd credentials are not configured. Set BUGCROWD_TOKEN."
            return await client.get_scope(program.handle), None

    if program.platform == BBPlatform.INTIGRITI:
        from netra.integrations.intigriti import IntigritiClient

        async with IntigritiClient() as client:
            if not client.token:
                return [], "Intigriti credentials are not configured. Set INTIGRITI_TOKEN."
            return await client.get_scope(program.handle), None

    return [], "No platform scope API is available for this program type."


async def _doctor_checks() -> list[DoctorCheckResponse]:
    from netra.bugbounty.cli import _doctor_checks as cli_doctor_checks

    checks = cli_doctor_checks(include_local_tools=True)
    if inspect.isawaitable(checks):
        checks = await checks
    normalized: list[DoctorCheckResponse] = []
    for check in checks:
        if isinstance(check, tuple):
            name, ok, detail = check
            normalized.append(
                DoctorCheckResponse(name=name, status="ok" if ok else "warn", detail=detail)
            )
        else:
            normalized.append(
                DoctorCheckResponse(
                    name=check.name,
                    status=check.status,
                    detail=check.detail,
                )
            )
    return normalized


@router.get("/doctor", response_model=list[DoctorCheckResponse])
async def doctor() -> list[DoctorCheckResponse]:
    """Return the same readiness checks as `netra-bb doctor`."""
    return await _doctor_checks()


@router.get("/trends", response_model=TrendSummaryResponse)
async def trend_summary(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db_session),
) -> TrendSummaryResponse:
    """Return a compact trend summary from the local learning corpus."""
    from netra.bugbounty.learning.trends import summarize_trends

    return TrendSummaryResponse.model_validate(await summarize_trends(db, days=days))


@router.get("/findings/{finding_id}/similar-reports", response_model=FindingCorpusContextResponse)
async def finding_corpus_context(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> FindingCorpusContextResponse:
    """Return similar public prior art for a finding review workflow."""
    from netra.bugbounty.learning.search import build_corpus_context

    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    program = await db.get(BBProgram, _program_id_from_scan(scan)) if scan else None
    vuln_class = _finding_vuln_class(finding)
    query = " ".join(
        filter(
            None,
            [
                program.handle if program else "",
                finding.title,
                vuln_class,
                finding.url or "",
                finding.description or "",
            ],
        )
    )
    filters = {"vuln_class": vuln_class}
    if program:
        filters["program_handle"] = program.handle
    reports = await build_corpus_context(db, query, top_k=4, filters=filters)
    if not reports and program:
        reports = await build_corpus_context(
            db,
            query,
            top_k=4,
            filters={"vuln_class": vuln_class},
        )
    return FindingCorpusContextResponse(finding_id=finding.id, similar_reports=reports)


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(db: AsyncSession = Depends(get_db_session)) -> DashboardResponse:
    """Return a single aggregate payload for the BB dashboard."""
    active_programs = await db.scalar(
        select(func.count(BBProgram.id)).where(
            BBProgram.active.is_(True),
            BBProgram.deleted_at.is_(None),
        )
    ) or 0
    scope_rules = await db.scalar(
        select(func.count(BBScopeRule.id)).where(BBScopeRule.active.is_(True))
    ) or 0
    assets = await db.scalar(select(func.count(BBAsset.id))) or 0
    submissions_draft = await db.scalar(
        select(func.count(BBSubmission.id)).where(BBSubmission.status == "draft")
    ) or 0

    recent_scan_result = await db.execute(
        select(Scan)
        .where(Scan.profile.in_([ScanProfile.BUGBOUNTY_PASSIVE, ScanProfile.BUGBOUNTY_ACTIVE]))
        .order_by(Scan.created_at.desc())
        .limit(5)
    )
    recent_hunts = [
        await _hunt_response(db, scan) for scan in recent_scan_result.scalars().all()
    ]

    open_findings = 0
    rows = await db.execute(select(Finding, Scan).join(Scan, Finding.scan_id == Scan.id))
    for finding, scan in rows.all():
        if _program_id_from_scan(scan) is None:
            continue
        if str(_value(finding.status)) not in {
            FindingStatus.RESOLVED.value,
            FindingStatus.FALSE_POSITIVE.value,
            FindingStatus.ACCEPTED_RISK.value,
        }:
            open_findings += 1

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    out_of_scope_blocks = await db.scalar(
        select(func.count(ScanPhase.id)).where(
            ScanPhase.status == PhaseStatus.BLOCKED,
            ScanPhase.created_at >= since,
        )
    ) or 0

    return DashboardResponse(
        active_programs=active_programs,
        scope_rules=scope_rules,
        assets=assets,
        open_findings=open_findings,
        submissions_draft=submissions_draft,
        out_of_scope_blocks_24h=out_of_scope_blocks,
        recent_hunts=recent_hunts,
        doctor=await _doctor_checks(),
    )


@router.get("/programs", response_model=list[BBProgramResponse])
async def list_programs(
    platform: BBPlatform | None = None,
    active: bool | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> list[BBProgramResponse]:
    """List bug bounty programs."""
    stmt = select(BBProgram).where(BBProgram.deleted_at.is_(None))
    if platform:
        stmt = stmt.where(BBProgram.platform == platform)
    if active is not None:
        stmt = stmt.where(BBProgram.active.is_(active))
    stmt = stmt.order_by(BBProgram.platform, BBProgram.handle)
    result = await db.execute(stmt)
    return [await _program_response(db, program) for program in result.scalars().all()]


@router.post("/programs", response_model=BBProgramResponse, status_code=status.HTTP_201_CREATED)
async def create_bb_program(
    payload: BBProgramCreate,
    db: AsyncSession = Depends(get_db_session),
) -> BBProgramResponse:
    """Create a program and optionally sync platform scope."""
    program = await create_program(
        db,
        ProgramInput(
            platform=payload.platform,
            handle=payload.handle,
            name=payload.name or payload.handle,
            policy_url=payload.policy_url,
            payout_min=payload.payout_min,
            payout_max=payload.payout_max,
            currency=payload.currency.upper(),
        ),
    )
    if payload.auto_sync_scope:
        rules, warning = await _platform_scope_rules(program)
        if rules:
            await replace_scope_rules(db, program, rules)
        elif warning:
            program.metadata_ = {**(program.metadata_ or {}), "sync_warning": warning}
    await db.commit()
    await db.refresh(program)
    return await _program_response(db, program)


@router.get("/programs/{program_id}", response_model=BBProgramResponse)
async def get_bb_program(
    program_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> BBProgramResponse:
    """Fetch a single program."""
    program = await db.get(BBProgram, program_id)
    if not program or program.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Program not found")
    return await _program_response(db, program)


@router.post("/programs/{program_id}/sync-scope", response_model=ScopeDiffResponse)
async def sync_program_scope(
    program_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ScopeDiffResponse:
    """Sync scope from the owning platform, when credentials are available."""
    program = await db.get(BBProgram, program_id)
    if not program or program.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Program not found")
    rules, warning = await _platform_scope_rules(program)
    if not rules:
        return ScopeDiffResponse(
            added=[],
            removed=[],
            unchanged_count=0,
            has_changes=False,
            warning=warning,
        )
    diff = await replace_scope_rules(db, program, rules)
    await db.commit()
    return ScopeDiffResponse(
        added=[_scope_rule_input_to_dict(rule) for rule in diff.added],
        removed=[_scope_rule_to_dict(rule) for rule in diff.removed],
        unchanged_count=diff.unchanged_count,
        has_changes=diff.has_changes,
        warning=warning,
    )


@router.get("/scope/rules", response_model=list[BBScopeRuleResponse])
async def list_scope_rules(
    program_id: uuid.UUID | None = None,
    active: bool | None = None,
    rule_type: str | None = Query(default=None, alias="type"),
    db: AsyncSession = Depends(get_db_session),
) -> list[BBScopeRuleResponse]:
    """List scope rules with filters."""
    stmt = select(BBScopeRule)
    if program_id:
        stmt = stmt.where(BBScopeRule.program_id == program_id)
    if active is not None:
        stmt = stmt.where(BBScopeRule.active.is_(active))
    if rule_type:
        stmt = stmt.where(BBScopeRule.rule_type == rule_type)
    stmt = stmt.order_by(BBScopeRule.rule_type, BBScopeRule.asset_type, BBScopeRule.pattern)
    result = await db.execute(stmt)
    return [BBScopeRuleResponse.model_validate(rule) for rule in result.scalars().all()]


@router.post("/scope/rules", response_model=BBScopeRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_scope_rule(
    payload: BBScopeRuleCreate,
    db: AsyncSession = Depends(get_db_session),
) -> BBScopeRuleResponse:
    """Create a manual scope rule."""
    program = await db.get(BBProgram, payload.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    rule = BBScopeRule(
        program_id=payload.program_id,
        rule_type=payload.rule_type,
        asset_type=payload.asset_type,
        pattern=payload.pattern,
        severity_cap=payload.severity_cap,
        notes=payload.notes,
        active=True,
        synced_from_platform=False,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return BBScopeRuleResponse.model_validate(rule)


@router.post("/scope/check")
async def check_scope(
    payload: ScopeCheckRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Run the server-side scope validator and return the exact parsed decision."""
    rules = await get_active_scope_rules(db, payload.program_id)
    validator = ScopeValidator.from_db_rules(rules)
    decision = validator.check(payload.target)
    response = asdict(decision)
    if decision.matched_rule:
        response["matched_rule"] = asdict(decision.matched_rule)
    return response


@router.get("/hunts", response_model=list[HuntResponse])
async def list_hunts(
    program_id: uuid.UUID | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> list[HuntResponse]:
    """List bug bounty hunts."""
    stmt = (
        select(Scan)
        .where(Scan.profile.in_([ScanProfile.BUGBOUNTY_PASSIVE, ScanProfile.BUGBOUNTY_ACTIVE]))
        .order_by(Scan.created_at.desc())
    )
    if status:
        stmt = stmt.where(Scan.status == status)
    result = await db.execute(stmt)
    scans = list(result.scalars().all())
    if program_id:
        scans = [scan for scan in scans if _program_id_from_scan(scan) == program_id]
    return [await _hunt_response(db, scan) for scan in scans]


@router.post("/hunts/plan-preview", response_model=PlanPreviewResponse)
async def preview_hunt_plan(
    payload: PlanPreviewRequest,
    db: AsyncSession = Depends(get_db_session),
) -> PlanPreviewResponse:
    """Preview the agentic plan and its graph-backed coordination context."""
    from netra.bugbounty.agentic.planner import Planner
    from netra.bugbounty.learning.search import build_corpus_context

    program = await db.get(BBProgram, payload.program_id)
    if not program or not program.active or program.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Active program not found")
    rules = await get_active_scope_rules(db, program.id)
    allow = [rule.pattern for rule in rules if str(rule.rule_type) == "in"]
    asset = payload.asset or program.handle
    assets_result = await db.execute(
        select(BBAsset).where(BBAsset.program_id == program.id).order_by(BBAsset.last_seen.desc())
    )
    assets = list(assets_result.scalars().all())
    tech = sorted(
        {
            str(item).strip()
            for asset_row in assets
            for item in (asset_row.tech or [])
            if str(item).strip()
        }
    )
    corpus_hits = await build_corpus_context(
        db,
        " ".join([program.handle, program.name or "", asset, *tech[:5]]).strip(),
        top_k=5,
        filters={"program_handle": program.handle},
    )
    plan = await Planner().make_plan(
        asset_facts={
            "target": asset,
            "tech": tech[:20],
            "program_handle": program.handle,
            "program_name": program.name,
            "known_hosts": [row.host for row in assets[:20] if row.host],
            "active_classes_approved": list(program.active_classes_approved or []),
        },
        scope=allow or [asset],
        corpus_hits=corpus_hits,
    )
    return PlanPreviewResponse(
        rationale=plan.rationale,
        coordination=plan.coordination,
        steps=plan.to_dict().get("steps", []),
    )


@router.post("/hunts", response_model=HuntResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_hunt(
    payload: HuntCreate,
    db: AsyncSession = Depends(get_db_session),
) -> HuntResponse:
    """Create a BB scan and enqueue the Celery worker."""
    program = await db.get(BBProgram, payload.program_id)
    if not program or not program.active or program.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Active program not found")
    if payload.profile == "passive":
        profile = ScanProfile.BUGBOUNTY_PASSIVE
    else:
        if payload.options.get("enable_ffuf") or payload.options.get("enable_nuclei"):
            profile = ScanProfile.BUGBOUNTY_ACTIVE
        else:
            profile = ScanProfile.BUGBOUNTY_ACTIVE

    target = Target(
        name=f"BB {program.handle}",
        target_type=TargetType.DOMAIN,
        value=program.handle,
        scope_includes=[],
        scope_excludes=[],
        metadata_={"program_id": str(program.id), "bb": True},
    )
    db.add(target)
    await db.flush()
    scan = Scan(
        name=f"NETRA-BB {program.handle} {payload.profile}",
        target_id=target.id,
        profile=profile,
        status=ScanStatus.PENDING,
        config={
            "program_id": str(program.id),
            "program_handle": program.handle,
            "bb_profile": payload.profile,
            **payload.options,
        },
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        from netra.worker.tasks import run_bugbounty_scan

        task = run_bugbounty_scan.delay(str(scan.id))
        scan.config = {
            **(scan.config or {}),
            "celery_task_id": task.id,
        }
        await db.commit()
    except Exception as exc:
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "dispatch_warning": f"Celery dispatch failed: {exc}",
        }
        await db.commit()

    return await _hunt_response(db, scan)


@router.get("/hunts/{scan_id}", response_model=HuntResponse)
async def get_hunt(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> HuntResponse:
    """Fetch a hunt and its phases."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return await _hunt_response(db, scan)


@router.get("/hunts/{scan_id}/explain", response_model=HuntExplainResponse)
async def explain_hunt(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> HuntExplainResponse:
    """Return persisted agentic step telemetry for a hunt."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    rows = await db.execute(
        select(BBAgenticStep)
        .where(BBAgenticStep.scan_id == scan_id)
        .order_by(BBAgenticStep.step_n.asc())
    )
    checkpoint = scan.checkpoint_data or {}
    coordination = checkpoint.get("agentic_coordination") or checkpoint.get("agentic_plan", {}).get("coordination", {}) or {}
    return HuntExplainResponse(
        scan_id=scan.id,
        summary=coordination.get("summary"),
        focus_areas=list(coordination.get("focus_areas") or []),
        recommended_tools=list(coordination.get("recommended_tools") or []),
        corpus_hits=list(checkpoint.get("agentic_corpus_hits") or coordination.get("corpus_hits") or []),
        retrieval_hits=list(coordination.get("retrieval_hits") or []),
        attack_paths=list(coordination.get("attack_paths") or []),
        report_focus=list(coordination.get("report_focus") or []),
        steps=[
            {
                "step_n": row.step_n,
                "status": row.status,
                "tool_chosen": row.tool_chosen,
                "decision_rationale": row.decision_rationale,
                "observations_in": row.observations_in or {},
                "observations_out": row.observations_out or {},
                "metadata": row.metadata_ or {},
            }
            for row in rows.scalars().all()
        ],
    )


@router.post("/hunts/{scan_id}/cancel", response_model=HuntResponse)
async def cancel_hunt(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> HuntResponse:
    """Cancel a hunt and revoke the worker task when one is known."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Hunt not found")
    task_id = str((scan.config or {}).get("celery_task_id") or "").strip()
    if task_id:
        from netra.worker.celery_app import celery_app
        from netra.scanner.tools.process_control import kill_registered_processes

        celery_app.control.revoke(task_id, terminate=True, signal="SIGKILL")
        kill_registered_processes(task_id)
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(scan)
    return await _hunt_response(db, scan)


def _finding_vuln_class(finding: Finding) -> str:
    tags = finding.tags or []
    if tags:
        return str(tags[0])
    if finding.cwe_id:
        return str(finding.cwe_id)
    return finding.title.split()[0].lower() if finding.title else "finding"


def _finding_asset(finding: Finding) -> str | None:
    if finding.url:
        parsed = urlparse(finding.url)
        return parsed.netloc or parsed.path or finding.url
    evidence = finding.evidence or {}
    if isinstance(evidence, dict):
        return evidence.get("host") or evidence.get("url")
    return None


async def _triage_row(
    db: AsyncSession,
    finding: Finding,
    program_id: uuid.UUID | None,
    graph_aware: bool = False,
) -> TriageRowResponse:
    ai = finding.ai_analysis or {}
    bounty = ai.get("bounty_hunter") or {}
    skeptic = ai.get("skeptic") or {}
    vuln_class = _finding_vuln_class(finding)
    asset = _finding_asset(finding)
    exact = None
    similar: list[dict[str, Any]] = []
    if program_id:
        path = urlparse(finding.url or asset or "/").path or "/"
        fp = fingerprint(vuln_class, path, finding.parameter or "")
        duplicate = await is_duplicate(db, program_id, fp)
        if duplicate:
            exact = {"finding_id": str(duplicate.finding_id), "signature": duplicate.signature_hash}
        if graph_aware:
            similar = find_graph_similar(program_id, path, vuln_class)
    return TriageRowResponse(
        id=finding.id,
        title=finding.title,
        asset=asset,
        vuln_class=vuln_class,
        severity=str(_value(finding.severity)),
        status=str(_value(finding.status)),
        cvss=finding.cvss_score,
        bounty_hunter=bounty,
        skeptic_vetoed=bool(skeptic.get("veto") or skeptic.get("vetoed")),
        dedup={"exact": exact, "similar": similar},
        created_at=finding.created_at,
    )


@router.get("/triage", response_model=list[TriageRowResponse])
async def triage(
    program_id: uuid.UUID | None = None,
    include_vetoed: bool = False,
    graph_aware: bool = False,
    limit: int = Query(default=20, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
) -> list[TriageRowResponse]:
    """List findings ranked for bug bounty triage."""
    result = await db.execute(select(Finding, Scan).join(Scan, Finding.scan_id == Scan.id))
    rows: list[TriageRowResponse] = []
    for finding, scan in result.all():
        scan_program_id = _program_id_from_scan(scan)
        if scan_program_id is None:
            continue
        if program_id and scan_program_id != program_id:
            continue
        row = await _triage_row(db, finding, scan_program_id, graph_aware)
        if row.skeptic_vetoed and not include_vetoed:
            continue
        rows.append(row)
    rows.sort(key=lambda row: float(row.bounty_hunter.get("composite") or 0), reverse=True)
    return rows[:limit]


@router.get("/triage/{finding_id}", response_model=TriageRowResponse)
async def triage_detail(
    finding_id: uuid.UUID,
    graph_aware: bool = True,
    db: AsyncSession = Depends(get_db_session),
) -> TriageRowResponse:
    """Fetch a single triage row."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    return await _triage_row(db, finding, _program_id_from_scan(scan) if scan else None, graph_aware)


@router.get("/submissions", response_model=list[SubmissionResponse])
async def list_submissions(
    program_id: uuid.UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db_session),
) -> list[SubmissionResponse]:
    """List submission drafts and verdicts."""
    stmt = select(BBSubmission).order_by(BBSubmission.created_at.desc())
    if program_id:
        stmt = stmt.where(BBSubmission.program_id == program_id)
    if status_filter:
        stmt = stmt.where(BBSubmission.status == status_filter)
    result = await db.execute(stmt)
    return [SubmissionResponse.model_validate(row) for row in result.scalars().all()]


@router.post("/submissions", response_model=SubmissionDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_submission(
    payload: SubmissionCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionDetailResponse:
    """Create a submission draft from a finding."""
    finding = await db.get(Finding, payload.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    from netra.services.bb_submission_service import (
        BBSubmissionService,
        DraftLeakRiskError,
        DuplicateFindingError,
    )

    service = BBSubmissionService(db)
    try:
        submission, _paths = await service.create_draft(
            finding,
            Path.home() / "netra_output" / "bb" / "submissions",
            formats=tuple(payload.formats),
            force=payload.force,
            include_poc=payload.include_poc,
        )
    except DuplicateFindingError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DraftLeakRiskError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await db.refresh(submission)
    return SubmissionDetailResponse.model_validate(submission)


@router.get("/submissions/{submission_id}", response_model=SubmissionDetailResponse)
async def get_submission(
    submission_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionDetailResponse:
    """Fetch a submission draft."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return SubmissionDetailResponse.model_validate(submission)


@router.patch("/submissions/{submission_id}", response_model=SubmissionDetailResponse)
async def update_submission(
    submission_id: uuid.UUID,
    payload: SubmissionUpdateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionDetailResponse:
    """Update editable submission fields."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    if payload.title is not None:
        submission.title = payload.title
    if payload.draft_md is not None:
        submission.draft_md = payload.draft_md
    if payload.platform_report_id is not None:
        submission.platform_report_id = payload.platform_report_id
    if payload.verdict_notes is not None:
        submission.verdict_notes = payload.verdict_notes
    await db.commit()
    await db.refresh(submission)
    return SubmissionDetailResponse.model_validate(submission)


@router.post("/submissions/{submission_id}/transition", response_model=SubmissionDetailResponse)
async def transition_submission(
    submission_id: uuid.UUID,
    payload: SubmissionTransitionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionDetailResponse:
    """Run a submission through the state machine."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    from netra.bugbounty.submission.tracker import InvalidTransition, transition

    try:
        await transition(db, submission, SubmissionStatus(payload.to_status), payload.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Unknown status: {payload.to_status}") from exc
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(submission)
    return SubmissionDetailResponse.model_validate(submission)


@router.post("/submissions/{submission_id}/render", response_model=SubmissionRenderResponse)
async def render_submission(
    submission_id: uuid.UUID,
    payload: SubmissionRenderRequest,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionRenderResponse:
    """Render markdown/docx/pdf artifact locally."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    finding = await db.get(Finding, submission.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    output_dir = SUBMISSION_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    path = await _submission_artifact_path(db, submission, payload.format)
    if payload.format == "md":
        path.write_text(submission.draft_md or "", encoding="utf-8")
    elif payload.format == "docx":
        from netra.services.report_service import generate_word_h1

        path = generate_word_h1(finding, submission, path)
    else:
        path.write_text(submission.draft_md or "", encoding="utf-8")
    return SubmissionRenderResponse(
        format=payload.format,
        path=str(path),
        download_url=f"/api/v1/bb/submissions/{submission_id}/artifact?format={payload.format}",
    )


@router.get("/submissions/{submission_id}/artifact")
async def download_submission_artifact(
    submission_id: uuid.UUID,
    artifact_format: str = Query(alias="format", pattern="^(md|docx|pdf)$"),
    db: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    """Download a previously rendered local submission artifact."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    path = await _submission_artifact_path(db, submission, artifact_format)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Artifact has not been rendered yet")
    media_types = {
        "md": "text/markdown; charset=utf-8",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf",
    }
    return FileResponse(path, media_type=media_types[artifact_format], filename=path.name)


@router.post("/submissions/{submission_id}/verdict", response_model=SubmissionDetailResponse)
async def ingest_verdict(
    submission_id: uuid.UUID,
    payload: SubmissionVerdictRequest,
    db: AsyncSession = Depends(get_db_session),
) -> SubmissionDetailResponse:
    """Ingest a platform verdict and trigger graph export."""
    submission = await db.get(BBSubmission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    target = {
        "paid": SubmissionStatus.RESOLVED_PAID,
        "dup": SubmissionStatus.RESOLVED_DUP,
        "na": SubmissionStatus.RESOLVED_NA,
        "info": SubmissionStatus.RESOLVED_INFORMATIVE,
    }[payload.verdict]
    from netra.bugbounty.submission.tracker import InvalidTransition, transition

    try:
        await transition(db, submission, target, payload.notes)
    except InvalidTransition:
        submission.status = target
        submission.verdict_at = datetime.now(timezone.utc)
        submission.verdict_notes = payload.notes
    if payload.payout_actual is not None:
        submission.payout_actual = payload.payout_actual
    await db.commit()
    try:
        from netra.worker.tasks import export_bugbounty_submissions

        export_bugbounty_submissions.delay()
    except Exception:
        pass
    await db.refresh(submission)
    return SubmissionDetailResponse.model_validate(submission)


@router.get("/audit/scope-blocks")
async def scope_blocks(
    since_hours: int = Query(default=168, ge=1, le=24 * 90),
    program_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List blocked scope events recorded as blocked scan phases."""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    result = await db.execute(
        select(ScanPhase, Scan)
        .join(Scan, ScanPhase.scan_id == Scan.id)
        .where(ScanPhase.status == PhaseStatus.BLOCKED, ScanPhase.created_at >= since)
        .order_by(ScanPhase.created_at.desc())
        .limit(limit)
    )
    rows = []
    for phase, scan in result.all():
        scan_program_id = _program_id_from_scan(scan)
        if program_id and scan_program_id != program_id:
            continue
        rows.append(
            {
                "id": str(phase.id),
                "scan_id": str(scan.id),
                "program_id": str(scan_program_id) if scan_program_id else None,
                "timestamp": phase.created_at.isoformat(),
                "tool": str(_value(phase.phase_type)),
                "target": (phase.tool_outputs or {}).get("target"),
                "decision": "blocked",
                "reason": phase.error_message or (phase.tool_outputs or {}).get("reason"),
            }
        )
    return rows


@router.get("/audit/ui-actions")
async def ui_actions(
    since_hours: int = Query(default=168, ge=1, le=24 * 90),
    limit: int = Query(default=100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List audited state-changing BB API calls."""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    result = await db.execute(
        select(AuditUIAction)
        .where(AuditUIAction.created_at >= since)
        .order_by(AuditUIAction.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(row.id),
            "timestamp": row.created_at.isoformat(),
            "actor_id": str(row.actor_id) if row.actor_id else None,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "result_code": row.result_code,
            "trace_id": row.trace_id,
            "ip": row.ip,
        }
        for row in result.scalars().all()
    ]


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[EvidenceResponse]:
    """List evidence items for a finding."""
    result = await db.execute(
        select(BBEvidence)
        .where(BBEvidence.finding_id == finding_id, BBEvidence.deleted_at.is_(None))
        .order_by(BBEvidence.created_at.desc())
    )
    return [EvidenceResponse.model_validate(item) for item in result.scalars().all()]


@router.post("/findings/{finding_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    finding_id: uuid.UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceResponse:
    """Upload evidence through the redact/encrypt/store pipeline."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    program_id = _program_id_from_scan(scan) if scan else None
    if not program_id:
        raise HTTPException(status_code=400, detail="Finding is not attached to a bug bounty program")

    from netra.bugbounty.evidence.pipeline import store_evidence

    content = await file.read()
    stored = await store_evidence(
        db,
        finding_id=finding.id,
        program_id=program_id,
        filename=file.filename or "evidence.txt",
        content=content,
        content_type=file.content_type,
        metadata={"source": "gui_upload"},
    )
    await db.commit()
    await db.refresh(stored.evidence)
    return EvidenceResponse.model_validate(stored.evidence)


@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceResponse:
    """Fetch evidence metadata."""
    evidence = await db.get(BBEvidence, evidence_id)
    if not evidence or evidence.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return EvidenceResponse.model_validate(evidence)


@router.get("/evidence/{evidence_id}/blob")
async def get_evidence_blob(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream the permanently redacted evidence blob."""
    evidence = await db.get(BBEvidence, evidence_id)
    if not evidence or evidence.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    from netra.bugbounty.evidence.pipeline import read_evidence_blob

    return Response(
        content=read_evidence_blob(evidence),
        media_type=evidence.mime_type,
        headers={"content-disposition": f'inline; filename="{evidence.filename}"'},
    )


@router.post("/evidence/{evidence_id}/replay", response_model=ReplayResponse)
async def replay_evidence(
    evidence_id: uuid.UUID,
    payload: ReplayRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ReplayResponse:
    """Replay evidence through an allowlisted verifier."""
    evidence = await db.get(BBEvidence, evidence_id)
    if not evidence or evidence.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    finding = await db.get(Finding, evidence.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    program = await db.get(BBProgram, evidence.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    if payload.typed_confirm and payload.typed_confirm != program.handle:
        raise HTTPException(status_code=400, detail="Typed confirmation does not match the program handle")

    from netra.bugbounty.verifiers.loader import find_verifier
    from netra.bugbounty.verifiers.runner import run_replay

    spec = find_verifier(payload.verifier_id, _finding_vuln_class(finding))
    if spec is None:
        raise HTTPException(status_code=403, detail="Verifier is not allowlisted for this finding")
    rules = await get_active_scope_rules(db, program.id)
    validator = ScopeValidator.from_db_rules(rules)
    try:
        result = await run_replay(evidence, spec, validator)
    except Exception as exc:
        result = {"status": "blocked", "error": str(exc), "diff": {}}
    replay = BBEvidenceReplay(
        evidence_id=evidence.id,
        verifier_id=spec.id,
        status=str(result.get("status", "failed")),
        status_code=result.get("status_code"),
        latency_ms=result.get("latency_ms"),
        diff=result.get("diff") or {},
        error_message=result.get("error"),
    )
    db.add(replay)
    await db.commit()
    await db.refresh(replay)
    return ReplayResponse.model_validate(replay)


@router.get("/settings/verifiers")
async def list_verifiers() -> list[dict[str, Any]]:
    """Return verifier allowlist entries for read-only UI display."""
    from netra.bugbounty.verifiers.loader import verifiers_as_dicts

    return verifiers_as_dicts()


@router.post("/settings/verifiers/reload")
async def reload_verifier_allowlist() -> list[dict[str, Any]]:
    """Reload verifier allowlist from disk."""
    from netra.bugbounty.verifiers.loader import reload_verifiers

    return reload_verifiers()


@router.get("/graph/program/{program_id}")
async def program_graph(
    program_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Return a hierarchical program graph."""
    program = await db.get(BBProgram, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    nodes = [{"id": str(program.id), "label": program.handle, "type": "program"}]
    edges: list[dict[str, str]] = []
    assets = (await db.execute(select(BBAsset).where(BBAsset.program_id == program.id))).scalars().all()
    for asset in assets:
        nodes.append({"id": str(asset.id), "label": asset.host, "type": "asset"})
        edges.append({"source": str(program.id), "target": str(asset.id), "rel": "has_asset"})
    rows = await db.execute(select(Finding, Scan).join(Scan, Finding.scan_id == Scan.id))
    for finding, scan in rows.all():
        if _program_id_from_scan(scan) != program.id:
            continue
        nodes.append({"id": str(finding.id), "label": finding.title, "type": "finding", "severity": str(_value(finding.severity))})
        asset_label = _finding_asset(finding)
        target = str(program.id)
        for asset in assets:
            if asset_label and asset.host in asset_label:
                target = str(asset.id)
                break
        edges.append({"source": target, "target": str(finding.id), "rel": "has_finding"})
    submissions = (await db.execute(select(BBSubmission).where(BBSubmission.program_id == program.id))).scalars().all()
    for submission in submissions:
        nodes.append({"id": str(submission.id), "label": submission.title, "type": "submission", "status": str(_value(submission.status))})
        edges.append({"source": str(submission.finding_id), "target": str(submission.id), "rel": "drafted_as"})
    return {"nodes": nodes, "edges": edges}


@router.get("/graph/codebase")
async def codebase_graph() -> dict[str, Any]:
    """Return cached Graphify codebase graph if present."""
    import json
    from pathlib import Path

    candidates = [
        Path("data/graphify/netra/graphify-out/graph.json"),
        Path("data/graphify/netra/graph.json"),
    ]
    for path in candidates:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    return {"nodes": [], "edges": [], "warning": "Codebase graph has not been indexed yet."}


@router.post("/graph/reindex", status_code=status.HTTP_202_ACCEPTED)
async def reindex_graph(payload: dict[str, Any]) -> dict[str, Any]:
    """Trigger a best-effort local Graphify reindex."""
    kind = payload.get("kind", "codebase")
    if kind == "codebase":
        from pathlib import Path
        import asyncio
        from netra.bugbounty.graph_indexer import index_codebase

        asyncio.create_task(index_codebase(Path("src"), Path("data/graphify/netra")))
    return {"status": "accepted", "kind": kind}


@router.post("/kill-switch")
async def kill_switch(
    payload: dict[str, Any],
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Cancel all active bug bounty scans."""
    if payload.get("confirm") != "STOP":
        raise HTTPException(status_code=400, detail="Type STOP to trigger the kill switch")
    result = await db.execute(
        select(Scan).where(
            Scan.profile.in_([ScanProfile.BUGBOUNTY_PASSIVE, ScanProfile.BUGBOUNTY_ACTIVE]),
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    scans = list(result.scalars().all())
    now = datetime.now(timezone.utc)
    for scan in scans:
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = now
    await db.commit()
    return {"status": "cancelled", "count": len(scans)}
