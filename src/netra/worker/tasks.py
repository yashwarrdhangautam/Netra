"""Celery tasks for distributed scan execution."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from celery import chain
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.scanner.tools.amass import AmassTool
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.nikto import NiktoTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.process_control import (
    clear_task_registry,
    kill_registered_processes,
    reset_current_task_id,
    set_current_task_id,
)
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.scanner.tools.subfinder import SubfinderTool
from netra.worker.celery_app import celery_app

logger = structlog.get_logger()


def _get_db_session() -> AsyncSession:
    """Create a new database session for task execution."""
    from netra.db.session import async_session_factory

    return async_session_factory()


def _record_run(runs: list[dict], tool: str, target: str, result: Any) -> None:
    """Keep the outcome of one tool run so the phase can judge it instead of ignoring it."""
    runs.append(
        {
            "tool": tool,
            "target": str(target)[:200],
            "success": bool(result.success),
            "error": result.error,
        }
    )


def _phase_verdict(runs: list[dict]) -> dict:
    """Phase outcome from its tool runs.

    The phase fails only when every run it attempted failed. Partial failures are kept as
    warnings on the phase row, so they are visible instead of silently dropped.
    """
    failures = [
        f"{r['tool']} {r['target']}: {r['error'] or 'failed'}"[:300]
        for r in runs
        if not r["success"]
    ]
    if runs and len(failures) == len(runs):
        return {"status": "failed", "error": "all tool runs failed: " + "; ".join(failures[:3])}
    if failures:
        return {"status": "completed", "warnings": failures}
    return {"status": "completed"}


def _phase_note(result: dict) -> str | None:
    """Text stored on the phase row: the error for a failed phase, or the warnings."""
    if result.get("status") == "failed":
        return str(result.get("error", "Unknown error"))[:2000]
    if result.get("warnings"):
        return "; ".join(result["warnings"])[:2000]
    return None


def _phase_dir(scan_id: uuid.UUID, phase_type: str) -> Path:
    """Get working directory for a phase."""
    d = Path.home() / ".netra" / "scans" / str(scan_id)[:8] / phase_type
    d.mkdir(parents=True, exist_ok=True)
    return d


def _task_request_id(task: Any) -> str | None:
    """Best-effort Celery task id lookup that is easy to override in tests."""
    request = getattr(task, "request", None)
    task_id = getattr(request, "id", None)
    return str(task_id) if task_id else None


@celery_app.task(bind=True, name="netra.scope_resolution", acks_late=True)
def scope_resolution(self, scan_id: str) -> dict:
    """Phase 1: Resolve and validate scan targets.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Task result with target information
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_scope_resolution, scan_uuid))

        # Update phase status
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.SCOPE, result))

        return result
    except Exception as e:
        logger.error("scope_resolution_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "scope", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_scope_resolution(db: AsyncSession, scan_id: uuid.UUID) -> dict:
    """Execute scope resolution phase."""

    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    target = scan.target.value
    all_subdomains: set[str] = set()

    try:
        # Subfinder
        subfinder = SubfinderTool(work_dir=_phase_dir(scan_id, "subdomains"))
        runs: list[dict] = []
        sub_result = await subfinder.run(target)
        _record_run(runs, "subfinder", target, sub_result)
        for f in sub_result.findings:
            if hostname := f.get("hostname") or f.get("url", ""):
                all_subdomains.add(hostname)

        # Amass (if deep profile)
        if scan.profile in ["deep", "comprehensive"]:
            amass = AmassTool(work_dir=_phase_dir(scan_id, "amass"))
            amass_result = await amass.run(target)
            _record_run(runs, "amass", target, amass_result)
            for f in amass_result.findings:
                if hostname := f.get("hostname") or f.get("url", ""):
                    all_subdomains.add(hostname)

        # Always include root target
        all_subdomains.add(target)

        # Save to checkpoint
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "subdomains": list(all_subdomains),
        }
        await db.commit()

        return {
            "scan_id": str(scan_id),
            "phase": "scope",
            "status": "completed",
            "subdomains": list(all_subdomains),
            "count": len(all_subdomains),
            **_phase_verdict(runs),
        }

    except Exception as e:
        logger.error("subdomain_enum_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.recon", acks_late=True)
def recon(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 2: Passive reconnaissance and live host discovery.

    Args:
        previous_result: Result from scope resolution
        scan_id: The scan UUID as string

    Returns:
        Task result with live hosts
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_recon, scan_uuid, previous_result))
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.RECON_DISCOVERY, result))
        return result
    except Exception as e:
        logger.error("recon_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "recon", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_recon(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute reconnaissance phase."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    subdomains = previous_result.get("subdomains", [])
    if not subdomains:
        # Try from checkpoint
        subdomains = (scan.checkpoint_data or {}).get("subdomains", [scan.target.value])

    live_hosts: list[str] = []

    try:
        if not subdomains:
            return {"status": "completed", "live_hosts": [], "count": 0}

        httpx_tool = HttpxTool(work_dir=_phase_dir(scan_id, "discovery"))
        runs: list[dict] = []
        http_result = await httpx_tool.run(
            target=",".join(subdomains[:50]),
            follow_redirects=True,
            tech_detect=True,
        )
        _record_run(runs, "httpx", ",".join(subdomains[:50]), http_result)

        live_hosts = [
            f.get("url", "")
            for f in http_result.findings
            if f.get("status_code", 0) in range(200, 500)
        ]

        # Save checkpoint
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "live_hosts": live_hosts,
            # Host rows (tech, status, protections) feed the recon manifest and arsenal map.
            "http_hosts": [
                {
                    k: f.get(k)
                    for k in ("url", "hostname", "status_code", "title", "tech", "protections")
                }
                for f in http_result.findings[:500]
            ],
        }
        await db.commit()

        return {
            "scan_id": str(scan_id),
            "phase": "recon",
            "status": "completed",
            "live_hosts": live_hosts,
            "count": len(live_hosts),
            **_phase_verdict(runs),
        }

    except Exception as e:
        logger.error("discovery_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.vuln_scan", acks_late=True)
def vuln_scan(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 3: Vulnerability scanning with Nuclei + Nikto.

    Args:
        previous_result: Result from recon phase
        scan_id: The scan UUID as string

    Returns:
        Task result with vulnerability findings
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_vuln_scan, scan_uuid, previous_result))
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.VULN_SCAN, result))
        return result
    except Exception as e:
        logger.error("vuln_scan_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "vuln_scan", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_vuln_scan(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute vulnerability scanning phase."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    live_hosts = previous_result.get("live_hosts", [])
    if not live_hosts:
        live_hosts = (scan.checkpoint_data or {}).get("live_hosts", [])

    total_findings = 0

    try:
        from netra.services.finding_service import FindingService

        service = FindingService(db)

        # Nuclei: limits come from the scan profile, and the scan's own config can lower them.
        from netra.scanner.profiles import get_profile_config

        profile = get_profile_config(str(scan.profile))
        overrides = scan.config or {}
        profile_rate = int(profile.get("rate_limit", 150))
        nuclei_rate = min(int(overrides.get("rate_limit", profile_rate)), profile_rate)
        nuclei_severity = str(profile.get("severity_filter", "critical,high,medium"))

        runs: list[dict] = []
        nuclei = NucleiTool(work_dir=_phase_dir(scan_id, "nuclei"))
        for target in live_hosts[:50]:
            nuclei_result = await nuclei.run(
                target=target,
                severity=nuclei_severity,
                rate_limit=nuclei_rate,
            )
            _record_run(runs, "nuclei", target, nuclei_result)
            for f_data in nuclei_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="nuclei",
                    finding_data=f_data,
                )
            total_findings += len(nuclei_result.findings)

        # Nikto for web misconfigs
        nikto = NiktoTool(work_dir=_phase_dir(scan_id, "nikto"))
        nikto_enabled = bool(profile.get("use_nikto")) and bool(overrides.get("use_nikto", True))
        for target in live_hosts[:10] if nikto_enabled else []:
            nikto_result = await nikto.run(target=target)
            _record_run(runs, "nikto", target, nikto_result)
            for f_data in nikto_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="nikto",
                    finding_data=f_data,
                )
            total_findings += len(nikto_result.findings)

        return {
            "scan_id": str(scan_id),
            "phase": "vuln_scan",
            "status": "completed",
            "findings_count": total_findings,
            **_phase_verdict(runs),
        }

    except Exception as e:
        logger.error("vuln_scan_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.active_test", acks_late=True)
def active_test(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 4: Active exploitation testing (SQLi, XSS, directory fuzzing).

    Args:
        previous_result: Result from vuln_scan phase
        scan_id: The scan UUID as string

    Returns:
        Task result with penetration testing findings
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_active_test, scan_uuid, previous_result))
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.PENTEST, result))
        return result
    except Exception as e:
        logger.error("active_test_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "active_test", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_active_test(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute active penetration testing phase."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    live_hosts = previous_result.get("live_hosts", [])
    if not live_hosts:
        live_hosts = (scan.checkpoint_data or {}).get("live_hosts", [])

    from netra.scanner.profiles import get_profile_config

    total_findings = 0
    # Intrusive tests run only when the profile enables them. The scan config can turn one off.
    profile = get_profile_config(str(scan.profile))
    overrides = scan.config or {}
    allow = {
        key: bool(profile.get(key)) and bool(overrides.get(key, True))
        for key in ("test_sqli", "test_xss", "test_dirs")
    }

    try:
        from netra.db.models.finding import Finding
        from netra.services.finding_service import FindingService

        service = FindingService(db)

        # Get parameterized URLs
        inject_result = await db.execute(
            select(Finding.url)
            .where(Finding.scan_id == scan_id)
            .where(Finding.url.isnot(None))
            .where(Finding.url.contains("?"))
        )
        injectable_urls = [row[0] for row in inject_result.fetchall() if row[0]][:20]

        runs: list[dict] = []
        # SQLi testing
        sqlmap = SqlmapTool(work_dir=_phase_dir(scan_id, "sqlmap"))
        for url in injectable_urls if allow["test_sqli"] else []:
            sqlmap_result = await sqlmap.run(target=url, safe_mode=True, level=1, risk=1)
            _record_run(runs, "sqlmap", url, sqlmap_result)
            for f_data in sqlmap_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="sqlmap",
                    finding_data=f_data,
                )
            total_findings += len(sqlmap_result.findings)

        # XSS testing
        dalfox = DalfoxTool(work_dir=_phase_dir(scan_id, "dalfox"))
        for url in injectable_urls if allow["test_xss"] else []:
            dalfox_result = await dalfox.run(target=url)
            _record_run(runs, "dalfox", url, dalfox_result)
            for f_data in dalfox_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="dalfox",
                    finding_data=f_data,
                )
            total_findings += len(dalfox_result.findings)

        # Directory fuzzing
        ffuf = FfufTool(work_dir=_phase_dir(scan_id, "ffuf"))
        for target in live_hosts[:10] if allow["test_dirs"] else []:
            ffuf_result = await ffuf.run(target=f"{target}/FUZZ", wordlist="common.txt")
            _record_run(runs, "ffuf", target, ffuf_result)
            for f_data in ffuf_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="ffuf",
                    finding_data=f_data,
                )
            total_findings += len(ffuf_result.findings)

        return {
            "scan_id": str(scan_id),
            "phase": "active_test",
            "status": "completed",
            "findings_count": total_findings,
            **_phase_verdict(runs),
        }

    except Exception as e:
        logger.error("active_test_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.ai_analysis", acks_late=True)
def ai_analysis(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 5: AI Brain analysis and enrichment.

    Args:
        previous_result: Result from active_test phase
        scan_id: The scan UUID as string

    Returns:
        Task result with AI-enriched findings
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_ai_analysis, scan_uuid, previous_result))
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.AI_ANALYSIS, result))
        return result
    except Exception as e:
        logger.error("ai_analysis_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "ai_analysis", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_ai_analysis(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute AI analysis phase."""
    from netra.ai.brain import AIBrain
    from netra.db.models.finding import Finding

    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    try:
        brain = AIBrain()
        findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
        findings = list(findings_result.scalars().all())

        enriched_count = 0
        for finding in findings:
            enriched = await brain.analyze_finding(finding)
            if enriched:
                finding.ai_analysis = enriched
                finding.confidence = enriched.get("confidence", finding.confidence)
                enriched_count += 1

        # Attack chain discovery
        chains = await brain.discover_attack_chains(findings)
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "attack_chains": chains,
        }
        await db.commit()

        return {
            "scan_id": str(scan_id),
            "phase": "ai_analysis",
            "status": "completed",
            "enriched_count": enriched_count,
            "chains_discovered": len(chains),
        }

    except Exception as e:
        logger.error("ai_analysis_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.reporting", acks_late=True)
def reporting(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 6: Report generation.

    Args:
        previous_result: Result from ai_analysis phase
        scan_id: The scan UUID as string

    Returns:
        Task result with report information
    """
    scan_uuid = uuid.UUID(scan_id)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_reporting, scan_uuid, previous_result))
        asyncio.run(_in_session(_update_phase_status, scan_uuid, PhaseType.REPORTING, result))
        # The phase tasks report failure in their return value instead of raising, so the
        # chain keeps going. Use the previous phase's status to decide the final state.
        upstream_failed = (
            isinstance(previous_result, dict) and previous_result.get("status") == "failed"
        )
        problems = asyncio.run(_in_session(_phase_problems, scan_uuid))
        if upstream_failed or problems:
            error = problems or str(previous_result.get("error") or "upstream phase failed")
            asyncio.run(
                _update_scan_row(
                    scan_uuid,
                    status=ScanStatus.FAILED,
                    error_message=error,
                    completed_at=datetime.now(UTC),
                )
            )
        else:
            asyncio.run(
                _update_scan_row(
                    scan_uuid, status=ScanStatus.COMPLETED, completed_at=datetime.now(UTC)
                )
            )
        return result
    except Exception as e:
        logger.error("reporting_failed", scan_id=scan_id, error=str(e))
        try:
            asyncio.run(
                _update_scan_row(
                    scan_uuid,
                    status=ScanStatus.FAILED,
                    error_message=f"reporting: {e}"[:2000],
                    completed_at=datetime.now(UTC),
                )
            )
        except Exception as update_exc:
            logger.error("scan_status_update_failed", scan_id=scan_id, error=str(update_exc))
        return {"scan_id": scan_id, "phase": "reporting", "status": "failed", "error": str(e)}
    finally:
        pass


async def _execute_reporting(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute report generation phase."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    # Reports are generated on demand from the Reports page (POST /reports/{scan_id}/generate).
    # This phase used to call netra.reports.report_generator, which does not exist, so it
    # now records that no report was generated here instead of failing the scan.
    return {
        "scan_id": str(scan_id),
        "phase": "reporting",
        "status": "completed",
        "reports_generated": [],
        "note": "auto-report generation not wired; generate from the Reports page",
    }


# A phase that never wrote a completed row counts as failed. This covers a phase whose
# status write itself raised, which used to leave no row and so pass unnoticed.
REQUIRED_PHASES = (
    PhaseType.SCOPE,
    PhaseType.RECON_DISCOVERY,
    PhaseType.VULN_SCAN,
    PhaseType.PENTEST,
    PhaseType.AI_ANALYSIS,
)


async def _phase_problems(db: AsyncSession, scan_id: uuid.UUID) -> str | None:
    """Required phases that did not complete, or None when all of them did."""
    result = await db.execute(select(ScanPhase).where(ScanPhase.scan_id == scan_id))
    status_by_type = {str(p.phase_type): str(p.status) for p in result.scalars().all()}
    ok = {str(PhaseStatus.COMPLETED), str(PhaseStatus.SKIPPED)}
    problems = []
    for phase in REQUIRED_PHASES:
        status = status_by_type.get(str(phase))
        if status not in ok:
            problems.append(f"{phase}={status or 'missing'}")
    return f"phases not completed: {', '.join(problems)}" if problems else None


async def _update_phase_status(
    db: AsyncSession,
    scan_id: uuid.UUID,
    phase_type: PhaseType,
    result: dict,
) -> None:
    """Update or create scan phase status."""
    # Find existing phase or create new
    phase_result = await db.execute(
        select(ScanPhase)
        .where(ScanPhase.scan_id == scan_id)
        .where(ScanPhase.phase_type == phase_type)
    )
    phase = phase_result.scalar_one_or_none()

    if not phase:
        phase = ScanPhase(
            scan_id=scan_id,
            phase_type=phase_type,
            status=PhaseStatus.COMPLETED
            if result.get("status") == "completed"
            else PhaseStatus.FAILED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            findings_count=result.get("findings_count", result.get("count", 0)),
        )
        phase.error_message = _phase_note(result)
        db.add(phase)
    else:
        phase.status = (
            PhaseStatus.COMPLETED if result.get("status") == "completed" else PhaseStatus.FAILED
        )
        phase.completed_at = datetime.now(UTC)
        phase.findings_count = result.get("findings_count", result.get("count", 0))
        phase.error_message = _phase_note(result)

    await db.commit()


def create_scan_pipeline(scan_id: str) -> chain:
    """Create the full scan pipeline as a Celery chain.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Celery chain of tasks
    """
    return chain(
        scope_resolution.s(scan_id),
        recon.s(scan_id=scan_id),
        vuln_scan.s(scan_id=scan_id),
        active_test.s(scan_id=scan_id),
        ai_analysis.s(scan_id=scan_id),
        reporting.s(scan_id=scan_id),
    )


async def _in_session(fn: Any, *args: Any) -> Any:
    """Run one async helper with its own session, so nothing crosses an event loop."""
    async with _get_db_session() as session:
        return await fn(session, *args)


async def _update_scan_row(scan_uuid: uuid.UUID, **fields: Any) -> None:
    """Update one scan row in a fresh session, so no session outlives its event loop."""
    async with _get_db_session() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()
        if scan is None:
            return
        for name, value in fields.items():
            setattr(scan, name, value)
        await session.commit()


@celery_app.task(bind=True, name="netra.run_scan", acks_late=True)
def run_scan(self, scan_id: str) -> dict:
    """Main entry point for running a scan via Celery.

    This task orchestrates the full scan pipeline by executing
    the chain of phase tasks.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Final scan result summary
    """
    scan_uuid = uuid.UUID(scan_id)
    task_id = _task_request_id(self)
    task_token = set_current_task_id(task_id)

    try:
        import asyncio

        # Each status write opens its own session. A session must not be reused across
        # asyncio.run() calls, because asyncpg binds connections to the loop that created them.
        asyncio.run(
            _update_scan_row(scan_uuid, status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
        )

        # Execute the pipeline
        # Queue the phase chain. The last phase (reporting) sets COMPLETED or FAILED, so the
        # scan is not marked finished here, before any phase has run.
        pipeline = create_scan_pipeline(scan_id)
        queued = pipeline.apply_async()

        return {
            "scan_id": scan_id,
            "status": "enqueued",
            "pipeline_task_id": str(queued.id),
        }

    except Exception as e:
        logger.error("scan_failed", scan_id=scan_id, error=str(e))
        error_text = str(e)
        asyncio.run(
            _update_scan_row(
                scan_uuid,
                status=ScanStatus.FAILED,
                error_message=error_text,
                completed_at=datetime.now(UTC),
            )
        )
        return {"scan_id": scan_id, "status": "failed", "error": error_text}
    finally:
        if task_id:
            clear_task_registry(task_id)
        reset_current_task_id(task_token)


@celery_app.task(bind=True, name="netra.run_bugbounty_scan", acks_late=True)
def run_bugbounty_scan(self, scan_id: str) -> dict:
    """Run a NETRA-BB scan through the orchestrator."""
    scan_uuid = uuid.UUID(scan_id)
    task_id = _task_request_id(self)
    task_token = set_current_task_id(task_id)

    try:
        import asyncio

        async def execute(db: AsyncSession):
            from netra.db.models.finding import Finding
            from netra.scanner.orchestrator import ScanOrchestrator

            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(UTC)
                scan.config = {
                    **(scan.config or {}),
                    "celery_task_id": task_id,
                }
                await db.commit()

            orchestrator = ScanOrchestrator(db, scan_uuid)
            await orchestrator.execute()

            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if not scan:
                return {"scan_id": scan_id, "status": "failed", "error": "Scan not found"}

            findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_uuid))
            findings = list(findings_result.scalars().all())
            scan.checkpoint_data = {
                **(scan.checkpoint_data or {}),
                "findings_summary": {
                    "total": len(findings),
                    "by_severity": {
                        sev: sum(1 for f in findings if str(f.severity) == sev)
                        for sev in ["critical", "high", "medium", "low", "info"]
                    },
                },
            }
            scan.config = {
                **(scan.config or {}),
                "celery_task_id": task_id,
            }
            await db.commit()
            return {"scan_id": scan_id, "status": str(scan.status), "findings": len(findings)}

        return asyncio.run(_in_session(execute))
    except Exception as e:
        logger.error("bb_scan_failed", scan_id=scan_id, error=str(e))
        error_text = str(e)
        if task_id:
            kill_registered_processes(task_id)

        async def fail_scan(db: AsyncSession):
            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = error_text
                scan.completed_at = datetime.now(UTC)
                await db.commit()

        asyncio.run(_in_session(fail_scan))
        return {"scan_id": scan_id, "status": "failed", "error": error_text}
    finally:
        if task_id:
            clear_task_registry(task_id)
        reset_current_task_id(task_token)


@celery_app.task(bind=True, name="netra.export_bugbounty_submissions")
def export_bugbounty_submissions(self) -> dict:
    """Export submissions to Graphify JSON."""
    import asyncio

    async def run(db: AsyncSession) -> dict:
        from netra.bugbounty.graph_indexer import export_submissions_json
        from netra.db.models.bb_submission import BBSubmission

        result = await db.execute(select(BBSubmission))
        rows = result.scalars().all()
        records = [
            {
                "id": s.id,
                "title": s.title,
                "severity": s.severity,
                "status": s.status,
                "program_id": s.program_id,
                "finding_id": s.finding_id,
                "vuln_class": (s.metadata_ or {}).get("vuln_class"),
                "asset_path": (s.metadata_ or {}).get("asset_path"),
            }
            for s in rows
        ]
        path = export_submissions_json(records, Path("data/graphify/submissions.json"))
        return {"status": "completed", "count": len(records), "path": str(path)}

    return asyncio.run(_in_session(run))


@celery_app.task(bind=True, name="netra.ingest_hacktivity_daily", max_retries=3)
def ingest_hacktivity_daily(self) -> dict:
    """Ingest newly disclosed HackerOne hacktivity into the local corpus."""
    import asyncio

    try:

        async def run(db: AsyncSession) -> dict:
            from netra.bugbounty.learning.sources.hackerone import ingest_hacktivity

            return await ingest_hacktivity(db, since_days=1)

        result = asyncio.run(_in_session(run))
        return {"status": "completed", **result}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1)) from exc


@celery_app.task(bind=True, name="netra.ingest_advisories_daily", max_retries=3)
def ingest_advisories_daily(self) -> dict:
    """Ingest GHSA and NVD advisories into the local corpus."""
    import asyncio

    try:

        async def run(db: AsyncSession) -> dict:
            from netra.bugbounty.learning.sources.advisories import ingest_advisories

            return await ingest_advisories(db)

        result = asyncio.run(_in_session(run))
        return {"status": "completed", **result}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1)) from exc


@celery_app.task(bind=True, name="netra.ingest_public_writeups", max_retries=3)
def ingest_public_writeups(self) -> dict:
    """Ingest public RSS writeups into the local corpus."""
    import asyncio

    try:

        async def run(db: AsyncSession) -> dict:
            from netra.bugbounty.learning.sources.rss import ingest_public_writeups

            return await ingest_public_writeups(db)

        result = asyncio.run(_in_session(run))
        return {"status": "completed", **result}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1)) from exc


@celery_app.task(bind=True, name="netra.ingest_public_signatures", max_retries=3)
def ingest_public_signatures(self) -> dict:
    """Refresh the chaos index, the nuclei-templates and Wappalyzer heads, and Bugcrowd."""
    import asyncio

    try:

        async def run(db: AsyncSession) -> dict:
            from netra.bugbounty.learning.sources.bugcrowd import ingest_bugcrowd_disclosures
            from netra.bugbounty.learning.sources.signatures import (
                ingest_chaos_index,
                ingest_repo_heads,
            )

            chaos = await ingest_chaos_index(db)
            heads = await ingest_repo_heads(db)
            bugcrowd = await ingest_bugcrowd_disclosures(db)
            return {"chaos": chaos, "repo_heads": heads, "bugcrowd": bugcrowd}

        result = asyncio.run(_in_session(run))
        return {"status": "completed", **result}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1)) from exc


@celery_app.task(bind=True, name="netra.resync_all_active_programs", max_retries=3)
def resync_all_active_programs(self) -> dict:
    """Nightly scope resync for active H1 programs."""
    import asyncio

    try:

        async def run(db: AsyncSession) -> dict:
            from netra.bugbounty.programs import replace_scope_rules
            from netra.db.models.bb_program import BBPlatform, BBProgram
            from netra.integrations.hackerone import HackerOneClient
            from netra.notifications.bugbounty import notify_scope_diff

            result = await db.execute(select(BBProgram).where(BBProgram.active.is_(True)))
            programs = list(result.scalars().all())
            changed = 0
            async with HackerOneClient() as h1:
                for program in programs:
                    if program.platform != BBPlatform.HACKERONE or not h1.is_configured():
                        continue
                    rules = await h1.get_structured_scopes(program.handle)
                    diff = await replace_scope_rules(db, program, rules)
                    if diff.has_changes:
                        changed += 1
                        await notify_scope_diff(program, diff)
            await db.commit()
            return {"status": "completed", "programs": len(programs), "changed": changed}

        return asyncio.run(_in_session(run))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1)) from exc


@celery_app.task(name="netra.scanner_tool_inventory")
def scanner_tool_inventory() -> list[dict]:
    """Report which scanner binaries exist in the worker image (the image that runs scans)."""
    from netra.scanner.tools.inventory import tool_inventory

    return tool_inventory()
