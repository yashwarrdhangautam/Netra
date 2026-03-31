"""Celery tasks for distributed scan execution."""
import uuid
from datetime import UTC, datetime
from pathlib import Path

import structlog
from celery import chain
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.scanner.tools.amass import AmassTool
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.nikto import NiktoTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.scanner.tools.subfinder import SubfinderTool
from netra.worker.celery_app import celery_app

logger = structlog.get_logger()


def _get_db_session() -> AsyncSession:
    """Create a new database session for task execution."""
    from netra.db.session import AsyncSessionLocal

    return AsyncSessionLocal()


def _phase_dir(scan_id: uuid.UUID, phase_type: str) -> Path:
    """Get working directory for a phase."""
    d = Path.home() / ".netra" / "scans" / str(scan_id)[:8] / phase_type
    d.mkdir(parents=True, exist_ok=True)
    return d


@celery_app.task(bind=True, name="netra.scope_resolution", acks_late=True)
def scope_resolution(self, scan_id: str) -> dict:
    """Phase 1: Resolve and validate scan targets.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Task result with target information
    """
    scan_uuid = uuid.UUID(scan_id)
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_scope_resolution(db, scan_uuid))

        # Update phase status
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.RECON_SUBDOMAINS, result))

        return result
    except Exception as e:
        logger.error("scope_resolution_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "scope", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_scope_resolution(db: AsyncSession, scan_id: uuid.UUID) -> dict:
    """Execute scope resolution phase."""

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    target = scan.target.value
    all_subdomains: set[str] = set()

    try:
        # Subfinder
        subfinder = SubfinderTool(work_dir=_phase_dir(scan_id, "subdomains"))
        sub_result = await subfinder.run(target)
        for f in sub_result.findings:
            if hostname := f.get("hostname") or f.get("url", ""):
                all_subdomains.add(hostname)

        # Amass (if deep profile)
        if scan.profile in ["deep", "comprehensive"]:
            amass = AmassTool(work_dir=_phase_dir(scan_id, "amass"))
            amass_result = await amass.run(target)
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
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_recon(db, scan_uuid, previous_result))
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.RECON_DISCOVERY, result))
        return result
    except Exception as e:
        logger.error("recon_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "recon", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_recon(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute reconnaissance phase."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
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
        http_result = await httpx_tool.run(
            target=",".join(subdomains[:50]),
            follow_redirects=True,
            tech_detect=True,
        )

        live_hosts = [
            f.get("url", "")
            for f in http_result.findings
            if f.get("status_code", 0) in range(200, 500)
        ]

        # Save checkpoint
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "live_hosts": live_hosts,
        }
        await db.commit()

        return {
            "scan_id": str(scan_id),
            "phase": "recon",
            "status": "completed",
            "live_hosts": live_hosts,
            "count": len(live_hosts),
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
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_vuln_scan(db, scan_uuid, previous_result))
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.VULN_SCAN, result))
        return result
    except Exception as e:
        logger.error("vuln_scan_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "vuln_scan", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_vuln_scan(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute vulnerability scanning phase."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
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

        # Nuclei
        nuclei = NucleiTool(work_dir=_phase_dir(scan_id, "nuclei"))
        for target in live_hosts[:50]:
            nuclei_result = await nuclei.run(
                target=target,
                severity="critical,high,medium",
                rate_limit=150,
            )
            for f_data in nuclei_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="nuclei",
                    finding_data=f_data,
                )
            total_findings += len(nuclei_result.findings)

        # Nikto for web misconfigs
        nikto = NiktoTool(work_dir=_phase_dir(scan_id, "nikto"))
        for target in live_hosts[:10]:
            nikto_result = await nikto.run(target=target)
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
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_active_test(db, scan_uuid, previous_result))
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.PENTEST, result))
        return result
    except Exception as e:
        logger.error("active_test_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "active_test", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_active_test(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute active penetration testing phase."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    live_hosts = previous_result.get("live_hosts", [])
    if not live_hosts:
        live_hosts = (scan.checkpoint_data or {}).get("live_hosts", [])

    total_findings = 0

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

        # SQLi testing
        sqlmap = SqlmapTool(work_dir=_phase_dir(scan_id, "sqlmap"))
        for url in injectable_urls:
            sqlmap_result = await sqlmap.run(target=url, safe_mode=True, level=1, risk=1)
            for f_data in sqlmap_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="sqlmap",
                    finding_data=f_data,
                )
            total_findings += len(sqlmap_result.findings)

        # XSS testing
        dalfox = DalfoxTool(work_dir=_phase_dir(scan_id, "dalfox"))
        for url in injectable_urls:
            dalfox_result = await dalfox.run(target=url)
            for f_data in dalfox_result.findings:
                await service.create_finding_from_tool(
                    scan_id=scan_id,
                    tool_name="dalfox",
                    finding_data=f_data,
                )
            total_findings += len(dalfox_result.findings)

        # Directory fuzzing
        ffuf = FfufTool(work_dir=_phase_dir(scan_id, "ffuf"))
        for target in live_hosts[:10]:
            ffuf_result = await ffuf.run(target=f"{target}/FUZZ", wordlist="common.txt")
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
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_ai_analysis(db, scan_uuid, previous_result))
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.AI_ANALYSIS, result))
        return result
    except Exception as e:
        logger.error("ai_analysis_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "ai_analysis", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_ai_analysis(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute AI analysis phase."""
    from netra.ai.brain import AIBrain
    from netra.db.models.finding import Finding

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    try:
        brain = AIBrain()
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
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
    db = _get_db_session()

    try:
        import asyncio

        result = asyncio.run(_execute_reporting(db, scan_uuid, previous_result))
        asyncio.run(_update_phase_status(db, scan_uuid, PhaseType.REPORTING, result))
        return result
    except Exception as e:
        logger.error("reporting_failed", scan_id=scan_id, error=str(e))
        return {"scan_id": scan_id, "phase": "reporting", "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())


async def _execute_reporting(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute report generation phase."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    try:
        # Generate default reports
        from netra.reports.report_generator import ReportGenerator

        generator = ReportGenerator(db)
        reports_generated = []

        # Generate executive summary
        exec_report = await generator.generate_report(
            scan_id=scan_id,
            report_type="executive_pdf",
        )
        if exec_report:
            reports_generated.append(str(exec_report.id))

        # Generate technical report
        tech_report = await generator.generate_report(
            scan_id=scan_id,
            report_type="technical_docx",
        )
        if tech_report:
            reports_generated.append(str(tech_report.id))

        return {
            "scan_id": str(scan_id),
            "phase": "reporting",
            "status": "completed",
            "reports_generated": reports_generated,
        }

    except Exception as e:
        logger.error("reporting_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


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
            status=PhaseStatus.COMPLETED if result.get("status") == "completed" else PhaseStatus.FAILED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            findings_count=result.get("findings_count", result.get("count", 0)),
        )
        db.add(phase)
    else:
        phase.status = PhaseStatus.COMPLETED if result.get("status") == "completed" else PhaseStatus.FAILED
        phase.completed_at = datetime.now(UTC)
        phase.findings_count = result.get("findings_count", result.get("count", 0))
        if result.get("status") == "failed":
            phase.error_message = result.get("error", "Unknown error")

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
    db = _get_db_session()

    try:
        import asyncio

        # Update scan status
        async def update_status():
            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(UTC)
                await db.commit()

        asyncio.run(update_status())

        # Execute the pipeline
        pipeline = create_scan_pipeline(scan_id)
        result = pipeline()

        # Mark scan complete
        async def complete_scan():
            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(UTC)
                await db.commit()

        asyncio.run(complete_scan())

        return {
            "scan_id": scan_id,
            "status": "completed",
            "pipeline_result": result,
        }

    except Exception as e:
        logger.error("scan_failed", scan_id=scan_id, error=str(e))

        async def fail_scan(error_msg: str):
            result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = error_msg
                scan.completed_at = datetime.now(UTC)
                await db.commit()

        asyncio.run(fail_scan(str(e)))

        return {"scan_id": scan_id, "status": "failed", "error": str(e)}
    finally:
        asyncio.run(db.close())
