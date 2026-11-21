"""Celery tasks for distributed scan execution."""

import functools
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from celery import chain
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.scanner.passive import (
    PassivePosture,
    analyze_discovered_names,
    analyze_headers,
    probe_tls,
)
from netra.scanner.scope_gate import compile_rules
from netra.scanner.tools.base import RUN_GUARD
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.nikto import NiktoTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.process_control import (
    clear_task_registry,
    kill_registered_processes,
    reset_current_task_id,
    set_current_task_id,
)
from netra.scanner.tools.recontool import RecontoolTool, is_plain_hostname
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.services.scan_authorization import (
    AuthorizationDenied,
    require_scan_authorization,
    require_target_action,
)
from netra.worker.celery_app import celery_app

logger = structlog.get_logger()


async def _policy_failure(db: AsyncSession, scan_id: uuid.UUID, code: str) -> dict[str, Any]:
    scan = await db.get(Scan, scan_id)
    if scan is not None:
        if scan.status != ScanStatus.CANCELLED:
            scan.status = ScanStatus.FAILED
        scan.error_message = code
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "policy_denial": code,
        }
        await db.commit()
    return {"status": "failed", "error": code, "policy_denial": code}


async def _require_action(
    db: AsyncSession,
    scan: Scan,
    candidate: str,
    action: str,
    method: str | None = None,
) -> None:
    try:
        await require_target_action(
            db,
            scan.target_id,
            candidate,
            action,
            method=method,
            snapshot=(scan.checkpoint_data or {}).get("authorization_snapshot"),
        )
    except AuthorizationDenied as exc:
        await _policy_failure(db, scan.id, exc.code)
        raise


async def _authorize_dispatch(db: AsyncSession, scan_id: uuid.UUID) -> None:
    await require_scan_authorization(db, scan_id)


def _get_db_session() -> AsyncSession:
    """Create a new database session for task execution."""
    from netra.db.session import async_session_factory

    return async_session_factory()


RUN_STATES = {"completed", "skipped", "unavailable", "failed", "parse_error"}


def _record_unavailable(runs: list[dict], tool: str, target: str, reason: str) -> None:
    """A tool the phase intends to run but cannot yet: visible as missing coverage."""
    runs.append(
        {
            "tool": tool,
            "target": str(target)[:200],
            "success": False,
            "error": reason,
            "state": "unavailable",
            "reason_code": reason,
            "findings_count": None,
            "truncated": False,
        }
    )


def _passive_host(target: str) -> str | None:
    """The plain hostname to run passive discovery on, or None for IPs, ranges and lists."""
    from urllib.parse import urlsplit

    value = target.strip().lower()
    host = urlsplit(value).hostname if "://" in value else value
    return host if host and is_plain_hostname(host) else None


def _recontool_findings(rows: list[dict]) -> list[dict]:
    """Recontool's own findings as NETRA findings. Asset and endpoint rows are not findings."""
    findings = []
    for row in rows:
        if row.get("kind") != "finding":
            continue
        findings.append(
            {
                "title": row["title"],
                "severity": row.get("severity") or "info",
                "description": f"Reported by Recontool detector {row.get('detector') or 'unknown'}.",
                "url": row.get("asset"),
                "evidence": {"cve": row.get("cve"), "recontool": row.get("evidence")},
                "tags": ["recontool", "passive"],
            }
        )
    return findings


async def _analyze_http(db: AsyncSession, scan: Scan, runs: list[dict], rows: list[dict]) -> None:
    """Header and TLS findings for hosts the recon probe already reached.

    Everything here talks only to a host/port that passed the http_probe gate; the TLS check
    re-asks the gate for its own destination before connecting.
    """
    from urllib.parse import urlsplit

    findings: list[dict] = []
    tls_seen: set[tuple[str, int]] = set()
    for row in rows:
        url = str(row.get("url") or "")
        if not url or row.get("status_code") not in range(100, 600):
            continue
        if row.get("headers") is not None:
            findings += analyze_headers(url, row["headers"])
        parts = urlsplit(url)
        if parts.scheme == "https" and parts.hostname:
            key = (parts.hostname, parts.port or 443)
            if key in tls_seen:
                continue
            tls_seen.add(key)
            await _require_action(db, scan, f"https://{key[0]}:{key[1]}", "http_probe", "GET")
            tls_result = await probe_tls(key[0], key[1])
            _record_run(runs, "tls_probe", key[0], tls_result)
            findings += tls_result.findings
    await _persist_findings(db, scan.id, "http_analysis", findings)


async def _persist_findings(db: AsyncSession, scan_id: uuid.UUID, tool: str, findings: list) -> int:
    """Save tool findings with the shared dedup rules. Returns how many were new."""
    from netra.services.finding_service import FindingService

    service = FindingService(db)
    created = 0
    for data in findings:
        if await service.create_finding_from_tool(
            scan_id=scan_id, tool_name=tool, finding_data=data
        ):
            created += 1
    return created


def _record_run(runs: list[dict], tool: str, target: str, result: Any) -> None:
    """Keep one tool run with a coverage state, so the scan can show what was really covered.

    State follows spec 6.2. A run that exited cleanly but whose output was truncated or
    could not be read is not `completed`, even though the phase counts it as a success.
    """
    raw_metadata = getattr(result, "metadata", None)
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
    truncated = bool(metadata.get("output_truncated") or metadata.get("truncated"))
    if truncated:
        state, reason = "parse_error", "output_truncated"
    elif metadata.get("state") in RUN_STATES:
        state, reason = metadata["state"], metadata.get("reason_code")
    elif result.success:
        state, reason = "completed", None
    else:
        state, reason = "failed", None
    if not reason and result.error:
        reason = str(result.error)[:120]
    runs.append(
        {
            "tool": tool,
            "target": str(target)[:200],
            "success": bool(result.success),
            "error": result.error,
            "state": state,
            "reason_code": reason if isinstance(reason, str) else None,
            "findings_count": len(getattr(result, "findings", []) or [])
            if state == "completed"
            else None,
            "truncated": truncated,
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


# The phase chain every supported web-target profile runs, in order. The chain is built
# from this list, so a test can compare what runs with what is declared.
WEB_PIPELINE_PHASES = (
    "scope_resolution",
    "recon",
    "vuln_scan",
    "active_test",
    "ai_analysis",
    "reporting",
)

STOP_STATES = (ScanStatus.CANCELLED, ScanStatus.PAUSED)
CLAIMABLE_STATES = (ScanStatus.PENDING, ScanStatus.PAUSED, ScanStatus.FAILED)


async def _stop_requested(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """True when the scan was cancelled or paused, or no longer exists."""
    scan = await db.get(Scan, scan_id)
    return scan is None or scan.status in STOP_STATES


# A running scan with no heartbeat for this long belonged to a worker that stopped.
HEARTBEAT_SECONDS = 30
STALE_AFTER = timedelta(minutes=20)


def _run_guard(scan_uuid: uuid.UUID):
    """Checked every few seconds while a tool runs. Returns True when the tool must stop.

    It also refreshes the scan's updated_at (the heartbeat), so a restarted worker can tell a
    crashed run from one that is still working.
    """
    import time

    last_beat = [0.0]

    async def check() -> bool:
        async with _get_db_session() as session:
            status = await session.scalar(select(Scan.status).where(Scan.id == scan_uuid))
            if status is None or status in STOP_STATES:
                return True
            now = time.monotonic()
            if now - last_beat[0] >= HEARTBEAT_SECONDS:
                last_beat[0] = now
                await session.execute(
                    update(Scan).where(Scan.id == scan_uuid).values(updated_at=func.now())
                )
                await session.commit()
            return False

    return check


@contextmanager
def _guarded(scan_uuid: uuid.UUID):
    """Attach the cancel and heartbeat guard to every tool run inside the block."""
    token = RUN_GUARD.set(_run_guard(scan_uuid))
    try:
        yield
    finally:
        RUN_GUARD.reset(token)


async def _claim_scan(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Move the scan to running in one conditional write. Only one delivery can win.

    A RUNNING scan whose heartbeat is older than STALE_AFTER belonged to a stopped worker, so
    it can be claimed again. A live run keeps its heartbeat fresh and is never taken over.
    """
    stale_before = datetime.now(UTC) - STALE_AFTER
    result = await db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            or_(
                Scan.status.in_(CLAIMABLE_STATES),
                and_(Scan.status == ScanStatus.RUNNING, Scan.updated_at < stale_before),
            ),
        )
        .values(status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
        # The database decides the claim; do not re-evaluate the criteria in Python, where
        # SQLite's naive timestamps cannot be compared with the aware cutoff.
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return result.rowcount == 1


def _stop_at_boundary(fn: Any) -> Any:
    """Check for cancel or pause before a phase runs, so a stop takes effect between tools."""

    @functools.wraps(fn)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        import asyncio

        scan_id = kwargs.get("scan_id", args[-1] if args else None)
        if asyncio.run(_in_session(_stop_requested, uuid.UUID(str(scan_id)))):
            return {
                "scan_id": str(scan_id),
                "phase": fn.__name__,
                "status": "stopped",
                "stopped": True,
            }
        return fn(self, *args, **kwargs)

    return wrapper


@celery_app.task(bind=True, name="netra.scope_resolution", acks_late=True)
@_stop_at_boundary
def scope_resolution(self, scan_id: str) -> dict:
    """Phase 1: Resolve and validate scan targets.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Task result with target information
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        with _guarded(scan_uuid):
            result = asyncio.run(_in_session(_execute_scope_resolution, scan_uuid))

        # Update phase status
        asyncio.run(
            _in_session(_update_phase_status, scan_uuid, PhaseType.SCOPE, result, phase_started)
        )

        return result
    except Exception as e:
        logger.error("scope_resolution_failed", scan_id=scan_id, error=str(e))
        failed = {"scan_id": scan_id, "phase": "scope", "status": "failed", "error": str(e)}
        _record_phase_crash(scan_uuid, PhaseType.SCOPE, failed, phase_started)
        return failed
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

    try:
        scan, _, record, _ = await require_scan_authorization(db, scan_id)
    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)

    target = scan.target.value
    runs: list[dict] = []
    try:
        await _require_action(db, scan, target, "passive_recon")

        host = _passive_host(target)
        if host is None:
            # IPs and ranges have no passive hostname sources; recon probes the target as given.
            return {
                "scan_id": str(scan_id),
                "phase": "scope",
                "status": "completed",
                "subdomains": [target],
                "count": 1,
                "runs": runs,
            }

        validator = compile_rules(scan.target)

        def in_scope(name: str) -> bool:
            return validator.check(name).allowed

        # Discovery is Recontool, hard-wired to passive_only with active phases never authorised
        # here: that profile contacts third-party sources only, never the target, so the signed
        # per-second budget (which governs target traffic) does not apply to it. The DNS posture
        # lookups go to a public resolver and are throttled to that budget anyway.
        discovery = await RecontoolTool(work_dir=_phase_dir(scan_id, "scope")).run(
            host, profile="passive_only", authorize_active=False
        )
        _record_run(runs, "recontool", host, discovery)
        posture = await PassivePosture(
            host, max_requests_per_second=record.max_requests_per_second
        ).run()
        _record_run(runs, "passive_posture", host, posture)

        names = sorted(
            {
                row["value"].lower().rstrip(".")
                for row in discovery.findings
                if row.get("kind") == "asset" and is_plain_hostname(str(row.get("value", "")))
            }
        )
        zone = str(posture.metadata.get("zone") or host)
        await _persist_findings(db, scan_id, "recontool", _recontool_findings(discovery.findings))
        await _persist_findings(
            db,
            scan_id,
            "passive_posture",
            [*posture.findings, *analyze_discovered_names(zone, names, host, in_scope)],
        )

        # Only names the scope rules already allow move on to the recon phase; the rest stay
        # observations. Recon re-checks every one against the signed action policy.
        subdomains = [host, *[n for n in names if n != host and in_scope(n)]][:50]
        scan.checkpoint_data = {
            **(scan.checkpoint_data or {}),
            "subdomains": subdomains,
            "passive_zone": zone,
            "passive_names_observed": len(names),
        }
        await db.commit()

        return {
            "scan_id": str(scan_id),
            "phase": "scope",
            "status": "completed",
            "subdomains": subdomains,
            "count": len(subdomains),
            "runs": runs,
            **_phase_verdict(runs),
        }

    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)
    except Exception as e:
        logger.error("subdomain_enum_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.recon", acks_late=True)
@_stop_at_boundary
def recon(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 2: Passive reconnaissance and live host discovery.

    Args:
        previous_result: Result from scope resolution
        scan_id: The scan UUID as string

    Returns:
        Task result with live hosts
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        with _guarded(scan_uuid):
            result = asyncio.run(_in_session(_execute_recon, scan_uuid, previous_result))
        asyncio.run(
            _in_session(
                _update_phase_status, scan_uuid, PhaseType.RECON_DISCOVERY, result, phase_started
            )
        )
        return result
    except Exception as e:
        logger.error("recon_failed", scan_id=scan_id, error=str(e))
        failed = {"scan_id": scan_id, "phase": "recon", "status": "failed", "error": str(e)}
        _record_phase_crash(scan_uuid, PhaseType.RECON_DISCOVERY, failed, phase_started)
        return failed
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

    try:
        scan, _, record, _ = await require_scan_authorization(db, scan_id)
    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)

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
        probe_urls: list[str] = []
        for candidate in subdomains[:50]:
            if "://" in candidate:
                urls = [candidate]
            else:
                # httpx otherwise chooses ports implicitly, outside the signed policy.
                host = f"[{candidate}]" if ":" in candidate else candidate
                urls = [
                    f"{scheme}://{host}:{port}"
                    for scheme, port in (("http", 80), ("https", 443))
                    if port in record.ports
                ]
                if not urls:
                    raise AuthorizationDenied("adapter_unavailable")
            for url in urls:
                await _require_action(db, scan, url, "http_probe", "GET")
                probe_urls.append(url)
        http_result = await httpx_tool.run(
            target=",".join(probe_urls),
            follow_redirects=False,
            tech_detect=True,
            rate_limit=record.max_requests_per_second,
        )
        _record_run(runs, "httpx", ",".join(subdomains[:50]), http_result)
        await _analyze_http(db, scan, runs, http_result.findings)

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
            "runs": runs,
            **_phase_verdict(runs),
        }

    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)
    except Exception as e:
        logger.error("discovery_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


# A vuln scan held to a low grant rate (1 rps) needs hours for the full template set, so this
# phase gets its own limit. The broker visibility_timeout in celery_app.py must stay above it.
VULN_SCAN_SOFT_LIMIT = 10 * 3600
VULN_SCAN_TIME_LIMIT = VULN_SCAN_SOFT_LIMIT + 300
# Time kept back from the phase budget for nikto bookkeeping, the phase write, and shutdown.
_VULN_SCAN_MARGIN = 600


# Share of the phase budget nuclei gets when nikto also runs; nikto gets the rest. Nikto's
# filtered run is ~4,700 requests per host (~80 min at 1 rps), so 30% covers two hosts.
_NUCLEI_SHARE_WITH_NIKTO = 0.70


def _phase_budget(share: float) -> int:
    return int((VULN_SCAN_SOFT_LIMIT - _VULN_SCAN_MARGIN) * share)


def _nuclei_timeout(host_count: int, nikto_hosts: int = 0) -> int:
    """Per-host nuclei timeout: its share of the phase budget, never below 5 minutes."""
    share = _NUCLEI_SHARE_WITH_NIKTO if nikto_hosts else 1.0
    return max(300, _phase_budget(share) // max(1, host_count))


def _nikto_timeout(host_count: int) -> int:
    """Per-host nikto timeout: the budget nuclei leaves, never below 5 minutes."""
    return max(300, _phase_budget(1 - _NUCLEI_SHARE_WITH_NIKTO) // max(1, host_count))


@celery_app.task(
    bind=True,
    name="netra.vuln_scan",
    acks_late=True,
    soft_time_limit=VULN_SCAN_SOFT_LIMIT,
    time_limit=VULN_SCAN_TIME_LIMIT,
)
@_stop_at_boundary
def vuln_scan(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 3: Vulnerability scanning with Nuclei + Nikto.

    Args:
        previous_result: Result from recon phase
        scan_id: The scan UUID as string

    Returns:
        Task result with vulnerability findings
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        with _guarded(scan_uuid):
            result = asyncio.run(_in_session(_execute_vuln_scan, scan_uuid, previous_result))
        asyncio.run(
            _in_session(_update_phase_status, scan_uuid, PhaseType.VULN_SCAN, result, phase_started)
        )
        return result
    except Exception as e:
        logger.error("vuln_scan_failed", scan_id=scan_id, error=str(e))
        failed = {"scan_id": scan_id, "phase": "vuln_scan", "status": "failed", "error": str(e)}
        _record_phase_crash(scan_uuid, PhaseType.VULN_SCAN, failed, phase_started)
        return failed
    finally:
        pass


def _granted_rate(requested: Any, record: Any) -> int:
    """Requests per second for a tool: the profile or scan value, never above the signed grant."""
    try:
        value = int(requested)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, int(record.max_requests_per_second)))


def _nuclei_grant_args(record: Any) -> dict[str, Any]:
    """Nuclei template filters derived from the signed grant (methods, ports, no exploitation)."""
    from netra.scanner.tools.nuclei import NON_EXPLOIT_EXCLUDE_TAGS

    protocols = ["http", "dns"]
    if 443 in record.ports:
        protocols.append("ssl")
    return {
        "allowed_methods": sorted(record.http_methods),
        "protocol_types": protocols,
        "exclude_tags": list(NON_EXPLOIT_EXCLUDE_TAGS),
    }


async def _execute_vuln_scan(db: AsyncSession, scan_id: uuid.UUID, previous_result: dict) -> dict:
    """Execute vulnerability scanning phase."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        return {"status": "failed", "error": "Scan not found"}

    try:
        scan, _, record, _ = await require_scan_authorization(db, scan_id)
    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)

    live_hosts = previous_result.get("live_hosts", [])
    if not live_hosts:
        live_hosts = (scan.checkpoint_data or {}).get("live_hosts", [])

    total_findings = 0

    try:
        # Nuclei: limits come from the scan profile, and the scan's own config can lower them.
        from netra.scanner.profiles import get_profile_config

        profile = get_profile_config(str(scan.profile))
        overrides = scan.config or {}

        runs: list[dict] = []
        nuclei = NucleiTool(work_dir=_phase_dir(scan_id, "vuln_scan"))
        severity = str(profile.get("severity_filter", "critical,high,medium"))
        rate_limit = _granted_rate(
            overrides.get("rate_limit", profile.get("rate_limit", 150)), record
        )
        nuclei_hosts = live_hosts[:50]
        nikto_enabled = bool(profile.get("use_nikto")) and bool(overrides.get("use_nikto", True))
        nikto_hosts = live_hosts[:10] if nikto_enabled else []
        nuclei_timeout = _nuclei_timeout(len(nuclei_hosts), len(nikto_hosts))
        for target in nuclei_hosts:
            await _require_action(db, scan, target, "vulnerability_scan", "GET")
            run = await nuclei.run(
                target,
                severity=severity,
                rate_limit=rate_limit,
                timeout=nuclei_timeout,
                **_nuclei_grant_args(record),
            )
            _record_run(runs, "nuclei", target, run)
            total_findings += await _persist_findings(db, scan_id, "nuclei", run.findings)
        # Nikto runs only grant-allowed, non-exploit tests at the granted rate (see nikto.py).
        nikto = NiktoTool(work_dir=_phase_dir(scan_id, "vuln_scan") / "nikto")
        nikto_timeout = _nikto_timeout(len(nikto_hosts))
        for target in nikto_hosts:
            await _require_action(db, scan, target, "vulnerability_scan", "GET")
            run = await nikto.run(
                target,
                max_rps=rate_limit,
                allowed_methods=sorted(record.http_methods),
                timeout=nikto_timeout,
            )
            _record_run(runs, "nikto", target, run)
            total_findings += await _persist_findings(db, scan_id, "nikto", run.findings)
        return {
            "scan_id": str(scan_id),
            "phase": "vuln_scan",
            "status": "completed",
            "findings_count": total_findings,
            "runs": runs,
            **_phase_verdict(runs),
        }

    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)
    except Exception as e:
        logger.error("vuln_scan_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.active_test", acks_late=True)
@_stop_at_boundary
def active_test(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 4: Active exploitation testing (SQLi, XSS, directory fuzzing).

    Args:
        previous_result: Result from vuln_scan phase
        scan_id: The scan UUID as string

    Returns:
        Task result with penetration testing findings
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        with _guarded(scan_uuid):
            result = asyncio.run(_in_session(_execute_active_test, scan_uuid, previous_result))
        asyncio.run(
            _in_session(_update_phase_status, scan_uuid, PhaseType.PENTEST, result, phase_started)
        )
        return result
    except Exception as e:
        logger.error("active_test_failed", scan_id=scan_id, error=str(e))
        failed = {"scan_id": scan_id, "phase": "active_test", "status": "failed", "error": str(e)}
        _record_phase_crash(scan_uuid, PhaseType.PENTEST, failed, phase_started)
        return failed
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

    try:
        scan, _, record, _ = await require_scan_authorization(db, scan_id)
    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)

    if "active_test" not in record.allowed_actions:
        # The signed grant never allowed active testing, so no tool runs and nothing is
        # attempted. That is a skipped phase, not a denial: a denial means a tool asked for
        # something outside the grant mid-run.
        return {
            "scan_id": str(scan_id),
            "phase": "active_test",
            "status": "skipped",
            "findings_count": 0,
            "reason": "active_test_not_authorized",
        }

    live_hosts = previous_result.get("live_hosts", [])
    if not live_hosts:
        live_hosts = (scan.checkpoint_data or {}).get("live_hosts", [])

    from netra.scanner.profiles import get_profile_config

    total_findings = 0
    max_rps = int(record.max_requests_per_second)
    # Intrusive tests run only when the profile enables them. The scan config can turn one off.
    profile = get_profile_config(str(scan.profile))
    overrides = scan.config or {}
    allow = {
        key: bool(profile.get(key)) and bool(overrides.get(key, True))
        for key in ("test_sqli", "test_xss", "test_dirs")
    }

    try:
        from netra.db.models.finding import Finding

        # Get parameterized URLs
        inject_result = await db.execute(
            select(Finding.url)
            .where(Finding.scan_id == scan_id)
            .where(Finding.url.isnot(None))
            .where(Finding.url.contains("?"))
        )
        injectable_urls = [row[0] for row in inject_result.fetchall() if row[0]][:20]

        runs: list[dict] = []
        sqlmap = SqlmapTool(work_dir=_phase_dir(scan_id, "pentest"))
        dalfox = DalfoxTool(work_dir=_phase_dir(scan_id, "pentest"))
        sqlmap_level = int(profile.get("sqlmap_level", 1))
        sqlmap_risk = int(profile.get("sqlmap_risk", 1))
        # SQLi: detection only, batch mode, no data extraction (see SqlmapTool).
        for url in injectable_urls if allow["test_sqli"] else []:
            await _require_action(db, scan, url, "active_test", "GET")
            run = await sqlmap.run(url, level=sqlmap_level, risk=sqlmap_risk, max_rps=max_rps)
            _record_run(runs, "sqlmap", url, run)
            total_findings += await _persist_findings(db, scan_id, "sqlmap", run.findings)
        # Reflected XSS: dalfox, verified findings only.
        for url in injectable_urls if allow["test_xss"] else []:
            await _require_action(db, scan, url, "active_test", "GET")
            run = await dalfox.run(url, max_rps=max_rps)
            _record_run(runs, "dalfox", url, run)
            total_findings += await _persist_findings(db, scan_id, "dalfox", run.findings)
        # Directory fuzzing: ffuf has no parser yet, so its runs are recorded as unavailable.
        for target in live_hosts[:10] if allow["test_dirs"] else []:
            await _require_action(db, scan, target, "active_test", "GET")
            _record_unavailable(runs, "ffuf", target, "parser_not_implemented")
        return {
            "scan_id": str(scan_id),
            "phase": "active_test",
            "status": "completed",
            "findings_count": total_findings,
            "runs": runs,
            **_phase_verdict(runs),
        }

    except AuthorizationDenied as exc:
        return await _policy_failure(db, scan_id, exc.code)
    except Exception as e:
        logger.error("active_test_failed", scan_id=str(scan_id), error=str(e))
        return {"status": "failed", "error": str(e)}


@celery_app.task(bind=True, name="netra.ai_analysis", acks_late=True)
@_stop_at_boundary
def ai_analysis(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 5: AI Brain analysis and enrichment.

    Args:
        previous_result: Result from active_test phase
        scan_id: The scan UUID as string

    Returns:
        Task result with AI-enriched findings
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_ai_analysis, scan_uuid, previous_result))
        asyncio.run(
            _in_session(
                _update_phase_status, scan_uuid, PhaseType.AI_ANALYSIS, result, phase_started
            )
        )
        return result
    except Exception as e:
        logger.error("ai_analysis_failed", scan_id=scan_id, error=str(e))
        failed = {"scan_id": scan_id, "phase": "ai_analysis", "status": "failed", "error": str(e)}
        _record_phase_crash(scan_uuid, PhaseType.AI_ANALYSIS, failed, phase_started)
        return failed
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
@_stop_at_boundary
def reporting(self, previous_result: dict, scan_id: str) -> dict:
    """Phase 6: Report generation.

    Args:
        previous_result: Result from ai_analysis phase
        scan_id: The scan UUID as string

    Returns:
        Task result with report information
    """
    scan_uuid = uuid.UUID(scan_id)
    phase_started = datetime.now(UTC)

    try:
        import asyncio

        result = asyncio.run(_in_session(_execute_reporting, scan_uuid, previous_result))
        asyncio.run(
            _in_session(_update_phase_status, scan_uuid, PhaseType.REPORTING, result, phase_started)
        )
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


def _record_phase_crash(
    scan_uuid: uuid.UUID, phase_type: PhaseType, failed: dict, started_at: datetime
) -> None:
    """Write a failed phase row when a phase task raised, so the real error is kept.

    Without it the scan only reports `<phase>=missing`. Best effort: the database may be the
    thing that failed.
    """
    import asyncio

    try:
        asyncio.run(_in_session(_update_phase_status, scan_uuid, phase_type, failed, started_at))
    except Exception as exc:  # noqa: BLE001 - never mask the original failure
        logger.error("phase_crash_record_failed", scan_id=str(scan_uuid), error=str(exc))


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
    scan = await db.get(Scan, scan_id)
    checkpoint = (scan.checkpoint_data or {}) if scan else {}
    if checkpoint.get("policy_denial"):
        return str(checkpoint["policy_denial"])
    return f"phases not completed: {', '.join(problems)}" if problems else None


async def _update_phase_status(
    db: AsyncSession,
    scan_id: uuid.UUID,
    phase_type: PhaseType,
    result: dict,
    started_at: datetime | None = None,
) -> None:
    """Update or create scan phase status.

    started_at is when the phase task began. Without it the row would show the phase as
    starting and finishing at the moment it was written.
    """
    phase_result = await db.execute(
        select(ScanPhase)
        .where(ScanPhase.scan_id == scan_id)
        .where(ScanPhase.phase_type == phase_type)
    )
    phase = phase_result.scalar_one_or_none()

    status = {
        "completed": PhaseStatus.COMPLETED,
        "skipped": PhaseStatus.SKIPPED,
    }.get(str(result.get("status")), PhaseStatus.FAILED)
    now = datetime.now(UTC)
    if not phase:
        phase = ScanPhase(scan_id=scan_id, phase_type=phase_type, started_at=started_at or now)
        db.add(phase)
    elif started_at is not None:
        phase.started_at = started_at
    phase.status = status
    phase.completed_at = now
    phase.progress = 1.0 if status in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED) else 0.0
    phase.findings_count = result.get("findings_count", result.get("count", 0))
    phase.error_message = _phase_note(result)
    if status == PhaseStatus.SKIPPED and result.get("reason"):
        phase.error_message = str(result["reason"])[:2000]

    # Persist each run's evidence so coverage can be judged from it later (spec 6.2).
    if isinstance(result.get("runs"), list):
        phase.tool_outputs = {**(phase.tool_outputs or {}), "runs": result["runs"]}

    if result.get("policy_denial"):
        phase.status = PhaseStatus.BLOCKED
        phase.tool_outputs = {
            **(phase.tool_outputs or {}),
            "policy_denials": [
                {"state": "skipped", "required": True, "reason_code": result["policy_denial"]}
            ],
        }
    await db.commit()


def create_scan_pipeline(scan_id: str) -> chain:
    """Create the full scan pipeline as a Celery chain.

    Args:
        scan_id: The scan UUID as string

    Returns:
        Celery chain of tasks
    """
    tasks_by_name = {
        "scope_resolution": scope_resolution,
        "recon": recon,
        "vuln_scan": vuln_scan,
        "active_test": active_test,
        "ai_analysis": ai_analysis,
        "reporting": reporting,
    }
    steps = [tasks_by_name[name] for name in WEB_PIPELINE_PHASES]
    first, rest = steps[0], steps[1:]
    return chain(first.s(scan_id), *(step.s(scan_id=scan_id) for step in rest))


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
            if name == "status":
                if scan.status == ScanStatus.CANCELLED:
                    continue
                if (scan.checkpoint_data or {}).get("policy_denial"):
                    value = ScanStatus.FAILED
            setattr(scan, name, value)
        await session.commit()


async def _stale_running_scan_ids(db: AsyncSession) -> list[uuid.UUID]:
    stale_before = datetime.now(UTC) - STALE_AFTER
    rows = await db.scalars(
        select(Scan.id).where(
            Scan.status == ScanStatus.RUNNING,
            Scan.updated_at < stale_before,
        )
    )
    return list(rows)


@celery_app.task(name="netra.reclaim_stale_scans")
def reclaim_stale_scans() -> dict:
    """Re-dispatch scans whose worker stopped heartbeating. run_scan's claim keeps this exactly-once.

    A reclaimed scan restarts its pipeline from the first phase: phases do not yet skip the
    work a crashed run already finished.
    """
    import asyncio

    stale = asyncio.run(_in_session(_stale_running_scan_ids))
    for scan_id in stale:
        run_scan.apply_async(args=[str(scan_id)])
    logger.info("reclaim_stale_scans", count=len(stale))
    return {"reclaimed": [str(scan_id) for scan_id in stale]}


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

        asyncio.run(_in_session(_authorize_dispatch, scan_uuid))

        # Atomic claim: a redelivered or double-queued task finds the scan already running
        # and exits, so the same scan is never run twice. Each call opens its own session,
        # because asyncpg binds connections to the loop that created them.
        if not asyncio.run(_in_session(_claim_scan, scan_uuid)):
            return {"scan_id": scan_id, "status": "not_claimed"}

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
