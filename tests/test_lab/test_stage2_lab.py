"""Stage 2 lab validation: the product phases against a local page with known contents.

Requires nuclei, sqlmap and dalfox on PATH and a pinned nuclei template checkout. The lab page
is started on a free localhost port for the duration of the module. Expectations are fixed by
construction (see tests/fixtures/lab/vuln_server.py) and the manual nuclei baseline in
docs/validation/stage-2-lab-validation.md.
"""

import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from netra.db.models.finding import Finding
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.scanner.tools.nuclei import NucleiTool
from netra.schemas.authorization import AuthorizationRequest
from netra.services.scan_authorization import grant_authorization, prepare_scan_authorization
from netra.services.scan_coverage import build_coverage_manifest, scan_coverage
from netra.worker import tasks

LAB_SERVER = Path(__file__).resolve().parents[1] / "fixtures" / "lab" / "vuln_server.py"

REQUIRED_TOOLS = ("nuclei", "sqlmap", "dalfox")
pytestmark = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in REQUIRED_TOOLS),
    reason="lab tools (nuclei, sqlmap, dalfox) are not all installed",
)


@pytest.fixture(scope="module")
def event_loop_policy():
    import asyncio
    import os

    if os.name == "nt":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="module")
def lab_base_url():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([sys.executable, str(LAB_SERVER), "--port", str(port)])  # noqa: S603
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}", port
    server.terminate()
    server.wait(timeout=10)


def _request(port: int, actions: list[str]) -> AuthorizationRequest:
    return AuthorizationRequest(
        evidence_reference="stage-2-lab-local-fixture",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        allowed_actions=actions,
        http_methods=["GET"],
        ports=[port],
        max_requests_per_second=5,
    )


async def _authorized_scan(db, port: int, actions: list[str]) -> Scan:
    actor = User(
        id=uuid.uuid4(),
        email=f"lab-{uuid.uuid4().hex[:6]}@example.org",
        hashed_password="unused",
        role=UserRole.ADMIN,
    )
    target = Target(
        name="stage2-lab",
        target_type="url",
        value=f"http://127.0.0.1:{port}",
        scope_includes=["127.0.0.1"],
    )
    db.add_all([actor, target])
    await db.flush()
    await grant_authorization(db, target.id, _request(port, actions), actor)
    snapshot = await prepare_scan_authorization(db, target.id)
    scan = Scan(
        name="stage2",
        target_id=target.id,
        profile="standard",
        checkpoint_data={"authorization_snapshot": snapshot},
    )
    db.add(scan)
    await db.commit()
    return scan


async def test_authorized_vuln_scan_runs_nuclei_and_marks_nikto_unavailable(
    db_session, lab_base_url
):
    base, port = lab_base_url
    scan = await _authorized_scan(db_session, port, ["vulnerability_scan"])

    result = await tasks._execute_vuln_scan(db_session, scan.id, {"live_hosts": [base]})

    assert result["status"] == "completed"
    states = {(run["tool"], run["state"]) for run in result["runs"]}
    assert ("nuclei", "completed") in states
    # Nikto has no parser: its run is recorded as unavailable, so coverage cannot be complete.
    assert ("nikto", "unavailable") in states
    # The reviewed manual baseline for this page is zero nuclei findings (docs/validation).
    nuclei_runs = [run for run in result["runs"] if run["tool"] == "nuclei"]
    assert nuclei_runs and all(run["findings_count"] == 0 for run in nuclei_runs)


async def test_authorized_active_test_finds_the_known_lab_issues(db_session, lab_base_url):
    base, port = lab_base_url
    scan = await _authorized_scan(db_session, port, ["active_test"])
    for url in (f"{base}/item?id=1", f"{base}/reflect?q=hello"):
        db_session.add(
            Finding(
                scan_id=scan.id,
                title="Parameterised URL from crawl",
                description="Seeded for the Stage 2 lab: a parameterised URL the crawl would find.",
                severity="info",
                url=url,
                tool_source="stage2-seed",
                dedup_hash=uuid.uuid4().hex,
            )
        )
    await db_session.commit()

    result = await tasks._execute_active_test(db_session, scan.id, {"live_hosts": [base]})

    runs = {(run["tool"], run["state"]) for run in result["runs"]}
    assert ("sqlmap", "completed") in runs
    assert ("dalfox", "completed") in runs
    assert ("ffuf", "unavailable") in runs
    sqli = [r for r in result["runs"] if r["tool"] == "sqlmap" and r["findings_count"]]
    assert sqli, "sqlmap must report the known injection in the id parameter"
    xss = [r for r in result["runs"] if r["tool"] == "dalfox" and r["findings_count"]]
    assert xss, "dalfox must report the known reflection in the q parameter"


async def test_ungranted_lab_scan_executes_no_tool(db_session, lab_base_url, monkeypatch):
    base, port = lab_base_url
    actor = User(
        id=uuid.uuid4(), email="no-grant@example.org", hashed_password="unused", role=UserRole.ADMIN
    )
    target = Target(name="ungranted", target_type="url", value=base, scope_includes=["127.0.0.1"])
    db_session.add_all([actor, target])
    await db_session.flush()
    scan = Scan(name="ungranted", target_id=target.id, profile="standard")
    db_session.add(scan)
    await db_session.commit()
    run = AsyncMock()
    monkeypatch.setattr(NucleiTool, "run", run)

    result = await tasks._execute_vuln_scan(db_session, scan.id, {"live_hosts": [base]})

    assert result["status"] == "failed"
    run.assert_not_awaited()


async def test_lab_scan_coverage_is_incomplete_when_a_tool_is_unavailable(db_session, lab_base_url):
    base, port = lab_base_url
    scan = await _authorized_scan(db_session, port, ["vulnerability_scan"])
    scan.checkpoint_data = {
        **(scan.checkpoint_data or {}),
        "coverage_manifest": build_coverage_manifest("standard", {}),
    }
    result = await tasks._execute_vuln_scan(db_session, scan.id, {"live_hosts": [base]})
    await tasks._update_phase_status(db_session, scan.id, PhaseType.VULN_SCAN, result)
    await db_session.commit()
    scan.status = ScanStatus.COMPLETED
    phases = list(
        (await db_session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id))).all()
    )
    coverage = scan_coverage(scan, phases)
    assert coverage.outcome == "incomplete"
    assert any(c.tool == "nikto" and c.state == "unavailable" for c in coverage.coverage)
