"""Phases API: tool runs, honest outcomes and stored finding counts (modelled on scan 47b5dfc4)."""

import pytest
from httpx import AsyncClient

from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.services.scan_execution import run_status


@pytest.fixture
async def finished_scan(db_session):
    target = Target(name="T", target_type="domain", value="www.example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="deep", target_id=target.id, profile="deep")
    db_session.add(scan)
    await db_session.flush()
    runs = [
        {
            "tool": "nuclei",
            "target": "https://www.example.org:443",
            "state": "failed",
            "reason_code": "host_unresponsive",
            "error": "host_unresponsive",
            "findings_count": None,
        },
        {
            "tool": "nuclei",
            "target": "http://www.example.org:80",
            "state": "failed",
            "reason_code": "timeout",
            "error": "timeout",
            "findings_count": None,
        },
        {
            "tool": "nikto",
            "target": "http://www.example.org:80",
            "state": "skipped",
            "reason_code": "light_scan_4xx_root",
            "error": None,
            "findings_count": 0,
        },
        {
            "tool": "nikto",
            "target": "https://www.example.org:443",
            "state": "completed",
            "reason_code": None,
            "error": None,
            "findings_count": 18,
        },
    ]
    db_session.add_all(
        [
            ScanPhase(
                scan_id=scan.id,
                phase_type=PhaseType.RECON_DISCOVERY,
                status=PhaseStatus.COMPLETED,
                findings_count=2,
                tool_outputs={
                    "runs": [
                        {
                            "tool": "httpx",
                            "target": "www.example.org",
                            "state": "completed",
                            "findings_count": 2,
                        }
                    ]
                },
            ),
            ScanPhase(
                scan_id=scan.id,
                phase_type=PhaseType.VULN_SCAN,
                status=PhaseStatus.COMPLETED,
                findings_count=25,
                tool_outputs={"runs": runs},
            ),
        ]
    )
    for i in range(4):
        db_session.add(
            Finding(
                scan_id=scan.id,
                title=f"h{i}",
                description="d",
                severity="low",
                tool_source="http_analysis",
            )
        )
    for i in range(3):
        db_session.add(
            Finding(
                scan_id=scan.id,
                title=f"n{i}",
                description="d",
                severity="info",
                tool_source="nuclei",
            )
        )
    await db_session.commit()
    return scan


@pytest.mark.asyncio
async def test_phase_outcome_and_runs(client: AsyncClient, finished_scan) -> None:
    phases = {
        p["phase_type"]: p
        for p in (await client.get(f"/api/v1/scans/{finished_scan.id}/phases")).json()
    }
    vuln = phases["vuln_scan"]
    assert vuln["status"] == "completed"
    assert vuln["outcome"] == "completed_with_warnings"
    statuses = {(r["tool"], r["target"]): r["status"] for r in vuln["runs"]}
    assert statuses[("nuclei", "https://www.example.org:443")] == "failed"
    assert statuses[("nuclei", "http://www.example.org:80")] == "timed_out"
    assert statuses[("nikto", "http://www.example.org:80")] == "skipped"
    assert statuses[("nikto", "https://www.example.org:443")] == "completed"
    assert all(r["reason"] for r in vuln["runs"] if r["reason_code"])
    # Stored rows, not the phase's saved count.
    assert vuln["stored_findings"] == 3
    recon = phases["recon_discovery"]
    assert recon["outcome"] == "completed"
    assert recon["stored_findings"] == 4
    # The httpx "2" is raw results (hosts), kept apart from stored findings.
    assert recon["runs"][0]["raw_results"] == 2


def test_run_status_labels() -> None:
    assert run_status({"state": "completed"}) == "completed"
    assert run_status({"state": "completed", "reason_code": "tech_targeted"}) == (
        "completed_with_warnings"
    )
    assert run_status({"state": "unavailable"}) == "not_configured"
    assert run_status({"state": "failed", "reason_code": "timeout"}) == "timed_out"
    assert run_status({"state": "parse_error"}) == "failed"


@pytest.mark.asyncio
async def test_assets_and_owasp_endpoints(client: AsyncClient, finished_scan, db_session) -> None:
    finished_scan.checkpoint_data = {
        "live_hosts": ["https://www.example.org:443"],
        "http_hosts": [
            {"url": "https://www.example.org:443", "status_code": 200, "tech": ["Nginx"]}
        ],
        "authorization_snapshot": {"policy": {"allowed_actions": ["vulnerability_scan"]}},
    }
    await db_session.commit()
    assets = (await client.get(f"/api/v1/scans/{finished_scan.id}/assets")).json()
    assert assets["hosts"][0]["tech"] == ["Nginx"]
    assert assets["authorization"]["allowed_actions"] == ["vulnerability_scan"]
    rows = (await client.get(f"/api/v1/scans/{finished_scan.id}/owasp-coverage")).json()
    assert [r["id"] for r in rows] == [f"A{i:02d}" for i in range(1, 11)]
    states = {r["id"]: r["state"] for r in rows}
    # nuclei failed on one host and timed out on the other; nikto completed.
    assert states["A02"] == "partially_tested"
    assert states["A05"] == "not_tested"
