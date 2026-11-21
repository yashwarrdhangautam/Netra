"""Assessment report: built from stored records, works for partial scans, discloses gaps."""

import csv
import importlib
import json

import pytest
from sqlalchemy import select

from netra.db.models.finding import Finding
from netra.db.models.report import Report, ReportStatus, ReportType
from netra.db.models.scan import Scan, ScanStatus
from netra.db.models.scan_phase import PhaseStatus, PhaseType, ScanPhase
from netra.db.models.target import Target
from netra.reports.sarif import build_sarif
from netra.services import assessment_report as ar
from netra.services.owasp_coverage import owasp_coverage

report_routes = importlib.import_module("netra.api.routes.reports")

SNAPSHOT = {
    "policy": {
        "ports": [80, 443],
        "http_methods": ["GET", "HEAD"],
        "allowed_actions": ["http_probe", "passive_recon", "vulnerability_scan"],
        "max_requests_per_second": 1,
    },
    "record": {"expires_at": "2026-11-22T03:55:33Z"},
}


@pytest.fixture
async def partial_scan(db_session):
    """Shaped like scan 47b5dfc4: nuclei failed and timed out, nikto completed."""
    target = Target(name="T", target_type="domain", value="www.example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(
        name="deep <partial>",
        target_id=target.id,
        profile="deep",
        status=ScanStatus.COMPLETED,
        checkpoint_data={
            "authorization_snapshot": SNAPSHOT,
            "live_hosts": ["https://www.example.org:443"],
            "http_hosts": [
                {
                    "url": "https://www.example.org:443",
                    "status_code": 200,
                    "title": "Home",
                    "tech": ["Next.js"],
                }
            ],
            "coverage_manifest": {
                "version": 1,
                "required_tools": [
                    {"phase": "vuln_scan", "tool": "nuclei"},
                    {"phase": "vuln_scan", "tool": "nikto"},
                ],
                "optional_tools": [],
            },
        },
    )
    db_session.add(scan)
    await db_session.flush()
    db_session.add_all(
        [
            ScanPhase(
                scan_id=scan.id,
                phase_type=PhaseType.VULN_SCAN,
                status=PhaseStatus.COMPLETED,
                findings_count=2,
                tool_outputs={
                    "runs": [
                        {
                            "tool": "nuclei",
                            "target": "https://www.example.org:443",
                            "state": "failed",
                            "reason_code": "host_unresponsive",
                            "error": "host_unresponsive",
                            "success": False,
                        },
                        {
                            "tool": "nikto",
                            "target": "https://www.example.org:443",
                            "state": "completed",
                            "reason_code": None,
                            "error": None,
                            "success": True,
                            "findings_count": 2,
                        },
                    ]
                },
            ),
            ScanPhase(
                scan_id=scan.id,
                phase_type=PhaseType.PENTEST,
                status=PhaseStatus.SKIPPED,
                findings_count=0,
                error_message="active_test_not_authorized",
            ),
            Finding(
                scan_id=scan.id,
                title="Suggested security header missing: x-content-type-options.",
                description="Suggested security header missing: x-content-type-options.",
                severity="info",
                tool_source="nikto",
                url="https://www.example.org:443/",
                evidence={"nikto_id": "013587", "raw": "Cookie: session=abc123\nok"},
            ),
            Finding(
                scan_id=scan.id,
                title='=HYPERLINK("http://evil")',
                description="formula",
                severity="low",
                tool_source="nikto",
                cwe_id="CWE-200",
            ),
        ]
    )
    await db_session.commit()
    return scan


async def test_assessment_data_for_partial_scan(db_session, partial_scan) -> None:
    data = await ar.build_assessment(db_session, partial_scan.id)
    assert data["summary"]["total"] == 2
    assert data["summary"]["by_severity"]["info"] == 1
    assert data["coverage"]["outcome"] == "incomplete"
    statuses = {r["tool"]: r["status"] for r in data["tool_runs"]}
    assert statuses == {"nuclei": "failed", "nikto": "completed"}
    assert any("nuclei" in line and "failed" in line for line in data["limitations"])
    assert any("active testing" in line.lower() for line in data["limitations"])
    # Credentials never reach an export.
    evidence = json.dumps(data["findings"])
    assert "abc123" not in evidence and "Cookie: [REDACTED]" in evidence
    header = next(f for f in data["findings"] if "x-content-type" in f["title"])
    assert header["knowledge"][0]["cwe"] == "CWE-693"
    assert header["cve_ids"] == []
    owasp = {c["id"]: c["state"] for c in data["owasp_top10_2025"]}
    assert owasp["A05"] == "not_tested"  # no active_test in the grant
    assert owasp["A07"] == "requires_credentials"
    assert owasp["A06"] == "requires_manual_review"


async def test_renderers_write_files(db_session, partial_scan, tmp_path) -> None:
    data = await ar.build_assessment(db_session, partial_scan.id)
    pdf = ar.render_pdf(data, tmp_path)
    assert pdf.read_bytes()[:4] == b"%PDF"
    parsed = json.loads(ar.render_json(data, tmp_path).read_text(encoding="utf-8"))
    assert parsed["summary"]["total"] == 2
    rows = list(csv.reader(ar.render_csv(data, tmp_path).open(encoding="utf-8")))
    assert rows[0][0] == "id" and len(rows) == 3
    assert any(cell.startswith("'=HYPERLINK") for row in rows for cell in row)


async def test_report_job_completes_for_partial_scan(
    db_session, partial_scan, tmp_path, monkeypatch
):
    monkeypatch.setattr(ar.settings, "reports_dir", tmp_path, raising=False)
    for report_type in (
        ReportType.ASSESSMENT_PDF,
        ReportType.ASSESSMENT_JSON,
        ReportType.FINDINGS_CSV,
        ReportType.SARIF,
    ):
        report = Report(
            scan_id=partial_scan.id, report_type=report_type, status=ReportStatus.GENERATING
        )
        db_session.add(report)
        await db_session.commit()
        scan = await db_session.get(Scan, partial_scan.id)
        await report_routes._build_report(db_session, report, scan)
        await db_session.refresh(report)
        assert report.status == ReportStatus.COMPLETED, report.error_message
        assert report.file_size and report.config["built_from"]["coverage_outcome"] == "incomplete"
    assert len(list((await db_session.scalars(select(Report))).all())) == 4


def test_owasp_misconfiguration_tested_only_when_runs_complete() -> None:
    done = [{"tool": t, "state": "completed"} for t in ("httpx", "nuclei", "nikto")]
    assert owasp_coverage(done, [], [])[1]["state"] == "tested"
    mixed = [*done[:2], {"tool": "nuclei", "state": "failed"}]
    assert owasp_coverage(mixed, [], [])[1]["state"] == "partially_tested"
    assert owasp_coverage([{"tool": "nuclei", "state": "failed"}], [], [])[1]["state"] == (
        "failed_interrupted"
    )
    assert owasp_coverage([], [], [])[1]["state"] == "not_tested"


def test_sarif_uses_cwe_id() -> None:
    doc = build_sarif([{"title": "t", "severity": "low", "cwe_id": "CWE-693", "tool": "x"}])
    assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-693"
