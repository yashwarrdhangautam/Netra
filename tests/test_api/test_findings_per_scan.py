"""Findings for one scan: isolation, filters, severity order and a summary that reconciles."""

import pytest
from httpx import AsyncClient

from netra.db.models.finding import Finding
from netra.db.models.scan import Scan
from netra.db.models.target import Target


@pytest.fixture
async def two_scans(db_session):
    target = Target(name="T", target_type="domain", value="t.example.org")
    other_target = Target(name="O", target_type="domain", value="o.example.org")
    db_session.add_all([target, other_target])
    await db_session.flush()
    scan = Scan(name="mine", target_id=target.id, profile="deep")
    other = Scan(name="other", target_id=other_target.id, profile="deep")
    db_session.add_all([scan, other])
    await db_session.flush()

    def finding(scan_id, title, severity, tool, cwe=None, cves=None):
        return Finding(
            scan_id=scan_id,
            title=title,
            description=title,
            severity=severity,
            tool_source=tool,
            cwe_id=cwe,
            cve_ids=cves or [],
            url="https://t.example.org/",
        )

    db_session.add_all(
        [
            finding(scan.id, "Missing X-Content-Type-Options", "low", "http_analysis", "CWE-693"),
            finding(scan.id, "nginx outdated", "info", "nikto"),
            finding(scan.id, "Exposed metrics", "medium", "nuclei", "CWE-200"),
            finding(scan.id, "Known CVE", "high", "nuclei", None, ["CVE-2024-0001"]),
            finding(other.id, "Other scan finding", "critical", "nuclei"),
        ]
    )
    await db_session.commit()
    return scan, other, target


@pytest.mark.asyncio
async def test_scan_filter_returns_only_that_scan(client: AsyncClient, two_scans) -> None:
    scan, other, _ = two_scans
    body = (await client.get("/api/v1/findings/", params={"scan_id": str(scan.id)})).json()
    assert body["total"] == 4
    assert {i["scan_id"] for i in body["items"]} == {str(scan.id)}


@pytest.mark.asyncio
async def test_severity_order_is_by_risk_not_alphabet(client: AsyncClient, two_scans) -> None:
    scan, _, _ = two_scans
    body = (await client.get("/api/v1/findings/", params={"scan_id": str(scan.id)})).json()
    assert [i["severity"] for i in body["items"]] == ["high", "medium", "low", "info"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("params", "titles"),
    [
        ({"tool_source": "nuclei"}, {"Exposed metrics", "Known CVE"}),
        ({"severity": "low,info"}, {"Missing X-Content-Type-Options", "nginx outdated"}),
        ({"cwe_id": "CWE-693"}, {"Missing X-Content-Type-Options"}),
        ({"cve": "CVE-2024-0001"}, {"Known CVE"}),
        ({"q": "nginx"}, {"nginx outdated"}),
    ],
)
async def test_filters(client: AsyncClient, two_scans, params, titles) -> None:
    scan, _, _ = two_scans
    body = (
        await client.get("/api/v1/findings/", params={"scan_id": str(scan.id), **params})
    ).json()
    assert {i["title"] for i in body["items"]} == titles
    assert body["total"] == len(titles)


@pytest.mark.asyncio
async def test_target_filter(client: AsyncClient, two_scans) -> None:
    _, _, target = two_scans
    body = (await client.get("/api/v1/findings/", params={"target_id": str(target.id)})).json()
    assert body["total"] == 4


@pytest.mark.asyncio
async def test_list_items_carry_url_and_cwe(client: AsyncClient, two_scans) -> None:
    scan, _, _ = two_scans
    body = (
        await client.get("/api/v1/findings/", params={"scan_id": str(scan.id), "cwe_id": "CWE-693"})
    ).json()
    item = body["items"][0]
    assert item["url"] == "https://t.example.org/"
    assert item["cwe_id"] == "CWE-693"


@pytest.mark.asyncio
async def test_summary_reconciles_with_rows(client: AsyncClient, two_scans) -> None:
    scan, _, _ = two_scans
    summary = (
        await client.get("/api/v1/findings/summary", params={"scan_id": str(scan.id)})
    ).json()
    assert summary["total"] == 4
    assert summary["by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 1}
    assert summary["by_tool"] == {"http_analysis": 1, "nikto": 1, "nuclei": 2}
    assert summary["informational"] == 1
    assert summary["actionable"] == 3
    assert sum(summary["by_severity"].values()) == summary["total"]


@pytest.mark.asyncio
async def test_summary_requires_scan_id(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/findings/summary")).status_code == 422
