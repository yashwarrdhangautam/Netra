"""API coverage is additive and never inferred from a completed legacy scan."""

from netra.db.models.scan import Scan
from netra.db.models.target import Target


async def test_legacy_completed_scan_reports_unknown_coverage(client, db_session):
    target = Target(name="Legacy", target_type="domain", value="example.org")
    db_session.add(target)
    await db_session.flush()
    scan = Scan(name="Legacy completed", target_id=target.id, profile="quick", status="completed")
    db_session.add(scan)
    await db_session.commit()
    response = await client.get(f"/api/v1/scans/{scan.id}")
    assert response.status_code == 200
    assert response.json()["outcome"] == "incomplete"
    assert response.json()["coverage_reason"] == "coverage_unknown"
    listed = await client.get("/api/v1/scans/")
    assert listed.json()["items"][0]["outcome"] == "incomplete"
