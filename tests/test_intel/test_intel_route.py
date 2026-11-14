"""The intel route returns CVEs exploited-first and drops malformed identifiers."""

from netra.api.routes import intel
from netra.intel.cve_intel import CveIntel


async def test_route_orders_exploited_first(monkeypatch):
    async def fake_lookup(self, ids):
        return [
            CveIntel("CVE-2025-0002", False, 0.6),
            CveIntel("CVE-2024-0001", True, 0.01),
        ]

    monkeypatch.setattr(intel.CveIntelClient, "lookup", fake_lookup)
    body = await intel.cve_intel(ids="CVE-2025-0002, CVE-2024-0001")
    assert [i["cve"] for i in body["items"]] == ["CVE-2024-0001", "CVE-2025-0002"]
    assert body["items"][0]["priority"] == "exploited"
    assert body["count"] == 2


async def test_route_caps_number_of_ids(monkeypatch):
    seen = {}

    async def fake_lookup(self, ids):
        seen["n"] = len(ids)
        return []

    monkeypatch.setattr(intel.CveIntelClient, "lookup", fake_lookup)
    await intel.cve_intel(ids=",".join(f"CVE-2024-{i:04d}" for i in range(200)))
    assert seen["n"] == intel.MAX_IDS


async def test_payloads_route_503_when_not_synced(monkeypatch, tmp_path):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(intel.settings, "tools_dir", tmp_path)
    with pytest.raises(HTTPException) as exc:
        await intel.payloads()
    assert exc.value.status_code == 503


async def test_payloads_route_searches_checkout(monkeypatch, tmp_path):
    from netra.intel.payloads import checkout_dir

    monkeypatch.setattr(intel.settings, "tools_dir", tmp_path)
    root = checkout_dir(tmp_path)
    (root / "SQL Injection").mkdir(parents=True)
    (root / "SQL Injection" / "README.md").write_text(
        "## Union\n\n```sql\n' UNION SELECT NULL--\n```\n", encoding="utf-8"
    )
    body = await intel.payloads(q="union", topic="SQL Injection", limit=5)
    assert body["count"] == 1
    assert body["items"][0]["commit"]
    assert body["items"][0]["licence"] == "MIT"
