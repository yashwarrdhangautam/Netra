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
