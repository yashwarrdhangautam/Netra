"""MCP intel tools: callable directly, return the same data as the API, and send no traffic."""

from netra.intel import cve_intel
from netra.mcp import server


async def test_scanner_tools_status_shape():
    body = await server.scanner_tools_status()
    assert {"tools", "missing_required", "missing_count"} <= set(body)
    assert body["missing_count"] == len(body["missing_required"])


async def test_cve_priority_orders_exploited_first(monkeypatch):
    async def fake_lookup(self, ids):
        return [
            cve_intel.CveIntel("CVE-2025-0002", False, 0.6),
            cve_intel.CveIntel("CVE-2024-0001", True, 0.01),
        ]

    monkeypatch.setattr(cve_intel.CveIntelClient, "lookup", fake_lookup)
    body = await server.cve_priority(["CVE-2025-0002", "CVE-2024-0001"])
    assert [i["cve"] for i in body["items"]] == ["CVE-2024-0001", "CVE-2025-0002"]


async def test_protection_checklist_detects_without_traffic():
    body = await server.protection_checklist({"CF-Ray": "abc", "Retry-After": "5"}, status_code=429)
    assert "waf" in body["protections"]
    assert "rate_limit" in body["protections"]
    assert body["checklist"] and all("check" in c for c in body["checklist"])


async def test_payload_search_reports_unsynced(monkeypatch, tmp_path):
    from netra.core.config import settings

    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    body = await server.payload_search(query="union")
    assert body["count"] == 0
    assert "not synced" in body["error"]
