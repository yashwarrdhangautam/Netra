"""CVE intelligence: KEV membership, EPSS likelihood, ranking, and graceful degradation."""

import httpx
import pytest

from netra.intel.cve_intel import (
    CveIntel,
    CveIntelClient,
    normalise_cve_ids,
    rank_key,
)

KEV_BODY = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}, {"cveID": "CVE-2023-9999"}]}
EPSS_BODY = {
    "data": [
        {"cve": "CVE-2024-0001", "epss": "0.02"},
        {"cve": "CVE-2025-0002", "epss": "0.45"},
        {"cve": "CVE-2022-0003", "epss": "0.001"},
    ]
}


def _transport(kev=KEV_BODY, epss=EPSS_BODY, fail=False):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if fail:
            return httpx.Response(503)
        if "known_exploited" in str(request.url):
            return httpx.Response(200, json=kev)
        return httpx.Response(200, json=epss)

    return httpx.MockTransport(handler), calls


def test_normalise_drops_malformed_and_duplicates():
    raw = [" cve-2024-0001 ", "CVE-2024-0001", "not-a-cve", "CVE-2025-1", "CVE-2025-0002"]
    assert normalise_cve_ids(raw) == ["CVE-2024-0001", "CVE-2025-0002"]


async def test_lookup_marks_kev_and_epss():
    transport, _ = _transport()
    client = CveIntelClient(transport=transport)
    result = {r.cve: r for r in await client.lookup(["CVE-2024-0001", "CVE-2025-0002"])}
    assert result["CVE-2024-0001"].known_exploited is True
    assert result["CVE-2024-0001"].epss == pytest.approx(0.02)
    assert result["CVE-2025-0002"].known_exploited is False
    assert result["CVE-2025-0002"].priority == "likely"


async def test_cache_avoids_second_network_call():
    transport, calls = _transport()
    client = CveIntelClient(transport=transport)
    await client.lookup(["CVE-2024-0001"])
    await client.lookup(["CVE-2024-0001"])
    kev_calls = [c for c in calls if "known_exploited" in c]
    epss_calls = [c for c in calls if "epss" in c]
    assert len(kev_calls) == 1
    assert len(epss_calls) == 1


async def test_network_failure_degrades_to_unknown():
    transport, _ = _transport(fail=True)
    client = CveIntelClient(transport=transport)
    result = await client.lookup(["CVE-2024-0001"])
    assert result == [CveIntel("CVE-2024-0001", known_exploited=False, epss=None)]
    assert result[0].priority == "unknown"


async def test_empty_or_invalid_input_makes_no_calls():
    transport, calls = _transport()
    client = CveIntelClient(transport=transport)
    assert await client.lookup(["junk"]) == []
    assert calls == []


def test_ranking_puts_exploited_first_then_by_epss():
    items = [
        CveIntel("CVE-A", False, 0.9),
        CveIntel("CVE-B", True, 0.01),
        CveIntel("CVE-C", False, 0.3),
        CveIntel("CVE-D", False, None),
    ]
    ordered = [i.cve for i in sorted(items, key=rank_key)]
    assert ordered == ["CVE-B", "CVE-A", "CVE-C", "CVE-D"]
