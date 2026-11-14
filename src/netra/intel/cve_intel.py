"""Exploitation status (CISA KEV) and exploit likelihood (FIRST EPSS) for CVE identifiers.

Used to rank findings: a CVE known to be exploited in the wild outranks a higher CVSS score that
nobody exploits. Both sources are public. Results are cached in memory with a TTL, and every
network failure degrades to "unknown" instead of failing the caller.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CACHE_TTL_SECONDS = 24 * 3600
LIKELY_EPSS = 0.1


@dataclass(frozen=True)
class CveIntel:
    cve: str
    known_exploited: bool
    epss: float | None  # probability of exploitation in the next 30 days, 0..1

    @property
    def priority(self) -> str:
        """Operator-facing bucket: exploited first, then by likelihood."""
        if self.known_exploited:
            return "exploited"
        if self.epss is None:
            return "unknown"
        return "likely" if self.epss >= LIKELY_EPSS else "unlikely"


def rank_key(intel: CveIntel) -> tuple[int, float]:
    """Sort key: exploited first, then higher EPSS. Unknown likelihood sorts after known."""
    return (0 if intel.known_exploited else 1, -(intel.epss if intel.epss is not None else -1.0))


def normalise_cve_ids(raw_ids: list[str]) -> list[str]:
    """Upper-case, strip, validate and de-duplicate CVE identifiers, keeping their order."""
    out: list[str] = []
    for raw in raw_ids:
        cve = str(raw).strip().upper()
        if CVE_RE.match(cve) and cve not in out:
            out.append(cve)
    return out


class CveIntelClient:
    """Looks up KEV membership and EPSS scores with an in-memory cache."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._kev: set[str] = set()
        self._kev_loaded_at: float | None = None
        self._epss_cache: dict[str, tuple[float, float]] = {}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=15.0, transport=self._transport)

    async def _load_kev(self) -> set[str]:
        now = time.monotonic()
        if self._kev_loaded_at is not None and now - self._kev_loaded_at < CACHE_TTL_SECONDS:
            return self._kev
        try:
            async with self._client() as client:
                response = await client.get(KEV_URL)
                response.raise_for_status()
                entries = response.json().get("vulnerabilities", [])
            self._kev = {str(e["cveID"]).upper() for e in entries if e.get("cveID")}
            self._kev_loaded_at = now
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass  # keep the last good copy; if there is none, KEV status stays unknown-as-False
        return self._kev

    async def _epss(self, cves: list[str]) -> dict[str, float]:
        now = time.monotonic()
        result: dict[str, float] = {}
        missing: list[str] = []
        for cve in cves:
            cached = self._epss_cache.get(cve)
            if cached and now - cached[1] < CACHE_TTL_SECONDS:
                result[cve] = cached[0]
            else:
                missing.append(cve)
        if missing:
            try:
                async with self._client() as client:
                    response = await client.get(EPSS_URL, params={"cve": ",".join(missing)})
                    response.raise_for_status()
                    for row in response.json().get("data", []):
                        cve = str(row.get("cve", "")).upper()
                        value = float(row.get("epss", 0.0))
                        self._epss_cache[cve] = (value, now)
                        result[cve] = value
            except (httpx.HTTPError, ValueError, TypeError):
                pass  # likelihood stays unknown (epss=None) for these identifiers
        return result

    async def lookup(self, cve_ids: list[str]) -> list[CveIntel]:
        """Return intel for valid CVE identifiers. Malformed identifiers are dropped."""
        cves = normalise_cve_ids(cve_ids)
        if not cves:
            return []
        kev = await self._load_kev()
        epss = await self._epss(cves)
        return [CveIntel(cve=c, known_exploited=c in kev, epss=epss.get(c)) for c in cves]
