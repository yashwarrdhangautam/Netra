"""ProjectDiscovery Chaos: subdomains for a domain, from the Chaos dataset API.

Needs an API key (set NETRA_CHAOS_API_KEY). Without a key the client returns nothing and makes no
request. The endpoint and header are the documented public Chaos API; the live call has not been
exercised from this environment, because no key is configured here.
"""

from __future__ import annotations

import re

import httpx

CHAOS_API = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,63}$")


def valid_domain(domain: str) -> bool:
    return bool(_DOMAIN.match(domain.strip().lower()))


async def fetch_subdomains(
    domain: str,
    api_key: str | None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[str]:
    """Return fully qualified subdomains, or [] when there is no key or the lookup fails."""
    if not api_key or not valid_domain(domain):
        return []
    url = CHAOS_API.format(domain=domain.strip().lower())
    try:
        async with httpx.AsyncClient(timeout=20.0, transport=transport) as client:
            response = await client.get(url, headers={"Authorization": api_key})
            response.raise_for_status()
            labels = response.json().get("subdomains", [])
    except (httpx.HTTPError, ValueError, TypeError):
        return []
    domain = domain.strip().lower()
    out = sorted({f"{label}.{domain}".lower() for label in labels if label and "*" not in label})
    return out
