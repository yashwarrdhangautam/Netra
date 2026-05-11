"""Passive reconnaissance for NETRA-BB.

All sources in this module are passive: certificate transparency, public search APIs,
or scanner wrappers running in passive mode. Results are scope-filtered before the
caller persists them.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Iterable

import httpx
import structlog

from netra.bugbounty.scope import ScopeValidator, parse_target
from netra.scanner.tools.amass import AmassTool
from netra.scanner.tools.subfinder import SubfinderTool

logger = structlog.get_logger()


@dataclass
class PassiveReconResult:
    """Result of a passive recon run on a single program."""

    program_handle: str
    in_scope_hosts: list[str] = field(default_factory=list)
    out_of_scope_hosts: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
_GITHUB_CACHE: dict[str, tuple[float, list[str]]] = {}
_GITHUB_MISSING_TOKEN_LOGGED = False


def _normalise_hostname(value: str, seed_domain: str | None = None) -> str | None:
    """Extract and normalize a hostname from tool or API output."""
    if not value:
        return None
    value = value.strip().strip("*.").lower()
    parsed = parse_target(value)
    host = (parsed.host or value).strip().strip("*.").lower()
    if not host or "." not in host:
        return None
    if seed_domain and not (host == seed_domain or host.endswith("." + seed_domain)):
        return None
    return host


def _hosts_from_findings(findings: list[dict], seed_domain: str) -> list[str]:
    hosts: set[str] = set()
    for finding in findings:
        for key in ("hostname", "host", "url", "matched_at", "matched-at", "input"):
            host = _normalise_hostname(str(finding.get(key) or ""), seed_domain)
            if host:
                hosts.add(host)
    return sorted(hosts)


async def _run_subfinder(seed_domain: str) -> list[str]:
    """Run subfinder in passive-only mode and return normalized hostnames."""
    tool = SubfinderTool()
    result = await tool.run(seed_domain, passive_only=True)
    if not result.success:
        logger.warning("bb.recon.passive.subfinder_failed", seed=seed_domain, error=result.error)
        return []
    return _hosts_from_findings(result.findings, seed_domain)


async def _run_crtsh(seed_domain: str) -> list[str]:
    """Pull names from crt.sh certificate transparency."""
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{seed_domain}", "output": "json"},
        )
        response.raise_for_status()

    try:
        rows = response.json()
    except ValueError:
        rows = []

    hosts: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        name_value = str(row.get("name_value") or row.get("common_name") or "")
        for raw in name_value.splitlines():
            host = _normalise_hostname(raw, seed_domain)
            if host:
                hosts.add(host)
    return sorted(hosts)


async def _run_amass_passive(seed_domain: str) -> list[str]:
    """Run amass in passive mode and return normalized hostnames."""
    tool = AmassTool()
    result = await tool.run(seed_domain, passive=True)
    if not result.success:
        logger.warning("bb.recon.passive.amass_failed", seed=seed_domain, error=result.error)
        return []
    return _hosts_from_findings(result.findings, seed_domain)


async def _run_github_dorks(seed_domain: str) -> list[str]:
    """Search GitHub code for references to the seed domain and extract hosts."""
    global _GITHUB_MISSING_TOKEN_LOGGED

    cached = _GITHUB_CACHE.get(seed_domain)
    if cached and time.time() - cached[0] < 3600:
        return cached[1]

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        if not _GITHUB_MISSING_TOKEN_LOGGED:
            logger.info("bb.recon.passive.github_skipped", reason="GITHUB_TOKEN not set")
            _GITHUB_MISSING_TOKEN_LOGGED = True
        return []

    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        response = await client.get(
            "https://api.github.com/search/code",
            params={"q": f'"{seed_domain}"', "per_page": 50},
        )
        if response.status_code in {403, 429}:
            logger.warning("bb.recon.passive.github_rate_limited", seed=seed_domain)
            return []
        response.raise_for_status()
        data = response.json()

    hosts: set[str] = set()
    for item in data.get("items", []):
        haystacks = [item.get("name", ""), item.get("path", "")]
        for match in item.get("text_matches", []) or []:
            haystacks.append(match.get("fragment", ""))
        for text in haystacks:
            for raw in _HOST_RE.findall(str(text)):
                host = _normalise_hostname(raw, seed_domain)
                if host:
                    hosts.add(host)

    value = sorted(hosts)
    _GITHUB_CACHE[seed_domain] = (time.time(), value)
    return value


SOURCES = {
    "subfinder": _run_subfinder,
    "crtsh": _run_crtsh,
    "amass_passive": _run_amass_passive,
    "github_dorks": _run_github_dorks,
}


async def run_passive_recon(
    seed_domains: Iterable[str],
    validator: ScopeValidator,
    program_handle: str,
    sources: list[str] | None = None,
) -> PassiveReconResult:
    """Run selected passive sources, scope-filter, and aggregate host results."""
    selected = sources or list(SOURCES.keys())
    result = PassiveReconResult(program_handle=program_handle)
    seen: set[str] = set()

    for seed in seed_domains:
        for src_name in selected:
            fn = SOURCES.get(src_name)
            if fn is None:
                result.errors.append(f"unknown_source:{src_name}")
                continue
            try:
                hosts = await fn(seed)
            except Exception as exc:
                logger.warning("bb.recon.passive.source_failed", source=src_name, err=str(exc))
                result.errors.append(f"{src_name}:{exc}")
                continue

            normalized = sorted({h for h in (_normalise_hostname(host) for host in hosts) if h})
            result.sources[src_name] = result.sources.get(src_name, 0) + len(normalized)
            for host in normalized:
                if host in seen:
                    continue
                seen.add(host)
                decision = validator.check(host)
                if decision.allowed:
                    result.in_scope_hosts.append(host)
                else:
                    result.out_of_scope_hosts.append(host)

    logger.info(
        "bb.recon.passive.done",
        program=program_handle,
        in_scope=len(result.in_scope_hosts),
        out_of_scope=len(result.out_of_scope_hosts),
        errors=len(result.errors),
    )
    return result
