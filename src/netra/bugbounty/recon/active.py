"""Scope-gated active reconnaissance for NETRA-BB."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import structlog

from netra.bugbounty.scope import ScopeValidator, ScopeViolation
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.nuclei import NucleiTool

logger = structlog.get_logger()


@dataclass
class ActiveReconResult:
    """Result of an active phase against a list of in-scope hosts."""

    alive_hosts: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    nuclei_findings: list[dict] = field(default_factory=list)
    blocked_targets: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def httpx_alive(host: str) -> bool:
    """HEAD-only liveness probe via httpx; true only for 2xx/3xx."""
    tool = HttpxTool()
    result = await tool.run(host, follow_redirects=False, tech_detect=True, head=True)
    if not result.success:
        logger.warning("bb.recon.active.httpx_failed", host=host, error=result.error)
        return False
    return any((f.get("status_code") or 0) in range(200, 400) for f in result.findings)


async def ffuf_paths(host: str, wordlist: str = "common.txt", rate_limit: int | None = None) -> list[str]:
    """Run ffuf content discovery and return normalized paths."""
    target = host.rstrip("/") + "/FUZZ"
    result = await FfufTool().run(target, wordlist=wordlist, rate_limit=rate_limit)
    if not result.success:
        logger.warning("bb.recon.active.ffuf_failed", host=host, error=result.error)
        return []
    paths: set[str] = set()
    for finding in result.findings:
        path = finding.get("path")
        if not path and finding.get("url"):
            path = "/" + str(finding["url"]).split(host.rstrip("/"), 1)[-1].lstrip("/")
        if path:
            paths.add("/" + str(path).lstrip("/"))
    return sorted(paths)


async def nuclei_safe(host: str, severity_cap: str | None = None) -> list[dict]:
    """Run nuclei's safe template subset and normalize output."""
    severity = severity_cap or "medium"
    result = await NucleiTool().run(
        host,
        tags="cve,exposure,misconfig",
        severity=severity,
        rate_limit=25,
    )
    if not result.success:
        logger.warning("bb.recon.active.nuclei_failed", host=host, error=result.error)
        return []
    return [
        {
            "template_id": f.get("template_id") or f.get("template-id"),
            "matched_at": f.get("matched_at") or f.get("matched-at") or f.get("url"),
            "severity": f.get("severity", "info"),
            "title": f.get("title", "Nuclei finding"),
            "evidence": f.get("evidence", f),
        }
        for f in result.findings
    ]


async def run_active_recon(
    in_scope_hosts: Iterable[str],
    validator: ScopeValidator,
    *,
    enable_alive: bool = True,
    enable_ffuf: bool = False,
    enable_nuclei: bool = False,
    wordlist: str = "common.txt",
    rate_limit: int | None = None,
) -> ActiveReconResult:
    """Run gated active phases. Every host is re-checked against the validator."""
    result = ActiveReconResult()

    for host in in_scope_hosts:
        try:
            decision = validator.require(host)
        except ScopeViolation as exc:
            result.blocked_targets.append((host, exc.decision.reason))
            logger.warning("bb.recon.active.blocked", host=host, reason=exc.decision.reason)
            continue

        try:
            if enable_alive and await httpx_alive(host):
                result.alive_hosts.append(host)

            if enable_ffuf:
                for path in await ffuf_paths(host, wordlist=wordlist, rate_limit=rate_limit):
                    target = host.rstrip("/") + path
                    validator.require(target)
                    result.discovered_paths.append(target)

            if enable_nuclei:
                result.nuclei_findings.extend(
                    await nuclei_safe(host, severity_cap=decision.severity_cap)
                )

        except Exception as exc:
            logger.warning("bb.recon.active.host_failed", host=host, err=str(exc))
            result.errors.append(f"{host}:{exc}")

    logger.info(
        "bb.recon.active.done",
        alive=len(result.alive_hosts),
        paths=len(result.discovered_paths),
        nuclei=len(result.nuclei_findings),
        blocked=len(result.blocked_targets),
    )
    return result
