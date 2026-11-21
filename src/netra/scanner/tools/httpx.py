"""ProjectDiscovery httpx wrapper."""

from __future__ import annotations

from typing import Any

from netra.intel.bypass_checklist import checklist_for, detect_protections
from netra.scanner.passive import security_headers
from netra.scanner.tools.base import CliTool, ToolResult, parse_json_lines


class HttpxTool(CliTool):
    binary = "httpx"
    tool_name = "httpx"
    install_instructions = "Install ProjectDiscovery httpx and put it on PATH."

    async def run(
        self,
        target: str,
        follow_redirects: bool = True,
        tech_detect: bool = True,
        head: bool = False,
        rate_limit: int | None = None,
        **kwargs,
    ) -> ToolResult:
        targets = [t.strip() for t in target.split(",") if t.strip()]
        args = ["-json", "-silent", "-no-color", "-include-response-header"]
        if rate_limit is not None:
            if isinstance(rate_limit, bool) or not 1 <= rate_limit <= 300:
                raise ValueError("invalid httpx rate limit")
            args += ["-rate-limit", str(rate_limit)]
        if follow_redirects:
            args.append("-follow-redirects")
        if tech_detect:
            args.append("-tech-detect")
        if head:
            args.append("-head")
        result = await self._exec(args, stdin="\n".join(targets))
        rows = parse_json_lines(result.raw_output)
        result.findings = [_row_to_finding(row) for row in rows]
        return result


def _row_to_finding(row: dict[str, Any]) -> dict[str, Any]:
    """Map one httpx JSON row to a finding, including protections and the bypass checklist."""
    protections = detect_protections(row.get("header") or {}, row.get("status_code"))
    return {
        "url": row.get("url") or row.get("input"),
        "hostname": row.get("host") or row.get("input"),
        "status_code": row.get("status_code"),
        "location": row.get("location"),
        "tech": row.get("tech") or [],
        "title": row.get("title"),
        "protections": protections,
        "bypass_checklist": [c.check for c in checklist_for(protections)],
        # Only the hardening/disclosure headers: enough for header findings, nothing sensitive.
        # None means httpx returned no header data, which must never read as "no security headers".
        "headers": security_headers(row["header"]) if row.get("header") else None,
    }
