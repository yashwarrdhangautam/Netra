"""ProjectDiscovery httpx wrapper."""

from __future__ import annotations

from typing import Any

from netra.intel.bypass_checklist import checklist_for, detect_protections
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
        **kwargs,
    ) -> ToolResult:
        targets = [t.strip() for t in target.split(",") if t.strip()]
        args = ["-json", "-silent", "-no-color", "-include-response-header"]
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
        "tech": row.get("tech") or [],
        "title": row.get("title"),
        "protections": protections,
        "bypass_checklist": [c.check for c in checklist_for(protections)],
    }
