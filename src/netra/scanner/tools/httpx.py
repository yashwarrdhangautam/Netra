"""ProjectDiscovery httpx wrapper."""
from __future__ import annotations

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
        args = ["-json", "-silent", "-no-color"]
        if follow_redirects:
            args.append("-follow-redirects")
        if tech_detect:
            args.append("-tech-detect")
        if head:
            args.append("-head")
        result = await self._exec(args, stdin="\n".join(targets))
        rows = parse_json_lines(result.raw_output)
        result.findings = [
            {
                "url": row.get("url") or row.get("input"),
                "hostname": row.get("host") or row.get("input"),
                "status_code": row.get("status_code"),
                "tech": row.get("tech") or [],
                "title": row.get("title"),
            }
            for row in rows
        ]
        return result

