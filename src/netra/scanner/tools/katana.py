"""katana wrapper: crawl a site for endpoints, forms and JavaScript files."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class KatanaTool(CliTool):
    binary = "katana"
    tool_name = "katana"
    install_instructions = "Install ProjectDiscovery katana and put it on PATH."

    async def run(self, url: str, depth: int = 2, **kwargs) -> ToolResult:
        result = await self._exec(["-u", url, "-silent", "-jc", "-d", str(max(1, min(depth, 5)))])
        urls = sorted(
            {
                line.strip()
                for line in result.raw_output.splitlines()
                if line.strip().startswith("http")
            }
        )
        result.findings = [{"url": u} for u in urls]
        return result
