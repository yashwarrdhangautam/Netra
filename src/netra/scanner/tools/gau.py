"""gau wrapper: historical URLs from the Wayback Machine, Common Crawl, OTX and URLScan."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class GauTool(CliTool):
    binary = "gau"
    tool_name = "gau"
    install_instructions = "Install lc/gau (go install github.com/lc/gau/v2/cmd/gau@latest)."

    async def run(self, target: str, **kwargs) -> ToolResult:
        result = await self._exec(["--subs", target])
        urls = sorted(
            {
                line.strip()
                for line in result.raw_output.splitlines()
                if line.strip().startswith("http")
            }
        )
        result.findings = [
            {"url": u, "hostname": u.split("/")[2] if "//" in u else ""} for u in urls
        ]
        return result
