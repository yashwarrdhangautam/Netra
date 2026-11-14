"""assetfinder wrapper: subdomain discovery from certificate transparency and public sources."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class AssetfinderTool(CliTool):
    binary = "assetfinder"
    tool_name = "assetfinder"
    install_instructions = (
        "Install tomnomnom/assetfinder (go install github.com/tomnomnom/assetfinder@latest)."
    )

    async def run(self, target: str, **kwargs) -> ToolResult:
        result = await self._exec(["--subs-only", target])
        hosts = sorted(
            {
                line.strip().lstrip("*.").lower()
                for line in result.raw_output.splitlines()
                if line.strip()
            }
        )
        result.findings = [{"hostname": h, "url": h} for h in hosts]
        return result
