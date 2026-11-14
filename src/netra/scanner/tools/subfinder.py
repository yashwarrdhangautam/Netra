"""Subfinder wrapper."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class SubfinderTool(CliTool):
    binary = "subfinder"
    tool_name = "subfinder"
    install_instructions = "Install ProjectDiscovery subfinder and put it on PATH."

    async def run(
        self, target: str, passive_only: bool = False, recursive: bool = False, **kwargs
    ) -> ToolResult:
        args = ["-d", target, "-silent"]
        if passive_only or kwargs.get("sources") == "passive":
            args.append("-passive")
        if recursive:
            args.append("-recursive")
        result = await self._exec(args)
        result.findings = [
            {"hostname": h.strip(), "url": h.strip()}
            for h in result.raw_output.splitlines()
            if h.strip()
        ]
        return result
