"""Amass wrapper."""
from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class AmassTool(CliTool):
    binary = "amass"
    tool_name = "amass"
    install_instructions = "Install OWASP Amass and put it on PATH."

    async def run(self, target: str, passive: bool = True, timeout: int = 30, **kwargs) -> ToolResult:
        args = ["enum", "-d", target]
        if passive:
            args.append("-passive")
        if timeout:
            args += ["-timeout", str(timeout)]
        result = await self._exec(args, timeout=max(timeout * 60, 60))
        result.findings = [{"hostname": h.strip(), "url": h.strip()} for h in result.raw_output.splitlines() if h.strip()]
        return result

