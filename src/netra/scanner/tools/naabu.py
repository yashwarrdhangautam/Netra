"""naabu wrapper: fast TCP port discovery."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class NaabuTool(CliTool):
    binary = "naabu"
    tool_name = "naabu"
    install_instructions = "Install ProjectDiscovery naabu and put it on PATH."

    async def run(self, host: str, top_ports: str = "100", **kwargs) -> ToolResult:
        host = host.split("://", 1)[-1].split("/", 1)[0]
        args = ["-host", host, "-silent", "-top-ports", top_ports]
        result = await self._exec(args)
        findings: list[dict] = []
        for line in result.raw_output.splitlines():
            if ":" not in line:
                continue
            h, _, port = line.strip().rpartition(":")
            if port.isdigit():
                findings.append({"host": h, "port": int(port), "url": f"{h}:{port}"})
        result.findings = findings
        return result
