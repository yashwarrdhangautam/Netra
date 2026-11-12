"""ffuf wrapper."""
from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class FfufTool(CliTool):
    binary = "ffuf"
    tool_name = "ffuf"
    install_instructions = "Install ffuf and put it on PATH."

    async def run(self, target: str, wordlist: str = "common.txt", rate_limit: int | None = None, **kwargs) -> ToolResult:
        args = ["-u", target, "-w", wordlist, "-of", "json", "-s"]
        if rate_limit:
            args += ["-rate", str(rate_limit)]
        result = await self._exec(args)
        try:
            import json

            data = json.loads(result.raw_output or "{}")
            rows = data.get("results", [])
        except Exception:
            rows = []
        result.findings = [
            {
                "url": row.get("url"),
                "path": "/" + str(row.get("input", {}).get("FUZZ", "")).lstrip("/"),
                "status_code": row.get("status"),
                "length": row.get("length"),
            }
            for row in rows
        ]
        return result

