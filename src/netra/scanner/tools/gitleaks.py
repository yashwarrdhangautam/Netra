"""Gitleaks wrapper."""
from __future__ import annotations

import tempfile
from pathlib import Path

from netra.scanner.tools.base import CliTool, ToolResult


class GitleaksTool(CliTool):
    binary = "gitleaks"
    tool_name = "gitleaks"
    install_instructions = "Install gitleaks and put it on PATH."

    async def run(self, path: str, scan_history: bool = True, **kwargs) -> ToolResult:
        args = ["detect", "--source", path, "--report-format", "json", "--no-banner"]
        if not scan_history:
            args.append("--no-git")
        result = await self._exec(args)
        try:
            import json

            rows = json.loads(result.raw_output or "[]")
        except Exception:
            rows = []
        result.findings = rows if isinstance(rows, list) else []
        return result

    async def scan_text(self, text: str) -> ToolResult:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.txt"
            path.write_text(text, encoding="utf-8")
            return await self.run(str(tmp), scan_history=False)

