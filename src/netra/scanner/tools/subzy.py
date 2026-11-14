"""subzy wrapper: subdomain takeover detection across a list of hosts."""

from __future__ import annotations

import tempfile
from pathlib import Path

from netra.scanner.tools.base import CliTool, ToolResult


class SubzyTool(CliTool):
    binary = "subzy"
    tool_name = "subzy"
    install_instructions = (
        "Install PentestPad subzy (go install github.com/PentestPad/subzy@latest)."
    )

    async def run(self, targets: list[str] | str, **kwargs) -> ToolResult:
        hosts = [targets] if isinstance(targets, str) else list(targets)
        hosts = [h.strip() for h in hosts if h and h.strip()]
        with tempfile.TemporaryDirectory() as tmp:
            host_file = Path(tmp) / "hosts.txt"
            host_file.write_text("\n".join(hosts), encoding="utf-8")
            result = await self._exec(
                ["run", "--targets", str(host_file), "--hide_fails"], timeout=600
            )
        findings: list[dict] = []
        for line in result.raw_output.splitlines():
            upper = line.upper()
            if "NOT VULNERABLE" in upper or not line.split():
                continue
            if "VULNERABLE" in upper:
                host = line.split()[0]
                findings.append(
                    {
                        "title": f"Possible subdomain takeover: {host}",
                        "severity": "high",
                        "hostname": host,
                        "url": host,
                        "description": line.strip(),
                    }
                )
        result.findings = findings
        return result
