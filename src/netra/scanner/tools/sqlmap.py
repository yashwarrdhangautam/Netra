"""sqlmap wrapper: detection only, batch mode, no data extraction.

sqlmap has no stable machine-readable output, so the parser reads its text summary. A run
counts as completed only when the summary says either "vulnerable" with parameters, or
"not injectable". Anything else is parse_error, never a clean result (spec 6.4).
"""

from __future__ import annotations

import re

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable

_PARAM = re.compile(r"^Parameter: (\S+) \((\w+)\)\s*$")
_TYPE = re.compile(r"^\s*Type: (.+)$")
_NOT_INJECTABLE = re.compile(
    r"does not seem to be injectable|do not appear to be injectable|not injectable"
)


def parse_sqlmap_output(result: ToolResult) -> ToolResult:
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    lines = result.raw_output.splitlines()
    findings: list[dict] = []
    current: dict | None = None
    for line in lines:
        param = _PARAM.match(line.strip())
        if param:
            current = {"param": param.group(1), "method": param.group(2)}
            continue
        if current is not None:
            kind = _TYPE.match(line)
            if kind:
                technique = kind.group(1).strip()
                findings.append(
                    {
                        **current,
                        "technique": technique,
                        "title": f"SQL injection ({technique}) in parameter {current['param']}",
                        "description": "sqlmap confirmed the injection with a detection-only test.",
                        "parameter": current["param"],
                        "severity": "high",
                        "cwe_id": "CWE-89",
                    }
                )
                current = None
    if findings:
        result.findings = findings
        return mark_completed(result)
    if any(_NOT_INJECTABLE.search(line) for line in lines):
        result.findings = []
        return mark_completed(result)
    return mark_unreadable(result, "sqlmap_summary_missing")


class SqlmapTool(CliTool):
    binary = "sqlmap"
    tool_name = "sqlmap"
    install_instructions = "Install sqlmap and put a sqlmap launcher on PATH."

    async def run(
        self,
        target: str,
        level: int = 1,
        risk: int = 1,
        max_rps: int | None = None,
        **kwargs,
    ) -> ToolResult:
        if not (1 <= level <= 5 and 1 <= risk <= 3):
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                error="sqlmap level or risk out of range",
                metadata={"state": "failed", "reason_code": "invalid_options"},
            )
        result = await self._exec(
            [
                "-u",
                target,
                "--batch",
                "--technique=B",
                f"--level={level}",
                f"--risk={risk}",
                "--disable-coloring",
                "--flush-session",
                # One request at a time, spaced to the signed grant's requests per second.
                "--threads=1",
                *([f"--delay={1.0 / max_rps:.3f}"] if max_rps else []),
            ],
            timeout=900,
        )
        parsed = parse_sqlmap_output(result)
        for finding in parsed.findings:
            finding["url"] = target
        return parsed
