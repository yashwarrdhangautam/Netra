"""Trivy wrapper: config (IaC misconfiguration) mode with JSON output.

Image mode needs its vulnerability database loaded before the assessment, and that load is not
part of this wrapper yet. Image scans therefore return an explicit `unavailable` result rather
than silently reporting zero vulnerabilities (spec 6.4).
"""

from __future__ import annotations

import json

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable

_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def parse_trivy_config_output(result: ToolResult) -> ToolResult:
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    try:
        data = json.loads(result.raw_output)
    except ValueError:
        return mark_unreadable(result, "trivy_json_invalid")
    if not isinstance(data, dict) or not isinstance(data.get("Results", []), list):
        return mark_unreadable(result, "trivy_json_invalid")
    findings = []
    for entry in data.get("Results") or []:
        if not isinstance(entry, dict):
            return mark_unreadable(result, "trivy_result_invalid")
        misconfigs = entry.get("Misconfigurations") or []
        if not isinstance(misconfigs, list):
            return mark_unreadable(result, "trivy_result_invalid")
        for item in misconfigs:
            if not isinstance(item, dict) or item.get("Status", "FAIL") != "FAIL":
                continue
            findings.append(
                {
                    "check_id": item.get("ID"),
                    "title": str(item.get("Title", ""))[:300],
                    "severity": _SEVERITY.get(str(item.get("Severity", "")).upper(), "info"),
                    "target": entry.get("Target"),
                    "message": str(item.get("Message", ""))[:500],
                }
            )
    result.findings = findings
    return mark_completed(result)


class TrivyTool(CliTool):
    binary = "trivy"
    tool_name = "trivy"
    install_instructions = "Install trivy (winget install AquaSecurity.Trivy) and put it on PATH."

    async def run(self, target: str, mode: str = "config", **kwargs) -> ToolResult:
        if mode != "config":
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                error="trivy image mode is not available",
                metadata={"state": "unavailable", "reason_code": "image_mode_not_loaded"},
            )
        result = await self._exec(
            ["config", "--format", "json", "--quiet", "--exit-code", "0", target], timeout=900
        )
        return parse_trivy_config_output(result)
