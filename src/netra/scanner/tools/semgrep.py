"""Semgrep wrapper: NETRA-owned rules, JSON output, metrics and version checks off.

The caller passes a path that has already passed source containment (services/source_paths).
"""

from __future__ import annotations

import re
from pathlib import Path

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import load_json_object, mark_completed, mark_unreadable

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "netra-semgrep.yml"
# The check_id carries the scanned path before the rule id, so take the last "netra." segment.
_RULE_ID = re.compile(r"^.*(netra\.[\w.\-]+)$")
_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep_output(result: ToolResult) -> ToolResult:
    """Turn Semgrep JSON into findings. Anything unexpected is parse_error, not clean."""
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    data = load_json_object(result)
    if data is None or not isinstance(data.get("results"), list):
        return mark_unreadable(result, "semgrep_json_invalid")
    if data.get("errors"):
        return mark_unreadable(result, "semgrep_reported_errors")
    findings = []
    for item in data["results"]:
        if not isinstance(item, dict):
            return mark_unreadable(result, "semgrep_result_invalid")
        check_id = str(item.get("check_id", ""))
        match = _RULE_ID.search(check_id)
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        severity = str(extra.get("severity", "")).upper()
        findings.append(
            {
                "rule_id": match.group(1) if match else check_id,
                "path": item.get("path"),
                "line": (item.get("start") or {}).get("line"),
                "severity": _SEVERITY.get(severity, "info"),
                "message": str(extra.get("message", ""))[:500],
                "cwe": metadata.get("cwe"),
            }
        )
    result.findings = findings
    return mark_completed(result)


class SemgrepTool(CliTool):
    binary = "semgrep"
    tool_name = "semgrep"
    accepted_exit_codes = (0, 1)
    install_instructions = "Install semgrep (pip install semgrep) and put it on PATH."

    async def run(self, target: str, **kwargs) -> ToolResult:
        result = await self._exec(
            [
                "scan",
                "--config",
                str(RULES_PATH),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--quiet",
                target,
            ],
            timeout=900,
        )
        return parse_semgrep_output(result)
