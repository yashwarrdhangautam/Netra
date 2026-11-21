"""Checkov wrapper: directory mode, JSON output, no network checks."""

from __future__ import annotations

import json

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable


def parse_checkov_output(result: ToolResult) -> ToolResult:
    """Checkov prints one object per framework, or a single summary when nothing was checked."""
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    if not result.raw_output.strip():
        # Exit code 1 is accepted (checks failed), so a crash that printed nothing to stdout
        # also lands here. Say it crashed, instead of blaming the JSON.
        stderr = str(result.metadata.get("stderr") or "").strip()
        result.success = False
        result.findings = []
        result.error = "checkov produced no output" + (f": {stderr[-300:]}" if stderr else "")
        result.metadata = {**result.metadata, "state": "failed", "reason_code": "no_output"}
        return result
    try:
        data = json.loads(result.raw_output)
    except ValueError:
        return mark_unreadable(result, "checkov_json_invalid")
    docs = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    resources = 0
    for doc in docs:
        if not isinstance(doc, dict):
            return mark_unreadable(result, "checkov_result_invalid")
        if "resource_count" in doc:  # summary object: nothing matched a framework
            resources += int(doc.get("resource_count") or 0)
            continue
        body = doc.get("results")
        if not isinstance(body, dict) or not isinstance(body.get("failed_checks"), list):
            return mark_unreadable(result, "checkov_result_invalid")
        for check in body["failed_checks"]:
            if not isinstance(check, dict):
                return mark_unreadable(result, "checkov_result_invalid")
            findings.append(
                {
                    "check_id": check.get("check_id"),
                    "check_name": str(check.get("check_name", ""))[:300],
                    "file_path": check.get("file_path"),
                    "resource": check.get("resource"),
                }
            )
    result.findings = findings
    result.metadata = {**result.metadata, "resources_checked": resources}
    return mark_completed(result)


class CheckovTool(CliTool):
    binary = "checkov"
    tool_name = "checkov"
    accepted_exit_codes = (0, 1)
    install_instructions = "Install checkov (pip install checkov) and put it on PATH."

    async def run(self, target: str, **kwargs) -> ToolResult:
        result = await self._exec(["-d", target, "-o", "json", "--quiet", "--compact"], timeout=900)
        return parse_checkov_output(result)
