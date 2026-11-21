"""Dalfox wrapper: URL mode, JSON output, headless browser checks off.

Only verified findings (`type` == "V") become findings. Dalfox's headless-browser entries are
left out because they cannot be tied to a parameter reliably.
"""

from __future__ import annotations

import json

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable


def parse_dalfox_output(result: ToolResult) -> ToolResult:
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    try:
        data = json.loads(result.raw_output)
    except ValueError:
        return mark_unreadable(result, "dalfox_json_invalid")
    if not isinstance(data, list):
        return mark_unreadable(result, "dalfox_json_invalid")
    findings = []
    for item in data:
        if not isinstance(item, dict):
            return mark_unreadable(result, "dalfox_result_invalid")
        if not item:  # dalfox ends the array with an empty object
            continue
        if item.get("type") != "V" or item.get("inject_type") == "headless":
            continue
        inject_type = item.get("inject_type")
        findings.append(
            {
                "title": f"Cross-site scripting ({inject_type}) in parameter {item.get('param')}",
                "description": str(item.get("message_str", ""))[:2000],
                "parameter": item.get("param"),
                "cwe_id": item.get("cwe") or "CWE-79",
                "url": item.get("data"),
                "param": item.get("param"),
                "method": item.get("method"),
                "inject_type": item.get("inject_type"),
                "cwe": item.get("cwe"),
                "severity": str(item.get("severity", "")).lower() or "info",
                "message": str(item.get("message_str", ""))[:500],
            }
        )
    result.findings = findings
    return mark_completed(result)


class DalfoxTool(CliTool):
    binary = "dalfox"
    tool_name = "dalfox"
    install_instructions = "Install dalfox (go install github.com/hahwul/dalfox/v2@latest)."

    async def run(self, target: str, max_rps: int | None = None, **kwargs) -> ToolResult:
        args = ["url", target, "--format", "json", "--silence", "--no-color", "--skip-headless"]
        if max_rps:
            # One worker, with a delay (milliseconds) matching the grant's requests per second.
            args += ["--worker", "1", "--delay", str(max(1, int(1000 / max_rps)))]
        result = await self._exec(args, timeout=900)
        return parse_dalfox_output(result)
