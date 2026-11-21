"""Shared helpers for scanner wrappers.

PassthroughTool remains only for tools that have no parser yet. It must never feed a phase
that reports results (spec 6.4).
"""

from __future__ import annotations

import json
from typing import Any

from netra.scanner.tools.base import CliTool, ToolResult


class PassthroughTool(CliTool):
    async def run(self, target: str, **kwargs) -> ToolResult:
        return await self._exec([target])


def mark_unreadable(result: ToolResult, reason: str) -> ToolResult:
    """The tool ran but its output could not be read: never completed, never zero findings."""
    result.success = False
    result.findings = []
    result.error = f"unreadable output: {reason}"
    result.metadata = {**result.metadata, "state": "parse_error", "reason_code": reason}
    return result


def load_json_object(result: ToolResult) -> dict[str, Any] | None:
    """Return the decoded JSON object from the tool output, or None if it is not one."""
    try:
        data = json.loads(result.raw_output)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def mark_completed(result: ToolResult) -> ToolResult:
    result.success = True
    result.error = None
    result.metadata = {**result.metadata, "state": "completed", "reason_code": None}
    return result
