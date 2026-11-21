"""Nuclei wrapper: JSON Lines output, pinned template checkout when present.

Every non-empty output line must be a JSON object. A line that is not one makes the whole run
`parse_error`: silently dropping it would turn unreadable output into a clean result (spec 6.2).
"""

from __future__ import annotations

import json

from netra.core.config import settings
from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable
from netra.scanner.tools.template_pin import template_args

# Methods a template can use. Any not on the signed grant are filtered out with -tc.
HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT")
# Tags never run in a vulnerability scan: they change state, flood, or fuzz the target.
NON_EXPLOIT_EXCLUDE_TAGS = ("intrusive", "dos", "fuzz")

# Nuclei drops a host after repeated errors and still exits 0 with no output, which would
# read as "tested, nothing found". This line is how that case is recognised.
_HOST_SKIPPED_MARKER = "from target list as found unresponsive"


def method_condition(allowed_methods: list[str] | tuple[str, ...]) -> str | None:
    """A -tc expression that drops every template using a method outside the grant."""
    allowed = {m.upper() for m in allowed_methods}
    denied = [m for m in HTTP_METHODS if m not in allowed]
    if not denied:
        return None
    return " && ".join(f'!contains(http_method, "{m}")' for m in denied)


def parse_nuclei_output(result: ToolResult) -> ToolResult:
    timed_out = result.metadata.get("reason_code") == "timeout"
    if (not result.success and not timed_out) or result.metadata.get("state") == "parse_error":
        return result
    stderr = str(result.metadata.get("stderr") or "")
    rows: list[dict] = []
    lines = result.raw_output.splitlines()
    if timed_out and lines and not result.raw_output.endswith("\n"):
        lines = lines[:-1]  # the process was killed mid-write; the last line is incomplete
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            return mark_unreadable(result, "nuclei_jsonl_invalid")
        if not isinstance(row, dict):
            return mark_unreadable(result, "nuclei_jsonl_invalid")
        rows.append(row)
    result.findings = [
        {
            "title": (row.get("info") or {}).get("name")
            or row.get("template-id", "Nuclei finding"),
            "template_id": row.get("template-id"),
            "matched_at": row.get("matched-at"),
            "url": row.get("matched-at"),
            "severity": (row.get("info") or {}).get("severity", "info"),
            "description": (row.get("info") or {}).get("description", ""),
            "evidence": row,
        }
        for row in rows
    ]
    if timed_out:
        # Findings made before the time limit are kept; the run stays failed (not all covered).
        return result
    if _HOST_SKIPPED_MARKER in stderr:
        # Findings found before the skip are kept, but the run did not cover the host.
        result.success = False
        result.error = "host_unresponsive: nuclei stopped testing the host after repeated errors"
        result.metadata = {**result.metadata, "state": "failed", "reason_code": "host_unresponsive"}
        return result
    return mark_completed(result)


class NucleiTool(CliTool):
    binary = "nuclei"
    tool_name = "nuclei"
    install_instructions = "Install ProjectDiscovery nuclei and put it on PATH."

    async def run(
        self,
        target: str,
        templates: str = "default",
        severity: str = "critical,high,medium",
        rate_limit: int = 150,
        tags: str | None = None,
        allowed_methods: list[str] | tuple[str, ...] | None = None,
        protocol_types: list[str] | tuple[str, ...] | None = None,
        exclude_tags: list[str] | tuple[str, ...] | None = None,
        timeout: int = 300,
        **kwargs,
    ) -> ToolResult:
        args = [
            "-u",
            target,
            "-jsonl",
            # Not -silent: it also hides the "host skipped as unresponsive" line, which is the
            # only sign that a host was never tested. Results stay on stdout as JSON Lines.
            "-no-color",
            "-severity",
            severity,
            "-rate-limit",
            str(rate_limit),
            # Bounded template and host concurrency. With the default, nuclei on Windows hit
            # the Go runtime's 10000-thread limit against Juice Shop and wrote ~40 MB to stderr.
            "-concurrency",
            "10",
            "-bulk-size",
            "10",
            # No update check or template download at start: the run uses the pinned set.
            "-disable-update-check",
        ]
        if protocol_types:
            args += ["-type", ",".join(protocol_types)]
        if exclude_tags:
            args += ["-exclude-tags", ",".join(exclude_tags)]
        if allowed_methods is not None:
            condition = method_condition(allowed_methods)
            if condition:
                args += ["-template-condition", condition]
        if tags:
            # Tags filter within the template set below; they never switch to another set.
            args += ["-tags", tags]
        if templates and templates != "default":
            args += ["-templates", templates]
        else:
            # Default: use the pinned template checkout when it is present.
            args += template_args(settings.tools_dir)
        result = await self._exec(args, timeout=timeout)
        return parse_nuclei_output(result)
