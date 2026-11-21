"""Nuclei wrapper: JSON Lines output, pinned template checkout when present.

Every non-empty output line must be a JSON object. A line that is not one makes the whole run
`parse_error`: silently dropping it would turn unreadable output into a clean result (spec 6.2).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from netra.core.config import settings
from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable
from netra.scanner.tools.template_pin import template_args

# Methods a template can use. Any not on the signed grant are filtered out with -tc.
HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT")
# Tags never run in a vulnerability scan: they change state, flood, or fuzz the target.
NON_EXPLOIT_EXCLUDE_TAGS = ("intrusive", "dos", "fuzz")

# Nuclei's default (30) drops a host after 30 request errors. At a 1 rps grant a healthy but
# slow site reaches that on a handful of slow paths (scan 47b5dfc4 lost its main host this way
# while nikto later ran fine), so the limit is raised. A host that is really down still stops.
MAX_HOST_ERRORS = 100
# Progress line interval (seconds); one JSON line on stderr each time, well under the output cap.
STATS_INTERVAL = 60

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


def last_stats(stderr: str) -> dict[str, int] | None:
    """The latest -stats-json progress line: requests sent, total planned, percent, errors."""
    for line in reversed(stderr.splitlines()):
        line = line.strip()
        if not (line.startswith("{") and '"requests"' in line):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        out = {}
        for key in ("requests", "total", "percent", "errors", "matched"):
            try:
                out[key] = int(str(row.get(key, "")).strip())
            except ValueError:
                pass
        return out or None
    return None


def save_artifacts(work_dir: Path | None, target: str, result: ToolResult) -> list[dict]:
    """Keep raw stdout/stderr beside the phase so a stopped or empty run can be explained."""
    if work_dir is None:
        return []
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:80]
    saved = []
    for kind, text in (
        ("stdout", result.raw_output or ""),
        ("stderr", str(result.metadata.get("stderr") or "")),
    ):
        name = f"nuclei-{host}-{stamp}.{kind}.{'jsonl' if kind == 'stdout' else 'log'}"
        path = work_dir / name
        path.write_text(text, encoding="utf-8")
        saved.append({"kind": kind, "name": name, "path": str(path), "bytes": path.stat().st_size})
    return saved


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
            "-max-host-error",
            str(MAX_HOST_ERRORS),
            # Progress as JSON lines on stderr: how far a long run got, even if it stops.
            "-stats",
            "-stats-json",
            "-stats-interval",
            str(STATS_INTERVAL),
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
        metadata = dict(result.metadata or {})
        progress = last_stats(str(metadata.get("stderr") or ""))
        try:
            artifacts = save_artifacts(self.work_dir, target, result)
        except OSError:
            artifacts = []  # a full disk must not turn a finished scan into a crash
        result.metadata = {**metadata, "progress": progress, "artifacts": artifacts}
        return parse_nuclei_output(result)
