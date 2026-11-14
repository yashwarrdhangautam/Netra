"""Nuclei wrapper."""

from __future__ import annotations

from netra.core.config import settings
from netra.scanner.tools.base import CliTool, ToolResult, parse_json_lines
from netra.scanner.tools.template_pin import template_args


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
        **kwargs,
    ) -> ToolResult:
        args = [
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity",
            severity,
            "-rate-limit",
            str(rate_limit),
        ]
        if tags:
            args += ["-tags", tags]
        elif templates and templates != "default":
            args += ["-templates", templates]
        else:
            # Default: use the pinned template checkout when it is present.
            args += template_args(settings.tools_dir)
        result = await self._exec(args)
        rows = parse_json_lines(result.raw_output)
        result.findings = [
            {
                "title": row.get("info", {}).get("name")
                or row.get("template-id", "Nuclei finding"),
                "template_id": row.get("template-id"),
                "matched_at": row.get("matched-at"),
                "url": row.get("matched-at"),
                "severity": row.get("info", {}).get("severity", "info"),
                "description": row.get("info", {}).get("description", ""),
                "evidence": row,
            }
            for row in rows
        ]
        return result
