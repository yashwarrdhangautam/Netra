"""pip-audit wrapper: requirements file in, JSON advisories out."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import load_json_object, mark_completed, mark_unreadable


def parse_pip_audit_output(result: ToolResult) -> ToolResult:
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    data = load_json_object(result)
    if data is None or not isinstance(data.get("dependencies"), list):
        return mark_unreadable(result, "pip_audit_json_invalid")
    findings = []
    for dep in data["dependencies"]:
        if not isinstance(dep, dict) or not isinstance(dep.get("vulns"), list):
            return mark_unreadable(result, "pip_audit_result_invalid")
        for vuln in dep["vulns"]:
            if not isinstance(vuln, dict):
                return mark_unreadable(result, "pip_audit_result_invalid")
            findings.append(
                {
                    "advisory_id": vuln.get("id"),
                    "aliases": vuln.get("aliases", []),
                    "package": dep.get("name"),
                    "version": dep.get("version"),
                    "fix_versions": vuln.get("fix_versions", []),
                    "description": str(vuln.get("description", ""))[:300],
                }
            )
    result.findings = findings
    return mark_completed(result)


class PipAuditTool(CliTool):
    binary = "pip-audit"
    tool_name = "pip-audit"
    accepted_exit_codes = (0, 1)
    install_instructions = "Install pip-audit (pip install pip-audit) and put it on PATH."

    async def run(self, target: str, **kwargs) -> ToolResult:
        result = await self._exec(
            ["-r", target, "-f", "json", "--progress-spinner", "off"], timeout=900
        )
        return parse_pip_audit_output(result)
