"""wpscan wrapper: WordPress core, plugin and theme vulnerabilities (JSON output)."""

from __future__ import annotations

import json

from netra.scanner.tools.base import CliTool, ToolResult


class WpscanTool(CliTool):
    binary = "wpscan"
    tool_name = "wpscan"
    install_instructions = (
        "Install wpscan (gem install wpscan) and set WPSCAN_API_TOKEN for vulnerability data."
    )

    async def run(self, url: str, api_token: str | None = None, **kwargs) -> ToolResult:
        args = ["--url", url, "--format", "json", "--no-banner", "--random-user-agent"]
        if api_token:
            args += ["--api-token", api_token]
        result = await self._exec(args, timeout=900)
        findings: list[dict] = []
        try:
            report = json.loads(result.raw_output or "{}")
        except json.JSONDecodeError:
            report = {}
        for kind in ("version", "main_theme"):
            block = report.get(kind) or {}
            for vuln in block.get("vulnerabilities", []) or []:
                findings.append(_vuln(vuln, f"WordPress {kind.replace('_', ' ')}"))
        for plugin_name, plugin in (report.get("plugins") or {}).items():
            for vuln in plugin.get("vulnerabilities", []) or []:
                findings.append(_vuln(vuln, f"WordPress plugin {plugin_name}"))
        result.findings = findings
        return result


def _vuln(vuln: dict, component: str) -> dict:
    refs = vuln.get("references") or {}
    return {
        "title": f"{component}: {vuln.get('title', 'vulnerability')}",
        "severity": "high",
        "cve": ",".join(refs.get("cve", []) or []),
        "url": ",".join(refs.get("url", []) or [])[:500],
        "description": vuln.get("title", ""),
    }
