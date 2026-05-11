"""Uniform observation model for tool outputs."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from netra.scanner.tools.base import ToolResult


@dataclass
class Observation:
    tool_name: str
    target: str
    ts: datetime
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    derived_facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["ts"] = self.ts.isoformat()
        return row


def observation_from_tool_result(result: ToolResult) -> Observation:
    facts: dict[str, Any] = {"raw_findings": result.findings}
    kind = "generic"

    def _dedupe_str(items: list[Any]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            value = str(item).strip()
            if not value:
                continue
            lowered = value.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            out.append(value)
        return out

    if result.tool_name in {"subfinder", "amass"}:
        kind = "hosts"
        facts["hosts"] = _dedupe_str([
            item.get("hostname") or item.get("url")
            for item in result.findings
            if item.get("hostname") or item.get("url")
        ])
    elif result.tool_name == "httpx":
        kind = "tech"
        facts["tech"] = _dedupe_str([
            tech
            for item in result.findings
            for tech in item.get("tech", [])
        ])
        facts["http_services"] = result.findings
        facts["titles"] = _dedupe_str([item.get("title") for item in result.findings if item.get("title")])
        facts["status_codes"] = [
            item.get("status_code") for item in result.findings if item.get("status_code") is not None
        ]
    elif result.tool_name == "nuclei":
        kind = "findings"
        facts["findings"] = [
            {
                "template_id": item.get("template_id"),
                "severity": item.get("severity"),
                "name": item.get("name") or item.get("title"),
                "matched_at": item.get("matched_at") or item.get("host") or item.get("url"),
                "tags": item.get("tags") or [],
            }
            for item in result.findings
        ]
        facts["vuln_classes"] = _dedupe_str(
            [
                tag
                for item in result.findings
                for tag in (item.get("tags") or [])
            ]
        )
    elif result.tool_name == "ffuf":
        kind = "paths"
        facts["paths"] = _dedupe_str([
            item.get("path") or item.get("url")
            for item in result.findings
            if item.get("path") or item.get("url")
        ])
        facts["interesting_statuses"] = [
            item.get("status_code") for item in result.findings if item.get("status_code") is not None
        ]
    elif result.tool_name in {"nikto", "dalfox", "sqlmap"}:
        kind = "findings"
        facts["findings"] = [
            {
                "title": item.get("title") or item.get("name"),
                "severity": item.get("severity"),
                "url": item.get("url"),
                "parameter": item.get("parameter"),
            }
            for item in result.findings
        ]
    elif result.tool_name == "semgrep":
        kind = "code_findings"
        facts["code_findings"] = [
            {
                "rule_id": item.get("rule_id") or item.get("check_id"),
                "severity": item.get("severity"),
                "path": item.get("path") or item.get("file"),
                "line": item.get("line") or item.get("start", {}).get("line"),
            }
            for item in result.findings
        ]
    elif result.tool_name == "gitleaks":
        kind = "secrets"
        facts["secret_hits"] = [
            {
                "rule_id": item.get("rule_id") or item.get("rule"),
                "file": item.get("file") or item.get("path"),
                "description": item.get("description") or item.get("title"),
            }
            for item in result.findings
        ]
    elif result.tool_name in {"pip-audit", "trivy", "checkov", "prowler"}:
        kind = "risk_findings"
        facts["risk_findings"] = [
            {
                "id": item.get("id") or item.get("check_id") or item.get("template_id"),
                "severity": item.get("severity"),
                "target": item.get("target") or item.get("resource") or item.get("package"),
                "title": item.get("title") or item.get("name"),
            }
            for item in result.findings
        ]

    return Observation(
        tool_name=result.tool_name,
        target=result.target,
        ts=result.completed_at or datetime.now(timezone.utc),
        kind=kind,
        payload={
            "success": result.success,
            "metadata": result.metadata or {},
            "error": result.error,
        },
        derived_facts=facts,
    )
