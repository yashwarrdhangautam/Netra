"""SARIF 2.1.0 export for NETRA findings.

GitHub code scanning, GitLab and most CI tools read this format. Severity maps
to SARIF levels: critical and high become "error", medium becomes "warning",
low and info become "note".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from netra import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/yashwg/netra"

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _field(finding: Any, name: str, default: Any = None) -> Any:
    """Read a field from a dict or an ORM object."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _rule_id(finding: Any) -> str:
    # Findings store cwe_id ("CWE-693"); older callers pass cwe ("693").
    cwe = str(_field(finding, "cwe_id") or _field(finding, "cwe") or "").upper()
    if cwe:
        return cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
    tool = _field(finding, "tool_name") or _field(finding, "tool") or "netra"
    return str(tool)


def _severity(finding: Any) -> str:
    value = _field(finding, "severity") or "info"
    return str(getattr(value, "value", value)).lower()


def build_sarif(findings: list[Any]) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document as a dict."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        severity = _severity(finding)
        title = str(_field(finding, "title") or "Finding")
        description = str(_field(finding, "description") or title)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "properties": {"tags": ["security"]},
            }
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _LEVEL.get(severity, "note"),
            "message": {"text": description},
            "properties": {"severity": severity, "status": str(_field(finding, "status") or "")},
        }
        location = (
            _field(finding, "location") or _field(finding, "target") or _field(finding, "url")
        )
        if location:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": str(location)}}}
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NETRA",
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def generate_sarif(findings: list[Any], output_path: Path) -> Path:
    """Write a SARIF file and return its path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_sarif(findings), indent=2), encoding="utf-8")
    return output_path
