"""Tool capability metadata for the agentic loop."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SafetyClass(StrEnum):
    PASSIVE = "passive"
    ACTIVE_READONLY = "active_readonly"
    ACTIVE_INTRUSIVE = "active_intrusive"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    side_effects: str
    safety_class: SafetyClass
    rate_limit: int | None = None


TOOL_REGISTRY: dict[str, ToolSpec] = {
    "subfinder": ToolSpec("subfinder", "recon", ("domain",), ("hosts",), "none", SafetyClass.PASSIVE),
    "amass": ToolSpec("amass", "recon", ("domain",), ("hosts",), "none", SafetyClass.PASSIVE),
    "httpx": ToolSpec("httpx", "probe", ("host",), ("http_services", "tech"), "head/get", SafetyClass.ACTIVE_READONLY, 150),
    "ffuf": ToolSpec("ffuf", "fuzz", ("url",), ("paths",), "get", SafetyClass.ACTIVE_READONLY, 50),
    "nuclei": ToolSpec("nuclei", "scan", ("url",), ("findings",), "get/head", SafetyClass.ACTIVE_READONLY, 150),
    "gitleaks": ToolSpec("gitleaks", "content", ("text",), ("secret_hits",), "none", SafetyClass.PASSIVE),
    "semgrep": ToolSpec("semgrep", "code", ("path",), ("code_findings",), "none", SafetyClass.PASSIVE),
    "checkov": ToolSpec("checkov", "iac", ("path",), ("iac_findings",), "none", SafetyClass.PASSIVE),
    "pip-audit": ToolSpec("pip-audit", "deps", ("path",), ("dependency_findings",), "none", SafetyClass.PASSIVE),
    "trivy": ToolSpec("trivy", "container", ("image",), ("container_findings",), "none", SafetyClass.PASSIVE),
    "prowler": ToolSpec("prowler", "cloud", ("account",), ("cloud_findings",), "readonly api", SafetyClass.ACTIVE_READONLY),
    "shodan": ToolSpec("shodan", "intel", ("ip", "domain"), ("service_facts",), "none", SafetyClass.PASSIVE),
    "dalfox": ToolSpec("dalfox", "xss", ("url",), ("xss_findings",), "request with payloads", SafetyClass.ACTIVE_INTRUSIVE),
    "sqlmap": ToolSpec("sqlmap", "sqli", ("url",), ("sqli_findings",), "request with payloads", SafetyClass.ACTIVE_INTRUSIVE),
}


def get_tool_spec(name: str) -> ToolSpec | None:
    return TOOL_REGISTRY.get(name)


def registered_tool_names() -> set[str]:
    return set(TOOL_REGISTRY)
