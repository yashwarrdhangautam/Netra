"""NETRA MCP Server — exposes security scanning tools to AI assistants.

Run with: python -m netra.mcp.server
Or configure in Claude Desktop / Claude Code config.
"""

import os
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except Exception:

    class FastMCP:
        """Fallback FastMCP stub for incompatible local MCP/Pydantic installs."""

        def __init__(self, name: str, *args, **kwargs) -> None:
            self.name = name

        def tool(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def resource(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def prompt(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def run(self) -> None:
            return None


# Phase 1 tools
from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator, ScopeViolation
from netra.mcp.federated import FederatedMcpClient
from netra.scanner.tools.amass import AmassTool
from netra.scanner.tools.checkov import CheckovTool
from netra.scanner.tools.dalfox import DalfoxTool
from netra.scanner.tools.dependency_scan import PipAuditTool
from netra.scanner.tools.ffuf import FfufTool
from netra.scanner.tools.gitleaks import GitleaksTool
from netra.scanner.tools.httpx import HttpxTool
from netra.scanner.tools.llm_security import LLMSecurityTool
from netra.scanner.tools.nikto import NiktoTool
from netra.scanner.tools.nmap import NmapTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.scanner.tools.prowler import ProwlerTool

# Phase 2 tools
from netra.scanner.tools.semgrep import SemgrepTool
from netra.scanner.tools.shodan import ShodanTool
from netra.scanner.tools.sqlmap import SqlmapTool
from netra.scanner.tools.subfinder import SubfinderTool
from netra.scanner.tools.trivy import TrivyTool

mcp = FastMCP("netra")


def _bb_validator(scope_rules: list[dict[str, str]]) -> ScopeValidator:
    return ScopeValidator(
        [
            ScopeRule(
                rule_type=RuleType(r.get("rule_type", "in")),
                asset_type=AssetType(r.get("asset_type", "domain")),
                pattern=r["pattern"],
                severity_cap=r.get("severity_cap"),
            )
            for r in scope_rules
            if r.get("pattern")
        ]
    )


async def _call_federated_bb(
    tool_name: str, target: str, scope_rules: list[dict[str, str]], arguments: dict[str, Any]
) -> dict[str, Any]:
    try:
        _bb_validator(scope_rules).require(target)
    except ScopeViolation as exc:
        return {
            "success": False,
            "error": "scope_violation",
            "target": target,
            "reason": exc.decision.reason,
        }

    command = os.getenv("NETRA_BB_MCP_COMMAND", "gokulapap-mcp").split()
    try:
        async with FederatedMcpClient(command) as client:
            return await client.call_tool(tool_name, arguments)
    except Exception as exc:
        return {"success": False, "error": "downstream_unavailable", "detail": str(exc)}


# ══════════════════════════════════════════════════════════
# TOOLS (10 security tool wrappers + 4 stubs)
# ══════════════════════════════════════════════════════════


@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: str = "default",
    severity: str = "critical,high,medium",
    rate_limit: int = 150,
) -> dict[str, Any]:
    """Run Nuclei vulnerability scanner with template-based detection.

    Args:
        target: Domain, URL, or IP to scan
        templates: Template category or path (default, cves, misconfigurations, etc.)
        severity: Comma-separated severity filter
        rate_limit: Requests per second limit

    Returns:
        Dict with findings list, stats, and scan metadata
    """
    tool = NucleiTool()
    if not tool.is_installed():
        return {
            "status": "mock",
            "tool": "nuclei",
            "error": "Nuclei not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(target, templates=templates, severity=severity, rate_limit=rate_limit)
    return {
        "status": "ok",
        "tool": "nuclei",
        "success": result.success,
        "findings_count": len(result.findings),
        "findings": result.findings[:20],  # Limit for MCP response size
        "metadata": result.metadata,
        "error": result.error,
    }


@mcp.tool()
async def nmap_scan(
    target: str,
    scan_type: str = "service_version",
    ports: str = "top-1000",
    scripts: str = "",
) -> dict[str, Any]:
    """Run Nmap port scanner with service/version detection.

    Args:
        target: IP, hostname, or CIDR range
        scan_type: Scan type (syn, service_version, os_detect, aggressive)
        ports: Port specification (top-1000, all, or specific like 80,443,8080)
        scripts: NSE scripts to run (comma-separated)

    Returns:
        Dict with open ports, services, and script findings
    """
    tool = NmapTool()
    if not tool.is_installed():
        return {
            "status": "mock",
            "tool": "nmap",
            "error": "Nmap not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(target, scan_type=scan_type, ports=ports, scripts=scripts)
    return {
        "status": "ok",
        "tool": "nmap",
        "success": result.success,
        "ports_found": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


@mcp.tool()
async def sqlmap_test(
    url: str,
    method: str = "GET",
    parameter: str = "",
    level: int = 1,
    risk: int = 1,
    safe_mode: bool = True,
) -> dict[str, Any]:
    """Run sqlmap SQL injection testing.

    Args:
        url: Target URL with injectable parameter
        method: HTTP method (GET, POST)
        parameter: Specific parameter to test
        level: Testing level 1-5 (higher = more tests)
        risk: Risk level 1-3 (higher = more aggressive)
        safe_mode: If true, no data extraction (detection only)

    Returns:
        Dict with SQL injection findings
    """
    tool = SqlmapTool()
    if not tool.is_installed():
        return {
            "error": "sqlmap not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(
        url,
        method=method,
        parameter=parameter,
        level=level,
        risk=risk,
        safe_mode=safe_mode,
    )
    return {
        "success": result.success,
        "findings": result.findings,
        "metadata": result.metadata,
    }


@mcp.tool()
async def subfinder_enum(
    domain: str,
    sources: str = "all",
    recursive: bool = False,
) -> dict[str, Any]:
    """Enumerate subdomains using subfinder.

    Args:
        domain: Root domain to enumerate
        sources: Data sources (all, passive, or specific sources)
        recursive: Enable recursive subdomain enumeration

    Returns:
        Dict with discovered subdomains
    """
    tool = SubfinderTool()
    if not tool.is_installed():
        return {
            "error": "Subfinder not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(domain, sources=sources, recursive=recursive)
    subdomains = [f.get("url", "") for f in result.findings if f.get("url")]
    return {
        "success": result.success,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains[:100],
        "metadata": result.metadata,
    }


@mcp.tool()
async def httpx_probe(
    targets: list[str],
    follow_redirects: bool = True,
    tech_detect: bool = True,
) -> dict[str, Any]:
    """Probe HTTP services for live hosts and technology detection.

    Args:
        targets: List of domains/IPs to probe
        follow_redirects: Follow HTTP redirects
        tech_detect: Enable technology fingerprinting

    Returns:
        Dict with live hosts and technology data
    """
    tool = HttpxTool()
    if not tool.is_installed():
        return {
            "error": "httpx not installed",
            "install": tool.install_instructions,
        }
    target_str = ",".join(targets)
    result = await tool.run(target_str, follow_redirects=follow_redirects, tech_detect=tech_detect)
    return {
        "success": result.success,
        "live_hosts": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "common.txt",
    method: str = "GET",
    filter_codes: str = "404",
    extensions: str = "",
) -> dict[str, Any]:
    """Directory and file fuzzing with ffuf.

    Args:
        url: Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)
        wordlist: Wordlist name or path
        method: HTTP method
        filter_codes: Status codes to filter out
        extensions: File extensions to append (e.g., php,html,js)

    Returns:
        Dict with discovered resources
    """
    tool = FfufTool()
    if not tool.is_installed():
        return {
            "error": "ffuf not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(
        url,
        wordlist=wordlist,
        method=method,
        filter_codes=filter_codes,
        extensions=extensions,
    )
    return {
        "success": result.success,
        "discoveries": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def dalfox_xss(
    url: str,
    parameter: str = "",
    blind_url: str = "",
) -> dict[str, Any]:
    """XSS vulnerability scanning with Dalfox.

    Args:
        url: Target URL
        parameter: Specific parameter to test
        blind_url: Callback URL for blind XSS detection

    Returns:
        Dict with XSS findings
    """
    tool = DalfoxTool()
    if not tool.is_installed():
        return {
            "error": "Dalfox not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(url, parameter=parameter, blind_url=blind_url)
    return {
        "success": result.success,
        "findings": result.findings,
        "metadata": result.metadata,
    }


@mcp.tool()
async def nikto_scan(
    target: str,
    tuning: str = "",
    ssl: bool = True,
) -> dict[str, Any]:
    """Web server misconfiguration scanning with Nikto.

    Args:
        target: Target URL or IP
        tuning: Scan tuning options
        ssl: Force SSL/TLS

    Returns:
        Dict with web server findings
    """
    tool = NiktoTool()
    if not tool.is_installed():
        return {
            "error": "Nikto not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(target, tuning=tuning, ssl=ssl)
    return {
        "success": result.success,
        "findings_count": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


@mcp.tool()
async def amass_enum(
    domain: str,
    passive: bool = True,
    timeout: int = 30,
) -> dict[str, Any]:
    """Advanced subdomain enumeration with OWASP Amass.

    Args:
        domain: Target domain
        passive: Passive-only mode (no DNS resolution)
        timeout: Timeout in minutes

    Returns:
        Dict with discovered subdomains
    """
    tool = AmassTool()
    if not tool.is_installed():
        return {
            "error": "Amass not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(domain, passive=passive, timeout=timeout)
    subdomains = [f.get("url", "") for f in result.findings if f.get("url")]
    return {
        "success": result.success,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains[:100],
        "metadata": result.metadata,
    }


@mcp.tool()
async def shodan_search(
    query: str,
    max_results: int = 100,
) -> dict[str, Any]:
    """Search Shodan for exposed services and vulnerabilities.

    Args:
        query: Shodan search query (e.g., 'hostname:example.com')
        max_results: Maximum results to return

    Returns:
        Dict with Shodan results and vulnerabilities
    """
    tool = ShodanTool()
    if not tool.is_installed():
        return {
            "error": "Shodan SDK not installed or API key not configured",
            "install": tool.install_instructions,
        }
    result = await tool.run(query, max_results=max_results)
    return {
        "success": result.success,
        "results_count": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


@mcp.tool()
async def bb_passive_recon(target: str, scope_rules: list[dict[str, str]]) -> dict[str, Any]:
    """Proxy passive bug bounty recon through downstream MCP with NETRA scope gate."""
    return await _call_federated_bb("bb_passive_recon", target, scope_rules, {"target": target})


@mcp.tool()
async def bb_active_recon(target: str, scope_rules: list[dict[str, str]]) -> dict[str, Any]:
    """Proxy active bug bounty recon through downstream MCP with NETRA scope gate."""
    return await _call_federated_bb("bb_active_recon", target, scope_rules, {"target": target})


@mcp.tool()
async def bb_subdomain_enum(domain: str, scope_rules: list[dict[str, str]]) -> dict[str, Any]:
    """Proxy subdomain enumeration through downstream MCP with NETRA scope gate."""
    return await _call_federated_bb("bb_subdomain_enum", domain, scope_rules, {"domain": domain})


# ══════════════════════════════════════════════════════════
# PHASE 2 TOOLS (White-box, Cloud, AI/LLM)
# ══════════════════════════════════════════════════════════


@mcp.tool()
async def semgrep_scan(
    path: str,
    ruleset: str = "all",
    language: str = "",
    max_findings: int = 500,
) -> dict[str, Any]:
    """Static Application Security Testing (SAST) with Semgrep.

    Args:
        path: Path to source code directory or git repository URL
        ruleset: Ruleset category (security, python, javascript, go, java, secrets, all)
        language: Filter by language
        max_findings: Maximum findings to return

    Returns:
        Dict with SAST findings
    """
    tool = SemgrepTool()
    if not tool.is_installed():
        return {
            "error": "Semgrep not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(path, ruleset=ruleset, language=language, max_findings=max_findings)
    return {
        "success": result.success,
        "findings_count": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def gitleaks_scan(
    path: str,
    scan_history: bool = True,
) -> dict[str, Any]:
    """Secret detection in source code and git history with Gitleaks.

    Args:
        path: Path to source code or git repository
        scan_history: Scan git history (default: True)

    Returns:
        Dict with exposed secrets findings
    """
    tool = GitleaksTool()
    if not tool.is_installed():
        return {
            "error": "Gitleaks not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(path, scan_history=scan_history)
    return {
        "success": result.success,
        "secrets_found": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


@mcp.tool()
async def pip_audit_scan(
    path: str,
) -> dict[str, Any]:
    """Python dependency vulnerability scanning with pip-audit.

    Args:
        path: Path to project directory with requirements.txt

    Returns:
        Dict with vulnerable dependency findings
    """
    tool = PipAuditTool()
    if not tool.is_installed():
        return {
            "error": "pip-audit not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(path)
    return {
        "success": result.success,
        "vulnerabilities_found": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


@mcp.tool()
async def prowler_audit(
    provider: str = "aws",
    checks: str = "",
    compliance: str = "",
) -> dict[str, Any]:
    """Cloud Security Posture Management with Prowler.

    Args:
        provider: Cloud provider (aws, azure, gcp)
        checks: Specific checks to run (comma-separated)
        compliance: Compliance framework to assess (cis, pci, hipaa, etc.)

    Returns:
        Dict with cloud misconfiguration findings
    """
    tool = ProwlerTool()
    if not tool.is_installed():
        return {
            "error": "Prowler not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(provider, provider=provider, checks=checks, compliance=compliance)
    return {
        "success": result.success,
        "findings_count": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def trivy_scan(
    target: str,
    scan_type: str = "image",
    severity: str = "CRITICAL,HIGH",
) -> dict[str, Any]:
    """Container image and filesystem vulnerability scanning with Trivy.

    Args:
        target: Container image name, filesystem path, or git repo
        scan_type: Type of scan (image, fs, repo, config)
        severity: Severity filter

    Returns:
        Dict with vulnerability findings
    """
    tool = TrivyTool()
    if not tool.is_installed():
        return {
            "error": "Trivy not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(target, scan_type=scan_type, severity=severity)
    return {
        "success": result.success,
        "vulnerabilities_found": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def checkov_scan(
    path: str,
    framework: str = "",
) -> dict[str, Any]:
    """Infrastructure as Code security scanning with Checkov.

    Args:
        path: Path to IaC files directory
        framework: Specific framework (terraform, cloudformation, kubernetes, dockerfile)

    Returns:
        Dict with IaC misconfiguration findings
    """
    tool = CheckovTool()
    if not tool.is_installed():
        return {
            "error": "Checkov not installed",
            "install": tool.install_instructions,
        }
    result = await tool.run(path, framework=framework)
    return {
        "success": result.success,
        "misconfigurations_found": len(result.findings),
        "findings": result.findings[:50],
        "metadata": result.metadata,
    }


@mcp.tool()
async def llm_security_scan(
    target: str,
    test_categories: list[str] | None = None,
    max_payloads: int = 10,
) -> dict[str, Any]:
    """OWASP LLM Top 10 security testing for AI/LLM endpoints.

    Args:
        target: URL of the LLM endpoint (chat API, chatbot)
        test_categories: Categories to test (direct_injection, jailbreak, data_exfiltration, excessive_agency)
        max_payloads: Max payloads per category

    Returns:
        Dict with LLM security findings
    """
    tool = LLMSecurityTool()
    if test_categories is None:
        test_categories = ["direct_injection", "jailbreak", "data_exfiltration", "excessive_agency"]
    result = await tool.run(target, test_categories=test_categories, max_payloads=max_payloads)
    return {
        "success": result.success,
        "vulnerabilities_found": len(result.findings),
        "findings": result.findings[:30],
        "metadata": result.metadata,
    }


# ══════════════════════════════════════════════════════════
async def wpscan_check(
    url: str,
    enumerate: str = "vp,vt,u",  # noqa: A002 - public tool argument, matches WPScan
    api_token: str = "",
) -> dict[str, Any]:
    """WordPress-specific vulnerability scanning.

    Note: Not yet configured in Phase 1. Coming in Phase 2.

    Args:
        url: WordPress site URL
        enumerate: Enumeration options (vp=plugins, vt=themes, u=users)
        api_token: WPScan API token for vulnerability data
    """
    return {
        "status": "not_configured",
        "tool": "wpscan",
        "message": "WPScan integration is planned for Phase 2. This tool is not yet available.",
        "phase": "2",
    }


# ══════════════════════════════════════════════════════════
# RESOURCES (4 data endpoints)
# ══════════════════════════════════════════════════════════


@mcp.resource("netra://scan/status")
async def scan_status() -> str:
    """Current scan status and progress."""
    return "No active scans. Use the scan tools to start a scan."


@mcp.resource("netra://findings/summary")
async def findings_summary() -> str:
    """Summary of all findings across scans."""
    return "No findings yet. Run a scan to generate findings."


@mcp.resource("netra://scan/config")
async def scan_config() -> str:
    """Current scan configuration and available profiles."""
    return "Profiles: quick, standard, deep, api_only"


@mcp.resource("netra://compliance/status")
async def compliance_status() -> str:
    """Compliance posture across frameworks."""
    return "Compliance engine active. Supported frameworks: ISO 27001, PCI DSS, SOC 2, HIPAA"


# ══════════════════════════════════════════════════════════
# PROMPTS (6 templates)
# ══════════════════════════════════════════════════════════


@mcp.prompt()
def quick_scan(target: str) -> str:
    """Quick reconnaissance scan — subdomains, live hosts, top vulnerabilities."""
    return f"Run a quick security scan on {target}: enumerate subdomains, probe for live hosts, and check for critical/high vulnerabilities using Nuclei default templates."


@mcp.prompt()
def deep_scan(target: str) -> str:
    """Deep comprehensive scan — all recon, all vuln checks, active testing."""
    return f"Run a deep security assessment on {target}: full subdomain enum, port scanning, service detection, vulnerability scanning with all templates, directory fuzzing, and XSS/SQLi testing."


@mcp.prompt()
def api_audit(target: str) -> str:
    """API-focused security audit."""
    return f"Audit the API at {target}: test for BOLA/IDOR, broken auth, injection, mass assignment, rate limiting, and OWASP API Top 10."


@mcp.prompt()
def cloud_audit(provider: str = "aws") -> str:
    """Cloud security posture audit."""
    return f"Run a cloud security posture assessment on {provider}: check IAM, storage, compute, networking, logging, and encryption against CIS benchmarks."


@mcp.prompt()
def compliance_check(framework: str = "pci_dss") -> str:
    """Compliance gap analysis."""
    return f"Assess compliance against {framework}: map all findings to controls, identify gaps, calculate compliance score, and generate remediation roadmap."


@mcp.prompt()
def pentest_report(scan_id: str) -> str:
    """Generate professional pentest report."""
    return f"Generate a professional penetration test report for scan {scan_id}: include methodology, scope, timeline, executive summary, detailed findings with evidence, attack chains, and remediation priorities."


# ══════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════
# INTEL TOOLS (no traffic to targets)
# ══════════════════════════════════════════════════════════


@mcp.tool()
async def scanner_tools_status() -> dict[str, Any]:
    """List which scanner binaries are installed on this host and which required ones are missing.

    Returns:
        Dict with per-tool install state and the list of missing required tools
    """
    from netra.scanner.tools.inventory import tool_inventory

    rows = tool_inventory()
    missing = [r["binary"] for r in rows if not r["installed"] and not r["optional"]]
    return {"tools": rows, "missing_required": missing, "missing_count": len(missing)}


@mcp.tool()
async def cve_priority(cve_ids: list[str]) -> dict[str, Any]:
    """Rank CVE identifiers by exploitation: CISA KEV status first, then FIRST EPSS likelihood.

    Args:
        cve_ids: CVE identifiers such as CVE-2021-44228 (up to 50)

    Returns:
        Dict with one row per valid CVE, exploited first
    """
    from netra.intel.cve_intel import CveIntelClient, rank_key

    results = await CveIntelClient().lookup(cve_ids[:50])
    ordered = sorted(results, key=rank_key)
    return {
        "items": [
            {
                "cve": r.cve,
                "known_exploited": r.known_exploited,
                "epss": r.epss,
                "priority": r.priority,
            }
            for r in ordered
        ],
        "count": len(ordered),
    }


@mcp.tool()
async def protection_checklist(
    headers: dict[str, str], status_code: int | None = None
) -> dict[str, Any]:
    """Given the response headers from one normal request, return detected protections and the
    checks to try next. Sends no traffic.

    Args:
        headers: Response headers as name -> value
        status_code: HTTP status of that response, if known

    Returns:
        Dict with protection ids and the ordered checklist
    """
    from netra.intel.bypass_checklist import checklist_for, detect_protections

    found = detect_protections(headers, status_code)
    return {
        "protections": found,
        "checklist": [
            {"protection": c.protection, "label": c.label, "check": c.check}
            for c in checklist_for(found)
        ],
    }


@mcp.tool()
async def payload_search(
    query: str = "", topic: str | None = None, limit: int = 25
) -> dict[str, Any]:
    """Search the pinned PayloadsAllTheThings library. Each result names its source file and commit.

    Args:
        query: Free text to match in the payload or its section
        topic: Optional topic folder name, such as "SQL Injection"
        limit: Maximum results (1 to 100)

    Returns:
        Dict with matching passages, or an error if the library is not synced on this host
    """
    from netra.core.config import settings
    from netra.intel.payloads import checkout_dir, load_payloads, search

    root = checkout_dir(settings.tools_dir)
    if not root.is_dir():
        return {"error": "payload library not synced on this host", "items": [], "count": 0}
    hits = search(load_payloads(root), query=query, topic=topic, limit=max(1, min(limit, 100)))
    return {"items": [p.as_dict() for p in hits], "count": len(hits)}


# ENTRY POINT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    mcp.run()
