"""Scan profile configurations."""
from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    # ── Phase 1 Profiles ──
    "quick": {
        "description": "Fast pre-release check — critical/high only",
        "severity_filter": "critical,high",
        "max_targets": 20,
        "rate_limit": 300,
        "port_range": "top-100",
        "use_amass": False,
        "use_nikto": False,
        "test_sqli": False,
        "test_xss": False,
        "test_dirs": False,
        "max_injection_tests": 0,
        "timeout_minutes": 30,
        "threads": 20,
    },
    "standard": {
        "description": "Default balanced scan — recon + top vulns + basic pentest",
        "severity_filter": "critical,high,medium",
        "max_targets": 50,
        "rate_limit": 150,
        "port_range": "top-1000",
        "use_amass": False,
        "use_nikto": True,
        "test_sqli": True,
        "test_xss": True,
        "test_dirs": True,
        "sqlmap_level": 1,
        "sqlmap_risk": 1,
        "max_injection_tests": 20,
        "wordlist": "common.txt",
        "timeout_minutes": 180,
        "threads": 10,
    },
    "deep": {
        "description": "Full assessment — everything including info severity + SAST + secrets",
        "severity_filter": "critical,high,medium,low,info",
        "max_targets": 200,
        "rate_limit": 50,
        "port_range": "1-65535",
        "use_amass": True,
        "use_nikto": True,
        "test_sqli": True,
        "test_xss": True,
        "test_dirs": True,
        "sqlmap_level": 3,
        "sqlmap_risk": 2,
        "max_injection_tests": 100,
        "wordlist": "directory-list-2.3-medium.txt",
        "timeout_minutes": 720,
        "threads": 5,
        # Phase 2 options
        "run_sast": True,
        "run_secrets": True,
        "run_dependencies": True,
    },
    "api_only": {
        "description": "API-focused — REST/GraphQL testing",
        "severity_filter": "critical,high,medium",
        "max_targets": 30,
        "rate_limit": 100,
        "port_range": "top-100",
        "use_amass": False,
        "use_nikto": False,
        "test_sqli": True,
        "test_xss": False,
        "test_dirs": True,
        "sqlmap_level": 2,
        "sqlmap_risk": 1,
        "max_injection_tests": 50,
        "wordlist": "api-endpoints.txt",
        "timeout_minutes": 120,
        "threads": 10,
    },

    # ── Phase 2 Profiles ──
    "cloud": {
        "description": "Cloud security posture assessment — AWS, Azure, GCP",
        "provider": "aws",  # aws, azure, gcp
        "compliance_framework": "cis",  # cis, pci, hipaa, etc.
        "severity_filter": "critical,high,medium",
        "timeout_minutes": 360,
        "threads": 5,
        "run_prowler": True,
        "run_trivy_config": True,
    },
    "container": {
        "description": "Container image vulnerability scanning",
        "severity_filter": "critical,high,medium",
        "timeout_minutes": 120,
        "threads": 5,
        "run_trivy_image": True,
        "run_trivy_sbom": True,
    },
    "ai_llm": {
        "description": "AI/LLM attack surface testing — OWASP LLM Top 10",
        "test_categories": [
            "direct_injection",
            "indirect_injection",
            "jailbreak",
            "data_exfiltration",
            "excessive_agency",
        ],
        "max_payloads": 10,
        "severity_filter": "critical,high,medium",
        "timeout_minutes": 60,
        "threads": 10,
    },
    "sast": {
        "description": "Static application security testing",
        "ruleset": "all",  # security, python, javascript, go, java, secrets, all
        "max_findings": 500,
        "severity_filter": "critical,high,medium",
        "timeout_minutes": 180,
        "threads": 5,
        "run_semgrep": True,
        "run_gitleaks": True,
        "run_dependency_scan": True,
    },
    "iac": {
        "description": "Infrastructure as Code security scanning",
        "framework": "terraform",  # terraform, cloudformation, kubernetes, dockerfile
        "severity_filter": "critical,high,medium",
        "timeout_minutes": 60,
        "threads": 5,
        "run_checkov": True,
        "run_trivy_config": True,
    },

    # ── Phase 5 Profiles (NETRA-BB) ──
    "bugbounty_passive": {
        "description": "Bug bounty passive recon — no probes ever leave the agent",
        "severity_filter": "critical,high,medium,low,info",
        "max_targets": 500,
        "rate_limit": 10,        # rps cap on outbound passive sources
        "scope_required": True,  # the orchestrator MUST attach a ScopeValidator
        "active_phases": False,  # no active probing in this profile
        "use_amass": True,
        "amass_passive": True,
        "use_subfinder_passive": True,
        "use_crtsh": True,
        "use_github_dorks": True,
        "timeout_minutes": 60,
        "threads": 5,
    },
    "bugbounty_active": {
        "description": "Bug bounty active recon — scope-gated, opt-in, low-noise",
        "severity_filter": "critical,high,medium",
        "max_targets": 200,
        "rate_limit": 10,        # rps cap, per-host 2 rps
        "per_host_rate_limit": 2,
        "scope_required": True,
        "active_phases": True,
        # Active phases each require explicit operator approval at CLI invocation time.
        "use_httpx": True,
        "httpx_head_only": True,
        "use_ffuf": False,       # opt in via --enable-ffuf
        "use_nuclei_safe": False,  # opt in via --enable-nuclei
        "nuclei_template_tags": ["cve", "exposure", "misconfig"],
        "nuclei_severity_cap": "medium",
        "honour_robots_txt": True,
        "timeout_minutes": 120,
        "threads": 5,
    },
}


def get_profile_config(profile_name: str) -> dict[str, Any]:
    """Get profile configuration by name, with fallback to standard.

    Args:
        profile_name: Name of the scan profile

    Returns:
        Profile configuration dictionary
    """
    return PROFILES.get(profile_name, PROFILES["standard"])


_REQUIRED_DEFAULTS: dict[str, Any] = {
    "severity_filter": "critical,high,medium",
    "max_targets": 50,
    "rate_limit": 100,
    "port_range": "top-1000",
    "test_sqli": False,
    "test_xss": False,
    "test_dirs": False,
}

for _profile in PROFILES.values():
    for _key, _value in _REQUIRED_DEFAULTS.items():
        _profile.setdefault(_key, _value)


def get_available_profiles() -> list[str]:
    """Get list of available profile names.

    Returns:
        List of profile names
    """
    return list(PROFILES.keys())
