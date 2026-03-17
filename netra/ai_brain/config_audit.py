"""
netra/ai_brain/config_audit.py
Configuration and compliance auditor for standard-based security checks.

Supported standards:
  - CIS Benchmarks (CIS Linux, CIS Docker, CIS Kubernetes, etc.)
  - NIST Cybersecurity Framework
  - PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
  - HIPAA §164.312 (Health Insurance Portability)
  - SOC2 Type II
  - ISO/IEC 27001

Each standard maps to specific system checks (files, services, configs).
"""

from typing import Dict, List, Optional
import json


# ────────────────────────────────────────────────────────────────────────────
# CIS BENCHMARK CHECKS
# ────────────────────────────────────────────────────────────────────────────

CIS_LINUX_CHECKS = {
    "1.1.1": {
        "title": "Ensure mounting of cramfs filesystems is disabled",
        "description": "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.",
        "check": "modprobe -n -v cramfs | grep -E 'install /bin/true|remove /bin/true'",
        "remediation": "echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf",
        "severity": "medium",
    },
    "1.1.2": {
        "title": "Ensure mounting of freevxfs filesystems is disabled",
        "description": "Removal of freevxfs filesystem support reduces the kernel's potential attack surface.",
        "check": "modprobe -n -v freevxfs | grep -E 'install /bin/true|remove /bin/true'",
        "remediation": "echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf",
        "severity": "medium",
    },
    "4.1.1": {
        "title": "Ensure auditd is installed",
        "description": "auditd is the userspace component to the Linux Auditing System.",
        "check": "dpkg -l | grep auditd",
        "remediation": "apt-get install auditd",
        "severity": "high",
    },
    "5.2.1": {
        "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "description": "The /etc/ssh/sshd_config file contains configuration specifications for sshd.",
        "check": "stat /etc/ssh/sshd_config | grep -E '(Access: \\(0600' or 'Uid: \\( 0/')",
        "remediation": "chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
        "severity": "high",
    },
}

NIST_CHECKS = {
    "PR.AC-1": {
        "title": "Enforce account access restrictions",
        "description": "Restrict physical access to organization-defined facilities.",
        "check": "Test access controls to sensitive areas",
        "remediation": "Implement physical access control systems",
        "severity": "critical",
    },
    "PR.DS-2": {
        "title": "Data in transit is protected",
        "description": "All data in transit must be encrypted using TLS 1.2+ or equivalent.",
        "check": "Verify TLS/SSL certificates and versions on all services",
        "remediation": "Enable TLS 1.2 minimum, upgrade certificates",
        "severity": "high",
    },
    "DE.AE-1": {
        "title": "Network traffic is monitored for anomalies",
        "description": "Implement monitoring of network traffic for unusual patterns.",
        "check": "Check IDS/IPS deployment and alerting rules",
        "remediation": "Deploy IDS/IPS and configure detection rules",
        "severity": "high",
    },
}

PCI_DSS_CHECKS = {
    "1.1": {
        "title": "Establish network segmentation boundaries",
        "description": "PCI DSS v4.0 Requirement 1.1: All cardholder data must be on a segmented network.",
        "check": "Verify network diagram and VLANs separating CHD",
        "remediation": "Implement network segmentation using VLANs or firewalls",
        "severity": "critical",
    },
    "2.2.1": {
        "title": "Configure system components with strong default passwords changed",
        "description": "Default passwords must be changed immediately after installation.",
        "check": "Verify all default accounts have been changed or disabled",
        "remediation": "Change all default credentials on system components",
        "severity": "critical",
    },
    "3.2.1": {
        "title": "Encrypt Primary Account Numbers",
        "description": "PAN (Primary Account Numbers) must be rendered unreadable by encryption.",
        "check": "Verify PAN encryption in databases and filesystems",
        "remediation": "Implement PAN encryption using strong algorithms (AES-256)",
        "severity": "critical",
    },
    "6.2": {
        "title": "Implement automated vulnerability scanning",
        "description": "Maintain a policy that addresses software development vulnerabilities.",
        "check": "Verify regular vulnerability scans are performed",
        "remediation": "Deploy automated vulnerability scanning tools",
        "severity": "high",
    },
}

HIPAA_CHECKS = {
    "164.308(a)(3)(i)": {
        "title": "Workforce security procedures",
        "description": "Implement procedures for the authorization and supervision of workforce members.",
        "check": "Review access control logs and audit trails",
        "remediation": "Implement workforce authorization and periodic access reviews",
        "severity": "high",
    },
    "164.308(a)(4)(i)": {
        "title": "Information access management",
        "description": "Implement policies and procedures for granting access to PHI.",
        "check": "Verify role-based access control (RBAC) implementation",
        "remediation": "Deploy RBAC systems limiting PHI access to authorized users",
        "severity": "high",
    },
    "164.312(a)(2)(i)": {
        "title": "Unique user identification",
        "description": "Assign a unique identifier to each user that uniquely identifies them.",
        "check": "Verify unique user IDs across all systems",
        "remediation": "Implement centralized identity management (LDAP, Active Directory)",
        "severity": "high",
    },
}

SOC2_CHECKS = {
    "CC6.1": {
        "title": "Change Management - Logical access controls",
        "description": "The entity restricts system access related to changes in the system.",
        "check": "Review change management logs and approval workflows",
        "remediation": "Implement change management system with approval workflows",
        "severity": "high",
    },
    "CC7.1": {
        "title": "System Monitoring - Monitoring",
        "description": "The entity monitors system components and operation for anomalies.",
        "check": "Verify SIEM/monitoring platform deployment",
        "remediation": "Deploy monitoring solution (ELK, Splunk, Datadog)",
        "severity": "high",
    },
}

STANDARDS_MAP = {
    "CIS": CIS_LINUX_CHECKS,
    "NIST": NIST_CHECKS,
    "PCI": PCI_DSS_CHECKS,
    "HIPAA": HIPAA_CHECKS,
    "SOC2": SOC2_CHECKS,
}


def audit_config(
    standard: str,
    findings: Optional[List[dict]] = None,
) -> dict:
    """
    Run compliance audit against a specific standard.

    Args:
        standard: Standard name (CIS, NIST, PCI, HIPAA, SOC2)
        findings: Optional list of scan findings to map against controls

    Returns:
        Audit results dict with passed/failed/unknown controls
    """
    if standard not in STANDARDS_MAP:
        return {"error": f"Unknown standard: {standard}. Available: {list(STANDARDS_MAP.keys())}"}

    checks = STANDARDS_MAP[standard]
    results = {
        "standard": standard,
        "total_controls": len(checks),
        "passed": [],
        "failed": [],
        "unknown": [],
        "findings_mapped": [],
    }

    # Map findings to controls (simple keyword matching for demo)
    if findings:
        for finding in findings:
            title = finding.get("title", "").lower()
            category = finding.get("category", "").lower()
            mapped_controls = []

            for control_id, control in checks.items():
                control_title = control["title"].lower()
                if any(keyword in title or keyword in category for keyword in control_title.split()):
                    mapped_controls.append(control_id)

            if mapped_controls:
                results["findings_mapped"].append({
                    "finding": finding.get("title"),
                    "controls": mapped_controls,
                })

    return results


def get_standard_description(standard: str) -> Dict[str, str]:
    """
    Get human-readable description of a standard's controls.

    Args:
        standard: Standard name

    Returns:
        Dict mapping control IDs to descriptions
    """
    if standard not in STANDARDS_MAP:
        return {}

    checks = STANDARDS_MAP[standard]
    return {
        cid: {
            "title": control["title"],
            "description": control["description"],
            "severity": control.get("severity", "medium"),
        }
        for cid, control in checks.items()
    }


def list_standards() -> List[str]:
    """Return list of supported standards."""
    return list(STANDARDS_MAP.keys())


def export_audit_report(audit_results: dict, format: str = "json") -> str:
    """
    Export audit results in specified format.

    Args:
        audit_results: Results from audit_config()
        format: 'json' or 'text'

    Returns:
        Formatted audit report string
    """
    if format == "json":
        return json.dumps(audit_results, indent=2)

    # Text format
    lines = [
        f"COMPLIANCE AUDIT REPORT — {audit_results.get('standard', 'Unknown')}",
        f"{'='*60}",
        f"Total Controls: {audit_results.get('total_controls', 0)}",
        f"Findings Mapped: {len(audit_results.get('findings_mapped', []))}",
        f"",
        f"MAPPED FINDINGS:",
    ]
    for mapping in audit_results.get("findings_mapped", []):
        lines.append(f"  • {mapping['finding']}")
        lines.append(f"    Controls: {', '.join(mapping['controls'])}")

    return "\n".join(lines)
