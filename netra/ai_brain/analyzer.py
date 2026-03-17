"""
netra/ai_brain/analyzer.py
CVSS v3.1 scoring, MITRE ATT&CK mapping, finding deduplication,
and clustering for the NETRA AI brain pipeline.
"""

import re
import hashlib
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netra.ai_brain.analyzer")

# ── CVSS v3.1 base metric weights ─────────────────────────────────────

CVSS_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
CVSS_AC  = {"L": 0.77, "H": 0.44}                           # Attack Complexity
CVSS_PR  = {"N": 0.85, "L": 0.62, "H": 0.27}               # Privileges Required
CVSS_UI  = {"N": 0.85, "R": 0.62}                           # User Interaction
CVSS_S   = {"U": "unchanged", "C": "changed"}               # Scope
CVSS_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}               # CIA Impact metrics

# Severity bands
CVSS_BANDS = [
    (9.0,  10.0, "critical"),
    (7.0,  8.9,  "high"),
    (4.0,  6.9,  "medium"),
    (0.1,  3.9,  "low"),
    (0.0,  0.0,  "info"),
]

# ── OWASP Web Top 10 2021 mapping ─────────────────────────────────────
OWASP_WEB_MAP: Dict[str, str] = {
    "injection":         "A03:2021",
    "sqli":              "A03:2021",
    "xss":               "A03:2021",
    "xxe":               "A03:2021",
    "auth":              "A07:2021",
    "session":           "A07:2021",
    "broken_auth":       "A07:2021",
    "misconfig":         "A05:2021",
    "data_exposure":     "A02:2021",
    "takeover":          "A05:2021",
    "sca":               "A06:2021",
    "crypto":            "A02:2021",
    "ssrf":              "A10:2021",
    "rce":               "A03:2021",
    "deserialization":   "A08:2021",
    "logging":           "A09:2021",
    "cloud":             "A05:2021",
    "access_control":    "A01:2021",
    "idor":              "A01:2021",
    "privilege_esc":     "A01:2021",
}

# ── OWASP API Top 10 2023 mapping ─────────────────────────────────────
OWASP_API_MAP: Dict[str, str] = {
    "bola":              "API1:2023",
    "idor":              "API1:2023",
    "auth":              "API2:2023",
    "broken_auth":       "API2:2023",
    "object_property":   "API3:2023",
    "resource_limit":    "API4:2023",
    "function_level":    "API5:2023",
    "ssrf":              "API7:2023",
    "misconfig":         "API8:2023",
    "inventory":         "API9:2023",
    "unsafe_api":        "API10:2023",
    "injection":         "API10:2023",
}

# ── MITRE ATT&CK category mapping ─────────────────────────────────────
MITRE_CATEGORY_MAP: Dict[str, str] = {
    "injection":         "T1190",    # Exploit Public-Facing Application
    "sqli":              "T1190",
    "rce":               "T1059",    # Command and Scripting Interpreter
    "auth":              "T1078",    # Valid Accounts
    "session":           "T1550",    # Use Alternate Authentication Material
    "xss":               "T1185",    # Browser Session Hijacking
    "ssrf":              "T1090",    # Proxy
    "takeover":          "T1078",
    "data_exposure":     "T1552",    # Unsecured Credentials
    "misconfig":         "T1190",
    "cloud":             "T1078.004",# Cloud Accounts
    "network":           "T1046",    # Network Service Discovery
    "crypto":            "T1600",    # Weaken Encryption
    "deserialization":   "T1059",
    "privilege_esc":     "T1068",    # Exploitation for Privilege Escalation
    "xxe":               "T1190",
    "js_secrets":        "T1552",
}

# ── HIPAA control mapping ─────────────────────────────────────────────
HIPAA_MAP: Dict[str, str] = {
    "auth":          "§164.312(d)",      # Person or Entity Authentication
    "session":       "§164.312(a)(2)(iii)",  # Automatic Logoff
    "data_exposure": "§164.312(a)(2)(iv)",   # Encryption and Decryption
    "crypto":        "§164.312(a)(2)(iv)",
    "access_control": "§164.312(a)(1)",  # Access Control
    "audit":         "§164.312(b)",      # Audit Controls
    "misconfig":     "§164.308(a)(1)",   # Security Management Process
    "injection":     "§164.306(a)(1)",   # Ensure confidentiality, integrity, availability
    "rce":           "§164.306(a)(1)",
}

# ── PCI DSS v4.0 mapping ──────────────────────────────────────────────
PCI_MAP: Dict[str, str] = {
    "auth":          "Req 8",    # Identify Users and Authenticate Access
    "session":       "Req 8.2",
    "data_exposure": "Req 3",    # Protect Stored Account Data
    "crypto":        "Req 4",    # Protect Cardholder Data with Strong Crypto
    "misconfig":     "Req 2",    # Apply Secure Configurations
    "network":       "Req 1",    # Install and Maintain Network Security Controls
    "injection":     "Req 6",    # Develop and Maintain Secure Systems and Software
    "rce":           "Req 6.3",
    "xss":           "Req 6.2",
    "access_control": "Req 7",   # Restrict Access to System Components
    "logging":       "Req 10",   # Log and Monitor All Access to System Components
}


def compute_cvss_v3(vector: str) -> Tuple[float, str]:
    """
    Parse a CVSS v3.1 vector string and compute the base score.

    Args:
        vector: CVSS v3.1 vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        (score: float, severity: str) tuple.
        Returns (0.0, "info") on parse failure.
    """
    if not vector or "CVSS" not in vector.upper():
        return 0.0, "info"

    try:
        parts: Dict[str, str] = {}
        for segment in vector.split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k.upper()] = v.upper()

        av  = CVSS_AV.get(parts.get("AV", "N"), 0.85)
        ac  = CVSS_AC.get(parts.get("AC", "L"), 0.77)
        pr  = CVSS_PR.get(parts.get("PR", "N"), 0.85)
        ui  = CVSS_UI.get(parts.get("UI", "N"), 0.85)
        scope_changed = parts.get("S", "U") == "C"

        conf  = CVSS_CIA.get(parts.get("C", "N"), 0.0)
        integ = CVSS_CIA.get(parts.get("I", "N"), 0.0)
        avail = CVSS_CIA.get(parts.get("A", "N"), 0.0)

        # ISS — Impact Sub-Score
        iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return 0.0, "info"

        exploitability = 8.22 * av * ac * pr * ui

        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        # Round up to 1 decimal
        score = _roundup(base)
        return score, cvss_to_severity(score)

    except Exception as e:
        logger.debug(f"CVSS parse error for '{vector}': {e}")
        return 0.0, "info"


def _roundup(value: float) -> float:
    """CVSS rounding rule: round up to 1 decimal place."""
    import math
    return math.ceil(value * 10) / 10


def cvss_to_severity(score: float) -> str:
    """Map a CVSS base score to a severity string."""
    for lo, hi, sev in CVSS_BANDS:
        if lo <= score <= hi:
            return sev
    return "info"


def enrich_finding(finding: dict) -> dict:
    """
    Enrich a finding with computed OWASP, MITRE, HIPAA, and PCI mappings.
    If a CVSS vector is present but score is missing, compute it.

    Args:
        finding: Raw finding dict.

    Returns:
        Enriched finding dict (mutated in-place and returned).
    """
    cat = (finding.get("category") or "").lower().replace("-", "_").replace(" ", "_")

    # CVSS from vector if not set
    if finding.get("cvss_vector") and not finding.get("cvss_score"):
        score, sev = compute_cvss_v3(finding["cvss_vector"])
        finding["cvss_score"] = score
        if not finding.get("severity") or finding["severity"] == "info":
            finding["severity"] = sev

    # OWASP mappings
    if not finding.get("owasp_web"):
        finding["owasp_web"] = OWASP_WEB_MAP.get(cat, "")
    if not finding.get("owasp_api"):
        finding["owasp_api"] = OWASP_API_MAP.get(cat, "")

    # MITRE
    if not finding.get("mitre_technique"):
        finding["mitre_technique"] = MITRE_CATEGORY_MAP.get(cat, "")

    # HIPAA
    if not finding.get("hipaa_ref"):
        finding["hipaa_ref"] = HIPAA_MAP.get(cat, "")

    # PCI
    if not finding.get("pci_ref"):
        finding["pci_ref"] = PCI_MAP.get(cat, "")

    return finding


def deduplicate_findings(findings: List[dict]) -> List[dict]:
    """
    Remove duplicate findings based on title + host + path hash.

    Args:
        findings: List of raw finding dicts.

    Returns:
        Deduplicated list, preserving highest CVSS per group.
    """
    seen: Dict[str, dict] = {}

    for f in findings:
        key = hashlib.sha256(
            (
                (f.get("title") or "") +
                (f.get("host") or "") +
                (f.get("path") or "")
            ).lower().encode()
        ).hexdigest()[:12]

        if key not in seen:
            seen[key] = f
        else:
            # Keep the one with higher CVSS
            existing_cvss = seen[key].get("cvss_score") or 0
            new_cvss      = f.get("cvss_score") or 0
            if new_cvss > existing_cvss:
                seen[key] = f

    return list(seen.values())


def cluster_findings(findings: List[dict]) -> Dict[str, List[dict]]:
    """
    Group findings by host for report section organisation.

    Args:
        findings: List of finding dicts.

    Returns:
        Dict mapping host → sorted list of findings.
    """
    clusters: Dict[str, List[dict]] = {}

    for f in findings:
        host = f.get("host") or "unknown"
        clusters.setdefault(host, []).append(f)

    # Sort each cluster by CVSS descending
    for host in clusters:
        clusters[host].sort(
            key=lambda x: x.get("cvss_score") or 0,
            reverse=True
        )

    return clusters


def compute_compliance_gaps(
    findings: List[dict],
    framework: str = "HIPAA",
) -> List[dict]:
    """
    Map findings to compliance control gaps for a given framework.

    Args:
        findings:  List of finding dicts.
        framework: Compliance framework: HIPAA | PCI.

    Returns:
        List of gap dicts with control, status, and related finding IDs.
    """
    control_map = HIPAA_MAP if framework.upper() == "HIPAA" else PCI_MAP
    gaps: Dict[str, dict] = {}

    # Initialise all controls as passing
    for cat, control in control_map.items():
        if control not in gaps:
            gaps[control] = {
                "framework":   framework,
                "control":     control,
                "status":      "pass",
                "finding_ids": [],
                "notes":       "",
            }

    # Mark controls as failing where findings exist
    for f in findings:
        cat     = (f.get("category") or "").lower().replace("-", "_").replace(" ", "_")
        control = control_map.get(cat)
        if control and control in gaps:
            gaps[control]["status"] = "fail"
            gaps[control]["finding_ids"].append(f["id"])
            sev = f.get("severity", "medium")
            if sev in ("critical", "high"):
                gaps[control]["notes"] = f"Critical/High finding: {f.get('title', '')[:60]}"

    return list(gaps.values())


def get_top_findings(findings: List[dict], n: int = 10) -> List[dict]:
    """
    Return the top N findings sorted by CVSS score descending.

    Args:
        findings: Full list of finding dicts.
        n:        Number of findings to return.

    Returns:
        Top N findings sorted by CVSS.
    """
    return sorted(
        findings,
        key=lambda f: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.get("severity", "info"), 0
            ),
            f.get("cvss_score") or 0
        ),
        reverse=True
    )[:n]


def build_remediation_roadmap(findings: List[dict]) -> List[dict]:
    """
    Build a prioritised remediation roadmap from a list of findings.
    Groups by severity and estimates effort.

    Args:
        findings: List of finding dicts.

    Returns:
        List of roadmap items with priority, effort, and finding references.
    """
    roadmap: List[dict] = []

    sev_order = ["critical", "high", "medium", "low", "info"]
    effort_map = {"critical": "hours", "high": "1-2 days", "medium": "1 sprint", "low": "backlog"}

    for sev in sev_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        roadmap.append({
            "priority":   {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}[sev],
            "severity":   sev,
            "count":      len(sev_findings),
            "effort":     effort_map.get(sev, "TBD"),
            "finding_ids": [f["id"] for f in sev_findings],
            "top_titles": [f.get("title", "") for f in sev_findings[:3]],
        })

    return roadmap
