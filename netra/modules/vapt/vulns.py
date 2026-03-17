"""
recon/vulns.py
Nuclei vulnerability scanning.
Per-finding: CVSS lookup, HTTP evidence capture, DB insert, Slack notify.
Profile-aware template selection.
"""

import json
import re
from pathlib import Path

from netra.core.config import CONFIG
from netra.core.utils  import run_cmd, status, tool_exists, C
from netra.core.database import FindingsDB
from netra.core.notify import notify_finding


# Nuclei severity → CVSS score (approximate where CVE not available)
SEVERITY_CVSS = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.0,
}

# Nuclei severity → OWASP Web mapping (common)
OWASP_MAP = {
    "default-login":   "A05:2021",
    "sqli":            "A03:2021",
    "xss":             "A03:2021",
    "ssrf":            "A10:2021",
    "lfi":             "A01:2021",
    "rfi":             "A03:2021",
    "rce":             "A03:2021",
    "misconfig":       "A05:2021",
    "exposure":        "A06:2021",
    "cve":             "A06:2021",
    "takeover":        "A05:2021",
    "tech":            "A06:2021",
}


def run_nuclei(
    live_urls_file: str,
    workdir: str,
    scan_id: str = "",
    extra_targets: list = None,
) -> list:
    """
    Run nuclei on live URLs. Returns list of findings added to DB.
    
    Profile-based template selection:
    - fast: critical+high CVEs, RCE, default-login
    - balanced: above + misconfig, exposure, xss, sqli
    - deep: all templates
    - healthcare: above + HIPAA-relevant checks
    """
    workdir    = Path(workdir)
    pentest_dir = workdir / "pentest"
    pentest_dir.mkdir(exist_ok=True)

    nuclei_json = str(pentest_dir / "nuclei.json")

    if not tool_exists("nuclei"):
        status("nuclei not found", "error")
        return []

    profile = CONFIG.get("scan_profile", "balanced")
    tags    = _get_nuclei_tags(profile)
    sevs    = _get_severities(profile)

    # Build targets file (live URLs + any extra)
    all_targets = [live_urls_file]
    if extra_targets:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write("\n".join(extra_targets))
        tmp.close()
        all_targets.append(tmp.name)

    cmd = [
        "nuclei",
        "-l", live_urls_file,
        "-o", nuclei_json,
        "-json",
        "-silent",
        "-timeout", CONFIG.get("timeout", "10"),
        "-rate-limit", CONFIG.get("rate_limit", "100"),
        "-concurrency", CONFIG.get("threads", "10"),
        "-severity", sevs,
        "-stats",
    ]

    if tags:
        cmd.extend(["-tags", tags])

    # Exclude time-consuming/noisy templates in non-deep mode
    if profile != "deep":
        cmd.extend(["-exclude-tags", "dos,fuzz"])

    run_cmd(cmd, silent=False, timeout=7200)   # max 2hrs

    # Parse output and insert into DB
    findings = _parse_and_store(nuclei_json, workdir, scan_id)
    status(f"Nuclei: {len(findings)} findings stored", "ok")

    return findings


def _get_nuclei_tags(profile: str) -> str:
    profile_tags = {
        "fast":        "cve,rce,sqli,default-login,rce",
        "balanced":    "cve,rce,sqli,xss,ssrf,lfi,misconfig,exposure,default-login",
        "deep":        "",  # empty = all templates
        "healthcare":  "cve,rce,sqli,xss,ssrf,lfi,misconfig,exposure,default-login,disclosure",
        "legacy":      "cve,default-login,exposure",
        "mobile":      "cve,api,jwt,exposure,misconfig",
        "saas":        "cve,api,graphql,misconfig,exposure",
    }
    return profile_tags.get(profile, profile_tags["balanced"])


def _get_severities(profile: str) -> str:
    profile_sevs = {
        "fast":     "critical,high",
        "balanced": "critical,high,medium",
        "deep":     "critical,high,medium,low",
        "healthcare": "critical,high,medium",
        "legacy":   "critical,high",
        "mobile":   "critical,high,medium",
        "saas":     "critical,high,medium",
    }
    return profile_sevs.get(profile, "critical,high,medium")


def _parse_and_store(nuclei_json: str, workdir: Path, scan_id: str) -> list:
    """Parse nuclei JSON output and store findings in DB."""
    db       = FindingsDB()
    findings = []
    evidence_dir = workdir / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    if not Path(nuclei_json).exists():
        return findings

    for line in Path(nuclei_json).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        info     = entry.get("info", {})
        template = entry.get("template-id", "")
        host     = entry.get("host", "")
        url      = entry.get("url", host)
        severity = info.get("severity", "info").lower()
        name     = info.get("name", template)
        desc     = info.get("description", "")
        impact   = info.get("impact", "")
        remedy   = info.get("remediation", "")
        refs     = info.get("reference", [])
        cve_id   = ""
        cwe_id   = ""
        cvss_score  = SEVERITY_CVSS.get(severity, 0.0)
        cvss_vector = ""

        # Extract CVE/CWE from classification
        classification = info.get("classification", {})
        if classification:
            cve_list = classification.get("cve-id", [])
            cwe_list = classification.get("cwe-id", [])
            cvss_score  = classification.get("cvss-score", cvss_score)
            cvss_vector = classification.get("cvss-metrics", "")
            cve_id = cve_list[0] if cve_list else ""
            cwe_id = cwe_list[0] if cwe_list else ""

        # Extract HTTP evidence
        request  = ""
        response = ""
        matcher  = entry.get("matched-at", "")

        req_resp = entry.get("request", "") or entry.get("curl-command", "")
        if req_resp:
            request = req_resp[:2000]   # cap at 2KB

        resp_data = entry.get("response", "")
        if resp_data:
            response = resp_data[:2000]

        # Extract matched string
        matched = entry.get("extracted-results", [])
        evidence_str = f"Matched: {matcher}"
        if matched:
            evidence_str += f"\nExtracted: {', '.join(str(m) for m in matched[:5])}"
        if request:
            evidence_str += f"\n\nRequest:\n{request[:500]}"

        # Map to OWASP
        owasp_web = ""
        for tag_key, owasp_val in OWASP_MAP.items():
            if tag_key in template.lower() or tag_key in name.lower():
                owasp_web = owasp_val
                break

        # Save evidence file
        ev_file = evidence_dir / f"{template}_{host[:30].replace('/', '_')}.txt"
        ev_content = (
            f"Template:  {template}\n"
            f"Host:      {host}\n"
            f"URL:       {url}\n"
            f"Matched:   {matcher}\n"
            f"Severity:  {severity}\n"
            f"CVE:       {cve_id}\n"
            f"\n--- REQUEST ---\n{request}\n"
            f"\n--- RESPONSE ---\n{response}\n"
        )
        ev_file.write_text(ev_content)

        # MITRE mapping
        mitre = _get_mitre(template, severity)

        finding = {
            "scan_id":     scan_id,
            "title":       name,
            "template_id": template,
            "cve_id":      cve_id,
            "cwe_id":      cwe_id,
            "severity":    severity,
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "category":    _get_category(template),
            "owasp_web":   owasp_web,
            "mitre_technique": mitre,
            "host":        host,
            "url":         url,
            "description": desc,
            "evidence":    evidence_str,
            "request":     request[:1000],
            "response":    response[:1000],
            "poc_command": f"nuclei -u {url} -t {template}",
            "impact":      impact,
            "remediation": remedy,
            "references":  json.dumps(refs) if refs else "",
            "confidence":  _confidence(entry),
        }

        fid = db.add_finding(finding)
        if fid:
            findings.append(finding)
            # Real-time notify on critical/high
            notify_finding(finding)
            if severity in ("critical", "high"):
                status(f"{severity.upper()}: {name} — {host}", "finding")

    return findings


def _get_category(template: str) -> str:
    t = template.lower()
    if any(k in t for k in ("sqli", "nosql", "ldap", "ssti", "xxe", "xss", "lfi", "rfi", "cmdi")):
        return "injection"
    if any(k in t for k in ("default-login", "jwt", "oauth", "auth", "cred")):
        return "auth"
    if any(k in t for k in ("misconfig", "cors", "csrf", "headers")):
        return "misconfig"
    if any(k in t for k in ("exposure", "disclosure", "listing", "backup")):
        return "exposure"
    if any(k in t for k in ("ssrf", "redirect")):
        return "ssrf"
    if any(k in t for k in ("takeover",)):
        return "takeover"
    if "cve-" in t:
        return "cve"
    return "other"


def _get_mitre(template: str, severity: str) -> str:
    t = template.lower()
    if "sqli" in t or "xss" in t or "ssti" in t:
        return "T1190"
    if "default-login" in t or "auth" in t:
        return "T1078"
    if "ssrf" in t:
        return "T1599"
    if "exposure" in t or "disclosure" in t:
        return "T1552"
    if "takeover" in t:
        return "T1584"
    if severity == "critical":
        return "T1190"
    return ""


def _confidence(entry: dict) -> int:
    """Estimate confidence score based on nuclei entry type."""
    template = entry.get("template-id", "").lower()
    if "cve-" in template:
        return 95        # CVE templates are very precise
    if entry.get("extracted-results"):
        return 90        # has extracted data = confirmed
    if "fuzz" in template or "generic" in template:
        return 60        # fuzzing = lower confidence
    return 80
