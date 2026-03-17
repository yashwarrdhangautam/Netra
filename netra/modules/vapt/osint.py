"""
recon/osint.py
Passive OSINT gathering BEFORE any active scanning.
No requests hit the target — all passive sources.
Sources: theHarvester, Shodan API, GitHub dorking, HaveIBeenPwned,
         Google Dorks, Hunter.io email format, job postings tech detection.
"""

import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict

from netra.core.config import CONFIG
from netra.core.utils  import run_cmd, status, tool_exists, banner
from netra.core.database import FindingsDB
from netra.core.notify import notify_finding


def run_osint(
    domains: List[str],
    workdir: str,
    scan_id: str = "",
) -> dict:
    """
    Run all passive OSINT sources on target domains.
    Returns intelligence report dict.
    """
    if CONFIG.get("osint_passive", "true") != "true":
        return {}

    banner("OSINT PASSIVE RECON", "No requests hit the target")

    workdir   = Path(workdir)
    osint_dir = workdir / "recon" / "osint"
    osint_dir.mkdir(parents=True, exist_ok=True)

    intel = {
        "domains":    domains,
        "emails":     [],
        "employees":  [],
        "tech_hints": [],
        "breaches":   [],
        "github":     [],
        "shodan":     [],
    }

    for domain in domains[:10]:   # cap at 10 domains

        # ── theHarvester ──────────────────────────────────────────────
        if tool_exists("theHarvester"):
            _run_harvester(domain, osint_dir, intel)

        # ── Shodan API ─────────────────────────────────────────────────
        if CONFIG.get("shodan"):
            _query_shodan(domain, osint_dir, intel, scan_id)

        # ── HaveIBeenPwned ─────────────────────────────────────────────
        if CONFIG.get("haveibeenpwned"):
            _check_hibp(domain, intel, scan_id)

        # ── GitHub dorking ─────────────────────────────────────────────
        if CONFIG.get("github"):
            _github_dork(domain, osint_dir, intel, scan_id)

        # ── Hunter.io email format ─────────────────────────────────────
        if CONFIG.get("hunter"):
            _hunter_email_format(domain, intel)

    # Save intel report
    intel_file = osint_dir / "osint_report.json"
    intel_file.write_text(json.dumps(intel, indent=2))

    _print_osint_summary(intel)
    return intel


def _run_harvester(domain: str, osint_dir: Path, intel: dict) -> None:
    """theHarvester - email/employee/subdomain harvesting."""
    out_file = str(osint_dir / f"harvester_{domain}.xml")
    run_cmd(
        [
            "theHarvester",
            "-d", domain,
            "-b", "bing,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,threatcrowd",
            "-f", out_file,
        ],
        silent=True, timeout=120
    )

    # Parse output for emails
    try:
        txt_file = out_file.replace(".xml", ".txt")
        if Path(txt_file).exists():
            content = Path(txt_file).read_text()
            emails  = re.findall(r"[a-zA-Z0-9._%+-]+@" + re.escape(domain), content)
            intel["emails"].extend(list(set(emails)))
            status(f"theHarvester: {len(emails)} emails found for {domain}", "ok")
    except Exception:
        pass


def _query_shodan(domain: str, osint_dir: Path,
                  intel: dict, scan_id: str) -> None:
    """Query Shodan API for historical exposure data."""
    api_key = CONFIG.get("shodan", "")
    if not api_key:
        return

    try:
        url  = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}"
        req  = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        ip = data.get(domain, "")
        if not ip:
            return

        # Get host info
        host_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        req      = urllib.request.Request(host_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            host_data = json.loads(resp.read())

        shodan_entry = {
            "domain": domain,
            "ip":     ip,
            "ports":  host_data.get("ports", []),
            "vulns":  list(host_data.get("vulns", {}).keys()),
            "org":    host_data.get("org", ""),
            "os":     host_data.get("os", ""),
            "tags":   host_data.get("tags", []),
        }
        intel["shodan"].append(shodan_entry)

        # Flag Shodan-detected CVEs as findings
        db = FindingsDB()
        for cve in shodan_entry["vulns"][:10]:
            finding = {
                "scan_id":     scan_id,
                "title":       f"Shodan: {cve} detected on {ip}",
                "template_id": f"shodan-{cve.lower()}",
                "cve_id":      cve,
                "severity":    "high",
                "cvss_score":  7.5,
                "category":    "cve",
                "owasp_web":   "A06:2021",
                "host":        domain,
                "url":         f"https://{domain}",
                "description": f"Shodan passive scan detected {cve} on {ip}.",
                "evidence":    f"Source: Shodan API\nIP: {ip}\nPorts: {shodan_entry['ports']}",
                "impact":      "Unpatched vulnerability accessible from internet.",
                "remediation": f"Apply patch for {cve}. Check vendor advisory.",
                "confidence":  70,   # lower — needs active verification
            }
            fid = db.add_finding(finding)
            if fid:
                notify_finding(finding)

        status(f"Shodan: {domain} → {ip}, {len(shodan_entry['vulns'])} CVEs", "ok")

    except Exception as e:
        status(f"Shodan query failed for {domain}: {e}", "warn")


def _check_hibp(domain: str, intel: dict, scan_id: str) -> None:
    """HaveIBeenPwned - check if domain has breach data."""
    api_key = CONFIG.get("haveibeenpwned", "")
    if not api_key:
        return

    try:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        req = urllib.request.Request(url, headers={
            "hibp-api-key": api_key,
            "User-Agent":   "netra-scanner/1.0",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        if data:
            intel["breaches"].append({
                "domain":   domain,
                "breaches": data,
                "count":    len(data),
            })

            db = FindingsDB()
            finding = {
                "scan_id":     scan_id,
                "title":       f"Domain in {len(data)} breach(es) — {domain}",
                "template_id": "hibp-breach",
                "severity":    "high",
                "cvss_score":  7.5,
                "category":    "exposure",
                "owasp_web":   "A07:2021",
                "host":        domain,
                "description": f"HIBP reports {len(data)} data breach(es) for {domain}: {', '.join(str(b) for b in data[:3])}",
                "evidence":    f"Source: HaveIBeenPwned API\nBreaches: {json.dumps(data[:5])}",
                "impact":      "Breached credentials may be used for credential stuffing attacks against this domain.",
                "remediation": "Force password reset for all affected users. Implement MFA. Monitor for credential stuffing.",
                "confidence":  98,
            }
            fid = db.add_finding(finding)
            if fid:
                notify_finding(finding)
            status(f"HIBP: {domain} in {len(data)} breaches", "warn")

    except urllib.error.HTTPError as e:
        if e.code == 404:
            status(f"HIBP: {domain} — no breaches found", "ok")


def _github_dork(domain: str, osint_dir: Path,
                 intel: dict, scan_id: str) -> None:
    """Search GitHub for secrets related to the domain."""
    token = CONFIG.get("github", "")
    if not token:
        return

    dorks = [
        f"{domain} password",
        f"{domain} api_key",
        f"{domain} secret",
        f"{domain} token",
        f"{domain} credentials",
    ]

    db = FindingsDB()
    for dork in dorks:
        try:
            query = urllib.parse.quote(dork)
            url   = f"https://api.github.com/search/code?q={query}&per_page=5"
            req   = urllib.request.Request(url, headers={
                "Authorization": f"token {token}",
                "User-Agent":    "netra-scanner/1.0",
                "Accept":        "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            items = data.get("items", [])
            if items:
                for item in items[:3]:
                    repo    = item.get("repository", {}).get("full_name", "")
                    file_url = item.get("html_url", "")
                    intel["github"].append({
                        "dork":     dork,
                        "repo":     repo,
                        "file_url": file_url,
                    })

                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"GitHub: Possible secret exposure — {repo}",
                        "template_id": "github-dork-exposure",
                        "severity":    "high",
                        "cvss_score":  7.5,
                        "category":    "exposure",
                        "owasp_web":   "A02:2021",
                        "host":        domain,
                        "url":         file_url,
                        "description": f"GitHub code search found '{dork}' in public repository {repo}.",
                        "evidence":    f"Search: {dork}\nRepo: {repo}\nFile: {file_url}",
                        "impact":      "Hardcoded credentials in public repos provide direct access to systems.",
                        "remediation": "Remove secrets from repo history (git filter-branch). Rotate all exposed credentials. Use GitHub Secret Scanning alerts.",
                        "confidence":  75,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        notify_finding(finding)
                        status(f"HIGH: GitHub secret exposure in {repo}", "finding")

        except Exception:
            pass


def _hunter_email_format(domain: str, intel: dict) -> None:
    """Hunter.io - discover email format pattern for the domain."""
    api_key = CONFIG.get("hunter", "")
    if not api_key:
        return

    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=5"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        domain_data = data.get("data", {})
        pattern     = domain_data.get("pattern", "")
        emails_list = [e.get("value") for e in domain_data.get("emails", []) if e.get("value")]

        if pattern:
            intel["tech_hints"].append(f"Email format: {pattern}@{domain}")
        intel["emails"].extend(emails_list)

        status(f"Hunter.io: {domain} email pattern: {pattern or 'unknown'}", "ok")

    except Exception:
        pass


def _print_osint_summary(intel: dict) -> None:
    """Print a concise OSINT summary to terminal."""
    print()
    status(f"OSINT Summary:", "info")
    if intel["emails"]:
        status(f"  Emails found:   {len(intel['emails'])}", "info")
    if intel["breaches"]:
        total = sum(b.get("count", 0) for b in intel["breaches"])
        status(f"  Breach records: {total}", "warn")
    if intel["github"]:
        status(f"  GitHub hits:    {len(intel['github'])}", "warn")
    if intel["shodan"]:
        total_vulns = sum(len(s.get("vulns", [])) for s in intel["shodan"])
        status(f"  Shodan CVEs:    {total_vulns}", "warn")
    if intel["tech_hints"]:
        for hint in intel["tech_hints"][:3]:
            status(f"  Tech hint:      {hint}", "info")
