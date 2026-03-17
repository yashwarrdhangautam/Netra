"""
recon/subdomains.py
Multi-source subdomain enumeration.
Sources: subfinder (API keys), amass, assetfinder, crt.sh, waybackurls, gau
Deduplicates + resolves via dnsx.
"""

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import List

from netra.core.config import CONFIG
from netra.core.utils  import (
    run_cmd, status, banner, tool_exists, deduplicate,
    write_targets_file, count_lines, C
)
from netra.core.notify import notify_finding


def enumerate_subdomains(
    domains_file: str,
    workdir: str,
    scan_id: str = "",
) -> str:
    """
    Run full subdomain enumeration on domains in domains_file.
    Returns path to resolved live subdomains file.
    """
    banner("SUBDOMAIN ENUMERATION", f"Sources: subfinder, assetfinder, crt.sh, amass")

    workdir   = Path(workdir)
    recon_dir = workdir / "recon"
    recon_dir.mkdir(exist_ok=True)

    domains = [
        l.strip() for l in Path(domains_file).read_text().splitlines()
        if l.strip() and not l.startswith("#")
    ]
    status(f"Enumerating {len(domains)} root domains", "info")

    all_subs = []

    # ── 1. subfinder ────────────────────────────────────────────────
    if tool_exists("subfinder"):
        out = str(recon_dir / "subfinder.txt")
        cmd = [
            "subfinder", "-dL", domains_file,
            "-o", out,
            "-t", CONFIG.get("threads", "10"),
            "-silent",
        ]
        # Add API keys if configured
        _inject_subfinder_keys(cmd)

        run_cmd(cmd, silent=False)
        if Path(out).exists():
            subs = _read_file(out)
            all_subs.extend(subs)
            status(f"subfinder: {len(subs)} subdomains", "ok")
    else:
        status("subfinder not found — skipping", "warn")

    # ── 2. assetfinder ──────────────────────────────────────────────
    if tool_exists("assetfinder"):
        af_results = []
        for domain in domains:
            rc, out, _ = run_cmd(["assetfinder", "--subs-only", domain], silent=True)
            if rc == 0:
                af_results.extend(
                    l.strip() for l in out.splitlines() if l.strip()
                )
        af_file = str(recon_dir / "assetfinder.txt")
        write_targets_file(af_file, af_results)
        all_subs.extend(af_results)
        status(f"assetfinder: {len(af_results)} subdomains", "ok")

    # ── 3. crt.sh passive ───────────────────────────────────────────
    crt_results = []
    for domain in domains:
        crt_subs = _crtsh(domain)
        crt_results.extend(crt_subs)
        if crt_subs:
            status(f"crt.sh: +{len(crt_subs)} for {domain}", "ok")
    all_subs.extend(crt_results)

    # ── 4. amass (if available, slower) ─────────────────────────────
    if tool_exists("amass") and str(CONFIG.get("scan_profile")) in ("deep", "balanced"):
        for domain in domains:
            out = str(recon_dir / f"amass_{domain}.txt")
            run_cmd(
                ["amass", "enum", "-passive", "-d", domain, "-o", out],
                silent=True, timeout=300
            )
            if Path(out).exists():
                subs = _read_file(out)
                all_subs.extend(subs)
                status(f"amass: +{len(subs)} for {domain}", "ok")

    # ── 5. Wayback / GAU (historical endpoints) ─────────────────────
    if tool_exists("waybackurls") and str(CONFIG.get("scan_profile")) != "fast":
        wb_subs = []
        for domain in domains:
            rc, out, _ = run_cmd(["waybackurls", domain], silent=True, timeout=60)
            if rc == 0:
                # Extract unique hostnames from URLs
                for url in out.splitlines():
                    m = re.search(r"https?://([^/\?:]+)", url)
                    if m and domain in m.group(1):
                        wb_subs.append(m.group(1))
        all_subs.extend(wb_subs)
        if wb_subs:
            status(f"waybackurls: +{len(set(wb_subs))} historical hostnames", "ok")

    # ── Deduplicate + save raw ───────────────────────────────────────
    all_subs = deduplicate(all_subs)
    raw_file = str(recon_dir / "all_subdomains_raw.txt")
    write_targets_file(raw_file, all_subs)
    status(f"Total before DNS resolution: {len(all_subs)}", "info")

    # ── DNS resolution via dnsx ──────────────────────────────────────
    resolved_file = str(recon_dir / "subdomains_resolved.txt")
    if tool_exists("dnsx") and all_subs:
        run_cmd(
            [
                "dnsx", "-l", raw_file,
                "-o", resolved_file,
                "-silent", "-threads", "50",
                "-retry", "3",
            ],
            silent=False,
        )
        resolved = _read_file(resolved_file) if Path(resolved_file).exists() else all_subs
    else:
        resolved = all_subs
        write_targets_file(resolved_file, resolved)

    status(f"Resolved: {len(resolved)} live subdomains", "ok")

    # ── Subdomain takeover check (subzy) ─────────────────────────────
    if tool_exists("subzy") and resolved:
        _check_takeovers(resolved_file, workdir, scan_id)

    return resolved_file


def _crtsh(domain: str) -> List[str]:
    """Query crt.sh certificate transparency logs."""
    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        req  = urllib.request.Request(url, headers={"User-Agent": "netra/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub.lower())
        return list(subs)
    except Exception:
        return []


def _inject_subfinder_keys(cmd: list) -> None:
    """Add Shodan/Censys/VT keys to subfinder command if configured."""
    provider_config = []

    if CONFIG.get("shodan"):
        provider_config.append(f"shodan: ['{CONFIG['shodan']}']")
    if CONFIG.get("virustotal"):
        provider_config.append(f"virustotal: ['{CONFIG['virustotal']}']")
    if CONFIG.get("censys_id") and CONFIG.get("censys_secret"):
        provider_config.append(
            f"censys: ['{CONFIG['censys_id']}:{CONFIG['censys_secret']}']"
        )
    if CONFIG.get("securitytrails"):
        provider_config.append(f"securitytrails: ['{CONFIG['securitytrails']}']")

    if provider_config:
        import tempfile, yaml
        try:
            cfg = {"sources": {k.split(":")[0].strip(): {"apikeys": [k.split(":")[1].strip()]}
                               for k in provider_config}}
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False, prefix="subfinder_"
            )
            import json
            # Write minimal YAML manually (avoid yaml dependency)
            lines = ["sources:\n"]
            for entry in provider_config:
                key, vals = entry.split(": ", 1)
                val_clean = vals.strip("[]'")
                lines.append(f"  {key}:\n    apikeys:\n      - {val_clean}\n")
            tmp.write("".join(lines))
            tmp.close()
            cmd.extend(["-provider-config", tmp.name])
        except Exception:
            pass


def _check_takeovers(resolved_file: str, workdir: Path, scan_id: str) -> None:
    """Run subzy for subdomain takeover detection."""
    from netra.core.database import FindingsDB
    db = FindingsDB()

    out_file = str(workdir / "recon" / "takeovers.txt")
    rc, stdout, _ = run_cmd(
        ["subzy", "run", "--targets", resolved_file, "--output", out_file],
        silent=True, timeout=120
    )

    # Parse takeover results
    if Path(out_file).exists():
        for line in Path(out_file).read_text().splitlines():
            if "VULNERABLE" in line.upper():
                host = line.split("[")[0].strip() if "[" in line else line.strip()
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Subdomain Takeover — {host}",
                    "template_id": "subdomain-takeover",
                    "severity":    "critical",
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "category":    "takeover",
                    "host":        host,
                    "url":         f"https://{host}",
                    "owasp_web":   "A05:2021",
                    "description": "CNAME points to unclaimed external service. Attacker can claim the service and control this subdomain.",
                    "impact":      "Attacker can host malicious content under your domain, steal cookies, perform phishing.",
                    "remediation": "Remove the dangling CNAME record or claim the service.",
                    "confidence":  95,
                }
                fid = db.add_finding(finding)
                if fid:
                    notify_finding(finding)
                    status(f"CRITICAL: Subdomain takeover — {host}", "finding")


def _read_file(path: str) -> List[str]:
    try:
        return [l.strip() for l in Path(path).read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    except Exception:
        return []
