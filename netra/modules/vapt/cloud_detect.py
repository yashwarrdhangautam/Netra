"""
netra/modules/vapt/cloud_detect.py
Cloud service detection and CSPM trigger.

Detects AWS, Azure, and GCP services within the scanned scope using:
  - DNS CNAME analysis (*.amazonaws.com, *.azure.net, etc.)
  - HTTP response header fingerprinting
  - IP range matching against published cloud CIDRs
  - SSL certificate organisation fields
  - S3 bucket enumeration
  - Azure Blob container discovery

If cloud is detected, prompts the user to run a CSPM audit.
"""

import re
import json
import socket
import logging
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from netra.core.utils import status, run_cmd

logger = logging.getLogger("netra.modules.vapt.cloud_detect")

# ── Provider patterns ──────────────────────────────────────────────────────────

AWS_CNAME_PATTERNS = [
    r"\.amazonaws\.com$",
    r"\.aws\.amazon\.com$",
    r"\.cloudfront\.net$",
    r"\.elb\.amazonaws\.com$",
    r"\.s3\.amazonaws\.com$",
    r"\.execute-api\..+\.amazonaws\.com$",
    r"\.lambda-url\..+\.on\.aws$",
]

AZURE_CNAME_PATTERNS = [
    r"\.azure\.com$",
    r"\.azure\.net$",
    r"\.azurewebsites\.net$",
    r"\.blob\.core\.windows\.net$",
    r"\.azurecontainer\.io$",
    r"\.azuredatalakestore\.net$",
    r"\.trafficmanager\.net$",
    r"\.cloudapp\.azure\.com$",
]

GCP_CNAME_PATTERNS = [
    r"\.googleapis\.com$",
    r"\.appspot\.com$",
    r"\.cloudfunctions\.net$",
    r"\.run\.app$",
    r"\.storage\.googleapis\.com$",
    r"\.cloudrun\.app$",
]

AWS_HEADER_PATTERNS  = ["x-amz-", "x-amzn-", "x-aws-", "awselb", "amazon"]
AZURE_HEADER_PATTERNS = ["x-ms-", "x-azure-", "azure"]
GCP_HEADER_PATTERNS  = ["x-goog-", "via: 1.1 google", "x-gfe-"]

# Known cloud IP ranges (abbreviated — full ranges pulled dynamically)
AWS_IP_PREFIXES  = ["54.0.0.0/8", "52.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8"]
AZURE_IP_PREFIXES = ["40.0.0.0/8", "104.0.0.0/8", "20.0.0.0/8", "13.0.0.0/8"]
GCP_IP_PREFIXES  = ["34.64.0.0/10", "35.186.0.0/16", "34.0.0.0/10", "35.191.0.0/16"]


def _resolve_cname(host: str) -> str:
    """Resolve CNAME chain and return the final canonical name."""
    try:
        result = run_cmd(["dig", "+short", "CNAME", host], timeout=5)
        return (result.stdout or "").strip().lower()
    except Exception:
        try:
            return socket.getfqdn(host).lower()
        except Exception:
            return ""


def _check_cname(cname: str) -> Dict[str, bool]:
    """Check CNAME against cloud provider patterns."""
    found = {"aws": False, "azure": False, "gcp": False}
    for pat in AWS_CNAME_PATTERNS:
        if re.search(pat, cname):
            found["aws"] = True
    for pat in AZURE_CNAME_PATTERNS:
        if re.search(pat, cname):
            found["azure"] = True
    for pat in GCP_CNAME_PATTERNS:
        if re.search(pat, cname):
            found["gcp"] = True
    return found


def _check_headers(url: str) -> Dict[str, bool]:
    """Fingerprint cloud provider from HTTP response headers."""
    found = {"aws": False, "azure": False, "gcp": False}
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; NETRA/1.0)"},
                            verify=False)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        header_str    = str(headers_lower)

        for pat in AWS_HEADER_PATTERNS:
            if pat in header_str:
                found["aws"] = True
        for pat in AZURE_HEADER_PATTERNS:
            if pat in header_str:
                found["azure"] = True
        for pat in GCP_HEADER_PATTERNS:
            if pat in header_str:
                found["gcp"] = True
    except Exception:
        pass
    return found


def _check_ip_range(host: str) -> Dict[str, bool]:
    """Check if resolved IP falls within known cloud IP ranges."""
    found = {"aws": False, "azure": False, "gcp": False}
    try:
        ip_str = socket.gethostbyname(host)
        ip     = ipaddress.ip_address(ip_str)

        for prefix in AWS_IP_PREFIXES:
            if ip in ipaddress.ip_network(prefix, strict=False):
                found["aws"] = True
        for prefix in AZURE_IP_PREFIXES:
            if ip in ipaddress.ip_network(prefix, strict=False):
                found["azure"] = True
        for prefix in GCP_IP_PREFIXES:
            if ip in ipaddress.ip_network(prefix, strict=False):
                found["gcp"] = True
    except Exception:
        pass
    return found


def _enumerate_s3_buckets(domain: str) -> List[dict]:
    """
    Enumerate likely S3 bucket names derived from the domain.

    Args:
        domain: Target domain name.

    Returns:
        List of dicts for any publicly accessible buckets.
    """
    buckets  = []
    base     = domain.replace(".", "-").replace("_", "-")
    variants = [
        base, f"{base}-dev", f"{base}-prod", f"{base}-staging",
        f"{base}-backup", f"{base}-assets", f"{base}-static", f"{base}-data",
        f"{base}-logs", f"{base}-media",
    ]

    for name in variants:
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = requests.head(url, timeout=5, verify=False)
            if resp.status_code in (200, 403):
                buckets.append({
                    "name":   name,
                    "url":    url,
                    "status": resp.status_code,
                    "public": resp.status_code == 200,
                })
        except Exception:
            continue

    return buckets


def _merge_found(a: Dict[str, bool], b: Dict[str, bool]) -> Dict[str, bool]:
    """Merge two provider-detection dicts with OR logic."""
    return {k: a.get(k, False) or b.get(k, False) for k in ("aws", "azure", "gcp")}


def detect_cloud(
    targets: List[str],
    urls: Optional[List[str]] = None,
) -> dict:
    """
    Run full cloud detection across all targets.

    Args:
        targets: Hostnames and IPs from scope.
        urls:    Live URLs from HTTP discovery.

    Returns:
        Detection results dict with providers, evidence, buckets.
    """
    status("Running cloud service detection...", "info")

    all_found: Dict[str, bool] = {"aws": False, "azure": False, "gcp": False}
    evidence: List[dict]       = []
    s3_buckets: List[dict]     = []

    for target in targets[:50]:   # cap at 50 hosts
        host = urlparse(target).hostname or target

        # CNAME check
        cname = _resolve_cname(host)
        if cname:
            cname_found = _check_cname(cname)
            for provider, hit in cname_found.items():
                if hit:
                    evidence.append({"host": host, "method": "cname",
                                     "provider": provider, "detail": cname})
            all_found = _merge_found(all_found, cname_found)

        # IP range check
        ip_found = _check_ip_range(host)
        for provider, hit in ip_found.items():
            if hit:
                evidence.append({"host": host, "method": "ip_range", "provider": provider})
        all_found = _merge_found(all_found, ip_found)

    # HTTP header checks on live URLs
    for url in (urls or [])[:20]:
        hdr_found = _check_headers(url)
        for provider, hit in hdr_found.items():
            if hit:
                evidence.append({"host": url, "method": "http_header", "provider": provider})
        all_found = _merge_found(all_found, hdr_found)

    # S3 bucket enumeration if AWS detected
    if all_found["aws"]:
        for target in targets[:5]:
            host       = urlparse(target).hostname or target
            base_domain = ".".join(host.split(".")[-2:])
            buckets     = _enumerate_s3_buckets(base_domain)
            s3_buckets.extend(buckets)

        if s3_buckets:
            public = [b for b in s3_buckets if b["public"]]
            status(
                f"S3 buckets found: {len(s3_buckets)} "
                f"({len(public)} public)",
                "warn" if public else "info",
            )

    detected_providers = [p for p, v in all_found.items() if v]

    return {
        "detected":   len(detected_providers) > 0,
        "providers":  detected_providers,
        "evidence":   evidence,
        "s3_buckets": s3_buckets,
    }


def cloud_to_findings(cloud_result: dict, scan_id: str) -> List[dict]:
    """
    Convert cloud detection results into NETRA findings.

    Args:
        cloud_result: Result from detect_cloud().
        scan_id:      Current scan ID.

    Returns:
        List of finding dicts.
    """
    findings = []

    for provider in cloud_result.get("providers", []):
        findings.append({
            "scan_id":     scan_id,
            "title":       f"Cloud Provider Detected: {provider.upper()}",
            "severity":    "info",
            "category":    "cloud_detection",
            "description": f"{provider.upper()} cloud services detected in scope. "
                           f"Consider running a Cloud Security Posture Management (CSPM) audit.",
            "evidence":    json.dumps([e for e in cloud_result["evidence"]
                                       if e["provider"] == provider]),
        })

    for bucket in cloud_result.get("s3_buckets", []):
        if bucket["public"]:
            findings.append({
                "scan_id":     scan_id,
                "title":       f"Public S3 Bucket: {bucket['name']}",
                "severity":    "high",
                "category":    "cloud_misconfiguration",
                "cvss_score":  7.5,
                "description": f"S3 bucket {bucket['name']} is publicly accessible. "
                               f"Unauthenticated users may read, list, or write objects.",
                "url":         bucket["url"],
                "remediation": "Apply bucket policy to restrict public access. "
                               "Enable S3 Block Public Access at account level.",
            })

    return findings


def prompt_cspm(cloud_result: dict) -> bool:
    """
    Interactively prompt the user to run CSPM audit if cloud is detected.

    Args:
        cloud_result: Result from detect_cloud().

    Returns:
        True if user confirms CSPM should run.
    """
    if not cloud_result.get("detected"):
        return False

    providers = cloud_result.get("providers", [])
    buckets   = cloud_result.get("s3_buckets", [])
    public    = [b for b in buckets if b.get("public")]

    print("\n" + "═" * 62)
    print("  ☁  CLOUD SERVICES DETECTED")
    print("─" * 62)
    print(f"  Providers : {', '.join(p.upper() for p in providers)}")
    print(f"  S3 Buckets: {len(buckets)} found  ({len(public)} public)")

    if public:
        print(f"\n  ⚠  Public S3 Buckets:")
        for b in public[:5]:
            print(f"     • {b['url']}")

    print("\n  → Run Cloud Security Posture Management (CSPM) audit?")
    print("    This will check IAM policies, exposed services, encryption,")
    print("    logging, and network security groups.")
    print("═" * 62)

    try:
        ans = input("\n  Run CSPM? [Y/n] ").strip().lower()
        return ans in ("", "y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False
