"""
pentest/cloud.py
Cloud misconfiguration testing: S3 bucket enumeration,
Azure blob anonymous access, GCP metadata SSRF, Firebase open DB.
"""

import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List

from netra.core.config   import CONFIG
from netra.core.utils    import run_cmd, status, banner, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding

from pentest.payloads import S3_BUCKET_PATTERNS, GCP_METADATA_PATHS, SSRF_PAYLOADS


def run_cloud_tests(
    live_urls: List[str],
    workdir: str,
    scan_id: str = "",
    tech_map: dict = None,
) -> int:
    """Run cloud misconfiguration tests. Returns total findings."""
    banner("CLOUD TESTING", "S3 · Azure · GCP · Firebase")

    workdir  = Path(workdir)
    tech_map = tech_map or {}
    db       = FindingsDB()
    total    = 0

    # Extract unique domains
    domains = list(set(_extract_domain(u) for u in live_urls))

    total += _test_s3_buckets(domains, live_urls, scan_id, db)
    total += _test_azure_blobs(domains, scan_id, db)
    total += _test_gcp_metadata(live_urls, scan_id, db)
    total += _test_firebase(live_urls, scan_id, db, tech_map)

    status(f"Cloud tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  S3 Bucket Enumeration
# ═══════════════════════════════════════════════════════════════════════

def _test_s3_buckets(domains: list, live_urls: list, scan_id: str,
                     db: FindingsDB) -> int:
    status("S3 bucket enumeration...", "run")
    count = 0

    # Build candidate bucket names
    bucket_names = set()
    for domain in domains[:10]:
        base = domain.replace(".", "-").split(":")[0]
        company = base.split("-")[0] if "-" in base else base.split(".")[0]

        for pattern in S3_BUCKET_PATTERNS:
            bucket_names.add(pattern.format(domain=base, company=company))

    # Also extract S3 references from page content
    s3_pattern = re.compile(r"([a-zA-Z0-9._-]+)\.s3[.-](?:amazonaws\.com|[a-z]+-[a-z]+-\d+\.amazonaws\.com)")
    for url in live_urls[:20]:
        body = _fetch(url)
        if body:
            for match in s3_pattern.findall(body):
                bucket_names.add(match)

    status(f"Testing {len(bucket_names)} S3 bucket names...", "info")

    for bucket in bucket_names:
        # Test bucket listing
        bucket_url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            req = urllib.request.Request(bucket_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read(4096).decode("utf-8", errors="ignore")

                if "ListBucketResult" in body or "<Contents>" in body:
                    severity = "critical"
                    desc = "S3 bucket allows anonymous listing."
                elif resp.status == 200:
                    severity = "high"
                    desc = "S3 bucket exists and is publicly accessible."
                else:
                    continue

                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Open S3 Bucket — {bucket}",
                    "template_id": "pentest-s3-open",
                    "severity":    severity,
                    "cvss_score":  9.8 if severity == "critical" else 7.5,
                    "category":    "cloud",
                    "owasp_web":   "A05:2021",
                    "mitre_technique": "T1530",
                    "host":        domains[0] if domains else bucket,
                    "url":         bucket_url,
                    "description": desc,
                    "evidence":    f"Bucket: {bucket}\nURL: {bucket_url}\nStatus: {resp.status}",
                    "impact":      "Data exfiltration. All files in the bucket are readable (and possibly writable) by anyone.",
                    "remediation": "Set bucket ACL to private. Enable S3 Block Public Access. Review bucket policies.",
                    "confidence":  95,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"{severity.upper()}: Open S3 — {bucket}", "finding")

        except urllib.error.HTTPError as e:
            if e.code == 403:
                pass  # bucket exists but properly restricted
        except Exception:
            pass

    status(f"S3: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Azure Blob Storage
# ═══════════════════════════════════════════════════════════════════════

def _test_azure_blobs(domains: list, scan_id: str,
                      db: FindingsDB) -> int:
    status("Azure blob storage testing...", "run")
    count = 0

    containers = ["data", "backup", "uploads", "files", "static",
                  "assets", "logs", "media", "public", "$web"]

    for domain in domains[:5]:
        base = domain.replace(".", "").split(":")[0][:24]

        for container in containers:
            blob_url = f"https://{base}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                req = urllib.request.Request(blob_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(4096).decode("utf-8", errors="ignore")

                    if "EnumerationResults" in body or "<Blob>" in body:
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Open Azure Blob — {base}/{container}",
                            "template_id": "pentest-azure-blob-open",
                            "severity":    "critical",
                            "cvss_score":  9.8,
                            "category":    "cloud",
                            "owasp_web":   "A05:2021",
                            "mitre_technique": "T1530",
                            "host":        domain,
                            "url":         blob_url,
                            "description": f"Azure blob container '{container}' allows anonymous listing.",
                            "evidence":    f"Storage: {base}\nContainer: {container}\nAnonymous listing enabled.",
                            "impact":      "Full container contents accessible. Data exfiltration risk.",
                            "remediation": "Set container access level to Private. Use SAS tokens for controlled access.",
                            "confidence":  95,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"CRITICAL: Open Azure blob — {base}/{container}", "finding")

            except Exception:
                pass

    status(f"Azure: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  GCP Metadata SSRF
# ═══════════════════════════════════════════════════════════════════════

def _test_gcp_metadata(urls: list, scan_id: str,
                       db: FindingsDB) -> int:
    status("GCP/AWS metadata SSRF testing...", "run")
    count = 0

    # Test URLs that accept URL parameters (potential SSRF)
    ssrf_params = ["url", "link", "href", "src", "redirect", "dest",
                   "path", "file", "page", "load", "fetch", "proxy"]

    for url in urls[:20]:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        target_params = [p for p in params if p.lower() in ssrf_params]
        if not target_params:
            continue

        for param in target_params:
            # Test cloud metadata endpoints
            for metadata_url in SSRF_PAYLOADS[:3]:  # AWS, GCP, Azure
                test_url = _inject_param(url, param, metadata_url)
                body = _fetch(test_url)

                if body and any(ind in body for ind in
                               ["ami-id", "instance-id", "computeMetadata",
                                "iam/", "security-credentials", "latest/meta-data"]):

                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"SSRF to Cloud Metadata — {param} ({host})",
                        "template_id": "pentest-ssrf-metadata",
                        "severity":    "critical",
                        "cvss_score":  9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "category":    "cloud",
                        "owasp_web":   "A10:2021",
                        "mitre_technique": "T1552",
                        "host":        host,
                        "url":         url,
                        "parameter":   param,
                        "description": f"SSRF via '{param}' allows access to cloud instance metadata service.",
                        "evidence":    f"Parameter: {param}\nPayload: {metadata_url}\nMetadata indicators found in response.",
                        "impact":      "Cloud credential theft. Attacker can steal IAM tokens, access keys, and compromise the entire cloud account.",
                        "remediation": "Block requests to 169.254.169.254 and metadata.google.internal. Use IMDSv2. Validate URL schemes and destinations.",
                        "confidence":  95,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        count += 1
                        notify_finding(finding)
                        status(f"CRITICAL: SSRF to metadata — {host}", "finding")
                    break

    status(f"Metadata SSRF: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Firebase
# ═══════════════════════════════════════════════════════════════════════

def _test_firebase(urls: list, scan_id: str, db: FindingsDB,
                   tech_map: dict) -> int:
    status("Firebase testing...", "run")
    count = 0

    # Look for Firebase references in pages and tech map
    firebase_projects = set()
    firebase_pattern = re.compile(r"([a-zA-Z0-9-]+)\.firebaseio\.com")

    for url in urls[:30]:
        body = _fetch(url)
        if body:
            for match in firebase_pattern.findall(body):
                firebase_projects.add(match)
            # Also check for firebaseConfig
            config_match = re.search(r"apiKey\s*:\s*['\"]([^'\"]+)", body)
            if config_match:
                firebase_projects.add(_extract_domain(url).replace(".", "-"))

    for project in firebase_projects:
        # Test Realtime Database open read
        db_url = f"https://{project}.firebaseio.com/.json"
        body = _fetch(db_url)

        if body and body.strip() not in ('null', '{"error":"Permission denied"}', ''):
            try:
                json.loads(body)
                is_valid_data = True
            except json.JSONDecodeError:
                is_valid_data = False

            if is_valid_data:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Firebase DB Open Read — {project}",
                    "template_id": "pentest-firebase-open",
                    "severity":    "critical",
                    "cvss_score":  9.8,
                    "category":    "cloud",
                    "owasp_web":   "A01:2021",
                    "mitre_technique": "T1530",
                    "host":        f"{project}.firebaseio.com",
                    "url":         db_url,
                    "description": f"Firebase Realtime Database '{project}' allows unauthenticated read access.",
                    "evidence":    f"URL: {db_url}\nResponse: {body[:200]}",
                    "impact":      "Full database contents readable without authentication. May contain PII, credentials, business data.",
                    "remediation": "Set Firebase Security Rules to require authentication. Audit all database rules.",
                    "confidence":  98,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"CRITICAL: Firebase open DB — {project}", "finding")

    status(f"Firebase: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return url

def _extract_domain(url: str) -> str:
    try:
        host = urllib.parse.urlparse(url).netloc
        return host.split(":")[0]
    except Exception:
        return url

def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def _fetch(url: str, timeout: int = 8) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return ""
