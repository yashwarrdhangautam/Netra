"""
recon/js_analysis.py
JavaScript file secret scanner.
Fetches all JS files from live URLs and scans for 15 secret patterns:
API keys, tokens, passwords, internal endpoints, private IPs.
"""

import re
import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict

from netra.core.config import CONFIG
from netra.core.utils  import run_cmd, status, tool_exists
from netra.core.database import FindingsDB
from netra.core.notify import notify_finding


# ── Secret patterns ──────────────────────────────────────────────────
SECRET_PATTERNS = [
    # AWS
    {
        "name":    "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "cvss":    9.8,
    },
    {
        "name":    "AWS Secret Key",
        "pattern": r"(?:aws[_\-\s]?secret|aws[_\-\s]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})",
        "severity": "critical",
        "cvss":    9.8,
    },
    # Generic API Keys
    {
        "name":    "Generic API Key",
        "pattern": r"(?:api[_\-\s]?key|apikey|api_token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,50})",
        "severity": "high",
        "cvss":    7.5,
    },
    # Passwords in JS
    {
        "name":    "Hardcoded Password",
        "pattern": r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,50})",
        "severity": "critical",
        "cvss":    9.0,
    },
    # JWT tokens
    {
        "name":    "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "cvss":    7.5,
    },
    # Google / GCP
    {
        "name":    "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "cvss":    7.5,
    },
    # Stripe
    {
        "name":    "Stripe Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "severity": "critical",
        "cvss":    9.8,
    },
    # GitHub
    {
        "name":    "GitHub Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
        "severity": "high",
        "cvss":    7.5,
    },
    # Slack
    {
        "name":    "Slack Token",
        "pattern": r"xox[bpaso]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
        "severity": "high",
        "cvss":    7.5,
    },
    # Database connection strings
    {
        "name":    "Database Connection String",
        "pattern": r"(?:mysql|postgresql|mongodb|mssql)://[^\s'\"<>]{10,}",
        "severity": "critical",
        "cvss":    9.5,
    },
    # Private IPs in JS (internal endpoints)
    {
        "name":    "Internal IP Exposure",
        "pattern": r"https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s'\"]{5,}",
        "severity": "medium",
        "cvss":    5.3,
    },
    # Private endpoints / internal paths
    {
        "name":    "Possible Internal Endpoint",
        "pattern": r"['\"]\/(?:admin|internal|api\/v[0-9]|management|backend|debug|test)[\/\?][^\s'\"]*['\"]",
        "severity": "medium",
        "cvss":    5.3,
    },
    # SMTP credentials
    {
        "name":    "Email/SMTP Credentials",
        "pattern": r"smtp[_\s]?(?:user|pass|password|host)['\"]?\s*[:=]\s*['\"]([^\s'\"]{5,})",
        "severity": "high",
        "cvss":    7.5,
    },
    # Firebase
    {
        "name":    "Firebase Config",
        "pattern": r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "cvss":    7.5,
    },
    # Basic auth in URLs
    {
        "name":    "Basic Auth in URL",
        "pattern": r"https?://[^:@\s]+:[^@\s]+@[^\s'\"]+",
        "severity": "critical",
        "cvss":    9.0,
    },
]

COMPILED_PATTERNS = [
    {**p, "regex": re.compile(p["pattern"], re.IGNORECASE)}
    for p in SECRET_PATTERNS
]


def scan_js_secrets(
    live_urls_file: str,
    workdir: str,
    scan_id: str = "",
) -> list:
    """
    Fetch all JS files from live hosts and scan for secrets.
    Returns list of findings.
    """
    workdir   = Path(workdir)
    js_dir    = workdir / "recon" / "js_files"
    js_dir.mkdir(exist_ok=True)
    results_file = workdir / "recon" / "js_secrets.json"

    live_urls = [
        l.strip() for l in Path(live_urls_file).read_text().splitlines()
        if l.strip()
    ]

    # Collect JS URLs
    js_urls = _discover_js_urls(live_urls)
    status(f"JS analysis: {len(js_urls)} JS files to scan", "info")

    all_findings = []
    db = FindingsDB()

    for js_url in js_urls[:200]:   # cap at 200 files per scan
        content = _fetch_url(js_url)
        if not content:
            continue

        # Scan for secrets
        hits = _scan_content(content, js_url)
        for hit in hits:
            finding = {
                "scan_id":     scan_id,
                "title":       f"JS Secret: {hit['name']} — {_extract_host(js_url)}",
                "template_id": f"js-secret-{hit['name'].lower().replace(' ', '-')}",
                "severity":    hit["severity"],
                "cvss_score":  hit["cvss"],
                "category":    "js_secrets",
                "owasp_web":   "A02:2021",
                "host":        _extract_host(js_url),
                "url":         js_url,
                "description": f"Sensitive value matching '{hit['name']}' pattern found in JavaScript file.",
                "evidence":    f"File: {js_url}\nPattern: {hit['name']}\nLine: {hit['line'][:200]}",
                "impact":      "Exposed credentials or tokens allow direct access to backend systems, APIs, or cloud resources.",
                "remediation": "Remove secrets from client-side code. Use environment variables. Rotate all exposed credentials immediately.",
                "confidence":  85,
            }
            fid = db.add_finding(finding)
            if fid:
                all_findings.append(finding)
                notify_finding(finding)
                status(f"{hit['severity'].upper()}: {hit['name']} in {js_url[:60]}", "finding")

    # Save summary
    results_file.write_text(json.dumps(all_findings, indent=2))
    status(f"JS secrets: {len(all_findings)} findings", "ok" if not all_findings else "warn")

    return all_findings


def _discover_js_urls(live_urls: List[str]) -> List[str]:
    """
    Find JS file URLs from live hosts.
    Uses gau/waybackurls if available, otherwise extracts from page source.
    """
    js_urls = set()

    # Method 1: gau (fast, pulls from multiple archives)
    if tool_exists("gau"):
        for url in live_urls[:20]:  # limit to avoid slowness
            try:
                rc, stdout, _ = run_cmd(
                    ["gau", "--blacklist", "ttf,woff,svg,png,jpg,gif,css", url],
                    silent=True, timeout=30
                )
                if rc == 0:
                    for line in stdout.splitlines():
                        if line.strip().endswith(".js") and line.startswith("http"):
                            js_urls.add(line.strip())
            except Exception:
                pass

    # Method 2: Parse page source for <script src=...>
    for url in live_urls[:50]:
        content = _fetch_url(url)
        if not content:
            continue
        # Find script src attributes
        matches = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            content, re.IGNORECASE
        )
        base = _get_base_url(url)
        for m in matches:
            if m.startswith("http"):
                js_urls.add(m)
            elif m.startswith("/"):
                js_urls.add(base + m)
            else:
                js_urls.add(f"{url.rstrip('/')}/{m}")

    return list(js_urls)


def _scan_content(content: str, source_url: str) -> List[dict]:
    """Scan JS content against all secret patterns."""
    hits = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        for pattern_def in COMPILED_PATTERNS:
            match = pattern_def["regex"].search(line)
            if match:
                # Redact the actual secret in the finding
                redacted_line = _redact(line, match)
                hits.append({
                    "name":     pattern_def["name"],
                    "severity": pattern_def["severity"],
                    "cvss":     pattern_def["cvss"],
                    "line":     redacted_line,
                    "line_num": line_num,
                    "url":      source_url,
                })
                break   # one hit per line

    return hits


def _redact(line: str, match: re.Match) -> str:
    """Redact matched secret value for safe storage."""
    start, end = match.span()
    value = line[start:end]
    if len(value) > 8:
        redacted = value[:4] + "****" + value[-4:]
        return line[:start] + redacted + line[end:]
    return line[:start] + "****" + line[end:]


def _fetch_url(url: str, timeout: int = 10) -> str:
    """Fetch URL content. Returns empty string on error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if any(t in content_type for t in ("html", "javascript", "text", "json")):
                return resp.read(1024 * 1024).decode("utf-8", errors="ignore")  # max 1MB
    except Exception:
        pass
    return ""


def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return url


def _get_base_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url
