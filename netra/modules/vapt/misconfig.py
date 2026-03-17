"""
pentest/misconfig.py
Security misconfiguration testing: CORS wildcard, missing security headers,
open redirect, clickjacking, directory listing, information disclosure.
"""

import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List

from netra.core.config   import CONFIG
from netra.core.utils    import run_cmd, status, banner, tool_exists, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding

from pentest.payloads import (
    REQUIRED_SECURITY_HEADERS,
    REDIRECT_PAYLOADS, REDIRECT_PARAMS,
    CORS_ORIGINS, COMMON_PATHS,
)


def run_misconfig_tests(
    live_urls: List[str],
    workdir: str,
    scan_id: str = "",
    tech_map: dict = None,
    waf_map: dict = None,
) -> int:
    """Run misconfiguration tests. Returns total findings."""
    banner("MISCONFIG TESTING", "CORS · Headers · Redirect · Exposure")

    workdir  = Path(workdir)
    tech_map = tech_map or {}
    waf_map  = waf_map or {}
    db       = FindingsDB()
    total    = 0

    total += _test_cors(live_urls, scan_id, db)
    total += _test_security_headers(live_urls, scan_id, db)
    total += _test_open_redirect(live_urls, scan_id, db)
    total += _test_directory_listing(live_urls, scan_id, db)
    total += _test_sensitive_files(live_urls, scan_id, db)
    total += _test_tls(live_urls, scan_id, db, workdir)

    status(f"Misconfig tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  CORS Misconfiguration
# ═══════════════════════════════════════════════════════════════════════

def _test_cors(urls: list, scan_id: str, db: FindingsDB) -> int:
    status("CORS testing...", "run")
    count = 0

    for url in urls[:30]:
        host = _extract_host(url)

        for origin in CORS_ORIGINS:
            try:
                req = urllib.request.Request(
                    url, method="OPTIONS",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Origin":     origin,
                    },
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        severity = "high" if acac.lower() == "true" else "medium"
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"CORS Wildcard Origin ({host})",
                            "template_id": "pentest-cors-wildcard",
                            "severity":    severity,
                            "cvss_score":  7.5 if severity == "high" else 5.3,
                            "category":    "misconfig",
                            "owasp_web":   "A05:2021",
                            "host":        host,
                            "url":         url,
                            "description": f"CORS allows any origin (*). Credentials: {acac}.",
                            "evidence":    f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            "impact":      "Cross-origin data theft. Any website can read responses from this API.",
                            "remediation": "Restrict ACAO to specific trusted origins. Never use wildcard with credentials.",
                            "confidence":  95,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"{severity.upper()}: CORS wildcard — {host}", "finding")
                        break

                    elif origin in acao and origin != "null":
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"CORS Reflects Origin ({host})",
                            "template_id": "pentest-cors-reflect",
                            "severity":    "high",
                            "cvss_score":  7.5,
                            "category":    "misconfig",
                            "owasp_web":   "A05:2021",
                            "host":        host,
                            "url":         url,
                            "description": f"CORS reflects attacker-controlled Origin header back in ACAO.",
                            "evidence":    f"Origin sent: {origin}\nACAO returned: {acao}\nACLC: {acac}",
                            "impact":      "Any origin can read authenticated API responses.",
                            "remediation": "Validate Origin against a strict whitelist. Never reflect Origin.",
                            "confidence":  93,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"HIGH: CORS reflects origin — {host}", "finding")
                        break

            except Exception:
                pass

    status(f"CORS: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Security Headers
# ═══════════════════════════════════════════════════════════════════════

def _test_security_headers(urls: list, scan_id: str,
                           db: FindingsDB) -> int:
    status("Security headers check...", "run")
    count = 0

    # Sample unique hosts only
    tested_hosts = set()
    for url in urls:
        host = _extract_host(url)
        if host in tested_hosts:
            continue
        tested_hosts.add(host)
        if len(tested_hosts) > 30:
            break

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                missing = []
                for header, desc in REQUIRED_SECURITY_HEADERS.items():
                    if not resp.headers.get(header):
                        missing.append((header, desc))

                if missing:
                    missing_names = [h for h, _ in missing]
                    severity = "medium" if len(missing) <= 3 else "high"
                    cvss = 5.3 if severity == "medium" else 6.5

                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"Missing Security Headers ({host})",
                        "template_id": "pentest-missing-headers",
                        "severity":    severity,
                        "cvss_score":  cvss,
                        "category":    "misconfig",
                        "owasp_web":   "A05:2021",
                        "host":        host,
                        "url":         url,
                        "description": f"Missing {len(missing)} security headers: {', '.join(missing_names)}.",
                        "evidence":    "\n".join(f"✗ {h}: {d}" for h, d in missing),
                        "impact":      "Missing headers increase risk of XSS, clickjacking, MIME sniffing, and other attacks.",
                        "remediation": "Add all recommended security headers. Use HSTS with includeSubDomains.",
                        "confidence":  98,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        count += 1
                        notify_finding(finding)

        except Exception:
            pass

    status(f"Headers: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Open Redirect
# ═══════════════════════════════════════════════════════════════════════

def _test_open_redirect(urls: list, scan_id: str,
                        db: FindingsDB) -> int:
    status("Open redirect testing...", "run")
    count = 0

    for url in urls[:20]:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Check existing redirect params
        redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]

        # Also inject redirect params into base URL
        if not redirect_params:
            for rp in ["redirect", "url", "next", "return"]:
                redirect_params.append(rp)

        for param in redirect_params[:3]:
            for payload in REDIRECT_PAYLOADS[:5]:
                test_url = _inject_param(url, param, payload)
                try:
                    req = urllib.request.Request(
                        test_url, headers={"User-Agent": "Mozilla/5.0"},
                    )
                    # Don't follow redirects
                    class NoRedirect(urllib.request.HTTPRedirectHandler):
                        def redirect_request(self, req, fp, code, msg, hdrs, newurl) -> None:
                            """Capture redirect URL without following it."""
                            self.redirected_url = newurl
                            return None

                    handler = NoRedirect()
                    opener  = urllib.request.build_opener(handler)
                    try:
                        opener.open(req, timeout=8)
                    except Exception:
                        pass

                    redirected = getattr(handler, "redirected_url", "")
                    if redirected and "evil.com" in redirected:
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Open Redirect — {param} ({host})",
                            "template_id": "pentest-open-redirect",
                            "severity":    "medium",
                            "cvss_score":  6.1,
                            "category":    "misconfig",
                            "owasp_web":   "A01:2021",
                            "host":        host,
                            "url":         url,
                            "parameter":   param,
                            "description": f"Open redirect via '{param}' allows redirecting users to attacker site.",
                            "evidence":    f"Payload: {payload}\nRedirected to: {redirected}",
                            "impact":      "Phishing, OAuth token theft, reputation damage.",
                            "remediation": "Validate redirect targets against a whitelist. Use relative paths only.",
                            "confidence":  90,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"MEDIUM: Open redirect — {host}", "finding")
                        break
                except Exception:
                    pass

    status(f"Redirect: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Directory Listing
# ═══════════════════════════════════════════════════════════════════════

def _test_directory_listing(urls: list, scan_id: str,
                            db: FindingsDB) -> int:
    status("Directory listing check...", "run")
    count = 0

    dir_paths = ["/", "/images/", "/uploads/", "/files/", "/assets/",
                 "/static/", "/media/", "/backup/", "/data/", "/css/", "/js/"]

    tested = set()
    for url in urls[:20]:
        base = _get_base_url(url)
        for path in dir_paths:
            full = base + path
            if full in tested:
                continue
            tested.add(full)

            body = _fetch(full)
            if body and any(ind in body for ind in
                           ["Index of /", "Directory listing",
                            "<title>Index of", "Parent Directory",
                            '[To Parent Directory]']):
                host = _extract_host(full)
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Directory Listing — {path} ({host})",
                    "template_id": "pentest-dir-listing",
                    "severity":    "medium",
                    "cvss_score":  5.3,
                    "category":    "misconfig",
                    "owasp_web":   "A05:2021",
                    "host":        host,
                    "url":         full,
                    "description": f"Directory listing enabled at {path}.",
                    "evidence":    f"URL: {full}\nDirectory index page returned.",
                    "impact":      "Exposes internal file structure, backup files, configuration files.",
                    "remediation": "Disable directory listing in web server config. Add index.html or deny directive.",
                    "confidence":  98,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)

    status(f"Dir listing: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Sensitive File Exposure
# ═══════════════════════════════════════════════════════════════════════

SENSITIVE_INDICATORS = {
    ".env":            ("DB_PASSWORD", "critical", "Environment file with secrets"),
    ".git/config":     ("[core]",      "high",     "Git repository exposed"),
    ".git/HEAD":       ("ref: refs",   "high",     "Git repository exposed"),
    ".svn/entries":    ("dir",         "high",     "SVN repository exposed"),
    ".DS_Store":       ("\x00\x00\x00", "low",     "macOS metadata file"),
    "web.config":      ("<configuration", "high",  "IIS configuration exposed"),
    ".htpasswd":       (":",           "critical", "Password file exposed"),
    "phpinfo.php":     ("phpinfo()",   "medium",   "PHP info page exposed"),
    "server-status":   ("Apache Server Status", "medium", "Apache status page"),
    "actuator/env":    ("activeProfiles", "critical", "Spring Boot actuator — env"),
    "actuator/health": ("status",      "low",      "Spring Boot actuator — health"),
    "elmah.axd":       ("Error Log",   "high",     "ELMAH error log exposed"),
    "Dockerfile":      ("FROM",        "medium",   "Dockerfile exposed"),
    "docker-compose.yml": ("services:", "high",    "Docker Compose file exposed"),
    "package.json":    ("dependencies", "low",     "NPM package.json exposed"),
}

def _test_sensitive_files(urls: list, scan_id: str,
                          db: FindingsDB) -> int:
    status("Sensitive file exposure check...", "run")
    count = 0

    tested = set()
    for url in urls[:20]:
        base = _get_base_url(url)
        host = _extract_host(url)

        for path, (indicator, severity, desc) in SENSITIVE_INDICATORS.items():
            full = f"{base}/{path}"
            if full in tested:
                continue
            tested.add(full)

            body = _fetch(full)
            if body and indicator in body:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Sensitive File — {path} ({host})",
                    "template_id": f"pentest-sensitive-{path.replace('/', '-').replace('.', '-')}",
                    "severity":    severity,
                    "cvss_score":  {"critical": 9.0, "high": 7.5, "medium": 5.3, "low": 2.5}[severity],
                    "category":    "exposure",
                    "owasp_web":   "A01:2021",
                    "mitre_technique": "T1552",
                    "host":        host,
                    "url":         full,
                    "description": f"{desc}. File /{path} is publicly accessible.",
                    "evidence":    f"URL: {full}\nIndicator: '{indicator}' found in response.",
                    "impact":      f"Sensitive information disclosure via {path}.",
                    "remediation": f"Block access to {path} in web server configuration. Remove from deployment.",
                    "confidence":  95,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"{severity.upper()}: Sensitive file — {path} on {host}", "finding")

    status(f"Sensitive files: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  TLS / SSL Testing
# ═══════════════════════════════════════════════════════════════════════

def _test_tls(urls: list, scan_id: str, db: FindingsDB,
              workdir: Path) -> int:
    """Run testssl.sh if available."""
    if not tool_exists("testssl.sh"):
        status("testssl.sh not found — skipping TLS checks", "skip")
        return 0

    status("TLS testing (testssl.sh)...", "run")
    count = 0

    # Test unique HTTPS hosts
    https_hosts = list(set(
        _extract_host(u) for u in urls if u.startswith("https://")
    ))[:5]

    for host in https_hosts:
        output_file = str(workdir / "pentest" / f"testssl_{host.replace(':', '_')}.json")

        rc, stdout, stderr = run_cmd(
            [
                "testssl.sh", "--json", output_file,
                "--severity", "HIGH",
                "--fast",
                host,
            ],
            silent=True, timeout=300,
        )

        if Path(output_file).exists():
            try:
                data = json.loads(Path(output_file).read_text())
                for entry in data:
                    sev = entry.get("severity", "").upper()
                    if sev in ("CRITICAL", "HIGH"):
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"TLS: {entry.get('id', '?')} ({host})",
                            "template_id": f"pentest-tls-{entry.get('id', 'unknown')}",
                            "severity":    sev.lower(),
                            "cvss_score":  7.5 if sev == "HIGH" else 9.0,
                            "category":    "misconfig",
                            "owasp_web":   "A02:2021",
                            "host":        host,
                            "url":         f"https://{host}",
                            "description": entry.get("finding", "TLS misconfiguration detected."),
                            "evidence":    f"Check: {entry.get('id', '?')}\nFinding: {entry.get('finding', '')}",
                            "impact":      "Weak TLS configuration may allow traffic interception or downgrade attacks.",
                            "remediation": "Update TLS configuration. Disable weak ciphers and protocols.",
                            "confidence":  95,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
            except (json.JSONDecodeError, Exception):
                pass

    status(f"TLS: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

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
