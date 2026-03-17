"""
pentest/injection.py
Active injection testing: SQLi, XSS, SSTI, XXE, CMDi, path traversal.
Uses sqlmap (PoC mode), dalfox for XSS, ffuf for path traversal,
plus custom checks for SSTI/XXE/CMDi.
WAF-detected hosts get payloads routed through waf_evasion.
"""

import json
import re
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict

from netra.core.config   import CONFIG, is_on
from netra.core.utils    import run_cmd, status, banner, tool_exists, truncate, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding

from pentest.payloads     import (
    SQLI_PAYLOADS, SQLI_INDICATORS,
    XSS_PAYLOADS, XSS_CANARY,
    SSTI_PAYLOADS,
    XXE_PAYLOADS,
    CMDI_PAYLOADS, CMDI_INDICATORS,
    PATH_TRAVERSAL_PAYLOADS, PATH_INDICATORS,
)
from pentest.waf_evasion  import evade_for_host


def run_injection_tests(
    live_urls: List[str],
    workdir: str,
    scan_id: str = "",
    tech_map: dict = None,
    waf_map: dict = None,
) -> int:
    """
    Run all injection tests on live URLs.
    Returns total number of findings added.
    """
    banner("INJECTION TESTING", "SQLi · XSS · SSTI · XXE · CMDi · Path Traversal")

    workdir     = Path(workdir)
    pentest_dir = workdir / "pentest"
    pentest_dir.mkdir(exist_ok=True)
    tech_map = tech_map or {}
    waf_map  = waf_map or {}

    db       = FindingsDB()
    total    = 0
    is_legacy = CONFIG.get("legacy_mode") == "true"

    # ── 1. SQLi via sqlmap (PoC mode — safe) ─────────────────────────
    if tool_exists("sqlmap") and not is_legacy:
        count = _run_sqlmap(live_urls, pentest_dir, scan_id, db)
        total += count
    elif not tool_exists("sqlmap"):
        status("sqlmap not found — skipping SQLi", "warn")
    else:
        status("SQLi skipped (legacy mode)", "skip")

    # ── 2. XSS via dalfox ───────────────────────────────────────────
    if tool_exists("dalfox") and not is_legacy:
        count = _run_dalfox(live_urls, pentest_dir, scan_id, db)
        total += count
    elif not tool_exists("dalfox"):
        status("dalfox not found — running custom XSS checks", "warn")
        count = _custom_xss_check(live_urls, scan_id, db, waf_map)
        total += count

    # ── 3. SSTI ──────────────────────────────────────────────────────
    count = _test_ssti(live_urls, scan_id, db, waf_map)
    total += count

    # ── 4. XXE ───────────────────────────────────────────────────────
    count = _test_xxe(live_urls, scan_id, db, tech_map)
    total += count

    # ── 5. Command Injection ─────────────────────────────────────────
    if not is_legacy:
        count = _test_cmdi(live_urls, scan_id, db, waf_map)
        total += count

    # ── 6. Path Traversal via ffuf ───────────────────────────────────
    if tool_exists("ffuf"):
        count = _run_ffuf_traversal(live_urls, pentest_dir, scan_id, db)
        total += count
    else:
        count = _custom_path_traversal(live_urls, scan_id, db, waf_map)
        total += count

    status(f"Injection tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  SQLi — sqlmap
# ═══════════════════════════════════════════════════════════════════════

def _run_sqlmap(urls: list, pentest_dir: Path, scan_id: str,
                db: FindingsDB) -> int:
    """Run sqlmap in safe PoC mode against parameterized URLs."""
    status("SQLi testing (sqlmap — PoC mode)...", "run")
    count = 0

    # Filter for URLs with parameters
    param_urls = [u for u in urls if "?" in u and "=" in u][:30]  # cap at 30
    if not param_urls:
        status("No parameterized URLs for SQLi testing", "skip")
        return 0

    for url in param_urls:
        out_dir = str(pentest_dir / "sqlmap" / _safe_filename(url))

        rc, stdout, stderr = run_cmd(
            [
                "sqlmap",
                "-u", url,
                "--batch",              # non-interactive
                "--level=2",
                "--risk=1",             # safe PoC mode
                "--threads=3",
                "--timeout=10",
                "--retries=1",
                "--output-dir", out_dir,
                "--forms",              # test forms too
                "--smart",              # only test promising params
                "--tamper=space2comment",
            ],
            silent=True, timeout=120,
        )

        if rc == 0 and "is vulnerable" in stdout.lower():
            # Parse sqlmap output
            vuln_params = re.findall(r"Parameter: (.+?) \(", stdout)
            for param in vuln_params:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"SQL Injection — {param}",
                    "template_id": "pentest-sqli",
                    "severity":    "critical",
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "category":    "injection",
                    "owasp_web":   "A03:2021",
                    "mitre_technique": "T1190",
                    "host":        _extract_host(url),
                    "url":         url,
                    "parameter":   param,
                    "description": f"SQL injection vulnerability in parameter '{param}'. Confirmed by sqlmap.",
                    "evidence":    truncate(stdout, 2000),
                    "poc_command": f"sqlmap -u '{url}' --batch --level=2 --risk=1",
                    "impact":      "Full database access. Attacker can read, modify, or delete all data. May lead to OS command execution.",
                    "remediation": "Use parameterized queries (prepared statements). Never concatenate user input into SQL. Apply WAF rules.",
                    "confidence":  95,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"CRITICAL: SQLi in {param} — {_extract_host(url)}", "finding")

    status(f"SQLi: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  XSS — dalfox
# ═══════════════════════════════════════════════════════════════════════

def _run_dalfox(urls: list, pentest_dir: Path, scan_id: str,
                db: FindingsDB) -> int:
    """Run dalfox for XSS detection on parameterized URLs."""
    status("XSS testing (dalfox)...", "run")
    count = 0

    param_urls = [u for u in urls if "?" in u and "=" in u][:30]
    if not param_urls:
        status("No parameterized URLs for XSS testing", "skip")
        return 0

    # Write URLs to file
    url_file = str(pentest_dir / "xss_targets.txt")
    Path(url_file).write_text("\n".join(param_urls) + "\n")

    output_file = str(pentest_dir / "dalfox.json")

    rc, stdout, stderr = run_cmd(
        [
            "dalfox", "file", url_file,
            "-o", output_file,
            "--format", "json",
            "--silence",
            "--timeout", "10",
            "--worker", CONFIG.get("threads", "10"),
            "--skip-bav",
        ],
        silent=False, timeout=600,
    )

    # Parse dalfox output
    if Path(output_file).exists():
        for line in Path(output_file).read_text().splitlines():
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            vuln_url  = entry.get("data", "")
            poc       = entry.get("poc", "")
            param     = entry.get("param", "")
            xss_type  = entry.get("type", "reflected")

            severity = "high" if xss_type == "reflected" else "critical"
            cvss     = 8.2 if xss_type == "reflected" else 9.0

            finding = {
                "scan_id":     scan_id,
                "title":       f"XSS ({xss_type}) — {param or _extract_host(vuln_url)}",
                "template_id": f"pentest-xss-{xss_type}",
                "severity":    severity,
                "cvss_score":  cvss,
                "category":    "injection",
                "owasp_web":   "A03:2021",
                "mitre_technique": "T1189",
                "host":        _extract_host(vuln_url),
                "url":         vuln_url,
                "parameter":   param,
                "description": f"{xss_type.title()} XSS in parameter '{param}'.",
                "evidence":    f"PoC: {poc}\nURL: {vuln_url}",
                "poc_command": f"dalfox url '{vuln_url}'",
                "impact":      "Session hijacking, credential theft, defacement, phishing via injected content.",
                "remediation": "Encode all output. Use Content-Security-Policy. Validate and sanitize input.",
                "confidence":  92,
            }
            fid = db.add_finding(finding)
            if fid:
                count += 1
                notify_finding(finding)
                status(f"{severity.upper()}: XSS ({xss_type}) — {param}", "finding")

    status(f"XSS: {count} findings", "ok" if not count else "warn")
    return count


def _custom_xss_check(urls: list, scan_id: str, db: FindingsDB,
                      waf_map: dict) -> int:
    """Fallback XSS check when dalfox is unavailable."""
    count = 0
    param_urls = [u for u in urls if "?" in u and "=" in u][:20]

    for url in param_urls:
        host = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            # Inject canary and check reflection
            test_url = _inject_param(url, param_name, XSS_CANARY)
            body = _fetch(test_url)
            if body and XSS_CANARY in body:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"Reflected Input — {param_name} ({host})",
                    "template_id": "pentest-xss-reflection",
                    "severity":    "medium",
                    "cvss_score":  5.4,
                    "category":    "injection",
                    "owasp_web":   "A03:2021",
                    "host":        host,
                    "url":         url,
                    "parameter":   param_name,
                    "description": f"Input in parameter '{param_name}' is reflected in response without encoding. Potential XSS.",
                    "evidence":    f"Canary '{XSS_CANARY}' reflected in response body.",
                    "impact":      "May allow XSS if output encoding is insufficient.",
                    "remediation": "Encode all reflected output. Implement CSP.",
                    "confidence":  65,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)

    return count


# ═══════════════════════════════════════════════════════════════════════
#  SSTI
# ═══════════════════════════════════════════════════════════════════════

def _test_ssti(urls: list, scan_id: str, db: FindingsDB,
               waf_map: dict) -> int:
    """Test for Server-Side Template Injection."""
    status("SSTI testing...", "run")
    count = 0

    param_urls = [u for u in urls if "?" in u and "=" in u][:20]

    for url in param_urls:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            for payload, expected, engine in SSTI_PAYLOADS[:5]:  # top 5 detection payloads
                variants = evade_for_host(payload, host, waf_map)

                for variant in variants[:2]:
                    test_url = _inject_param(url, param_name, variant)
                    body = _fetch(test_url)

                    if body and expected in body:
                        severity = "critical" if "RCE" in engine or "config" in engine else "high"
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"SSTI ({engine}) — {param_name}",
                            "template_id": "pentest-ssti",
                            "severity":    severity,
                            "cvss_score":  9.8 if severity == "critical" else 8.5,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category":    "injection",
                            "owasp_web":   "A03:2021",
                            "mitre_technique": "T1190",
                            "host":        host,
                            "url":         url,
                            "parameter":   param_name,
                            "description": f"Server-Side Template Injection detected. Engine: {engine}. Payload '{payload}' produced expected output '{expected}'.",
                            "evidence":    f"Payload: {payload}\nExpected: {expected}\nResponse contains: {expected}",
                            "poc_command": f"curl '{test_url}'",
                            "impact":      "Remote code execution on the server. Full system compromise.",
                            "remediation": "Never pass user input to template engines. Use sandboxed template rendering. Validate all input.",
                            "confidence":  90,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"CRITICAL: SSTI ({engine}) — {host}", "finding")
                        break  # found for this param, skip remaining variants
                    break  # skip variants if first didn't match

    status(f"SSTI: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  XXE
# ═══════════════════════════════════════════════════════════════════════

def _test_xxe(urls: list, scan_id: str, db: FindingsDB,
              tech_map: dict) -> int:
    """Test for XML External Entity injection."""
    status("XXE testing...", "run")
    count = 0

    # Target endpoints likely to accept XML
    xml_endpoints = []
    for url in urls:
        info = tech_map.get(url, {})
        ctype = info.get("content_type", "")
        if "xml" in ctype.lower() or "soap" in url.lower() or "api" in url.lower():
            xml_endpoints.append(url)

    # Also try common API paths
    for url in urls[:20]:
        for path in ["/api/", "/upload", "/import", "/parse"]:
            if path in url:
                xml_endpoints.append(url)

    xml_endpoints = list(set(xml_endpoints))[:15]

    for url in xml_endpoints:
        host = _extract_host(url)

        for xxe in XXE_PAYLOADS:
            body = _post_xml(url, xxe["payload"])
            if body and xxe["indicator"] and xxe["indicator"] in body:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"XXE — {xxe['name']} ({host})",
                    "template_id": "pentest-xxe",
                    "severity":    "critical",
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "category":    "injection",
                    "owasp_web":   "A05:2021",
                    "mitre_technique": "T1190",
                    "host":        host,
                    "url":         url,
                    "description": f"XML External Entity injection: {xxe['name']}.",
                    "evidence":    f"Payload: {xxe['payload'][:200]}\nResponse indicator: {xxe['indicator']}",
                    "impact":      "File read, SSRF, denial of service, potentially remote code execution.",
                    "remediation": "Disable DTD processing. Disable external entities in XML parser. Use JSON instead of XML.",
                    "confidence":  93,
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"CRITICAL: XXE — {xxe['name']} on {host}", "finding")
                break

    status(f"XXE: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Command Injection
# ═══════════════════════════════════════════════════════════════════════

def _test_cmdi(urls: list, scan_id: str, db: FindingsDB,
               waf_map: dict) -> int:
    """Test for OS command injection."""
    status("Command injection testing...", "run")
    count = 0

    param_urls = [u for u in urls if "?" in u and "=" in u][:15]

    for url in param_urls:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            for payload in CMDI_PAYLOADS[:6]:  # top 6 payloads
                variants = evade_for_host(payload, host, waf_map)

                for variant in variants[:2]:
                    test_url = _inject_param(url, param_name, variant)
                    body = _fetch(test_url)

                    if body and any(ind in body for ind in CMDI_INDICATORS):
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Command Injection — {param_name} ({host})",
                            "template_id": "pentest-cmdi",
                            "severity":    "critical",
                            "cvss_score":  9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category":    "injection",
                            "owasp_web":   "A03:2021",
                            "mitre_technique": "T1059",
                            "host":        host,
                            "url":         url,
                            "parameter":   param_name,
                            "description": f"OS command injection in parameter '{param_name}'.",
                            "evidence":    f"Payload: {payload}\nResponse indicates command execution.",
                            "poc_command": f"curl '{test_url}'",
                            "impact":      "Full system compromise. Attacker can execute arbitrary commands.",
                            "remediation": "Never pass user input to shell commands. Use safe APIs. Validate and whitelist input.",
                            "confidence":  95,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"CRITICAL: CMDi in {param_name} — {host}", "finding")
                        break
                    break

    status(f"CMDi: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Path Traversal — ffuf
# ═══════════════════════════════════════════════════════════════════════

def _run_ffuf_traversal(urls: list, pentest_dir: Path,
                        scan_id: str, db: FindingsDB) -> int:
    """Path traversal via ffuf with traversal wordlist."""
    status("Path traversal testing (ffuf)...", "run")
    count = 0

    # Build traversal wordlist
    wordlist = pentest_dir / "traversal_payloads.txt"
    wordlist.write_text("\n".join(PATH_TRAVERSAL_PAYLOADS) + "\n")

    param_urls = [u for u in urls if "?" in u and "=" in u][:10]

    for url in param_urls:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            fuzz_url = _inject_param(url, param_name, "FUZZ")
            output   = str(pentest_dir / f"ffuf_traversal_{_safe_filename(host)}.json")

            rc, stdout, stderr = run_cmd(
                [
                    "ffuf",
                    "-u", fuzz_url,
                    "-w", str(wordlist),
                    "-mc", "200",
                    "-mr", "root:.*:0:0",   # match /etc/passwd content
                    "-o", output,
                    "-of", "json",
                    "-t", "5",
                    "-timeout", "10",
                    "-s",
                ],
                silent=True, timeout=120,
            )

            if Path(output).exists():
                try:
                    data = json.loads(Path(output).read_text())
                    for result in data.get("results", []):
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Path Traversal — {param_name} ({host})",
                            "template_id": "pentest-path-traversal",
                            "severity":    "high",
                            "cvss_score":  7.5,
                            "category":    "injection",
                            "owasp_web":   "A01:2021",
                            "mitre_technique": "T1005",
                            "host":        host,
                            "url":         url,
                            "parameter":   param_name,
                            "description": f"Path traversal in parameter '{param_name}' allows reading arbitrary files.",
                            "evidence":    f"Payload: {result.get('input', {}).get('FUZZ', '?')}\nStatus: {result.get('status', '?')}",
                            "poc_command": f"ffuf -u '{fuzz_url}' -w traversal.txt -mc 200",
                            "impact":      "Read sensitive files: /etc/passwd, config files, source code.",
                            "remediation": "Validate file paths. Use chroot or jail. Never use raw user input in file operations.",
                            "confidence":  88,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)
                            status(f"HIGH: Path traversal — {param_name} on {host}", "finding")
                except json.JSONDecodeError:
                    pass

    status(f"Path traversal: {count} findings", "ok" if not count else "warn")
    return count


def _custom_path_traversal(urls: list, scan_id: str, db: FindingsDB,
                           waf_map: dict) -> int:
    """Fallback path traversal check without ffuf."""
    count = 0
    param_urls = [u for u in urls if "?" in u and "=" in u][:10]

    for url in param_urls:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:5]:
                test_url = _inject_param(url, param_name, payload)
                body = _fetch(test_url)
                if body and any(ind in body for ind in PATH_INDICATORS):
                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"Path Traversal — {param_name} ({host})",
                        "template_id": "pentest-path-traversal",
                        "severity":    "high",
                        "cvss_score":  7.5,
                        "category":    "injection",
                        "owasp_web":   "A01:2021",
                        "host":        host,
                        "url":         url,
                        "parameter":   param_name,
                        "description": f"Path traversal in '{param_name}' confirmed.",
                        "evidence":    f"Payload: {payload}\nIndicator found in response.",
                        "impact":      "Arbitrary file read.",
                        "remediation": "Validate file paths. Deny directory traversal characters.",
                        "confidence":  85,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        count += 1
                        notify_finding(finding)
                    break
    return count


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return url


def _safe_filename(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)[:60]


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a query parameter value in a URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _fetch(url: str, timeout: int = 10) -> str:
    """Fetch URL content. Returns empty string on error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _post_xml(url: str, xml_body: str, timeout: int = 10) -> str:
    """POST XML payload. Returns response body or empty string."""
    try:
        data = xml_body.encode("utf-8")
        req  = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Content-Type": "application/xml",
                "User-Agent":   "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="ignore")
    except Exception:
        return ""
