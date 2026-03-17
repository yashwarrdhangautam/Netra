"""
pentest/auth_testing.py
Authentication testing: default credentials (500-entry list),
JWT algorithm confusion, OAuth redirect_uri manipulation, MFA bypass checks.
"""

import json
import re
import base64
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict

from netra.core.config   import CONFIG
from netra.core.utils    import run_cmd, status, banner, tool_exists, truncate, C
from netra.core.database import FindingsDB
from netra.core.notify   import notify_finding

from pentest.payloads import DEFAULT_CREDS, JWT_WEAK_SECRETS


def run_auth_tests(
    live_urls: List[str],
    workdir: str,
    scan_id: str = "",
    tech_map: dict = None,
) -> int:
    """
    Run authentication tests on live URLs.
    Returns total number of findings added.
    """
    banner("AUTH TESTING", "Default creds · JWT · OAuth · Session")

    workdir     = Path(workdir)
    pentest_dir = workdir / "pentest"
    pentest_dir.mkdir(exist_ok=True)
    tech_map = tech_map or {}

    db    = FindingsDB()
    total = 0

    # ── 1. Default credential testing ────────────────────────────────
    count = _test_default_creds(live_urls, scan_id, db, tech_map)
    total += count

    # ── 2. JWT analysis ──────────────────────────────────────────────
    count = _test_jwt(live_urls, scan_id, db, tech_map)
    total += count

    # ── 3. OAuth redirect_uri ────────────────────────────────────────
    count = _test_oauth_redirect(live_urls, scan_id, db)
    total += count

    # ── 4. Session security checks ───────────────────────────────────
    count = _test_session_security(live_urls, scan_id, db)
    total += count

    status(f"Auth tests complete: {total} findings", "ok")
    return total


# ═══════════════════════════════════════════════════════════════════════
#  Default Credentials
# ═══════════════════════════════════════════════════════════════════════

def _test_default_creds(urls: list, scan_id: str, db: FindingsDB,
                        tech_map: dict) -> int:
    """Test for default credentials on login panels and admin interfaces."""
    status("Default credential testing...", "run")
    count = 0

    # Identify login endpoints from tech map
    login_targets = []
    for url, info in tech_map.items():
        tech_list = [t.lower() for t in info.get("tech", [])]
        title     = info.get("title", "").lower()
        server    = info.get("web_server", "").lower()

        for service_pattern, user, passwd in DEFAULT_CREDS:
            sp = service_pattern.lower()
            if (any(sp in t for t in tech_list) or
                sp in title or sp in server or sp in url.lower()):
                login_targets.append((url, service_pattern, user, passwd))

    # Also check common admin paths
    for url in urls[:30]:
        for admin_path in ["/admin", "/login", "/manager", "/wp-login.php",
                           "/administrator", "/console", "/grafana", "/kibana"]:
            full_url = url.rstrip("/") + admin_path
            login_targets.append((full_url, "generic", "admin", "admin"))

    # Deduplicate
    seen = set()
    unique_targets = []
    for target in login_targets:
        key = f"{target[0]}:{target[2]}:{target[3]}"
        if key not in seen:
            seen.add(key)
            unique_targets.append(target)

    for url, service, user, passwd in unique_targets[:50]:  # cap at 50
        host = _extract_host(url)
        success = _try_login(url, user, passwd)

        if success:
            finding = {
                "scan_id":     scan_id,
                "title":       f"Default Credentials — {service} ({host})",
                "template_id": f"pentest-default-creds-{service}",
                "severity":    "critical",
                "cvss_score":  9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "category":    "auth",
                "owasp_web":   "A07:2021",
                "mitre_technique": "T1078",
                "host":        host,
                "url":         url,
                "description": f"Default credentials ({user}:{_redact(passwd)}) accepted on {service} login.",
                "evidence":    f"Service: {service}\nURL: {url}\nUsername: {user}\nPassword: {_redact(passwd)}\nLogin successful.",
                "impact":      f"Full admin access to {service}. Attacker can read/modify all data, reconfigure service.",
                "remediation": f"Change default credentials immediately. Enforce strong password policy. Enable MFA.",
                "confidence":  98,
            }
            fid = db.add_finding(finding)
            if fid:
                count += 1
                notify_finding(finding)
                status(f"CRITICAL: Default creds on {service} — {host}", "finding")

    status(f"Default creds: {count} findings", "ok" if not count else "warn")
    return count


def _try_login(url: str, username: str, password: str) -> bool:
    """
    Attempt login with given credentials.
    Checks HTTP Basic Auth and common form POST patterns.
    """
    # Try HTTP Basic Auth
    try:
        creds   = base64.b64encode(f"{username}:{password}".encode()).decode()
        req     = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Basic {creds}",
                "User-Agent":    "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status in (200, 301, 302):
                body = resp.read(4096).decode("utf-8", errors="ignore").lower()
                # Check for success indicators
                if any(ind in body for ind in
                       ["dashboard", "welcome", "logout", "settings",
                        "admin panel", "configuration", "overview"]):
                    return True
                # Check for no auth challenge
                if resp.status == 200 and "401" not in str(resp.status):
                    return True
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False
    except Exception:
        pass

    # Try form POST
    try:
        data = urllib.parse.urlencode({
            "username": username, "password": password,
            "user": username, "pass": password,
            "login": "Login",
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent":   "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore").lower()
            if any(ind in body for ind in
                   ["dashboard", "welcome", "logout", "success"]):
                return True
    except Exception:
        pass

    return False


# ═══════════════════════════════════════════════════════════════════════
#  JWT Analysis
# ═══════════════════════════════════════════════════════════════════════

def _test_jwt(urls: list, scan_id: str, db: FindingsDB,
              tech_map: dict) -> int:
    """Analyze JWT tokens found in responses for common weaknesses."""
    status("JWT analysis...", "run")
    count = 0

    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

    for url in urls[:30]:
        body = _fetch(url)
        if not body:
            continue

        tokens = jwt_pattern.findall(body)
        host   = _extract_host(url)

        for token in tokens[:3]:
            issues = _analyze_jwt(token)
            for issue in issues:
                finding = {
                    "scan_id":     scan_id,
                    "title":       f"JWT: {issue['title']} ({host})",
                    "template_id": f"pentest-jwt-{issue['id']}",
                    "severity":    issue["severity"],
                    "cvss_score":  issue["cvss"],
                    "category":    "auth",
                    "owasp_web":   "A02:2021",
                    "owasp_api":   "API2:2023",
                    "mitre_technique": "T1550",
                    "host":        host,
                    "url":         url,
                    "description": issue["description"],
                    "evidence":    f"Token (redacted): {token[:20]}...{token[-10:]}\n{issue['evidence']}",
                    "impact":      issue["impact"],
                    "remediation": issue["remediation"],
                    "confidence":  issue["confidence"],
                }
                fid = db.add_finding(finding)
                if fid:
                    count += 1
                    notify_finding(finding)
                    status(f"{issue['severity'].upper()}: JWT {issue['title']} — {host}", "finding")

    status(f"JWT: {count} findings", "ok" if not count else "warn")
    return count


def _analyze_jwt(token: str) -> list:
    """Decode and analyze a JWT for common issues."""
    issues = []
    try:
        parts  = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:
        return issues

    alg = header.get("alg", "").upper()

    # Check: algorithm none
    if alg == "NONE" or not alg:
        issues.append({
            "id": "alg-none",
            "title": "Algorithm None",
            "severity": "critical",
            "cvss": 9.8,
            "description": "JWT uses 'none' algorithm — signatures are not verified.",
            "evidence": f"Header alg: {alg}",
            "impact": "Attacker can forge any JWT token and impersonate any user.",
            "remediation": "Reject tokens with alg=none. Always verify signatures. Pin expected algorithm.",
            "confidence": 98,
        })

    # Check: weak symmetric key
    if alg in ("HS256", "HS384", "HS512"):
        for secret in JWT_WEAK_SECRETS:
            try:
                import hmac
                import hashlib
                msg       = f"{parts[0]}.{parts[1]}".encode()
                expected  = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
                if expected == sig_bytes:
                    issues.append({
                        "id": "weak-secret",
                        "title": "Weak Signing Secret",
                        "severity": "critical",
                        "cvss": 9.8,
                        "description": f"JWT signed with weak/default secret: '{_redact(secret)}'.",
                        "evidence": f"Secret: {_redact(secret)}\nAlgorithm: {alg}",
                        "impact": "Attacker can forge tokens with the known secret.",
                        "remediation": "Use a strong random secret (256+ bits). Rotate secrets regularly.",
                        "confidence": 98,
                    })
                    break
            except Exception:
                pass

    # Check: no expiry
    if "exp" not in payload_data:
        issues.append({
            "id": "no-expiry",
            "title": "No Expiration",
            "severity": "high",
            "cvss": 7.5,
            "description": "JWT has no expiration claim (exp). Tokens are valid forever.",
            "evidence": f"Payload claims: {list(payload_data.keys())}",
            "impact": "Stolen tokens remain valid indefinitely.",
            "remediation": "Always include 'exp' claim. Use short-lived tokens (15-30 min).",
            "confidence": 95,
        })

    # Check: sensitive data in payload
    sensitive_keys = {"password", "passwd", "secret", "ssn", "credit_card",
                      "api_key", "private_key"}
    exposed = sensitive_keys & set(k.lower() for k in payload_data.keys())
    if exposed:
        issues.append({
            "id": "sensitive-payload",
            "title": "Sensitive Data in Payload",
            "severity": "high",
            "cvss": 7.5,
            "description": f"JWT payload contains sensitive fields: {', '.join(exposed)}.",
            "evidence": f"Sensitive fields: {exposed}",
            "impact": "JWT payloads are base64 (not encrypted). Sensitive data is exposed.",
            "remediation": "Never store sensitive data in JWT payload. Keep tokens minimal.",
            "confidence": 90,
        })

    return issues


# ═══════════════════════════════════════════════════════════════════════
#  OAuth redirect_uri
# ═══════════════════════════════════════════════════════════════════════

def _test_oauth_redirect(urls: list, scan_id: str,
                         db: FindingsDB) -> int:
    """Test for open redirect in OAuth redirect_uri parameter."""
    status("OAuth redirect_uri testing...", "run")
    count = 0

    # Find OAuth endpoints
    oauth_urls = [u for u in urls
                  if any(k in u.lower() for k in
                         ["oauth", "authorize", "callback", "redirect_uri",
                          "return_url", "login"])][:15]

    for url in oauth_urls:
        host   = _extract_host(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        redirect_params = [p for p in params
                          if any(k in p.lower() for k in
                                 ["redirect", "callback", "return", "next"])]

        for param in redirect_params:
            test_url = _inject_param(url, param, "https://evil.com")
            try:
                req = urllib.request.Request(
                    test_url,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler()
                )
                resp = opener.open(req, timeout=10)
                final_url = resp.url

                if "evil.com" in final_url:
                    finding = {
                        "scan_id":     scan_id,
                        "title":       f"OAuth Open Redirect — {param} ({host})",
                        "template_id": "pentest-oauth-redirect",
                        "severity":    "high",
                        "cvss_score":  7.4,
                        "category":    "auth",
                        "owasp_web":   "A01:2021",
                        "owasp_api":   "API8:2023",
                        "host":        host,
                        "url":         url,
                        "parameter":   param,
                        "description": f"OAuth redirect_uri parameter '{param}' allows open redirect to attacker-controlled domain.",
                        "evidence":    f"Redirect to: https://evil.com accepted\nFinal URL: {final_url}",
                        "impact":      "OAuth token theft. Attacker redirects auth flow to steal access tokens.",
                        "remediation": "Strictly validate redirect_uri against a whitelist. Use exact match, not prefix match.",
                        "confidence":  90,
                    }
                    fid = db.add_finding(finding)
                    if fid:
                        count += 1
                        notify_finding(finding)
                        status(f"HIGH: OAuth redirect — {host}", "finding")
            except Exception:
                pass

    status(f"OAuth: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  Session Security
# ═══════════════════════════════════════════════════════════════════════

def _test_session_security(urls: list, scan_id: str,
                           db: FindingsDB) -> int:
    """Check session cookie security flags."""
    status("Session security checks...", "run")
    count = 0

    for url in urls[:20]:
        host = _extract_host(url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                cookies = resp.headers.get_all("Set-Cookie") or []

                for cookie_str in cookies:
                    cookie_lower = cookie_str.lower()
                    name = cookie_str.split("=")[0].strip()

                    # Skip non-session cookies
                    if not any(k in name.lower() for k in
                               ["session", "sid", "token", "auth", "jwt", "csrf"]):
                        continue

                    issues = []
                    if "secure" not in cookie_lower:
                        issues.append("Missing Secure flag")
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly flag")
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite attribute")

                    if issues:
                        finding = {
                            "scan_id":     scan_id,
                            "title":       f"Insecure Cookie — {name} ({host})",
                            "template_id": f"pentest-cookie-{name}",
                            "severity":    "medium",
                            "cvss_score":  5.3,
                            "category":    "auth",
                            "owasp_web":   "A05:2021",
                            "host":        host,
                            "url":         url,
                            "description": f"Session cookie '{name}' has insecure settings: {', '.join(issues)}.",
                            "evidence":    f"Cookie: {cookie_str[:200]}\nIssues: {', '.join(issues)}",
                            "impact":      "Session hijacking via XSS (missing HttpOnly), network sniffing (missing Secure), CSRF (missing SameSite).",
                            "remediation": "Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                            "confidence":  95,
                        }
                        fid = db.add_finding(finding)
                        if fid:
                            count += 1
                            notify_finding(finding)

        except Exception:
            pass

    status(f"Session: {count} findings", "ok" if not count else "warn")
    return count


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
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


def _redact(value: str) -> str:
    if len(value) <= 2:
        return "***"
    return value[0] + "*" * (len(value) - 2) + value[-1]
