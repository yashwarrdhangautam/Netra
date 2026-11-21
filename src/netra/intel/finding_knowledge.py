"""Reviewed explanations for common observation types (security headers, disclosure, email).

Each entry explains what a check means, why it matters, when it is a false positive and how
to fix it. Entries never add a CVE, never raise the tool's severity and never claim
exploitation: a missing header is a hardening gap, not proof of an attack path. Mappings use
OWASP Top 10:2025 and CWE ids that describe the weakness class, and are left empty when no
mapping is accurate. Findings no entry matches get no generated text; the UI says so.
"""

from __future__ import annotations

import re
from typing import Any

OWASP_TOP10_2025 = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging and Alerting Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
}

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

KNOWLEDGE: dict[str, dict[str, Any]] = {
    "header:strict-transport-security": {
        "title": "Strict-Transport-Security (HSTS) not set",
        "category": "Security headers",
        "purpose": (
            "HSTS tells browsers to use HTTPS only for this host for a set period, so later "
            "visits cannot be downgraded to plain HTTP."
        ),
        "impact": (
            "Without it, a user who types the address or follows an http:// link makes a first "
            "request in cleartext. An attacker on the same network can intercept that request "
            "(SSL stripping) and keep the user on HTTP."
        ),
        "conditions": "Attacker position on the user's network path (public Wi-Fi, rogue AP).",
        "false_positive": (
            "Browsers ignore HSTS on plain-HTTP responses, so its absence on an http:// "
            "response is expected. It matters on the HTTPS response. Also check whether a CDN "
            "or load balancer adds it on other paths."
        ),
        "remediation": (
            "Send on every HTTPS response: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains (add preload only after confirming every subdomain serves HTTPS)."
            ' nginx: add_header Strict-Transport-Security "max-age=31536000; '
            'includeSubDomains" always;'
        ),
        "retest": "curl -sI https://HOST/ | grep -i strict-transport-security",
        "cwe": "CWE-319",
        "owasp": ["A02", "A04"],
        "references": [_MDN + "Strict-Transport-Security", _OWASP_HEADERS],
    },
    "header:content-security-policy": {
        "title": "Content-Security-Policy (CSP) not set",
        "category": "Security headers",
        "purpose": (
            "CSP limits which sources may supply scripts, styles, frames and other content, "
            "so an injected script cannot load or run."
        ),
        "impact": (
            "No direct vulnerability. If the application has a cross-site scripting flaw, "
            "there is no browser-side control to contain it."
        ),
        "conditions": "Only matters if an injection (XSS) flaw exists elsewhere.",
        "false_positive": (
            "Some sites set CSP in a <meta> tag or only on HTML pages; check the main "
            "application pages, not only redirects or static files."
        ),
        "remediation": (
            "Start with Content-Security-Policy-Report-Only to collect violations, then enforce "
            "a policy such as default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'self'. Next.js: set it in next.config headers() or middleware, "
            "using nonces for inline scripts."
        ),
        "retest": "curl -sI https://HOST/ | grep -i content-security-policy",
        "cwe": "CWE-693",
        "owasp": ["A02"],
        "references": [_MDN + "Content-Security-Policy", _OWASP_HEADERS],
    },
    "header:x-frame-options": {
        "title": "Framing protection (X-Frame-Options / CSP frame-ancestors) not set",
        "category": "Security headers",
        "purpose": "Stops other sites from loading this site's pages in a frame.",
        "impact": (
            "Pages can be framed by another site, which enables clickjacking: tricking a user "
            "into clicking a hidden control. Impact depends on whether the framed pages have "
            "state-changing actions for a signed-in user."
        ),
        "conditions": "A page with a sensitive one-click action and a signed-in victim.",
        "false_positive": (
            "CSP frame-ancestors supersedes X-Frame-Options; if frame-ancestors is set, a "
            "missing X-Frame-Options is not a gap. Purely static marketing pages carry little risk."
        ),
        "remediation": (
            "Set Content-Security-Policy: frame-ancestors 'self' (preferred), and "
            "X-Frame-Options: SAMEORIGIN for older browsers."
        ),
        "retest": "curl -sI https://HOST/ | grep -iE 'x-frame-options|frame-ancestors'",
        "cwe": "CWE-1021",
        "owasp": ["A02"],
        "references": [_MDN + "X-Frame-Options", _OWASP_HEADERS],
    },
    "header:x-content-type-options": {
        "title": "X-Content-Type-Options not set",
        "category": "Security headers",
        "purpose": (
            "X-Content-Type-Options: nosniff tells browsers to trust the declared Content-Type "
            "and not guess (MIME-sniff) the type from the content."
        ),
        "impact": (
            "Without it, a browser may treat a file served as text or image as script or HTML. "
            "This matters mainly where users can upload or influence content the site serves; "
            "on its own it is a low-severity hardening gap."
        ),
        "conditions": "User-influenced content served from the same origin.",
        "false_positive": (
            "Modern browsers already block some sniffing cases, but the header is still the "
            "standard control. Check that it is missing on application responses, not only "
            "on one redirect."
        ),
        "remediation": (
            "Send X-Content-Type-Options: nosniff on all responses and make sure every response "
            "has a correct Content-Type. nginx: add_header X-Content-Type-Options nosniff always;"
        ),
        "retest": "curl -sI https://HOST/ | grep -i x-content-type-options",
        "cwe": "CWE-693",
        "owasp": ["A02"],
        "references": [_MDN + "X-Content-Type-Options", _OWASP_HEADERS],
    },
    "header:referrer-policy": {
        "title": "Referrer-Policy not set",
        "category": "Security headers",
        "purpose": "Controls how much of the current URL is sent in the Referer header.",
        "impact": (
            "Full URLs, including any tokens or identifiers in paths or query strings, can be "
            "sent to third-party sites the page links to or loads from. Current browsers default "
            "to strict-origin-when-cross-origin, which limits this."
        ),
        "conditions": "Sensitive data in URLs and links or resources on other origins.",
        "false_positive": "Low risk when URLs carry no sensitive data.",
        "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        "retest": "curl -sI https://HOST/ | grep -i referrer-policy",
        "cwe": "CWE-200",
        "owasp": ["A02"],
        "references": [_MDN + "Referrer-Policy"],
    },
    "header:permissions-policy": {
        "title": "Permissions-Policy not set",
        "category": "Security headers",
        "purpose": (
            "Restricts which browser features (camera, microphone, geolocation, etc.) the "
            "page and its embedded frames may use."
        ),
        "impact": "Defence in depth only; no direct exposure on its own.",
        "conditions": "Embedded third-party content or a script injection elsewhere.",
        "false_positive": "Optional hardening; many sites omit it without risk.",
        "remediation": "Send e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "retest": "curl -sI https://HOST/ | grep -i permissions-policy",
        "cwe": "CWE-693",
        "owasp": ["A02"],
        "references": [_MDN + "Permissions-Policy"],
    },
    "disclosure:server-version": {
        "title": "Server software and version disclosed",
        "category": "Information disclosure",
        "purpose": "Response headers such as Server or X-Powered-By name the software in use.",
        "impact": (
            "Helps an attacker pick known vulnerabilities for that exact version. It is not a "
            "vulnerability by itself."
        ),
        "conditions": "A known vulnerability in the disclosed version.",
        "false_positive": "Hiding the banner does not fix an outdated version; patching does.",
        "remediation": (
            "nginx: server_tokens off; Next.js: poweredByHeader: false in next.config. Keep "
            "the software patched regardless."
        ),
        "retest": "curl -sI https://HOST/ | grep -iE '^server:|x-powered-by'",
        "cwe": "CWE-200",
        "owasp": ["A02"],
        "references": [_OWASP_HEADERS],
    },
    "component:outdated": {
        "title": "Software version reported as outdated",
        "category": "Vulnerable and outdated components",
        "purpose": (
            "The scanner compared the version string the server reports with the latest "
            "version it knows of."
        ),
        "impact": (
            "Older versions may lack security fixes. This check does not prove a specific "
            "vulnerability: it is based on the banner only, and distributions often backport "
            "fixes without changing the version string."
        ),
        "conditions": "A published vulnerability affecting the running version and its config.",
        "false_positive": (
            "Backported patches, a different real version behind a proxy, or a scanner "
            "database that is itself out of date."
        ),
        "remediation": (
            "Confirm the running version, check the vendor's security advisories for it, and "
            "upgrade to a supported release."
        ),
        "retest": "Compare the Server header and package version after upgrading.",
        "cwe": "CWE-1104",
        "owasp": ["A03"],
        "references": ["https://nginx.org/en/security_advisories.html"],
    },
    "email:dmarc-none": {
        "title": "DMARC policy is monitor-only (p=none)",
        "category": "Email security (outside OWASP Top 10)",
        "purpose": "DMARC tells receivers what to do with mail that fails SPF/DKIM alignment.",
        "impact": (
            "With p=none, receivers deliver mail that spoofs the domain, which makes phishing "
            "in the organisation's name easier."
        ),
        "conditions": "An attacker sending mail with the domain in the From address.",
        "false_positive": "p=none is normal during a monitored rollout; check the rua reports.",
        "remediation": "Review DMARC aggregate reports, then move to p=quarantine and p=reject.",
        "retest": "dig +short TXT _dmarc.DOMAIN",
        "cwe": None,
        "owasp": [],
        "references": ["https://www.rfc-editor.org/rfc/rfc7489"],
    },
    "email:spf-softfail": {
        "title": "SPF uses soft fail (~all)",
        "category": "Email security (outside OWASP Top 10)",
        "purpose": "SPF lists the servers allowed to send mail for the domain.",
        "impact": (
            "~all asks receivers to accept but mark unauthorised mail, so spoofed mail is "
            "often still delivered, especially without an enforcing DMARC policy."
        ),
        "conditions": "Spoofed mail and no enforcing DMARC policy.",
        "false_positive": "With DMARC at p=reject, ~all is common and acceptable.",
        "remediation": "Enforce DMARC (preferred), or use -all once all senders are listed.",
        "retest": "dig +short TXT DOMAIN | grep spf",
        "cwe": None,
        "owasp": [],
        "references": ["https://www.rfc-editor.org/rfc/rfc7208"],
    },
    "dns:no-caa": {
        "title": "No CAA record",
        "category": "DNS hardening (outside OWASP Top 10)",
        "purpose": "CAA lists the certificate authorities allowed to issue certificates.",
        "impact": "Any public CA may issue for the domain. Defence in depth only.",
        "conditions": "A CA mis-issuing a certificate to an attacker.",
        "false_positive": "Informational; many domains have no CAA record.",
        "remediation": 'Add e.g. DOMAIN. CAA 0 issue "letsencrypt.org" for the CAs you use.',
        "retest": "dig +short CAA DOMAIN",
        "cwe": None,
        "owasp": [],
        "references": ["https://www.rfc-editor.org/rfc/rfc8659"],
    },
    "inventory:discovery": {
        "title": "Inventory observation (not a vulnerability)",
        "category": "Asset and technology inventory",
        "purpose": (
            "Detection checks record what is present (technology, robots.txt, sitemap, "
            "well-known files, e-mail addresses) to build the asset inventory."
        ),
        "impact": "None by itself. Useful context for other findings and for review.",
        "conditions": "n/a",
        "false_positive": "n/a",
        "remediation": "No action needed unless the content exposes something sensitive.",
        "retest": "n/a",
        "cwe": None,
        "owasp": [],
        "references": [],
    },
}

_HEADERS = {
    "strict-transport-security": "header:strict-transport-security",
    "content-security-policy": "header:content-security-policy",
    "x-frame-options": "header:x-frame-options",
    "x-content-type-options": "header:x-content-type-options",
    "referrer-policy": "header:referrer-policy",
    "permissions-policy": "header:permissions-policy",
}

_INVENTORY = re.compile(
    r"detect|fingerprint|wappalyzer|extractor|sitemap|robots|security\.txt|asset links|"
    r"app links|uncommon header|link header|x-powered-by header|carddav|deprecated",
    re.IGNORECASE,
)


def knowledge_keys(title: str, evidence: Any, tool: str = "") -> list[str]:
    """Knowledge entries that apply to one finding, most specific first."""
    text = (title or "").lower()
    keys: list[str] = []
    headers: list[str] = []
    if isinstance(evidence, dict) and isinstance(evidence.get("missing"), list):
        headers += [str(h).lower() for h in evidence["missing"]]
    if "header" in text and ("missing" in text or "not set" in text):
        headers += [h for h in _HEADERS if h in text]
    if "x-content-type-options header is not set" in text:
        headers.append("x-content-type-options")
    for header in headers:
        key = _HEADERS.get(header)
        if key and key not in keys:
            keys.append(key)
    if "outdated" in text:
        keys.append("component:outdated")
    if "technology disclosed" in text or "server banner" in text:
        keys.append("disclosure:server-version")
    if "dmarc" in text and "p=none" in text:
        keys.append("email:dmarc-none")
    if "spf" in text and "~all" in text:
        keys.append("email:spf-softfail")
    if "caa" in text:
        keys.append("dns:no-caa")
    if not keys and _INVENTORY.search(text):
        keys.append("inventory:discovery")
    return keys


def knowledge_for(title: str, evidence: Any, tool: str = "") -> list[dict[str, Any]]:
    """Explanations for a finding, with OWASP ids expanded to their names."""
    out = []
    for key in knowledge_keys(title, evidence, tool):
        entry = dict(KNOWLEDGE[key])
        entry["key"] = key
        entry["owasp"] = [OWASP_TOP10_2025[c] for c in entry.get("owasp") or []]
        out.append(entry)
    return out
