"""Protection-to-bypass checklist: map detected protections to the checks worth trying next.

Detection reads only the headers and status code of a response that a normal request already
returns. It sends no probe traffic of its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

# protection id -> (label, checks to try, in order)
PROTECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "waf": (
        "Web application firewall",
        (
            "Vary the payload encoding (URL, double URL, Unicode normalisation)",
            "Move the payload to a header or JSON body that the WAF rule may not inspect",
            "Check whether the origin is reachable directly, bypassing the WAF",
        ),
    ),
    "csp": (
        "Content Security Policy",
        (
            "Look for allow-listed hosts that serve JSONP or user-uploaded scripts",
            "Check for base-uri or object-src gaps",
            "Look for nonce reuse across responses",
        ),
    ),
    "cors": (
        "Cross-origin resource sharing",
        (
            "Test reflected Origin values and the null origin",
            "Check subdomain and suffix matching on the allow-list",
            "Check whether credentials are allowed for the reflected origin",
        ),
    ),
    "rate_limit": (
        "Rate limit or lockout",
        (
            "Compare responses when client-identifying headers (X-Forwarded-For) change",
            "Check whether the limit applies per endpoint or per account",
            "Check alternate routes (older API version, mobile endpoint) for the same action",
        ),
    ),
    "frame_protection": (
        "Clickjacking protection",
        (
            "Check whether X-Frame-Options is set on every route, not only the main page",
            "Check frame-ancestors coverage in the CSP",
        ),
    ),
}


@dataclass(frozen=True)
class ChecklistItem:
    protection: str
    label: str
    check: str


def detect_protections(headers: Mapping[str, str], status_code: int | None = None) -> list[str]:
    """Return the protection ids visible in one normal response."""
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "").lower()
    found: list[str] = []
    if any(k in h for k in ("cf-ray", "x-sucuri-id", "x-akamai-transformed")) or any(
        s in server for s in ("cloudflare", "akamai", "mod_security", "barracuda")
    ):
        found.append("waf")
    if "content-security-policy" in h or "content-security-policy-report-only" in h:
        found.append("csp")
    if "access-control-allow-origin" in h:
        found.append("cors")
    if status_code == 429 or "retry-after" in h or "x-ratelimit-limit" in h:
        found.append("rate_limit")
    if "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""):
        found.append("frame_protection")
    return found


def checklist_for(protections: list[str]) -> list[ChecklistItem]:
    """Expand detected protection ids into an ordered, de-duplicated checklist."""
    items: list[ChecklistItem] = []
    for pid in dict.fromkeys(protections):
        if pid not in PROTECTIONS:
            continue
        label, checks = PROTECTIONS[pid]
        items.extend(ChecklistItem(pid, label, check) for check in checks)
    return items
