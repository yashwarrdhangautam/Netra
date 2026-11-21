"""OWASP Top 10:2025 coverage for one scan, from the tool runs that actually happened.

A category is only "tested" when the checks NETRA has for it ran to completion on every host
they were meant for. Running a scanner never counts as covering a category by itself, and
categories NETRA cannot assess from outside without credentials or a human are labelled so.

States: tested, partially_tested, not_tested, requires_credentials, requires_manual_review,
failed_interrupted.
"""

from __future__ import annotations

from typing import Any

from netra.intel.finding_knowledge import KNOWLEDGE, OWASP_TOP10_2025, knowledge_keys

# CWE -> OWASP Top 10:2025 for the CWEs NETRA's own checks emit. Unlisted CWEs are not mapped.
CWE_TO_OWASP = {
    "CWE-16": "A02",
    "CWE-200": "A02",
    "CWE-693": "A02",
    "CWE-1021": "A02",
    "CWE-319": "A04",
    "CWE-326": "A04",
    "CWE-327": "A04",
    "CWE-295": "A04",
    "CWE-1104": "A03",
    "CWE-937": "A03",
    "CWE-79": "A05",
    "CWE-89": "A05",
    "CWE-22": "A01",
    "CWE-284": "A01",
    "CWE-918": "A01",
    "CWE-287": "A07",
    "CWE-209": "A10",
}

# What NETRA can do per category, which tools carry it, and the limits that always apply.
CATEGORIES: dict[str, dict[str, Any]] = {
    "A01": {
        "tools": ["nuclei"],
        "kind": "credentials",
        "checks": "Nuclei exposure templates look for a few unauthenticated admin panels and "
        "files.",
        "limits": "Access control needs authenticated testing with at least two roles and "
        "manual review (IDOR, privilege escalation). NETRA does not run authenticated scans.",
    },
    "A02": {
        "tools": ["httpx", "nuclei", "nikto"],
        "kind": "automated",
        "checks": "Security headers and banners (httpx analysis), nuclei misconfiguration and "
        "exposure templates, nikto server checks.",
        "limits": "Only externally visible configuration on the scanned hosts and paths.",
    },
    "A03": {
        "tools": ["nuclei", "nikto"],
        "kind": "automated",
        "checks": "Version banners compared with known releases (nikto), nuclei CVE templates "
        "for detected products.",
        "limits": "Banner-based only; no dependency or SBOM analysis of the application.",
        "partial_only": True,
    },
    "A04": {
        "tools": ["tls_probe", "httpx"],
        "kind": "automated",
        "checks": "TLS protocol and certificate probe, HSTS header.",
        "limits": "Transport only; storage and in-application cryptography are not visible.",
        "partial_only": True,
    },
    "A05": {
        "tools": ["sqlmap", "dalfox", "nuclei"],
        "kind": "active",
        "checks": "SQL injection (sqlmap) and XSS (dalfox) need active testing; nuclei has a "
        "few passive injection-indicator templates.",
        "limits": "Requires active_test in the signed authorization, and discovered "
        "parameters. Not a complete injection assessment.",
    },
    "A06": {
        "tools": [],
        "kind": "manual",
        "checks": "None automated.",
        "limits": "Insecure design is assessed by threat modelling and design review.",
    },
    "A07": {
        "tools": [],
        "kind": "credentials",
        "checks": "None automated.",
        "limits": "Needs authenticated testing of login, session and recovery flows.",
    },
    "A08": {
        "tools": [],
        "kind": "manual",
        "checks": "None automated (subresource integrity and update pipelines not checked).",
        "limits": "Needs review of build, update and deserialisation paths.",
    },
    "A09": {
        "tools": [],
        "kind": "manual",
        "checks": "None: logging and alerting are not observable from outside.",
        "limits": "Ask the owner for detection evidence for the test window.",
    },
    "A10": {
        "tools": ["nuclei"],
        "kind": "automated",
        "checks": "A few nuclei templates detect verbose error pages and stack traces.",
        "limits": "No fault injection or malformed-input testing.",
        "partial_only": True,
    },
}


def _finding_categories(finding: dict[str, Any]) -> set[str]:
    cats: set[str] = set()
    cwe = str(finding.get("cwe_id") or "").upper()
    if cwe in CWE_TO_OWASP:
        cats.add(CWE_TO_OWASP[cwe])
    for key in knowledge_keys(finding.get("title") or "", finding.get("evidence"), ""):
        cats.update(KNOWLEDGE[key].get("owasp") or [])
    return cats


def owasp_coverage(
    runs: list[dict[str, Any]], allowed_actions: list[str], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One row per OWASP Top 10:2025 category with state, tools, evidence and limitations."""
    by_tool: dict[str, list[str]] = {}
    for run in runs:
        by_tool.setdefault(str(run.get("tool")), []).append(str(run.get("state")))
    evidence: dict[str, int] = {}
    for finding in findings:
        for cat in _finding_categories(finding):
            evidence[cat] = evidence.get(cat, 0) + 1

    rows = []
    for code, spec in CATEGORIES.items():
        states = [s for tool in spec["tools"] for s in by_tool.get(tool, [])]
        completed = [s for s in states if s == "completed"]
        failed = [s for s in states if s in {"failed", "parse_error"}]
        if spec["kind"] == "manual":
            state = "requires_manual_review"
        elif spec["kind"] == "credentials" and not completed:
            state = "requires_credentials"
        elif spec["kind"] == "active" and "active_test" not in allowed_actions:
            state = "not_tested"
        elif not states:
            state = "not_tested"
        elif failed and not completed:
            state = "failed_interrupted"
        elif failed or spec.get("partial_only") or spec["kind"] == "credentials":
            state = "partially_tested"
        else:
            state = "tested"
        note = spec["limits"]
        if spec["kind"] == "active" and "active_test" not in allowed_actions:
            note = "Not authorized: the signed grant has no active_test. " + note
        if failed:
            note = f"{len(failed)} run(s) failed or were interrupted. " + note
        rows.append(
            {
                "id": code,
                "name": OWASP_TOP10_2025[code],
                "state": state,
                "tools": [t for t in spec["tools"] if t in by_tool],
                "checks": spec["checks"],
                "findings": evidence.get(code, 0),
                "limitations": note,
            }
        )
    return rows
