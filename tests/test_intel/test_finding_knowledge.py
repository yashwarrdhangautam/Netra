"""Finding explanations: matched by evidence and title, never inventing CVEs or severity."""

from netra.intel.finding_knowledge import KNOWLEDGE, knowledge_for, knowledge_keys


def test_nikto_header_title() -> None:
    keys = knowledge_keys("Suggested security header missing: x-content-type-options.", {})
    assert keys == ["header:x-content-type-options"]


def test_nikto_long_xcto_title() -> None:
    title = "The X-Content-Type-Options header is not set. This could allow the user agent"
    assert knowledge_keys(title, {}) == ["header:x-content-type-options"]


def test_http_analysis_missing_list() -> None:
    evidence = {"missing": ["Strict-Transport-Security", "X-Frame-Options"]}
    keys = knowledge_keys("Missing security headers: ...", evidence)
    assert keys == ["header:strict-transport-security", "header:x-frame-options"]


def test_email_and_dns_and_outdated() -> None:
    assert knowledge_keys("DMARC policy for x.com is monitor-only (p=none)", {}) == [
        "email:dmarc-none"
    ]
    assert knowledge_keys("SPF record for x.com uses soft fail (~all)", {}) == [
        "email:spf-softfail"
    ]
    assert knowledge_keys("No CAA record for x.com", {}) == ["dns:no-caa"]
    assert knowledge_keys("nginx/1.30.4 appears to be outdated", {}) == ["component:outdated"]


def test_inventory_and_unknown() -> None:
    assert knowledge_keys("Nginx version detect", {}) == ["inventory:discovery"]
    assert knowledge_keys("Some unusual finding", {}) == []


def test_entries_never_claim_cves_or_severity() -> None:
    for entry in KNOWLEDGE.values():
        assert "cve" not in entry
        assert "severity" not in entry
        for field in ("purpose", "impact", "false_positive", "remediation"):
            assert entry[field]
        assert "CVE-" not in " ".join(str(v) for v in entry.values())


def test_owasp_ids_expand_to_2025_names() -> None:
    entry = knowledge_for("Suggested security header missing: content-security-policy.", {})[0]
    assert entry["owasp"] == ["A02:2025 Security Misconfiguration"]
    assert entry["cwe"] == "CWE-693"
