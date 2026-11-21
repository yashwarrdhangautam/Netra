"""Posture checks: email authentication, CAA, headers, TLS expiry, and the DoH collector."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from netra.scanner.passive import (
    PassivePosture,
    analyze_caa,
    analyze_certificate,
    analyze_discovered_names,
    analyze_email_auth,
    analyze_headers,
    security_headers,
)


def _titles(findings):
    return [f["title"] for f in findings]


# ── email authentication ─────────────────────────────────────────────────────


def test_zone_without_mail_gets_no_email_findings():
    assert analyze_email_auth("example.org", {"TXT": [], "_dmarc": []}) == []


def test_missing_spf_and_dmarc_are_medium():
    findings = analyze_email_auth("example.org", {"MX": ["10 mail.example.org."]})
    assert _titles(findings) == ["No SPF record for example.org", "No DMARC record for example.org"]
    assert {f["severity"] for f in findings} == {"medium"}
    assert all("Acceptance:" in f["description"] for f in findings)


def test_soft_fail_spf_and_monitor_only_dmarc_are_low():
    records = {
        "MX": ["10 mail.example.org."],
        "TXT": ['"v=spf1 include:_spf.example.net ~all"'],
        "_dmarc": ['"v=DMARC1; p=none; rua=mailto:d@example.org"'],
    }
    findings = analyze_email_auth("example.org", records)
    assert _titles(findings) == [
        "SPF record for example.org uses soft fail (~all)",
        "DMARC policy for example.org is monitor-only (p=none)",
    ]
    assert {f["severity"] for f in findings} == {"low"}


def test_strict_email_posture_has_no_findings():
    records = {
        "MX": ["10 mail.example.org."],
        "TXT": ['"v=spf1 include:_spf.example.net -all"'],
        "_dmarc": ['"v=DMARC1; p=reject"'],
    }
    assert analyze_email_auth("example.org", records) == []


def test_plus_all_spf_is_high_and_chunked_txt_is_joined():
    records = {"MX": ["10 m."], "TXT": ['"v=spf1 +a" " +all"'], "_dmarc": ['"v=DMARC1; p=reject"']}
    (finding,) = analyze_email_auth("example.org", records)
    assert finding["severity"] == "high"


def test_caa_finding_only_when_absent():
    assert _titles(analyze_caa("example.org", {"CAA": []})) == ["No CAA record for example.org"]
    assert analyze_caa("example.org", {"CAA": ['0 issue "letsencrypt.org"']}) == []


# ── discovered names ─────────────────────────────────────────────────────────


def test_discovered_names_are_observations_and_flag_internal_looking_hosts():
    names = ["example.org", "www.example.org", "metabase.example.org", "shop.example.org"]
    findings = analyze_discovered_names(
        "example.org", names, "www.example.org", lambda n: n == "shop.example.org"
    )
    summary, internal = findings
    assert summary["severity"] == "info"
    assert summary["evidence"]["outside_scope"] == ["example.org", "metabase.example.org"]
    assert internal["severity"] == "low"
    assert internal["evidence"]["names"] == ["metabase.example.org"]


def test_no_other_names_means_no_findings():
    assert (
        analyze_discovered_names("example.org", ["www.example.org"], "www.example.org", bool) == []
    )


# ── headers ──────────────────────────────────────────────────────────────────


def test_security_headers_normalises_httpx_names_and_drops_the_rest():
    raw = {"strict_transport_security": "max-age=1", "Server": "nginx/1.30", "set_cookie": "a=b"}
    assert security_headers(raw) == {
        "strict-transport-security": "max-age=1",
        "server": "nginx/1.30",
    }
    assert security_headers(None) == {}


def test_missing_headers_and_disclosure_are_reported_for_https():
    headers = {"server": "nginx/1.30.4", "x-powered-by": "Next.js"}
    missing, disclosure = analyze_headers("https://www.example.org:443", headers)
    assert missing["severity"] == "low"
    assert "Strict-Transport-Security" in missing["title"]
    assert missing["cwe_id"] == "CWE-693"
    assert disclosure["evidence"]["headers"] == {
        "server": "nginx/1.30.4",
        "x-powered-by": "Next.js",
    }


def test_hsts_is_not_required_over_plain_http_and_frame_ancestors_counts():
    headers = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    assert analyze_headers("http://example.org:80", headers) == []


def test_unversioned_server_header_is_not_disclosure():
    findings = analyze_headers("https://example.org", {"server": "nginx"})
    assert all(f["title"] != "Server technology disclosed in response headers" for f in findings)


# ── certificate ──────────────────────────────────────────────────────────────


def _not_after(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).strftime("%b %d %H:%M:%S %Y GMT")


def test_certificate_expiring_soon_is_medium_and_expired_is_high():
    soon = analyze_certificate(
        "example.org", 443, {"notAfter": _not_after(timedelta(days=10))}, "TLSv1.3"
    )
    assert soon[0]["severity"] == "medium"
    gone = analyze_certificate(
        "example.org", 443, {"notAfter": _not_after(timedelta(days=-2))}, "TLSv1.3"
    )
    assert gone[0]["severity"] == "high"


def test_healthy_certificate_has_no_findings():
    cert = {"notAfter": _not_after(timedelta(days=90))}
    assert analyze_certificate("example.org", 443, cert, "TLSv1.3") == []
    assert analyze_certificate("example.org", 443, {}, "TLSv1.3") == []


# ── DoH collector ────────────────────────────────────────────────────────────


def _doh_handler(requests: list):
    answers = {
        ("www.example.org", "SOA"): {"Authority": [{"name": "example.org.", "type": 6}]},
        ("example.org", "MX"): {"Answer": [{"type": 15, "data": "10 mail.example.org."}]},
        ("example.org", "TXT"): {"Answer": [{"type": 16, "data": '"v=spf1 -all"'}]},
        ("example.org", "CAA"): {},
        ("_dmarc.example.org", "TXT"): {"Answer": [{"type": 16, "data": '"v=DMARC1; p=none"'}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        key = (request.url.params["name"], request.url.params["type"])
        return httpx.Response(200, json=answers.get(key, {}))

    return handler


async def test_posture_resolves_the_zone_from_soa_and_reports_findings():
    requests: list[httpx.Request] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(_doh_handler(requests)))
    result = await PassivePosture(
        "WWW.example.org.", max_requests_per_second=300, client=client
    ).run()
    await client.aclose()

    assert result.success and result.metadata["state"] == "completed"
    assert result.metadata["zone"] == "example.org"
    assert set(_titles(result.findings)) == {
        "DMARC policy for example.org is monitor-only (p=none)",
        "No CAA record for example.org",
    }
    # Only the public resolver is contacted, never the target.
    assert {r.url.host for r in requests} == {"cloudflare-dns.com"}
    assert result.metadata["requests"] == len(requests) == 5


async def test_posture_reports_failure_when_the_resolver_is_down():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    result = await PassivePosture("example.org", max_requests_per_second=300, client=client).run()
    await client.aclose()
    assert not result.success
    assert result.metadata["state"] == "failed"
    assert result.metadata["reason_code"] == "providers_unreachable"


@pytest.mark.parametrize("rate", [0, 301, True])
def test_posture_rejects_an_invalid_rate(rate):
    with pytest.raises(ValueError):
        PassivePosture("example.org", max_requests_per_second=rate)
