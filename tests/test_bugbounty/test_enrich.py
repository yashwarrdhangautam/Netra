"""Tests for bug bounty asset enrichment."""

from netra.bugbounty.recon.enrich import extract_js_endpoints, fingerprint_tech, hunt_secrets


def test_fingerprint_tech_header_and_body_rules() -> None:
    labels = fingerprint_tech({"server": "nginx", "cf-ray": "abc"}, "__NEXT_DATA__ wp-content")
    assert "nginx" in labels
    assert "cloudflare" in labels
    assert "nextjs" in labels
    assert "wordpress" in labels


def test_extract_js_endpoints_common_clients() -> None:
    js = """
    fetch('/api/me');
    axios.get("https://api.example.com/v1/users");
    xhr.open('GET', '/internal/status');
    """
    assert extract_js_endpoints(js) == [
        "/api/me",
        "/internal/status",
        "https://api.example.com/v1/users",
    ]


def test_hunt_secrets_regex_fallback() -> None:
    hits = hunt_secrets("const key = 'AKIA1234567890ABCDEF';")
    assert hits[0]["rule"] == "aws_access_key"

