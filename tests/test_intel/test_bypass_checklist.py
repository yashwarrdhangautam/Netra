"""Protection detection from ordinary response headers, and the checklist it produces."""

from netra.intel.bypass_checklist import checklist_for, detect_protections


def test_detects_waf_from_cdn_header():
    assert "waf" in detect_protections({"CF-Ray": "abc"})


def test_detects_waf_from_server_banner():
    assert "waf" in detect_protections({"Server": "Barracuda/9"})


def test_detects_csp_cors_frame_and_rate_limit():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Access-Control-Allow-Origin": "https://a.example",
        "X-Frame-Options": "DENY",
    }
    found = detect_protections(headers)
    assert {"csp", "cors", "frame_protection"} <= set(found)
    assert "rate_limit" not in found
    assert detect_protections({"Retry-After": "30"}) == ["rate_limit"]
    assert detect_protections({}, status_code=429) == ["rate_limit"]


def test_plain_response_detects_nothing():
    assert detect_protections({"Content-Type": "text/html"}, status_code=200) == []


def test_frame_ancestors_in_csp_counts_as_frame_protection():
    found = detect_protections({"Content-Security-Policy": "frame-ancestors 'none'"})
    assert "frame_protection" in found


def test_checklist_is_ordered_deduplicated_and_skips_unknown_ids():
    items = checklist_for(["csp", "waf", "csp", "not-a-protection"])
    protections = [i.protection for i in items]
    assert protections[0] == "csp"
    assert "not-a-protection" not in protections
    assert protections.count("csp") == 3
    assert all(i.check for i in items)
