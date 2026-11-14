"""Chaos client: no key means no request; results are normalised and wildcard labels dropped."""

import httpx

from netra.intel.chaos import fetch_subdomains, valid_domain


def _transport(payload, calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handler)


async def test_no_key_makes_no_request():
    calls: list = []
    result = await fetch_subdomains("example.org", None, transport=_transport({}, calls))
    assert result == []
    assert calls == []


async def test_invalid_domain_makes_no_request():
    calls: list = []
    result = await fetch_subdomains("not a domain", "k", transport=_transport({}, calls))
    assert result == []
    assert calls == []


async def test_results_are_qualified_deduped_and_wildcards_dropped():
    calls: list = []
    payload = {"subdomains": ["api", "WWW", "api", "*", ""]}
    result = await fetch_subdomains("Example.org", "secret", transport=_transport(payload, calls))
    assert result == ["api.example.org", "www.example.org"]
    assert calls[0].headers["Authorization"] == "secret"


async def test_http_failure_returns_empty():
    def handler(request):
        return httpx.Response(500)

    result = await fetch_subdomains("example.org", "k", transport=httpx.MockTransport(handler))
    assert result == []


def test_domain_validation():
    assert valid_domain("example.org")
    assert not valid_domain("localhost")
    assert not valid_domain("exa mple.org")
