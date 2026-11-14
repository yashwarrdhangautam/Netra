"""httpx output carries protections and the bypass checklist for each live host."""

import json

from netra.scanner.tools.base import ToolResult
from netra.scanner.tools.httpx import HttpxTool


async def test_httpx_rows_include_protections_and_checklist(monkeypatch):
    rows = [
        {
            "url": "https://a.example.org",
            "status_code": 200,
            "tech": ["nginx"],
            "header": {"content_security_policy": "default-src 'self'", "cf_ray": "abc"},
        },
        {"url": "https://b.example.org", "status_code": 429, "header": {"retry_after": "5"}},
    ]
    raw = "\n".join(json.dumps(r) for r in rows)

    async def fake_exec(self, args, stdin=None, timeout=300):
        assert "-include-response-header" in args
        return ToolResult("httpx", True, raw_output=raw)

    monkeypatch.setattr(HttpxTool, "_exec", fake_exec)
    result = await HttpxTool().run("a.example.org,b.example.org")

    first, second = result.findings
    assert "waf" in first["protections"]
    assert "csp" in first["protections"]
    assert first["bypass_checklist"], "a detected protection must yield checks"
    assert second["protections"] == ["rate_limit"]
    assert any("X-Forwarded-For" in c for c in second["bypass_checklist"])
