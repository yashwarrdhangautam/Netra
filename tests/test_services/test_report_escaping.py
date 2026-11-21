"""Report generators must survive target-controlled text (regression for scan 47b5dfc4)."""

import pytest

from netra.services import report_service as rs

# The real nikto title that broke the full PDF, plus script and control characters.
HOSTILE = [
    {
        "id": "1",
        "title": "Link header(s) found with value(s): </_next/static/media/a.woff2>; rel=preload",
        "description": "<script>alert(1)</script> & \x07 bell",
        "severity": "info",
        "url": 'https://x.example/"><img src=x onerror=alert(1)>',
        "cwe_id": None,
        "cve_ids": [],
        "tool_source": "nikto",
        "evidence": {"raw": "<b>unclosed", "ctrl": "a\x01b"},
        "ai_analysis": {},
        "tags": [],
    }
]
SCAN = {
    "id": "esc-test",
    "name": "<i>scan & co",
    "target": "x.example",
    "profile": "deep",
    "created_at": "2026-11-21",
    "attack_chains": [{"name": "<b>chain", "description": "</para> & more"}],
}


@pytest.mark.parametrize(
    "name",
    [
        "generate_executive_report",
        "generate_pentest_report",
        "generate_full_report",
        "generate_technical_report",
        "generate_html_report",
        "generate_excel_report",
    ],
)
async def test_generators_handle_hostile_text(tmp_path, monkeypatch, name) -> None:
    monkeypatch.setattr(rs.settings, "reports_dir", tmp_path, raising=False)
    path = await getattr(rs, name)(SCAN, HOSTILE)
    assert path.exists() and path.stat().st_size > 0


async def test_html_report_escapes_target_text(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rs.settings, "reports_dir", tmp_path, raising=False)
    html = (await rs.generate_html_report(SCAN, HOSTILE)).read_text(encoding="utf-8")
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "<i>scan" not in html
