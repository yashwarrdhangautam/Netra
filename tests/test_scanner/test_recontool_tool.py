"""Tests for the Recontool wrapper. The subprocess is stubbed; nothing runs against a network."""

import json

import pytest

from netra.scanner.tools.base import ToolResult
from netra.scanner.tools.recontool import RecontoolTool, is_plain_hostname, parse_export


@pytest.mark.parametrize(
    "value",
    ["example.com", "a.b.example.co.uk", "xn--bcher-kva.example"],
)
def test_plain_hostnames_accepted(value: str) -> None:
    assert is_plain_hostname(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "10.0.0.1",
        "example.com/path",
        "*.example.com",
        "example.com;rm -rf /",
        "localhost",
        "",
        "-bad.example.com",
    ],
)
def test_non_hostnames_refused(value: str) -> None:
    assert not is_plain_hostname(value)


def test_parse_export_keeps_assets_endpoints_and_findings() -> None:
    rows = parse_export(
        {
            "scan_id": "s1",
            "assets": [
                {
                    "type": "subdomain",
                    "value": "api.example.com",
                    "in_scope": True,
                    "is_live": True,
                    "confidence": 0.9,
                    "sources": ["subfinder"],
                },
                {"type": "ip", "value": ""},
            ],
            "endpoints": [{"url": "https://api.example.com/v1", "status": 200, "title": "API"}],
            "findings": [
                {
                    "title": "Exposed .git",
                    "severity": "HIGH",
                    "asset": "api.example.com",
                    "evidence": "[redacted]",
                    "detector": "probe",
                },
                {"severity": "low"},
            ],
        }
    )
    kinds = [r["kind"] for r in rows]
    assert kinds == ["asset", "endpoint", "finding"]
    assert rows[0]["value"] == "api.example.com"
    assert rows[2]["severity"] == "high"


def test_parse_export_handles_empty_or_odd_payload() -> None:
    assert parse_export({}) == []
    assert parse_export({"assets": "nope", "findings": None}) == []


async def test_refuses_url_target_without_running(tmp_path, monkeypatch) -> None:
    tool = RecontoolTool(work_dir=tmp_path)

    async def must_not_run(*args, **kwargs):
        raise AssertionError("subprocess must not run for a refused target")

    monkeypatch.setattr(RecontoolTool, "_exec", must_not_run)
    result = await tool.run("https://example.com")
    assert result.success is False
    assert "plain hostname" in (result.error or "")


async def test_refuses_bad_profile_name(tmp_path, monkeypatch) -> None:
    tool = RecontoolTool(work_dir=tmp_path)
    monkeypatch.setattr(RecontoolTool, "_exec", lambda *a, **k: None)
    result = await tool.run("example.com", profile="x; rm -rf")
    assert result.success is False


async def test_missing_work_dir_is_an_error() -> None:
    tool = RecontoolTool(work_dir=None)
    result = await tool.run("example.com")
    assert result.success is False


async def test_passive_default_and_export_parsed(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    async def fake_exec(self, args, stdin=None, timeout=300):
        captured["args"] = args
        export = args[args.index("--export") + 1]
        with open(export, "w", encoding="utf-8") as fh:
            json.dump(
                {"scan_id": "abc", "assets": [{"type": "subdomain", "value": "a.example.com"}]},
                fh,
            )
        return ToolResult(tool_name="recontool", success=True)

    monkeypatch.setattr(RecontoolTool, "_exec", fake_exec)
    result = await RecontoolTool(work_dir=tmp_path).run("Example.com")
    assert "--authorize-active" not in captured["args"]
    assert captured["args"][1] == "example.com"
    assert result.success is True
    assert result.metadata["active_authorized"] is False
    assert result.findings[0]["value"] == "a.example.com"
    assert not any(p.name.startswith("recontool-") for p in tmp_path.iterdir())


async def test_active_only_when_authorized(tmp_path, monkeypatch) -> None:
    captured: dict = {}

    async def fake_exec(self, args, stdin=None, timeout=300):
        captured["args"] = args
        return ToolResult(tool_name="recontool", success=False, error="not installed")

    monkeypatch.setattr(RecontoolTool, "_exec", fake_exec)
    await RecontoolTool(work_dir=tmp_path).run("example.com", authorize_active=True)
    assert "--authorize-active" in captured["args"]


async def test_no_export_file_reports_failure(tmp_path, monkeypatch) -> None:
    async def fake_exec(self, args, stdin=None, timeout=300):
        return ToolResult(tool_name="recontool", success=True)

    monkeypatch.setattr(RecontoolTool, "_exec", fake_exec)
    result = await RecontoolTool(work_dir=tmp_path).run("example.com")
    assert result.success is False
    assert "without writing an export" in (result.error or "")
