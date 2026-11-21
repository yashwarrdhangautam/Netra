"""Nikto wrapper: only grant-allowed, non-exploit tests run, and its JSON report is parsed."""

import json
from pathlib import Path

import pytest

from netra.scanner.tools.base import ToolResult
from netra.scanner.tools.nikto import (
    NIKTO_PLUGINS,
    NiktoTool,
    build_nikto_workspace,
    filter_db_tests,
    parse_nikto_report,
)

HEADER = '# Format: "ID","References","Tuning","URI","Method","DSL","Message","Data","Headers"\n'


def row(tid, tuning, method, data="", uri="/x"):
    return f'"{tid}","","{tuning}","{uri}","{method}","CODE:200","msg {tid}","{data}",""\n'


def test_filter_keeps_only_allowed_methods_and_non_exploit_tuning():
    text = (
        HEADER
        + row("000001", "1", "GET")
        + row("000002", "3b", "HEAD")
        + row("000003", "2", "POST")  # method not on the grant
        + row("000004", "9", "GET")  # SQL injection
        + row("000005", "4", "GET")  # XSS / injection
        + row("000006", "c", "GET")  # remote source inclusion
        + row("000007", "13", "GET", data="a=b")  # carries a request body
        + row("000008", "1", "get")  # lower-case method is still GET
        + '"000009","broken line"\n'  # unreadable rows are dropped, never sent
    )
    out = filter_db_tests(text, ["GET", "HEAD"])
    kept = [line.split('","')[0].strip('"') for line in out.splitlines() if line.startswith('"')]
    assert kept == ["000001", "000002", "000008"]
    assert out.startswith("# Format")  # comments are kept


def test_filter_with_get_only_drops_head():
    out = filter_db_tests(HEADER + row("000011", "1", "GET") + row("000012", "1", "HEAD"), ["GET"])
    assert '"000012"' not in out and '"000011"' in out


def test_no_plugin_sends_other_methods_or_attacks():
    for banned in (
        "options",
        "optionsbleed",
        "put_del_test",
        "auth",
        "shellshock",
        "ms10_070",
        "apacheusers",
        "dictionary",
    ):
        assert banned not in NIKTO_PLUGINS


def fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "nikto"
    (home / "databases").mkdir(parents=True)
    (home / "plugins").mkdir()
    (home / "templates").mkdir()
    (home / "databases" / "db_tests").write_text(
        HEADER + row("1", "1", "GET") + row("2", "1", "POST"), encoding="utf-8"
    )
    (home / "databases" / "db_variables").write_text("@CGIDIRS=/cgi-bin/\n", encoding="utf-8")
    (home / "databases" / "udb_tests").write_text(row("9", "1", "PUT"), encoding="utf-8")
    return home


def test_workspace_uses_filtered_copy_and_safe_config(tmp_path):
    home = fake_home(tmp_path)
    conf = build_nikto_workspace(home, tmp_path / "work", ["GET", "HEAD"])
    text = conf.read_text(encoding="utf-8")
    db = tmp_path / "work" / "nikto-db"
    assert f"DBDIR={db.as_posix()}" in text
    assert f"PLUGINDIR={(home / 'plugins').as_posix()}" in text
    assert "UPDATES=no" in text and "PROMPTS=no" in text and "CHECKMETHODS=GET" in text
    assert (db / "db_variables").exists()
    assert '"2"' not in (db / "db_tests").read_text(encoding="utf-8")
    # A user test file could add other methods; it is filtered the same way.
    assert "PUT" not in (db / "udb_tests").read_text(encoding="utf-8")
    # The installed database is never changed.
    assert '"2"' in (home / "databases" / "db_tests").read_text(encoding="utf-8")


REPORT = [
    {
        "host": "example.test",
        "ip": "192.0.2.1",
        "port": 443,  # nikto 2.6.1 writes the port as a number
        "server_banner": "nginx",
        "vulnerabilities": [
            {
                "id": "999100",
                "references": "",
                "method": "GET",
                "url": "/",
                "msg": "The X-Content-Type-Options header is not set.",
            },
            {
                "id": "001234",
                "references": "CVE-2003-1418 https://example.test/ref",
                "method": "GET",
                "url": "/icons/README",
                "msg": "Apache default file found.",
            },
        ],
    }
]


def result(stdout="", success=True):
    return ToolResult(
        tool_name="nikto",
        success=success,
        raw_output=stdout,
        metadata={"state": "completed" if success else "failed"},
    )


def test_report_becomes_findings(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps(REPORT), encoding="utf-8")
    out = parse_nikto_report(result(), report)
    assert out.metadata["state"] == "completed"
    assert len(out.findings) == 2
    second = out.findings[1]
    assert second["url"] == "https://example.test:443/icons/README"
    assert second["cve_ids"] == ["CVE-2003-1418"]
    assert second["severity"] == "low"
    assert out.findings[0]["severity"] == "info"
    assert second["evidence"]["nikto_id"] == "001234"


def test_zero_findings_is_completed_only_when_host_was_tested(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps([{**REPORT[0], "vulnerabilities": []}]), encoding="utf-8")
    assert parse_nikto_report(result(), report).metadata["state"] == "completed"
    report.write_text("[]", encoding="utf-8")
    untested = parse_nikto_report(result(), report)
    assert (untested.success, untested.metadata["reason_code"]) == (False, "host_not_tested")


@pytest.mark.parametrize("content", [None, "", "{not json", '{"a": 1}'])
def test_missing_or_bad_report_is_parse_error(tmp_path, content):
    report = tmp_path / "r.json"
    if content is not None:
        report.write_text(content, encoding="utf-8")
    out = parse_nikto_report(result(), report)
    assert out.metadata["state"] == "parse_error" and not out.findings


def test_maxtime_keeps_findings_but_is_not_completed(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps(REPORT), encoding="utf-8")
    out = parse_nikto_report(
        result("+ ERROR: Host maximum execution time of 60 seconds reached\n"), report
    )
    assert len(out.findings) == 2
    assert (out.success, out.metadata["state"], out.metadata["reason_code"]) == (
        False,
        "failed",
        "timeout",
    )


def test_failed_run_passes_through(tmp_path):
    out = parse_nikto_report(result(success=False), tmp_path / "missing.json")
    assert out.metadata["state"] == "failed"


async def test_run_args_pace_and_limit(tmp_path, monkeypatch):
    home = fake_home(tmp_path)
    tool = NiktoTool(work_dir=tmp_path / "work")
    seen = {}

    async def fake_exec(args, stdin=None, timeout=300):
        seen["args"], seen["timeout"] = args, timeout
        Path(args[args.index("-o") + 1]).write_text(json.dumps(REPORT), encoding="utf-8")
        return result()

    monkeypatch.setattr(tool, "_nikto_home", lambda: home)
    monkeypatch.setattr(tool, "_exec", fake_exec)
    out = await tool.run("https://example.test", max_rps=2, allowed_methods=["GET"], timeout=900)
    args = seen["args"]
    assert seen["timeout"] == 900
    assert args[args.index("-Pause") + 1] == "0.500"
    assert args[args.index("-maxtime") + 1] == "780s"
    assert args[args.index("-Plugins") + 1] == ";".join((*NIKTO_PLUGINS, "report_json"))
    assert "-nocheck" in args and "-nointeractive" in args
    assert args[args.index("-config") + 1].endswith("nikto.conf")
    assert out.metadata["state"] == "completed" and len(out.findings) == 2


async def test_run_without_install_is_unavailable(tmp_path, monkeypatch):
    tool = NiktoTool(work_dir=tmp_path)
    monkeypatch.setattr(tool, "_nikto_home", lambda: None)
    out = await tool.run("https://example.test")
    assert (out.success, out.metadata["state"]) == (False, "unavailable")
