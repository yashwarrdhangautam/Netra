"""Semgrep, Checkov and pip-audit wrappers, parsed from output captured from the real tools (spec 6.4)."""

import asyncio
import os
import shutil
from pathlib import Path

import pytest

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.checkov import CheckovTool, parse_checkov_output
from netra.scanner.tools.dependency_scan import PipAuditTool, parse_pip_audit_output
from netra.scanner.tools.semgrep import SemgrepTool, parse_semgrep_output

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "scanner"


@pytest.fixture(scope="module")
def event_loop_policy():
    # The Windows selector loop cannot run asyncio subprocesses; the live tests need Proactor.
    if os.name == "nt":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


def _result(name: str, *, success: bool = True) -> ToolResult:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return ToolResult(
        tool_name="fixture",
        success=success,
        raw_output=text,
        metadata={"state": "completed" if success else "failed", "output_truncated": False},
    )


# ── Semgrep ──────────────────────────────────────────────────────────────────


def test_semgrep_findings_are_parsed_by_rule_id():
    result = parse_semgrep_output(_result("semgrep-findings.json"))
    assert result.metadata["state"] == "completed"
    assert {f["rule_id"] for f in result.findings} == {
        "netra.python.subprocess-shell-true",
        "netra.python.eval-call",
    }
    assert all(f["path"] for f in result.findings)


def test_semgrep_clean_run_is_completed_with_zero_findings():
    result = parse_semgrep_output(_result("semgrep-clean.json"))
    assert result.success is True
    assert result.metadata["state"] == "completed"
    assert result.findings == []


def test_semgrep_truncated_output_is_parse_error_not_clean():
    result = parse_semgrep_output(_result("semgrep-truncated.json"))
    assert result.success is False
    assert result.metadata["state"] == "parse_error"
    assert result.findings == []


# ── Checkov ──────────────────────────────────────────────────────────────────


def test_checkov_failed_checks_are_parsed():
    result = parse_checkov_output(_result("checkov-findings.json"))
    assert result.metadata["state"] == "completed"
    assert result.findings
    assert "CKV2_AWS_62" in {f["check_id"] for f in result.findings}


def test_checkov_summary_with_no_resources_is_completed_zero():
    result = parse_checkov_output(_result("checkov-clean.json"))
    assert result.success is True
    assert result.findings == []
    assert result.metadata["resources_checked"] == 0


def test_checkov_truncated_output_is_parse_error():
    broken = ToolResult(
        tool_name="fixture",
        success=True,
        raw_output='[{"results": {"failed_checks": [',
        metadata={"state": "completed"},
    )
    parsed = parse_checkov_output(broken)
    assert parsed.success is False
    assert parsed.metadata["state"] == "parse_error"


# ── pip-audit ────────────────────────────────────────────────────────────────


def test_pip_audit_findings_match_the_captured_advisories():
    result = parse_pip_audit_output(_result("pip-audit-findings.json"))
    assert result.metadata["state"] == "completed"
    assert len(result.findings) == 37
    assert len({f["package"] for f in result.findings}) == 3
    assert any(f["advisory_id"] == "PYSEC-2018-28" for f in result.findings)


def test_pip_audit_clean_run_is_completed_zero():
    result = parse_pip_audit_output(_result("pip-audit-clean.json"))
    assert result.success is True
    assert result.findings == []


def test_pip_audit_truncated_output_is_parse_error():
    result = parse_pip_audit_output(_result("pip-audit-truncated.json"))
    assert result.success is False
    assert result.metadata["state"] == "parse_error"


# ── Wiring and exit codes ────────────────────────────────────────────────────


@pytest.mark.parametrize("tool_cls", [SemgrepTool, CheckovTool, PipAuditTool])
def test_findings_exit_code_is_accepted(tool_cls):
    assert 1 in tool_cls.accepted_exit_codes
    assert 0 in tool_cls.accepted_exit_codes


async def test_missing_binary_is_unavailable_not_failed(tmp_path):
    class Missing(CliTool):
        binary = "netra-definitely-missing-binary"
        tool_name = "missing"

    result = await Missing(tmp_path)._exec(["--version"])
    assert result.success is False
    assert result.metadata["state"] == "unavailable"
    assert result.metadata["reason_code"] == "not_installed"


# Semgrep skips directories named "tests" by default, so the live fixtures are copied out first.
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
async def test_live_semgrep_reports_both_rules(tmp_path):
    shutil.copytree(FIXTURES / "sast", tmp_path / "sast")
    result = await SemgrepTool(tmp_path).run(str(tmp_path / "sast"))
    assert result.metadata["state"] == "completed"
    rules = {f["rule_id"] for f in result.findings}
    assert {"netra.python.subprocess-shell-true", "netra.python.eval-call"} <= rules


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")
async def test_live_checkov_reports_the_known_check(tmp_path):
    shutil.copytree(FIXTURES / "iac", tmp_path / "iac")
    result = await CheckovTool(tmp_path).run(str(tmp_path / "iac"))
    assert result.metadata["state"] == "completed"
    assert "CKV2_AWS_62" in {f["check_id"] for f in result.findings}


# ── Trivy (config mode) ──────────────────────────────────────────────────────

from netra.scanner.tools.trivy import TrivyTool, parse_trivy_config_output  # noqa: E402


def test_trivy_failed_misconfigurations_are_parsed():
    result = parse_trivy_config_output(_result("trivy-config-findings.json"))
    assert result.metadata["state"] == "completed"
    assert result.findings
    assert all(f["check_id"] for f in result.findings)
    assert "AWS-0086" in {f["check_id"] for f in result.findings}


def test_trivy_clean_run_is_completed_zero():
    result = parse_trivy_config_output(_result("trivy-config-clean.json"))
    assert result.success is True
    assert result.findings == []


def test_trivy_truncated_output_is_parse_error():
    result = parse_trivy_config_output(_result("trivy-config-truncated.json"))
    assert result.success is False
    assert result.metadata["state"] == "parse_error"


async def test_trivy_image_mode_is_explicitly_unavailable(tmp_path):
    result = await TrivyTool(tmp_path).run("alpine:3", mode="image")
    assert result.success is False
    assert result.metadata["state"] == "unavailable"


@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy not installed")
async def test_live_trivy_reports_the_known_misconfiguration(tmp_path):
    shutil.copytree(FIXTURES / "iac", tmp_path / "iac")
    result = await TrivyTool(tmp_path).run(str(tmp_path / "iac"))
    assert result.metadata["state"] == "completed"
    assert "AWS-0086" in {f["check_id"] for f in result.findings}


# ── dalfox and sqlmap ────────────────────────────────────────────────────────

import socket  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

from netra.scanner.tools.dalfox import DalfoxTool, parse_dalfox_output  # noqa: E402
from netra.scanner.tools.sqlmap import SqlmapTool, parse_sqlmap_output  # noqa: E402

LAB_SERVER = FIXTURES.parent / "lab" / "vuln_server.py"


def test_dalfox_verified_reflections_are_parsed():
    result = parse_dalfox_output(_result("dalfox-findings.json"))
    assert result.metadata["state"] == "completed"
    assert result.findings
    assert {f["param"] for f in result.findings} == {"q"}


def test_dalfox_clean_run_ignores_the_empty_object():
    result = parse_dalfox_output(_result("dalfox-clean.json"))
    assert result.success is True
    assert result.findings == []


def test_dalfox_truncated_output_is_parse_error():
    result = parse_dalfox_output(_result("dalfox-truncated.json"))
    assert result.success is False
    assert result.metadata["state"] == "parse_error"


def test_sqlmap_known_injection_is_parsed():
    result = parse_sqlmap_output(_result("sqlmap-findings.txt"))
    assert result.metadata["state"] == "completed"
    assert result.findings[0]["param"] == "id"
    assert result.findings[0]["method"] == "GET"
    assert "boolean-based blind" in result.findings[0]["technique"]


def test_sqlmap_not_injectable_is_completed_zero():
    result = parse_sqlmap_output(_result("sqlmap-clean.txt"))
    assert result.success is True
    assert result.findings == []


def test_sqlmap_without_a_summary_is_parse_error_not_clean():
    result = parse_sqlmap_output(_result("sqlmap-inconclusive.txt"))
    assert result.success is False
    assert result.metadata["state"] == "parse_error"


@pytest.fixture(scope="module")
def lab_base_url():
    """Start the localhost lab page on a free port for the live tests, then stop it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([sys.executable, str(LAB_SERVER), "--port", str(port)])  # noqa: S603 - fixed local script
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    yield url
    server.terminate()
    server.wait(timeout=10)


@pytest.mark.skipif(shutil.which("dalfox") is None, reason="dalfox not installed")
async def test_live_dalfox_finds_the_reflected_parameter(tmp_path, lab_base_url):
    result = await DalfoxTool(tmp_path).run(f"{lab_base_url}/reflect?q=hello")
    assert result.metadata["state"] == "completed"
    assert "q" in {f["param"] for f in result.findings}


@pytest.mark.skipif(shutil.which("sqlmap") is None, reason="sqlmap launcher not on PATH")
async def test_live_sqlmap_finds_the_known_injection(tmp_path, lab_base_url):
    result = await SqlmapTool(tmp_path).run(f"{lab_base_url}/item?id=1")
    assert result.metadata["state"] == "completed"
    assert result.findings[0]["param"] == "id"


def test_checkov_crash_with_no_output_is_failed_not_bad_json():
    from netra.scanner.tools.checkov import parse_checkov_output

    crashed = ToolResult(
        tool_name="checkov",
        success=True,
        raw_output="",
        metadata={"stderr": "ModuleNotFoundError: No module named 'checkov'"},
    )
    result = parse_checkov_output(crashed)
    assert result.success is False
    assert result.metadata["state"] == "failed"
    assert result.metadata["reason_code"] == "no_output"
    assert "No module named" in result.error
