"""Tests for NETRA-BB readiness checks."""

from netra.bugbounty.cli import _doctor_checks


def test_doctor_checks_report_missing_prerequisites(monkeypatch) -> None:
    """Doctor should be safe to run without live credentials or tools."""
    monkeypatch.setattr("netra.bugbounty.cli.shutil.which", lambda _name: None)
    monkeypatch.setattr("netra.bugbounty.cli._check_broker", lambda _url: (False, "offline"))
    for key in [
        "H1_API_USERNAME",
        "H1_API_TOKEN",
        "GITHUB_TOKEN",
        "NETRA_BB_MCP_COMMAND",
        "CELERY_BROKER_URL",
        "REDIS_URL",
    ]:
        monkeypatch.delenv(key, raising=False)

    checks = dict((name, ok) for name, ok, _detail in _doctor_checks(include_local_tools=False))

    assert checks["tool:subfinder"] is False
    assert checks["hackerone:credentials"] is False
    assert checks["github:token"] is False


def test_doctor_checks_detect_configured_environment(monkeypatch) -> None:
    """Doctor should recognize configured live-hunt prerequisites."""
    monkeypatch.setattr("netra.bugbounty.cli.shutil.which", lambda name: f"C:/tools/{name}.exe")
    monkeypatch.setattr("netra.bugbounty.cli._check_broker", lambda _url: (True, "reachable"))
    monkeypatch.setenv("H1_API_USERNAME", "user")
    monkeypatch.setenv("H1_API_TOKEN", "token")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_token")
    monkeypatch.setenv("NETRA_BB_MCP_COMMAND", "node server.js")
    monkeypatch.setenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

    checks = dict((name, ok) for name, ok, _detail in _doctor_checks())

    assert checks["tool:subfinder"] is True
    assert checks["tool:graphify"] is True
    assert checks["hackerone:credentials"] is True
    assert checks["celery:broker"] is True


def test_doctor_checks_include_corpus_freshness(monkeypatch) -> None:
    monkeypatch.setattr("netra.bugbounty.cli.shutil.which", lambda name: f"C:/tools/{name}.exe")
    monkeypatch.setattr("netra.bugbounty.cli._check_broker", lambda _url: (True, "reachable"))
    monkeypatch.setattr("netra.bugbounty.cli._check_agentic_budget_table", lambda: (True, "ok"))
    monkeypatch.setattr("netra.bugbounty.cli._check_corpus_freshness", lambda source_name, max_age_hours: (True, f"{source_name}:{max_age_hours}"))

    checks = dict((name, ok) for name, ok, _detail in _doctor_checks())

    assert checks["corpus:hackerone_hacktivity"] is True
    assert checks["corpus:public_advisories"] is True
    assert checks["corpus:public_rss_writeups"] is True
