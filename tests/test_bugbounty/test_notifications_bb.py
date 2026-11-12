"""Tests for bug-bounty Slack notifications. The Slack client is always mocked."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from netra.notifications import bugbounty as bb_notify


class _FakeSlack:
    instances: list[_FakeSlack] = []

    def __init__(self) -> None:
        self.send = AsyncMock(return_value=True)
        self.send_finding_alert = AsyncMock(return_value=True)
        _FakeSlack.instances.append(self)


@pytest.fixture(autouse=True)
def _fake_slack(monkeypatch):
    _FakeSlack.instances = []
    monkeypatch.setattr(bb_notify, "SlackNotifier", _FakeSlack)
    return _FakeSlack


def _program(handle: str = "shopify", platform: str = "hackerone"):
    return SimpleNamespace(handle=handle, platform=platform)


def _diff(added: int = 0, removed: int = 0, has_changes: bool | None = None):
    return SimpleNamespace(
        has_changes=(added + removed > 0) if has_changes is None else has_changes,
        added=[object()] * added,
        removed=[object()] * removed,
    )


async def test_scope_diff_without_changes_sends_nothing(_fake_slack) -> None:
    assert await bb_notify.notify_scope_diff(_program(), _diff(has_changes=False)) is False
    assert _fake_slack.instances == []


async def test_scope_diff_with_changes_sends_summary(_fake_slack) -> None:
    sent = await bb_notify.notify_scope_diff(_program(), _diff(added=2, removed=1))
    assert sent is True
    payload = _fake_slack.instances[0].send.await_args.args[0]
    assert "shopify" in payload["text"]
    fields = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
    assert fields == {"Program": "hackerone/shopify", "Added": "2", "Removed": "1"}


async def test_scope_diff_tolerates_diff_without_has_changes(_fake_slack) -> None:
    bare = SimpleNamespace(added=[], removed=[])
    assert await bb_notify.notify_scope_diff(_program(), bare) is False
    assert _fake_slack.instances == []


async def test_critical_finding_sends_alert(_fake_slack) -> None:
    finding = SimpleNamespace(
        severity="critical",
        title="SQLi in login",
        description="Unauthenticated injection",
        url="https://api.example.com/login",
        cwe_id="CWE-89",
    )
    assert await bb_notify.notify_critical_finding(finding, _program()) is True
    alert = _fake_slack.instances[0].send_finding_alert
    payload, severity = alert.await_args.args
    assert severity == "critical"
    assert payload == {
        "title": "SQLi in login",
        "description": "Unauthenticated injection",
        "target": "https://api.example.com/login",
        "cwe": "CWE-89",
    }
    assert alert.await_args.kwargs == {"scan_name": "BB shopify"}


async def test_non_critical_finding_is_not_sent(_fake_slack) -> None:
    finding = SimpleNamespace(severity="high", title="x", description="y", url=None, cwe_id=None)
    assert await bb_notify.notify_critical_finding(finding, _program()) is False
    assert _fake_slack.instances == []


async def test_critical_finding_falls_back_to_program_handle_and_na_cwe(_fake_slack) -> None:
    finding = SimpleNamespace(
        severity="critical", title="t", description="d", url=None, cwe_id=None
    )
    await bb_notify.notify_critical_finding(finding, _program(handle="acme"))
    payload = _fake_slack.instances[0].send_finding_alert.await_args.args[0]
    assert payload["target"] == "acme"
    assert payload["cwe"] == "N/A"
