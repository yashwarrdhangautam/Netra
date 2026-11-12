"""Additional coverage for netra.bugbounty.cli.

Targets commands not exercised by test_cli_coverage.py: add-program, list-programs,
corpus forget/reembed, plan, trend, hunt-explain, cancel-hunt, program-approve,
verify, the scope --add/--list/--check branches, and main().

Every service, DB session, Celery app, subprocess and network client is replaced
with a fake. Nothing touches the network or spawns tool / Graphify processes.
"""

from __future__ import annotations

import importlib
import io
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from rich.console import Console

from netra.bugbounty import cli as bb_cli
from netra.db.models.bb_evidence import BBEvidenceReplay
from netra.db.models.bb_program import BBProgram
from netra.db.models.finding import Finding
from netra.db.models.scan import Scan, ScanStatus


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


class _Result:
    def __init__(self, rows):
        self._rows = list(rows)

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class FakeSession:
    """In-memory stand-in for AsyncSession. `get` is keyed by model class."""

    def __init__(self, by_model=None, rows=None):
        self.by_model = dict(by_model or {})
        self.rows = list(rows or [])
        self.commits = 0
        self.flushes = 0
        self.added: list = []

    async def get(self, model, _key):
        return self.by_model.get(model)

    async def execute(self, _stmt):
        return _Result(self.rows)

    async def commit(self):
        self.commits += 1

    async def flush(self):
        self.flushes += 1

    def add(self, obj):
        self.added.append(obj)


def _install_session(monkeypatch, session: FakeSession) -> None:
    @asynccontextmanager
    async def _fake_get_session():
        yield session

    monkeypatch.setattr("netra.db.engine.get_session", _fake_get_session)


def _forbid_db(monkeypatch) -> None:
    def _boom():
        raise AssertionError("DB must not be touched for this path")

    monkeypatch.setattr("netra.db.engine.get_session", _boom)


def _patch_get_program(monkeypatch, prog) -> None:
    async def _get_program(_s, _platform, _handle):
        return prog

    monkeypatch.setattr("netra.bugbounty.programs.get_program", _get_program)


@pytest.fixture
def out_console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(
        bb_cli,
        "console",
        Console(file=buf, width=200, force_terminal=False, color_system=None),
    )
    return buf


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args: list[str]):
    return runner.invoke(bb_cli.bb, args, catch_exceptions=False)


# --------------------------------------------------------------------------- #
# add-program
# --------------------------------------------------------------------------- #


def _make_h1_client(*, configured: bool, rules=None):
    class _FakeH1:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        def is_configured(self):
            return configured

        async def get_program(self, handle):
            return {"handle": handle}

        async def get_structured_scopes(self, _handle):
            return list(rules or [])

    return _FakeH1


class TestAddProgram:
    def test_existing_program_is_not_recreated(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, SimpleNamespace(id="prog-9"))

        def _no_create(*_a, **_k):
            raise AssertionError("create_program must not run for an existing program")

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _no_create)
        result = _invoke(runner, ["add-program", "--platform", "private", "--handle", "acme"])
        assert result.exit_code == 0
        assert "already registered" in out_console.getvalue()
        assert "prog-9" in out_console.getvalue()
        assert session.commits == 0

    def test_private_platform_creates_program_without_scope(
        self, runner, monkeypatch, out_console
    ):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, None)
        captured = {}

        async def _create(_s, data):
            captured["data"] = data
            return SimpleNamespace(id="prog-1")

        async def _replace(*_a, **_k):
            raise AssertionError("no scope rules should be replaced for private programs")

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _create)
        monkeypatch.setattr("netra.bugbounty.programs.replace_scope_rules", _replace)

        result = _invoke(
            runner,
            [
                "add-program",
                "--platform",
                "private",
                "--handle",
                "acme",
                "--policy-url",
                "https://acme.example/policy",
                "--payout-min",
                "50",
                "--payout-max",
                "500",
            ],
        )
        assert result.exit_code == 0, result.output
        data = captured["data"]
        assert data.handle == "acme"
        assert data.name == "acme"  # defaults to handle
        assert data.policy_url == "https://acme.example/policy"
        assert data.payout_min == 50 and data.payout_max == 500
        assert session.commits == 1
        assert "added program private/acme (id=prog-1, scope_rules=0)" in out_console.getvalue()

    def test_hackerone_configured_fetches_metadata_and_scope(
        self, runner, monkeypatch, out_console
    ):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, None)
        rules = [SimpleNamespace(rule_type="in", pattern="*.shopify.com")] * 2
        monkeypatch.setattr(
            "netra.integrations.hackerone.HackerOneClient", _make_h1_client(configured=True, rules=rules)
        )
        monkeypatch.setattr(
            "netra.integrations.hackerone.to_program_input",
            lambda _p: SimpleNamespace(
                name="Shopify Inc",
                policy_url="https://hackerone.com/shopify",
                payout_min=100,
                payout_max=5000,
            ),
        )
        created = {}
        replaced = {}
        bootstrapped = {}

        async def _create(_s, data):
            created["data"] = data
            return SimpleNamespace(id="prog-h1")

        async def _replace(_s, program, scope_rules):
            replaced["program"] = program
            replaced["rules"] = scope_rules

        async def _bootstrap(_s, *, handle, since_days):
            bootstrapped["handle"] = handle
            bootstrapped["since_days"] = since_days

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _create)
        monkeypatch.setattr("netra.bugbounty.programs.replace_scope_rules", _replace)
        monkeypatch.setattr("netra.bugbounty.learning.sources.hackerone.bootstrap_program", _bootstrap)

        result = _invoke(runner, ["add-program", "--platform", "hackerone", "--handle", "shopify"])
        assert result.exit_code == 0, result.output
        data = created["data"]
        assert data.name == "Shopify Inc"
        assert data.policy_url == "https://hackerone.com/shopify"
        assert data.payout_min == 100 and data.payout_max == 5000
        assert replaced["program"].id == "prog-h1"
        assert len(replaced["rules"]) == 2
        assert bootstrapped == {"handle": "shopify", "since_days": 90}
        assert session.commits == 1
        assert "scope_rules=2" in out_console.getvalue()

    def test_explicit_flags_override_fetched_hackerone_metadata(
        self, runner, monkeypatch, out_console
    ):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, None)
        monkeypatch.setattr(
            "netra.integrations.hackerone.HackerOneClient", _make_h1_client(configured=True)
        )
        monkeypatch.setattr(
            "netra.integrations.hackerone.to_program_input",
            lambda _p: SimpleNamespace(
                name="Fetched", policy_url="https://fetched", payout_min=1, payout_max=2
            ),
        )
        captured = {}

        async def _create(_s, data):
            captured["data"] = data
            return SimpleNamespace(id="p")

        async def _bootstrap(*_a, **_k):
            return None

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _create)
        monkeypatch.setattr(
            "netra.bugbounty.learning.sources.hackerone.bootstrap_program", _bootstrap
        )

        result = _invoke(
            runner,
            [
                "add-program",
                "--platform",
                "hackerone",
                "--handle",
                "shopify",
                "--name",
                "Mine",
                "--policy-url",
                "https://mine",
                "--payout-min",
                "7",
                "--payout-max",
                "9",
            ],
        )
        assert result.exit_code == 0, result.output
        data = captured["data"]
        assert (data.name, data.policy_url, data.payout_min, data.payout_max) == (
            "Mine",
            "https://mine",
            7,
            9,
        )

    def test_hackerone_unconfigured_warns_and_registers_without_scope(
        self, runner, monkeypatch, out_console
    ):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, None)
        monkeypatch.setattr(
            "netra.integrations.hackerone.HackerOneClient", _make_h1_client(configured=False)
        )

        async def _create(_s, data):
            return SimpleNamespace(id="p-unc")

        async def _replace(*_a, **_k):
            raise AssertionError("no scope should be replaced without credentials")

        async def _bootstrap(*_a, **_k):
            return None

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _create)
        monkeypatch.setattr("netra.bugbounty.programs.replace_scope_rules", _replace)
        monkeypatch.setattr(
            "netra.bugbounty.learning.sources.hackerone.bootstrap_program", _bootstrap
        )

        result = _invoke(runner, ["add-program", "--platform", "hackerone", "--handle", "shopify"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "H1 credentials not configured" in out
        assert "scope_rules=0" in out

    def test_hacktivity_bootstrap_failure_is_reported_not_fatal(
        self, runner, monkeypatch, out_console
    ):
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, None)
        monkeypatch.setattr(
            "netra.integrations.hackerone.HackerOneClient", _make_h1_client(configured=False)
        )

        async def _create(_s, _data):
            return SimpleNamespace(id="p-boot")

        async def _bootstrap(*_a, **_k):
            raise RuntimeError("hacktivity down")

        monkeypatch.setattr("netra.bugbounty.programs.create_program", _create)
        monkeypatch.setattr(
            "netra.bugbounty.learning.sources.hackerone.bootstrap_program", _bootstrap
        )

        result = _invoke(runner, ["add-program", "--platform", "hackerone", "--handle", "shopify"])
        assert result.exit_code == 0, result.output
        assert "hacktivity bootstrap skipped" in out_console.getvalue()
        assert "hacktivity down" in out_console.getvalue()
        assert session.commits == 1

    def test_rejects_unknown_platform(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["add-program", "--platform", "nope", "--handle", "x"])
        assert result.exit_code != 0


# --------------------------------------------------------------------------- #
# list-programs
# --------------------------------------------------------------------------- #


class TestListPrograms:
    def test_renders_payout_and_sync_columns(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        programs = [
            SimpleNamespace(
                platform="hackerone",
                handle="shopify",
                payout_min=100,
                payout_max=5000,
                scope_synced_at=None,
            ),
            SimpleNamespace(
                platform="private",
                handle="acme",
                payout_min=None,
                payout_max=None,
                scope_synced_at=None,
            ),
        ]

        async def _list(_s):
            return programs

        monkeypatch.setattr("netra.bugbounty.programs.list_active_programs", _list)
        result = _invoke(runner, ["list-programs"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Bug Bounty Programs" in out
        assert "shopify" in out and "acme" in out
        assert "$100-$5000" in out
        assert "never" in out


# --------------------------------------------------------------------------- #
# corpus forget / reembed
# --------------------------------------------------------------------------- #


class TestCorpusForget:
    def test_wrong_confirm_token_exits_2(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["corpus", "forget", "--author", "bob", "--confirm", "yes"])
        assert result.exit_code == 2
        assert "type --confirm FORGET" in out_console.getvalue()

    def test_requires_author_or_source_url(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["corpus", "forget", "--confirm", "FORGET"])
        assert result.exit_code == 2
        assert "pass --author or --source-url" in out_console.getvalue()

    def test_forgets_by_author_and_logs_ingest(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        calls = {}

        async def _forget(_s, *, author=None, source_url=None):
            calls["forget"] = (author, source_url)
            return {"reports": 2, "writeups": 1, "advisories": 0}

        async def _log(_s, **kwargs):
            calls["log"] = kwargs

        monkeypatch.setattr("netra.bugbounty.learning.ingest.forget_corpus_entries", _forget)
        monkeypatch.setattr("netra.bugbounty.learning.ingest.log_ingest", _log)

        result = _invoke(
            runner, ["corpus", "forget", "--author", "bob", "--confirm", "FORGET"]
        )
        assert result.exit_code == 0, result.output
        assert calls["forget"] == ("bob", None)
        assert calls["log"]["source_name"] == "corpus_forget"
        assert "author=bob" in calls["log"]["notes"]
        assert "deleted=" in calls["log"]["notes"]
        assert session.commits == 1
        assert "forgot" in out_console.getvalue()
        assert "{'reports': 2, 'writeups': 1, 'advisories': 0}" in out_console.getvalue()

    def test_forgets_by_source_url(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        calls = {}

        async def _forget(_s, *, author=None, source_url=None):
            calls["forget"] = (author, source_url)
            return {"reports": 0, "writeups": 0, "advisories": 1}

        async def _log(_s, **kwargs):
            calls["log"] = kwargs

        monkeypatch.setattr("netra.bugbounty.learning.ingest.forget_corpus_entries", _forget)
        monkeypatch.setattr("netra.bugbounty.learning.ingest.log_ingest", _log)

        result = _invoke(
            runner,
            [
                "corpus",
                "forget",
                "--source-url",
                "https://example.org/post",
                "--confirm",
                "FORGET",
            ],
        )
        assert result.exit_code == 0, result.output
        assert calls["forget"] == (None, "https://example.org/post")
        assert "source_url=https://example.org/post" in calls["log"]["notes"]


class TestCorpusReembed:
    def test_wrong_confirm_token_exits_2(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["corpus", "reembed", "--confirm", "forget"])
        assert result.exit_code == 2
        assert "type --confirm REEMBED" in out_console.getvalue()

    def test_reembeds_and_logs_total_updated(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        calls = {}

        async def _reembed(_s):
            return {"reports": 2, "writeups": 1, "advisories": 0}

        async def _log(_s, **kwargs):
            calls["log"] = kwargs

        monkeypatch.setattr("netra.bugbounty.learning.ingest.reembed_corpus", _reembed)
        monkeypatch.setattr("netra.bugbounty.learning.ingest.log_ingest", _log)

        result = _invoke(runner, ["corpus", "reembed", "--confirm", "REEMBED"])
        assert result.exit_code == 0, result.output
        assert calls["log"]["source_name"] == "corpus_reembed"
        assert calls["log"]["items_updated"] == 3
        assert "reports=2" in calls["log"]["notes"]
        assert session.commits == 1
        assert "re-embedded" in out_console.getvalue()


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #


class _FakePlan:
    def __init__(self, steps=None, coordination=None):
        self.steps = steps or []
        self.coordination = coordination
        self._dict = {"steps": len(self.steps), "marker": "plan-json"}

    def to_dict(self):
        return dict(self._dict)


def _capture_planner(monkeypatch, plan):
    calls = {}

    class _FakePlanner:
        async def make_plan(self, asset_facts, scope, corpus_hits):
            calls["asset_facts"] = asset_facts
            calls["scope"] = scope
            calls["corpus_hits"] = corpus_hits
            return plan

    monkeypatch.setattr("netra.bugbounty.agentic.planner.Planner", _FakePlanner)
    return calls


class TestPlan:
    def test_unknown_program_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, None)
        result = _invoke(runner, ["plan", "--program", "ghost", "--asset", "a.example.com"])
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()

    def test_table_output_with_coordination_and_attack_paths(
        self, runner, monkeypatch, out_console
    ):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return [SimpleNamespace(rule_type="in", pattern="*.shopify.com")]

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        steps = [
            SimpleNamespace(
                vuln_class="ssrf",
                suggested_tool="httpx",
                target="api.shopify.com",
                hypothesis="internal fetch via webhook",
            )
        ]
        coordination = {
            "summary": "focus on webhooks",
            "focus_areas": ["ssrf", "idor", "xss", "a", "b", "c", "d"],
            "recommended_tools": ["httpx", "ffuf"],
            "retrieval_hits": [
                {"title": "Writeup A", "source": "corpus", "snippet": "snip a"},
                {"title": "", "source": "", "snippet": ""},
                {"title": "C", "source": "c", "snippet": "c"},
                {"title": "D", "source": "d", "snippet": "d"},
                {"title": "E", "source": "e", "snippet": "e"},
                {"title": "F-dropped", "source": "f", "snippet": "f"},
            ],
            "attack_paths": [
                {"name": "SSRF to metadata", "steps": ["fetch", "read"], "narrative": "n"},
            ],
        }
        calls = _capture_planner(monkeypatch, _FakePlan(steps, coordination))

        result = _invoke(runner, ["plan", "--program", "shopify", "--asset", "api.shopify.com"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Agentic plan: hackerone/shopify" in out
        assert "ssrf" in out and "httpx" in out and "internal fetch" in out
        assert "focus on webhooks" in out
        assert "Focus" in out and "ssrf, idor" in out
        assert "Suggested tools" in out and "httpx, ffuf" in out
        assert "Graph / Knowledge Hits" in out and "Writeup A" in out
        assert "F-dropped" not in out  # only the first five hits are rendered
        assert "Attack Paths" in out and "fetch -> read" in out
        assert calls["scope"] == ["*.shopify.com"]
        assert calls["asset_facts"]["target"] == "api.shopify.com"

    def test_json_output_and_scope_fallback_to_asset(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return []

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        calls = _capture_planner(monkeypatch, _FakePlan())

        result = _invoke(
            runner,
            ["plan", "--program", "shopify", "--asset", "x.shopify.com", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert "plan-json" in out_console.getvalue()
        assert calls["scope"] == ["x.shopify.com"]

    def test_no_coordination_skips_extra_sections(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return []

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        _capture_planner(monkeypatch, _FakePlan(coordination={}))

        result = _invoke(runner, ["plan", "--program", "shopify", "--asset", "x.example"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Agentic plan" in out
        assert "Coordination" not in out
        assert "Attack Paths" not in out


# --------------------------------------------------------------------------- #
# trend
# --------------------------------------------------------------------------- #


_SUMMARY = {
    "total_reports": 3,
    "total_writeups": 2,
    "total_advisories": 1,
    "top_vuln_classes": [{"name": "xss", "count": 4}],
    "top_tech": [{"name": "django", "count": 2}],
    "top_programs": [{"name": "shopify", "count": 5}],
}


def _patch_trends(monkeypatch, captured):
    async def _trends(_s, *, days=7):
        captured["days"] = days
        return dict(_SUMMARY)

    monkeypatch.setattr("netra.bugbounty.learning.trends.summarize_trends", _trends)


class TestTrend:
    def test_text_output_renders_three_bucket_tables(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        captured = {}
        _patch_trends(monkeypatch, captured)

        result = _invoke(runner, ["trend", "--days", "14"])
        assert result.exit_code == 0, result.output
        assert captured["days"] == 14
        # Rich wraps narrow table titles, so compare on whitespace-normalised text.
        out = " ".join(out_console.getvalue().split())
        assert "Learning Trends 14d" in out
        assert "reports=3 writeups=2 advisories=1" in out
        assert "Top Vulnerability Classes" in out and "xss" in out
        assert "Top Tech / Packages" in out and "django" in out
        assert "Top Programs" in out and "shopify" in out

    def test_default_window_is_seven_days(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        captured = {}
        _patch_trends(monkeypatch, captured)
        result = _invoke(runner, ["trend"])
        assert result.exit_code == 0, result.output
        assert captured["days"] == 7
        assert "7d" in out_console.getvalue()

    def test_json_output(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_trends(monkeypatch, {})
        result = _invoke(runner, ["trend", "--json"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert '"total_reports": 3' in out
        assert "Learning Trends" not in out


# --------------------------------------------------------------------------- #
# hunt-explain
# --------------------------------------------------------------------------- #


def _trace_row(step_n, status, tool, rationale, observed):
    return SimpleNamespace(
        step_n=step_n,
        status=status,
        tool_chosen=tool,
        decision_rationale=rationale,
        observations_out=observed,
    )


class TestHuntExplain:
    def test_trace_without_scan_row_still_renders_steps(self, runner, monkeypatch, out_console):
        session = FakeSession(
            rows=[
                _trace_row(1, "done", "httpx", "probe host", {"kind": "http"}),
                _trace_row(2, "skipped", None, None, None),
            ]
        )
        _install_session(monkeypatch, session)
        result = _invoke(runner, ["hunt-explain", "scan-1"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Agentic trace: scan-1" in out
        assert "probe host" in out
        assert "http" in out
        assert "Coordination" not in out

    def test_coordination_from_checkpoint_is_rendered(self, runner, monkeypatch, out_console):
        scan = SimpleNamespace(
            checkpoint_data={
                "agentic_coordination": {
                    "summary": "map auth flows",
                    "focus_areas": ["idor"],
                    "recommended_tools": ["ffuf"],
                    "retrieval_hits": [{"title": "Hit T", "source": "s", "snippet": "sn"}],
                    "attack_paths": [{"name": "AP", "steps": ["one", "two"], "narrative": "nar"}],
                }
            }
        )
        session = FakeSession(by_model={Scan: scan}, rows=[])
        _install_session(monkeypatch, session)
        result = _invoke(runner, ["hunt-explain", "scan-2"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "map auth flows" in out
        assert "Focus" in out and "idor" in out
        assert "Suggested tools" in out and "ffuf" in out
        assert "Graph / Knowledge Hits" in out and "Hit T" in out
        assert "Attack Paths" in out and "one -> two" in out

    def test_scan_without_coordination_prints_only_trace(self, runner, monkeypatch, out_console):
        scan = SimpleNamespace(checkpoint_data=None)
        _install_session(monkeypatch, FakeSession(by_model={Scan: scan}, rows=[]))
        result = _invoke(runner, ["hunt-explain", "scan-3"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Agentic trace: scan-3" in out
        assert "Coordination" not in out


# --------------------------------------------------------------------------- #
# cancel-hunt
# --------------------------------------------------------------------------- #


class TestCancelHunt:
    def test_unknown_scan_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        result = _invoke(runner, ["cancel-hunt", "missing"])
        assert result.exit_code == 1
        assert "scan not found" in out_console.getvalue()

    def test_revokes_celery_task_and_kills_processes(self, runner, monkeypatch, out_console):
        scan = SimpleNamespace(status=ScanStatus.RUNNING, config={"celery_task_id": "task-9"})
        session = FakeSession(by_model={Scan: scan})
        _install_session(monkeypatch, session)

        fake_app = SimpleNamespace(control=Mock())
        monkeypatch.setattr(importlib.import_module("netra.worker.celery_app"), "celery_app", fake_app)
        killed = []
        monkeypatch.setattr(
            "netra.scanner.tools.process_control.kill_registered_processes",
            lambda task_id: killed.append(task_id),
        )

        result = _invoke(runner, ["cancel-hunt", "scan-4"])
        assert result.exit_code == 0, result.output
        fake_app.control.revoke.assert_called_once_with(
            "task-9", terminate=True, signal="SIGKILL"
        )
        assert killed == ["task-9"]
        assert scan.status == ScanStatus.CANCELLED
        assert session.commits == 1
        assert "cancel requested" in out_console.getvalue()

    def test_without_task_id_skips_revoke_but_still_cancels(
        self, runner, monkeypatch, out_console
    ):
        scan = SimpleNamespace(status=ScanStatus.PENDING, config={"celery_task_id": "  "})
        session = FakeSession(by_model={Scan: scan})
        _install_session(monkeypatch, session)

        fake_app = SimpleNamespace(control=Mock())
        monkeypatch.setattr(importlib.import_module("netra.worker.celery_app"), "celery_app", fake_app)

        def _no_kill(_task_id):
            raise AssertionError("no processes should be killed without a task id")

        monkeypatch.setattr("netra.scanner.tools.process_control.kill_registered_processes", _no_kill)

        result = _invoke(runner, ["cancel-hunt", "scan-5"])
        assert result.exit_code == 0, result.output
        fake_app.control.revoke.assert_not_called()
        assert scan.status == ScanStatus.CANCELLED
        assert session.commits == 1


# --------------------------------------------------------------------------- #
# program-approve
# --------------------------------------------------------------------------- #


class TestProgramApprove:
    def test_unknown_program_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, None)
        result = _invoke(
            runner, ["program-approve", "--program", "ghost", "--vuln-classes", "xss"]
        )
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()

    def test_stores_trimmed_classes_and_timestamp(self, runner, monkeypatch, out_console):
        prog = SimpleNamespace(
            handle="shopify", active_classes_approved=None, metadata_={"keep": "me"}
        )
        session = FakeSession()
        _install_session(monkeypatch, session)
        _patch_get_program(monkeypatch, prog)

        result = _invoke(
            runner,
            [
                "program-approve",
                "--program",
                "shopify",
                "--vuln-classes",
                " xss, csrf ,,ssrf ",
            ],
        )
        assert result.exit_code == 0, result.output
        assert prog.active_classes_approved == ["xss", "csrf", "ssrf"]
        assert prog.metadata_["keep"] == "me"
        stamp = prog.metadata_["active_approval_updated_at"]
        assert stamp.endswith("Z") and "T" in stamp
        assert session.commits == 1
        assert "xss, csrf, ssrf" in out_console.getvalue()


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


def _verify_finding(**extra):
    data = dict(
        id=uuid.uuid4(),
        title="Reflected XSS",
        description="desc",
        severity="high",
        url="https://app.example.com/search?q=1",
        tags=["xss"],
        cwe_id=None,
        evidence={},
    )
    data.update(extra)
    return SimpleNamespace(**data)


def _verify_evidence(program_id):
    return SimpleNamespace(id=uuid.uuid4(), program_id=program_id, finding_id=uuid.uuid4())


class _FakePoc:
    calls: list = []

    def __init__(self):
        pass

    async def build(self, finding, evidence, vuln_class):
        type(self).calls.append((finding, evidence, vuln_class))
        return "PoC-BODY"


@pytest.fixture
def verify_env(monkeypatch):
    """Wire up the verify command with a finding, evidence, program and fakes."""
    _FakePoc.calls = []
    program = SimpleNamespace(id=uuid.uuid4(), handle="shopify")
    finding = _verify_finding()
    evidence = _verify_evidence(program.id)
    state = {"find_args": None, "replay_args": None, "replay_result": {}}

    def _find_verifier(verifier_id, vuln_class):
        state["find_args"] = (verifier_id, vuln_class)
        return SimpleNamespace(id=verifier_id, methods=("GET",))

    async def _rules(_s, _pid):
        return []

    async def _replay(evidence_arg, spec, validator, *, vuln_class):
        state["replay_args"] = (evidence_arg, spec, vuln_class)
        return state["replay_result"]

    monkeypatch.setattr("netra.bugbounty.verifiers.loader.find_verifier", _find_verifier)
    monkeypatch.setattr("netra.bugbounty.verifiers.runner.run_replay", _replay)
    monkeypatch.setattr("netra.bugbounty.agentic.poc_builder.PocBuilder", _FakePoc)
    monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
    monkeypatch.setattr("netra.bugbounty.scope.ScopeValidator.from_db_rules", classmethod(lambda cls, rules: object()))

    return SimpleNamespace(
        program=program, finding=finding, evidence=evidence, state=state
    )


class TestVerify:
    def _session(self, monkeypatch, env, *, evidence_rows=None, by_model=None):
        models = {Finding: env.finding, BBProgram: env.program}
        models.update(by_model or {})
        session = FakeSession(
            by_model=models,
            rows=[env.evidence] if evidence_rows is None else evidence_rows,
        )
        _install_session(monkeypatch, session)
        return session

    def test_unknown_finding_exits_1(self, runner, monkeypatch, out_console, verify_env):
        self._session(monkeypatch, verify_env, by_model={Finding: None})
        result = _invoke(runner, ["verify", "--finding-id", "nope"])
        assert result.exit_code == 1
        assert "finding not found" in out_console.getvalue()

    def test_no_evidence_exits_1(self, runner, monkeypatch, out_console, verify_env):
        self._session(monkeypatch, verify_env, evidence_rows=[])
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        assert result.exit_code == 1
        assert "no evidence found" in out_console.getvalue()

    def test_explicit_evidence_id_is_fetched_directly(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(
            monkeypatch,
            verify_env,
            evidence_rows=[],
            by_model={BBEvidenceModel(): verify_env.evidence},
        )
        result = _invoke(
            runner,
            [
                "verify",
                "--finding-id",
                str(verify_env.finding.id),
                "--evidence-id",
                "ev-1",
                "--typed-confirm",
                "shopify",
            ],
        )
        # evidence was found via session.get, so the replay path executes
        assert result.exit_code == 0, result.output
        assert verify_env.state["replay_args"][0] is verify_env.evidence

    def test_missing_program_for_evidence_exits_1(
        self, runner, monkeypatch, out_console, verify_env
    ):
        session = self._session(monkeypatch, verify_env)
        session.by_model.pop(BBProgram)
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        assert result.exit_code == 1
        assert "program not found for this evidence" in out_console.getvalue()

    def test_unallowlisted_verifier_exits_2(self, runner, monkeypatch, out_console, verify_env):
        self._session(monkeypatch, verify_env)
        monkeypatch.setattr(
            "netra.bugbounty.verifiers.loader.find_verifier", lambda _v, _c: None
        )
        result = _invoke(
            runner,
            ["verify", "--finding-id", str(verify_env.finding.id), "--verifier-id", "evil"],
        )
        assert result.exit_code == 2
        assert "verifier not allowlisted" in out_console.getvalue()
        assert verify_env.state["replay_args"] is None

    def test_typed_confirm_mismatch_exits_2_before_replay(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        result = _invoke(
            runner,
            [
                "verify",
                "--finding-id",
                str(verify_env.finding.id),
                "--typed-confirm",
                "wrong-handle",
            ],
        )
        assert result.exit_code == 2
        assert "does not match the program handle" in out_console.getvalue()
        assert verify_env.state["replay_args"] is None

    def test_default_verifier_selected_by_vuln_class(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"status": "completed", "status_code": 200}
        result = _invoke(
            runner,
            ["verify", "--finding-id", str(verify_env.finding.id), "--typed-confirm", "shopify"],
        )
        assert result.exit_code == 0, result.output
        assert verify_env.state["find_args"] == ("xss_reflected_passive", "xss")

    def test_default_verifier_for_other_classes_is_generic(
        self, runner, monkeypatch, out_console, verify_env
    ):
        verify_env.finding.tags = ["idor"]
        self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"status": "completed", "status_code": 204}
        result = _invoke(
            runner,
            ["verify", "--finding-id", str(verify_env.finding.id), "--typed-confirm", "shopify"],
        )
        assert result.exit_code == 0, result.output
        assert verify_env.state["find_args"] == ("generic_read_only_replay", "idor")

    def test_success_persists_replay_and_prints_poc(
        self, runner, monkeypatch, out_console, verify_env
    ):
        session = self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {
            "status": "completed",
            "status_code": 200,
            "latency_ms": 12,
            "diff": {"status_changed": False},
        }
        result = _invoke(
            runner,
            [
                "verify",
                "--finding-id",
                str(verify_env.finding.id),
                "--typed-confirm",
                "shopify",
            ],
        )
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "PoC preview" in out and "PoC-BODY" in out
        assert "completed verifier=xss_reflected_passive status_code=200" in out
        assert len(session.added) == 1
        replay = session.added[0]
        assert isinstance(replay, BBEvidenceReplay)
        assert replay.status == "completed"
        assert replay.status_code == 200
        assert replay.latency_ms == 12
        assert session.commits == 1
        assert _FakePoc.calls[0][2] == "xss"

    def test_failed_replay_prints_error_message(
        self, runner, monkeypatch, out_console, verify_env
    ):
        session = self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"error": "connection reset"}
        result = _invoke(
            runner,
            ["verify", "--finding-id", str(verify_env.finding.id), "--typed-confirm", "shopify"],
        )
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "failed verifier=xss_reflected_passive" in out
        assert "connection reset" in out
        assert session.added[0].status == "failed"
        assert session.added[0].error_message == "connection reset"

    def test_replay_requires_typed_confirmation(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"status": "completed", "status_code": 200}
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        # Intended: no replay without a matching typed confirmation.
        assert verify_env.state["replay_args"] is None
        assert result.exit_code == 2

    def test_refused_without_matching_handle_when_prompted(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        monkeypatch.setattr(bb_cli, "_is_interactive_stdin", lambda: True)
        monkeypatch.setattr("click.prompt", lambda *_a, **_k: "not-the-handle")
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        assert result.exit_code == 2
        assert "does not match the program handle" in out_console.getvalue()
        assert verify_env.state["replay_args"] is None

    def test_proceeds_when_prompted_handle_matches(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"status": "completed", "status_code": 200}
        monkeypatch.setattr(bb_cli, "_is_interactive_stdin", lambda: True)
        monkeypatch.setattr("click.prompt", lambda *_a, **_k: "shopify")
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        assert result.exit_code == 0, result.output
        assert verify_env.state["replay_args"] is not None

    def test_refused_when_not_interactive_without_typed_confirm(
        self, runner, monkeypatch, out_console, verify_env
    ):
        self._session(monkeypatch, verify_env)
        monkeypatch.setattr(bb_cli, "_is_interactive_stdin", lambda: False)

        def _no_prompt(*_a, **_k):
            raise AssertionError("must not prompt when stdin is not interactive")

        monkeypatch.setattr("click.prompt", _no_prompt)
        result = _invoke(runner, ["verify", "--finding-id", str(verify_env.finding.id)])
        assert result.exit_code == 2
        assert "stdin is not interactive" in out_console.getvalue()
        assert verify_env.state["replay_args"] is None
        assert _FakePoc.calls == []

    def test_matching_handle_runs_replay(self, runner, monkeypatch, out_console, verify_env):
        session = self._session(monkeypatch, verify_env)
        verify_env.state["replay_result"] = {"status": "completed", "status_code": 200}
        result = _invoke(
            runner,
            ["verify", "--finding-id", str(verify_env.finding.id), "--typed-confirm", "shopify"],
        )
        assert result.exit_code == 0, result.output
        assert verify_env.state["replay_args"] is not None
        assert len(session.added) == 1


class TestSinceParser:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("24h", timedelta(hours=24)), ("7d", timedelta(days=7)), ("1h", timedelta(hours=1))],
    )
    def test_accepts_hours_and_days(self, value, expected):
        assert bb_cli.parse_since_window(value) == expected

    @pytest.mark.parametrize(
        "value", ["7w", "d", "h", "1.5d", "-1h", "0d", "24", "24hours", " 7d", "7D", ""]
    )
    def test_rejects_other_formats(self, value):
        with pytest.raises(ValueError, match="invalid --since"):
            bb_cli.parse_since_window(value)

    def test_cli_rejects_bad_since_without_touching_db(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["audit", "out-of-scope", "--since", "7w"])
        assert result.exit_code == 2
        assert "invalid --since" in out_console.getvalue()


class _RecordingSession(FakeSession):
    def __init__(self, rows=None):
        super().__init__(rows=rows)
        self.statements: list = []

    async def execute(self, stmt):
        self.statements.append(stmt)
        return _Result(self.rows)


class TestAuditSinceWindow:
    @staticmethod
    def _cutoff_from(session):
        compiled = session.statements[0].compile()
        stamps = [v for v in compiled.params.values() if isinstance(v, datetime)]
        assert len(stamps) == 1, compiled.params
        return stamps[0]

    @pytest.mark.parametrize(
        ("since", "window"), [("24h", timedelta(hours=24)), ("7d", timedelta(days=7))]
    )
    def test_filters_rows_to_window(self, runner, monkeypatch, out_console, since, window):
        session = _RecordingSession(rows=[])
        _install_session(monkeypatch, session)
        before = datetime.now(UTC)
        result = _invoke(runner, ["audit", "out-of-scope", "--since", since])
        after = datetime.now(UTC)
        assert result.exit_code == 0, result.output
        assert "created_at >=" in str(session.statements[0])
        cutoff = self._cutoff_from(session)
        assert before - window <= cutoff <= after - window

    def test_defaults_to_seven_days(self, runner, monkeypatch, out_console):
        session = _RecordingSession(rows=[])
        _install_session(monkeypatch, session)
        result = _invoke(runner, ["audit", "out-of-scope"])
        assert result.exit_code == 0, result.output
        cutoff = self._cutoff_from(session)
        now = datetime.now(UTC)
        expected = now - timedelta(days=7)
        assert expected - timedelta(minutes=1) <= cutoff <= expected + timedelta(minutes=1)


def BBEvidenceModel():
    from netra.db.models.bb_evidence import BBEvidence

    return BBEvidence


# --------------------------------------------------------------------------- #
# scope: --add / --list / --check and error paths
# --------------------------------------------------------------------------- #


class TestScopeBranches:
    def test_unknown_program_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, None)
        result = _invoke(runner, ["scope", "--program", "ghost", "--list"])
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()

    def test_add_rule_passes_all_options_and_commits(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        prog = SimpleNamespace(id=uuid.uuid4(), handle="shopify")
        _patch_get_program(monkeypatch, prog)
        captured = {}

        async def _add(_s, program, **kwargs):
            captured["program"] = program
            captured.update(kwargs)
            return SimpleNamespace(rule_type="out", asset_type="domain", pattern="blog.shopify.com")

        monkeypatch.setattr("netra.bugbounty.programs.add_scope_rule", _add)

        result = _invoke(
            runner,
            [
                "scope",
                "--program",
                "shopify",
                "--add",
                "blog.shopify.com",
                "--rule-type",
                "out",
                "--asset-type",
                "domain",
                "--severity-cap",
                "low",
            ],
        )
        assert result.exit_code == 0, result.output
        assert captured["program"] is prog
        assert captured["pattern"] == "blog.shopify.com"
        assert captured["rule_type"] == "out"
        assert captured["asset_type"] == "domain"
        assert captured["severity_cap"] == "low"
        assert session.commits == 1
        assert "scope rule added" in out_console.getvalue()
        assert "blog.shopify.com" in out_console.getvalue()

    def test_list_renders_in_and_out_rules(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return [
                SimpleNamespace(
                    rule_type="in", asset_type="wildcard", pattern="*.shopify.com", severity_cap=None
                ),
                SimpleNamespace(
                    rule_type="out", asset_type="domain", pattern="blog.shopify.com", severity_cap="low"
                ),
            ]

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        result = _invoke(runner, ["scope", "--program", "shopify", "--list"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "Scope rules for hackerone/shopify" in out
        assert "*.shopify.com" in out and "blog.shopify.com" in out
        assert "low" in out

    def test_check_reports_in_and_out_of_scope(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return [
                SimpleNamespace(
                    rule_type="in",
                    asset_type="wildcard",
                    pattern="*.shopify.com",
                    severity_cap=None,
                    notes=None,
                    active=True,
                )
            ]

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)

        result = _invoke(
            runner, ["scope", "--program", "shopify", "--check", "api.shopify.com"]
        )
        assert result.exit_code == 0, result.output
        assert "in scope" in out_console.getvalue()

        out_console.seek(0)
        out_console.truncate()
        result = _invoke(runner, ["scope", "--program", "shopify", "--check", "evil.example"])
        assert result.exit_code == 0, result.output
        assert "out of scope" in out_console.getvalue()

    def test_no_action_prints_hint(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _patch_get_program(monkeypatch, SimpleNamespace(id=uuid.uuid4(), handle="shopify"))

        async def _rules(_s, _pid):
            return []

        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        result = _invoke(runner, ["scope", "--program", "shopify"])
        assert result.exit_code == 0, result.output
        assert "Pass --check <target> or --list." in out_console.getvalue()


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #


def test_main_invokes_the_bb_group(monkeypatch):
    seen = {}
    monkeypatch.setattr(bb_cli, "bb", lambda: seen.setdefault("called", True))
    bb_cli.main()
    assert seen == {"called": True}
