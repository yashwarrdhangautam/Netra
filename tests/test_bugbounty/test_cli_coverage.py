"""Coverage tests for the NETRA-BB CLI command groups not exercised elsewhere.

Covers submission status/list/verdict, draft, triage, audit out-of-scope,
graphify index-codebase, and hunt flag validation.

All database access is replaced by an in-memory fake session, all services are
stubbed, and nothing touches the network or spawns Graphify / tool subprocesses.
Filesystem writes are confined to pytest's tmp_path.
"""

from __future__ import annotations

import io
import json
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from rich.console import Console

from netra.bugbounty import cli as bb_cli
from netra.bugbounty.graph_indexer import IndexResult
from netra.db.models.bb_submission import SubmissionStatus

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


class _FakeScalars:
    def __init__(self, rows):
        self._rows = list(rows)

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class FakeSession:
    """Minimal stand-in for AsyncSession used by the CLI commands."""

    def __init__(self, objects=None, rows=None):
        self.objects = dict(objects or {})
        self.rows = list(rows or [])
        self.commits = 0
        self.flushes = 0
        self.statements = []

    async def get(self, _model, key):
        return self.objects.get(key)

    async def execute(self, stmt):
        self.statements.append(stmt)
        return _FakeResult(self.rows)

    async def commit(self):
        self.commits += 1

    async def flush(self):
        self.flushes += 1


def _install_session(monkeypatch, session: FakeSession) -> None:
    @asynccontextmanager
    async def _fake_get_session():
        yield session

    monkeypatch.setattr("netra.db.engine.get_session", _fake_get_session)


def _forbid_db(monkeypatch) -> None:
    """Make any attempt to open a DB session fail the test."""

    def _boom():
        raise AssertionError("DB must not be touched for this path")

    monkeypatch.setattr("netra.db.engine.get_session", _boom)


@pytest.fixture
def out_console(monkeypatch):
    """Route the module-level rich console into a buffer so output can be asserted."""
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
    return runner.invoke(bb_cli.bb, args, catch_exceptions=True)


def _submission(status: SubmissionStatus | str, **extra):
    data = dict(
        id="sub-1",
        status=status,
        title="Reflected XSS in search",
        severity="high",
        payout_expected=500,
        payout_actual=None,
        submitted_at=None,
        verdict_at=None,
        verdict_notes=None,
        metadata_={"vuln_class": "xss"},
        program_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
    )
    data.update(extra)
    return SimpleNamespace(**data)


# --------------------------------------------------------------------------- #
# hunt: flag validation
# --------------------------------------------------------------------------- #


class TestHuntFlagValidation:
    @pytest.mark.parametrize("flag", ["--enable-nuclei", "--enable-ffuf"])
    def test_active_only_flags_rejected_on_passive_profile(
        self, runner, monkeypatch, out_console, flag
    ):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["hunt", "--program", "shopify", "--profile", "passive", flag])
        assert result.exit_code == 2
        assert "require --profile active" in out_console.getvalue()

    def test_active_only_flag_rejected_when_profile_defaults_to_passive(
        self, runner, monkeypatch, out_console
    ):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["hunt", "--program", "shopify", "--enable-nuclei"])
        assert result.exit_code == 2

    @pytest.mark.parametrize("flag", ["--dry-run", "--plan-only"])
    def test_dry_run_and_plan_only_require_agentic(self, runner, monkeypatch, out_console, flag):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["hunt", "--program", "shopify", flag])
        assert result.exit_code == 2
        assert "require --agentic" in out_console.getvalue()

    def test_active_profile_with_nuclei_passes_validation(self, runner, monkeypatch, out_console):
        # Validation passes; the next failure is the program lookup (no DB here).
        session = FakeSession()
        _install_session(monkeypatch, session)

        async def _no_program(_s, _platform, _handle):
            return None

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _no_program)
        result = _invoke(
            runner,
            ["hunt", "--program", "shopify", "--profile", "active", "--enable-nuclei"],
        )
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()

    def test_hunt_queues_scan_with_flags_passed_through(self, runner, monkeypatch, out_console):
        session = FakeSession()
        _install_session(monkeypatch, session)
        prog = SimpleNamespace(id=uuid.uuid4(), handle="shopify", platform="hackerone")

        async def _get_program(_s, _platform, _handle):
            return prog

        captured = {}

        class _FakeScanService:
            def __init__(self, db):
                captured["db"] = db

            async def create_bugbounty_scan(self, **kwargs):
                captured.update(kwargs)
                return SimpleNamespace(id="scan-42")

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _get_program)
        monkeypatch.setattr("netra.services.scan_service.ScanService", _FakeScanService)

        result = _invoke(
            runner,
            [
                "hunt",
                "--program",
                "shopify",
                "--profile",
                "active",
                "--enable-nuclei",
                "--enable-ffuf",
                "--agentic",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert captured["db"] is session
        assert captured["program"] is prog
        assert captured["profile"] == "active"
        assert captured["enable_nuclei"] is True
        assert captured["enable_ffuf"] is True
        assert captured["agentic"] is True
        assert captured["dry_run"] is True
        assert captured["enqueue"] is True
        out = out_console.getvalue()
        assert "queued" in out
        assert "scan-42" in out
        assert "profile=bugbounty_active" in out
        assert "mode=agentic" in out
        assert "dry-run" in out

    def test_hunt_unknown_program_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())

        async def _no_program(_s, _platform, _handle):
            return None

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _no_program)
        result = _invoke(runner, ["hunt", "--program", "ghost"])
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()

    def test_plan_only_prints_plan_with_in_scope_patterns(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        prog = SimpleNamespace(id=uuid.uuid4(), handle="shopify", platform="hackerone")

        async def _get_program(_s, _platform, _handle):
            return prog

        async def _rules(_s, _program_id):
            return [
                SimpleNamespace(rule_type="in", pattern="*.shopify.com"),
                SimpleNamespace(rule_type="out", pattern="blog.shopify.com"),
            ]

        calls = {}

        class _FakePlanner:
            async def make_plan(self, asset_facts, scope, corpus_hits):
                calls["scope"] = scope
                calls["asset_facts"] = asset_facts
                return SimpleNamespace(to_dict=lambda: {"steps": [], "marker": "plan-ok"})

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _get_program)
        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        monkeypatch.setattr("netra.bugbounty.agentic.planner.Planner", _FakePlanner)

        result = _invoke(runner, ["hunt", "--program", "shopify", "--agentic", "--plan-only"])
        assert result.exit_code == 0, result.output
        assert calls["scope"] == ["*.shopify.com"]
        assert calls["asset_facts"]["program_handle"] == "shopify"
        assert "plan-ok" in out_console.getvalue()

    def test_plan_only_falls_back_to_handle_when_no_in_scope_rules(
        self, runner, monkeypatch, out_console
    ):
        _install_session(monkeypatch, FakeSession())
        prog = SimpleNamespace(id=uuid.uuid4(), handle="shopify", platform="hackerone")

        async def _get_program(_s, _platform, _handle):
            return prog

        async def _rules(_s, _program_id):
            return []

        calls = {}

        class _FakePlanner:
            async def make_plan(self, asset_facts, scope, corpus_hits):
                calls["scope"] = scope
                return SimpleNamespace(to_dict=lambda: {})

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _get_program)
        monkeypatch.setattr("netra.bugbounty.programs.get_active_scope_rules", _rules)
        monkeypatch.setattr("netra.bugbounty.agentic.planner.Planner", _FakePlanner)

        result = _invoke(runner, ["hunt", "--program", "shopify", "--agentic", "--plan-only"])
        assert result.exit_code == 0, result.output
        assert calls["scope"] == ["shopify"]


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #


def _finding(title, composite, *, verdict=None, url="https://app.example.com/search?q=1"):
    ai = {"bounty_hunter": {"composite": composite, "tier": "high"}}
    if verdict is not None:
        ai["skeptic"] = {"verdict": verdict}
    return SimpleNamespace(
        ai_analysis=ai,
        tags=["xss"],
        cwe_id=None,
        title=title,
        url=url,
        parameter="q",
        severity="high",
    )


class TestTriage:
    def _patch(self, monkeypatch, findings, *, dup_for=None, graph_similar=False):
        session = FakeSession(rows=findings)
        _install_session(monkeypatch, session)
        prog = SimpleNamespace(id=uuid.uuid4(), handle="shopify", platform="hackerone")

        async def _get_program(_s, _platform, _handle):
            return prog

        async def _is_duplicate(_s, _program_id, fp):
            if dup_for is not None and fp.hash() == dup_for:
                return SimpleNamespace(finding_id=uuid.UUID(int=1))
            return None

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _get_program)
        monkeypatch.setattr("netra.bugbounty.triage.deduper.is_duplicate", _is_duplicate)
        monkeypatch.setattr(
            "netra.bugbounty.triage.deduper.find_graph_similar",
            lambda *_args, **_kwargs: graph_similar,
        )
        return session

    def test_ranks_by_composite_score_descending(self, runner, monkeypatch, out_console):
        self._patch(
            monkeypatch,
            [_finding("low one", 2.0), _finding("high one", 9.1), _finding("mid one", 5.5)],
        )
        result = _invoke(runner, ["triage", "--program", "shopify"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert out.index("high one") < out.index("mid one") < out.index("low one")
        assert "9.1" in out

    def test_false_positive_hidden_unless_show_vetoed(self, runner, monkeypatch, out_console):
        findings = [
            _finding("real bug", 4.0),
            _finding("vetoed bug", 8.0, verdict="false_positive"),
        ]
        self._patch(monkeypatch, findings)
        result = _invoke(runner, ["triage", "--program", "shopify"])
        assert result.exit_code == 0
        assert "vetoed bug" not in out_console.getvalue()

        out_console.seek(0)
        out_console.truncate()
        self._patch(monkeypatch, findings)
        result = _invoke(runner, ["triage", "--program", "shopify", "--show-vetoed"])
        assert result.exit_code == 0
        assert "vetoed bug" in out_console.getvalue()

    def test_limit_caps_rows(self, runner, monkeypatch, out_console):
        self._patch(monkeypatch, [_finding(f"bug {i}", float(i)) for i in range(5)])
        result = _invoke(runner, ["triage", "--program", "shopify", "--limit", "2"])
        assert result.exit_code == 0
        out = out_console.getvalue()
        assert "bug 4" in out and "bug 3" in out
        assert "bug 1" not in out and "bug 0" not in out

    def test_dedup_column_reports_duplicate_and_similar(self, runner, monkeypatch, out_console):
        finding = _finding("dup bug", 7.0)
        # Compute the fingerprint the CLI will compute so the fake can match it.
        from urllib.parse import urlparse

        from netra.bugbounty.triage.deduper import fingerprint

        url = finding.url
        fp = fingerprint("xss", urlparse(url).path or url, "q").hash()
        self._patch(monkeypatch, [finding], dup_for=fp, graph_similar=True)
        result = _invoke(runner, ["triage", "--program", "shopify", "--graph-aware"])
        assert result.exit_code == 0
        assert "dup of 00000000" in out_console.getvalue()

    def test_graph_aware_marks_similar_when_not_duplicate(self, runner, monkeypatch, out_console):
        self._patch(monkeypatch, [_finding("sim bug", 3.0)], graph_similar=True)
        result = _invoke(runner, ["triage", "--program", "shopify", "--graph-aware"])
        assert result.exit_code == 0
        assert "similar" in out_console.getvalue()

    def test_new_dedup_status_without_graph_flag(self, runner, monkeypatch, out_console):
        self._patch(monkeypatch, [_finding("fresh bug", 3.0)], graph_similar=True)
        result = _invoke(runner, ["triage", "--program", "shopify"])
        assert result.exit_code == 0
        out = out_console.getvalue()
        assert "new" in out
        assert "similar" not in out

    def test_unknown_program_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())

        async def _no_program(_s, _platform, _handle):
            return None

        monkeypatch.setattr("netra.bugbounty.programs.get_program", _no_program)
        result = _invoke(runner, ["triage", "--program", "ghost"])
        assert result.exit_code == 1
        assert "program not found" in out_console.getvalue()


# --------------------------------------------------------------------------- #
# audit out-of-scope
# --------------------------------------------------------------------------- #


class TestAuditOutOfScope:
    def test_lists_blocked_phases_with_reason_fallback(self, runner, monkeypatch, out_console):
        phases = [
            SimpleNamespace(
                created_at="2026-11-10T10:00:00",
                phase_type="recon",
                tool_outputs={"target": "evil.example.org", "reason": "not in scope"},
                error_message=None,
            ),
            SimpleNamespace(
                created_at="2026-11-10T11:00:00",
                phase_type="httpx",
                tool_outputs={"target": "cdn.other.net"},
                error_message="ScopeViolation: host blocked",
            ),
        ]
        session = FakeSession(rows=phases)
        _install_session(monkeypatch, session)

        result = _invoke(runner, ["audit", "out-of-scope", "--since", "7d", "--limit", "5"])
        assert result.exit_code == 0, result.output
        out = out_console.getvalue()
        assert "evil.example.org" in out
        assert "not in scope" in out
        assert "cdn.other.net" in out
        assert "ScopeViolation: host blocked" in out
        assert "7d" in out

        # The query must filter on BLOCKED phases and honour --limit.
        compiled = str(session.statements[0].compile(compile_kwargs={"literal_binds": True}))
        assert "LIMIT 5" in compiled
        assert "blocked" in compiled.lower()

    def test_empty_audit_renders_table_without_rows(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession(rows=[]))
        result = _invoke(runner, ["audit", "out-of-scope"])
        assert result.exit_code == 0
        assert "Out-of-scope audit" in out_console.getvalue()


# --------------------------------------------------------------------------- #
# submission list / status / verdict
# --------------------------------------------------------------------------- #


class _FakeSubmissionService:
    last_status = "unset"
    rows: list = []

    def __init__(self, _db):
        pass

    async def list_submissions(self, status=None):
        type(self).last_status = status
        return list(type(self).rows)


class TestSubmissionList:
    def test_lists_rows_and_passes_status_filter(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _FakeSubmissionService.rows = [
            _submission(SubmissionStatus.DRAFT, title="A" * 100),
            _submission("sent", payout_expected=None),
        ]
        monkeypatch.setattr(
            "netra.services.bb_submission_service.BBSubmissionService", _FakeSubmissionService
        )
        result = _invoke(runner, ["submission", "list", "--status", "draft"])
        assert result.exit_code == 0, result.output
        assert _FakeSubmissionService.last_status == "draft"
        out = out_console.getvalue()
        assert "Bug Bounty Submissions" in out
        assert "A" * 80 in out
        assert "A" * 81 not in out  # title truncated to 80 chars

    def test_list_without_filter_passes_none(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        _FakeSubmissionService.rows = []
        monkeypatch.setattr(
            "netra.services.bb_submission_service.BBSubmissionService", _FakeSubmissionService
        )
        result = _invoke(runner, ["submission", "list"])
        assert result.exit_code == 0
        assert _FakeSubmissionService.last_status is None


class TestSubmissionStatus:
    def test_valid_transition_commits_and_reports(self, runner, monkeypatch, out_console):
        sub = _submission(SubmissionStatus.DRAFT)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(
            runner,
            ["submission", "status", "sub-1", "ready_to_send", "--notes", "checked PoC"],
        )
        assert result.exit_code == 0, result.output
        assert sub.status == SubmissionStatus.READY_TO_SEND
        assert sub.verdict_notes == "checked PoC"
        assert session.commits == 1
        assert "updated" in out_console.getvalue()

    def test_invalid_transition_exits_2_without_commit(self, runner, monkeypatch, out_console):
        sub = _submission(SubmissionStatus.DRAFT)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(runner, ["submission", "status", "sub-1", "sent"])
        assert result.exit_code == 2
        assert "Invalid submission transition" in out_console.getvalue()
        assert session.commits == 0

    def test_terminal_state_cannot_transition(self, runner, monkeypatch, out_console):
        sub = _submission(SubmissionStatus.RESOLVED_PAID)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(runner, ["submission", "status", "sub-1", "triaging"])
        assert result.exit_code == 2
        assert session.commits == 0

    def test_unknown_submission_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        result = _invoke(runner, ["submission", "status", "missing", "sent"])
        assert result.exit_code == 1
        assert "submission not found" in out_console.getvalue()

    def test_unknown_status_string_exits_2_with_valid_list(self, runner, monkeypatch, out_console):
        sub = _submission(SubmissionStatus.DRAFT)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(runner, ["submission", "status", "sub-1", "bogus"])
        assert result.exit_code == 2
        assert isinstance(result.exception, SystemExit)
        out = out_console.getvalue()
        assert "invalid status" in out
        for status in SubmissionStatus:
            assert status.value in out
        assert sub.status == SubmissionStatus.DRAFT
        assert session.commits == 0


class TestSubmissionVerdict:
    @pytest.mark.parametrize(
        ("verdict", "expected"),
        [
            ("paid", SubmissionStatus.RESOLVED_PAID),
            ("dup", SubmissionStatus.RESOLVED_DUP),
            ("na", SubmissionStatus.RESOLVED_NA),
            ("info", SubmissionStatus.RESOLVED_INFORMATIVE),
        ],
    )
    def test_verdict_maps_to_resolved_status(
        self, runner, monkeypatch, out_console, tmp_path, verdict, expected
    ):
        monkeypatch.chdir(tmp_path)
        sub = _submission(SubmissionStatus.TRIAGING)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(
            runner,
            ["submission", "verdict", "sub-1", verdict, "--payout-actual", "750", "--notes", "ok"],
        )
        assert result.exit_code == 0, result.output
        assert sub.status == expected
        assert sub.payout_actual == 750
        assert sub.verdict_notes == "ok"
        assert sub.verdict_at is not None
        assert session.commits == 1
        assert "recorded" in out_console.getvalue()

        history = json.loads((tmp_path / "data/graphify/submissions.json").read_text())
        assert len(history) == 1
        assert history[0]["id"] == "sub-1"
        assert history[0]["attrs"]["vuln_class"] == "xss"
        assert history[0]["attrs"]["status"] == expected.value

    def test_verdict_merges_into_existing_history(self, runner, monkeypatch, out_console, tmp_path):
        monkeypatch.chdir(tmp_path)
        history_file = tmp_path / "data/graphify/submissions.json"
        history_file.parent.mkdir(parents=True)
        older = {"id": "sub-0", "type": "submission", "attrs": {"title": "old"}, "edges": []}
        stale = {"id": "sub-1", "type": "submission", "attrs": {"title": "stale"}, "edges": []}
        history_file.write_text(json.dumps([older, stale]))

        sub = _submission(SubmissionStatus.TRIAGING)
        _install_session(monkeypatch, FakeSession(objects={"sub-1": sub}))
        result = _invoke(runner, ["submission", "verdict", "sub-1", "na"])
        assert result.exit_code == 0, result.output

        history = json.loads(history_file.read_text())
        assert [r["id"] for r in history] == ["sub-0", "sub-1"]
        assert history[0] == older  # unrelated history preserved
        assert history[1]["attrs"]["title"] == "Reflected XSS in search"  # replaced

    def test_verdict_starts_history_when_file_missing(
        self, runner, monkeypatch, out_console, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        sub = _submission(SubmissionStatus.TRIAGING)
        _install_session(monkeypatch, FakeSession(objects={"sub-1": sub}))
        result = _invoke(runner, ["submission", "verdict", "sub-1", "na"])
        assert result.exit_code == 0, result.output
        assert "starting a new history" in out_console.getvalue()
        history = json.loads((tmp_path / "data/graphify/submissions.json").read_text())
        assert [r["id"] for r in history] == ["sub-1"]

    def test_verdict_recovers_from_unreadable_history(
        self, runner, monkeypatch, out_console, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        history_file = tmp_path / "data/graphify/submissions.json"
        history_file.parent.mkdir(parents=True)
        history_file.write_text("{not json")

        sub = _submission(SubmissionStatus.TRIAGING)
        _install_session(monkeypatch, FakeSession(objects={"sub-1": sub}))
        result = _invoke(runner, ["submission", "verdict", "sub-1", "na"])
        assert result.exit_code == 0, result.output
        assert "starting from an empty history" in out_console.getvalue()
        history = json.loads(history_file.read_text())
        assert [r["id"] for r in history] == ["sub-1"]

    def test_verdict_from_draft_is_rejected_by_state_machine(
        self, runner, monkeypatch, out_console, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        sub = _submission(SubmissionStatus.DRAFT)
        session = FakeSession(objects={"sub-1": sub})
        _install_session(monkeypatch, session)

        result = _invoke(
            runner, ["submission", "verdict", "sub-1", "paid", "--payout-actual", "999"]
        )
        assert result.exit_code == 2
        assert isinstance(result.exception, SystemExit)
        assert "Invalid submission transition" in out_console.getvalue()
        assert session.commits == 0
        assert sub.status == SubmissionStatus.DRAFT
        assert sub.payout_actual is None  # not touched by the rejected verdict
        assert not (tmp_path / "data/graphify/submissions.json").exists()

    def test_verdict_unknown_submission_exits_1(self, runner, monkeypatch, out_console):
        _install_session(monkeypatch, FakeSession())
        result = _invoke(runner, ["submission", "verdict", "missing", "paid"])
        assert result.exit_code == 1
        assert "submission not found" in out_console.getvalue()

    def test_verdict_rejects_unknown_choice(self, runner, monkeypatch, out_console):
        _forbid_db(monkeypatch)
        result = _invoke(runner, ["submission", "verdict", "sub-1", "maybe"])
        assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# draft
# --------------------------------------------------------------------------- #


class _FakeDraftService:
    calls: list = []
    raise_duplicate = False

    def __init__(self, _db):
        pass

    async def create_draft(self, finding, out, *, formats, force, include_poc):
        from netra.services.bb_submission_service import DuplicateFindingError

        type(self).calls.append(
            dict(finding=finding, out=out, formats=formats, force=force, include_poc=include_poc)
        )
        if type(self).raise_duplicate:
            raise DuplicateFindingError("finding is a duplicate; pass --force to draft anyway")
        paths = {fmt: out / f"draft.{fmt}" for fmt in formats}
        return SimpleNamespace(id="sub-9"), paths


class TestDraft:
    def _setup(self, monkeypatch, finding=None):
        _FakeDraftService.calls = []
        _FakeDraftService.raise_duplicate = False
        session = FakeSession(objects={"f-1": finding} if finding is not None else {})
        _install_session(monkeypatch, session)
        monkeypatch.setattr(
            "netra.services.bb_submission_service.BBSubmissionService", _FakeDraftService
        )
        return session

    def test_draft_writes_requested_formats_via_service(
        self, runner, monkeypatch, out_console, tmp_path
    ):
        finding = SimpleNamespace(id="f-1")
        self._setup(monkeypatch, finding)
        result = _invoke(
            runner,
            [
                "draft",
                "--finding-id",
                "f-1",
                "--output",
                str(tmp_path / "reports"),
                "--format",
                "md",
                "--format",
                "pdf",
                "--include-poc",
                "--force",
            ],
        )
        assert result.exit_code == 0, result.output
        call = _FakeDraftService.calls[0]
        assert call["finding"] is finding
        assert call["out"] == tmp_path / "reports"
        assert tuple(call["formats"]) == ("md", "pdf")
        assert call["force"] is True
        assert call["include_poc"] is True
        out = out_console.getvalue()
        assert "drafted" in out and "sub-9" in out
        assert "md:" in out and "pdf:" in out

    def test_draft_defaults_to_md_and_docx_in_home_reports(self, runner, monkeypatch, out_console):
        self._setup(monkeypatch, SimpleNamespace(id="f-1"))
        result = _invoke(runner, ["draft", "--finding-id", "f-1"])
        assert result.exit_code == 0, result.output
        call = _FakeDraftService.calls[0]
        assert tuple(call["formats"]) == ("md", "docx")
        assert call["out"] == Path.home() / "reports"
        assert call["force"] is False
        assert call["include_poc"] is False

    def test_draft_duplicate_exits_2(self, runner, monkeypatch, out_console):
        self._setup(monkeypatch, SimpleNamespace(id="f-1"))
        _FakeDraftService.raise_duplicate = True
        result = _invoke(runner, ["draft", "--finding-id", "f-1"])
        assert result.exit_code == 2
        assert "duplicate" in out_console.getvalue()

    def test_draft_unknown_finding_exits_1(self, runner, monkeypatch, out_console):
        self._setup(monkeypatch, finding=None)
        result = _invoke(runner, ["draft", "--finding-id", "nope"])
        assert result.exit_code == 1
        assert "finding not found" in out_console.getvalue()
        assert _FakeDraftService.calls == []

    def test_draft_rejects_unsupported_format(self, runner, monkeypatch, out_console):
        self._setup(monkeypatch, SimpleNamespace(id="f-1"))
        result = _invoke(runner, ["draft", "--finding-id", "f-1", "--format", "html"])
        assert result.exit_code == 2
        assert _FakeDraftService.calls == []


# --------------------------------------------------------------------------- #
# graphify index-codebase
# --------------------------------------------------------------------------- #


class TestGraphifyIndexCodebase:
    def test_success_reports_output_dir(self, runner, monkeypatch, out_console, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        out_dir = tmp_path / "out"
        seen = {}

        async def _index(src_root, output_dir, **_kwargs):
            seen["src"] = src_root
            seen["out"] = output_dir
            return IndexResult(
                target=str(src_root), output_dir=output_dir, nodes=3, edges=2, success=True
            )

        monkeypatch.setattr("netra.bugbounty.graph_indexer.index_codebase", _index)
        result = _invoke(
            runner,
            ["graphify", "index-codebase", "--src-root", str(src), "--output", str(out_dir)],
        )
        assert result.exit_code == 0, result.output
        assert seen["src"] == src
        assert seen["out"] == out_dir
        assert "indexed" in out_console.getvalue()

    def test_failure_exits_1_with_error(self, runner, monkeypatch, out_console, tmp_path):
        src = tmp_path / "src"
        src.mkdir()

        async def _index(src_root, output_dir, **_kwargs):
            return IndexResult(
                target=str(src_root),
                output_dir=output_dir,
                nodes=0,
                edges=0,
                success=False,
                error="graphify not installed",
            )

        monkeypatch.setattr("netra.bugbounty.graph_indexer.index_codebase", _index)
        result = _invoke(
            runner,
            [
                "graphify",
                "index-codebase",
                "--src-root",
                str(src),
                "--output",
                str(tmp_path / "out"),
            ],
        )
        assert result.exit_code == 1
        out = out_console.getvalue()
        assert "graphify failed/skipped" in out
        assert "graphify not installed" in out

    def test_missing_src_root_rejected_before_indexing(
        self, runner, monkeypatch, out_console, tmp_path
    ):
        called = []

        async def _index(*_a, **_k):
            called.append(True)  # pragma: no cover - must not run

        monkeypatch.setattr("netra.bugbounty.graph_indexer.index_codebase", _index)
        result = _invoke(
            runner,
            [
                "graphify",
                "index-codebase",
                "--src-root",
                str(tmp_path / "does-not-exist"),
                "--output",
                str(tmp_path / "out"),
            ],
        )
        assert result.exit_code == 2
        assert called == []
