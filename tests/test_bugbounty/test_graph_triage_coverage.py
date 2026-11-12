"""Coverage tests for graph_indexer, triage/deduper and triage/bounty_persona.

All Graphify CLI calls are mocked; no real subprocess, LLM or network is used.

Known source defects are recorded as strict xfail tests so the suite stays green
while the defect remains visible. Source files are intentionally not modified.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from netra.bugbounty import graph_indexer
from netra.bugbounty.graph_indexer import (
    GraphifyNotAvailable,
    IndexResult,
    export_submissions_json,
    index_codebase,
    index_recon_output,
)
from netra.bugbounty.triage import deduper
from netra.bugbounty.triage.bounty_persona import (
    BOUNTY_HUNTER_PROMPT,
    BountyScore,
    parse_response,
)
from netra.bugbounty.triage.deduper import (
    DedupFingerprint,
    find_graph_similar,
    fingerprint,
    is_duplicate,
    normalise_path,
    record_signature,
)
from netra.db.models.bb_dedup_signature import BBDedupSignature

# ---------------------------------------------------------------------------
# graph_indexer
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, pid: int = 4242, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
        self.pid = pid
        self.returncode = returncode
        self._out = stdout
        self._err = stderr

    async def communicate(self):
        return self._out, self._err


def test_check_available_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: None)
    with pytest.raises(GraphifyNotAvailable, match="graphify CLI not found"):
        graph_indexer._check_available()


def test_check_available_returns_binary_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: "/usr/bin/graphify")
    assert graph_indexer._check_available() == "/usr/bin/graphify"


@pytest.mark.asyncio
async def test_run_graphify_passes_args_and_registers_pid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: "graphify-bin")
    captured: dict = {}

    async def fake_exec(binary, *args, **kwargs):
        captured["binary"] = binary
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProc(pid=777, returncode=3, stdout=b"hello \xff", stderr=b"oops")

    registered: list[int] = []
    unregistered: list[int] = []
    monkeypatch.setattr(graph_indexer.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(graph_indexer, "register_process", lambda pid: registered.append(pid))
    monkeypatch.setattr(graph_indexer, "unregister_process", lambda pid: unregistered.append(pid))

    rc, out, err = await graph_indexer._run_graphify(["extract", "x"], cwd=tmp_path)

    assert captured["binary"] == "graphify-bin"
    assert captured["args"] == ("extract", "x")
    assert captured["kwargs"]["cwd"] == str(tmp_path)
    assert "creationflags" in captured["kwargs"] or "start_new_session" in captured["kwargs"]
    assert rc == 3
    assert out.startswith("hello ")  # invalid utf-8 is replaced, not raised
    assert err == "oops"
    assert registered == [777]
    assert unregistered == [777]


@pytest.mark.asyncio
async def test_run_graphify_unregisters_even_when_communicate_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: "graphify-bin")

    class _Boom(_FakeProc):
        async def communicate(self):
            raise RuntimeError("pipe broke")

    async def fake_exec(binary, *args, **kwargs):
        return _Boom(pid=99)

    unregistered: list[int] = []
    monkeypatch.setattr(graph_indexer.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(graph_indexer, "register_process", lambda pid: None)
    monkeypatch.setattr(graph_indexer, "unregister_process", lambda pid: unregistered.append(pid))

    with pytest.raises(RuntimeError, match="pipe broke"):
        await graph_indexer._run_graphify(["extract"])
    assert unregistered == [99]


@pytest.mark.asyncio
async def test_run_graphify_never_spawns_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: None)
    spawn = AsyncMock()
    monkeypatch.setattr(graph_indexer.asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(GraphifyNotAvailable):
        await graph_indexer._run_graphify(["extract"])
    spawn.assert_not_awaited()


@pytest.mark.asyncio
async def test_index_codebase_rejects_unsupported_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported output_format: neo4j"):
        await index_codebase(tmp_path, tmp_path / "out", output_format="neo4j")


@pytest.mark.asyncio
async def test_index_codebase_success_parses_graph_counts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("print(1)")
    out = tmp_path / "out"

    async def fake_run(args, cwd=None):
        assert args[0] == "extract"
        assert args[1] == str(src)
        assert args[args.index("--out") + 1] == str(out)
        graph_dir = out / "graphify-out"
        graph_dir.mkdir(parents=True, exist_ok=True)
        (graph_dir / "graph.json").write_text(
            json.dumps({"nodes": [{"id": 1}, {"id": 2}], "links": [{"s": 1, "t": 2}]})
        )
        return 0, "", ""

    monkeypatch.setattr(graph_indexer, "_run_graphify", fake_run)
    monkeypatch.delenv("GRAPHIFY_BACKEND", raising=False)

    result = await index_codebase(src, out)

    assert isinstance(result, IndexResult)
    assert result.success is True
    assert result.error is None
    assert result.nodes == 2
    assert result.edges == 1
    assert (out / ".netra_graphify_mtime").exists()


@pytest.mark.asyncio
async def test_index_codebase_uses_backend_env_and_edges_fallback_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    out = tmp_path / "out"
    seen_args: list[str] = []

    async def fake_run(args, cwd=None):
        seen_args.extend(args)
        (out / "graphify-out").mkdir(parents=True, exist_ok=True)
        (out / "graphify-out" / "graph.json").write_text(json.dumps({"nodes": [], "edges": [{}, {}, {}]}))
        return 0, "", ""

    monkeypatch.setattr(graph_indexer, "_run_graphify", fake_run)
    monkeypatch.setenv("GRAPHIFY_BACKEND", "openai")

    result = await index_codebase(src, out)

    assert seen_args[seen_args.index("--backend") + 1] == "openai"
    assert result.nodes == 0
    assert result.edges == 3


@pytest.mark.asyncio
async def test_index_codebase_tolerates_corrupt_graph_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    out = tmp_path / "out"

    async def fake_run(args, cwd=None):
        (out / "graphify-out").mkdir(parents=True, exist_ok=True)
        (out / "graphify-out" / "graph.json").write_text("{not json")
        return 0, "", ""

    monkeypatch.setattr(graph_indexer, "_run_graphify", fake_run)
    result = await index_codebase(src, out)
    assert result.success is True
    assert (result.nodes, result.edges) == (0, 0)


@pytest.mark.asyncio
async def test_index_codebase_nonzero_exit_reports_failure_and_truncates_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    out = tmp_path / "out"

    async def fake_run(args, cwd=None):
        return 2, "", "E" * 900

    monkeypatch.setattr(graph_indexer, "_run_graphify", fake_run)
    result = await index_codebase(src, out)

    assert result.success is False
    assert result.nodes == 0 and result.edges == 0
    assert result.error == "E" * 500
    assert not (out / ".netra_graphify_mtime").exists()


@pytest.mark.asyncio
async def test_index_codebase_skips_extract_when_cache_is_fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    out = tmp_path / "out"
    (out / "graphify-out").mkdir(parents=True)
    (out / "graphify-out" / "graph.json").write_text("{}")
    (out / ".netra_graphify_mtime").write_text("9999999999.0")

    runner = AsyncMock()
    monkeypatch.setattr(graph_indexer, "_run_graphify", runner)

    result = await index_codebase(src, out)

    runner.assert_not_awaited()
    assert result.success is True
    assert result.nodes == 0


@pytest.mark.asyncio
async def test_index_codebase_reindexes_when_manifest_is_stale_or_garbage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    out = tmp_path / "out"
    (out / "graphify-out").mkdir(parents=True)
    (out / "graphify-out" / "graph.json").write_text("{}")
    (out / ".netra_graphify_mtime").write_text("not-a-float")

    runner = AsyncMock(return_value=(0, "", ""))
    monkeypatch.setattr(graph_indexer, "_run_graphify", runner)

    result = await index_codebase(src, out)

    runner.assert_awaited_once()
    assert result.success is True


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect: graph_indexer.py:126 does not catch GraphifyNotAvailable from "
        "_run_graphify, so a missing CLI raises instead of returning a failed IndexResult."
    ),
)
@pytest.mark.asyncio
async def test_index_codebase_missing_graphify_returns_failure_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Desired behaviour: degrade to success=False when the Graphify CLI is absent."""
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: None)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")

    result = await index_codebase(src, tmp_path / "out")

    assert result.success is False
    assert result.error is not None


@pytest.mark.asyncio
async def test_index_codebase_missing_graphify_raises_current_behaviour(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(graph_indexer.shutil, "which", lambda name: None)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")

    with pytest.raises(GraphifyNotAvailable):
        await index_codebase(src, tmp_path / "out")


@pytest.mark.asyncio
async def test_index_recon_output_missing_dir_returns_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    result = await index_recon_output("no-such-program", tmp_path / "root")

    assert result.success is False
    assert result.error is not None and "no-such-program" in result.error


@pytest.mark.asyncio
async def test_index_recon_output_delegates_to_index_codebase(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_home = tmp_path / "home"
    program_dir = fake_home / "netra_output" / "bb" / "acme"
    program_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    delegated = AsyncMock(return_value=IndexResult("t", tmp_path, 1, 0, True))
    monkeypatch.setattr(graph_indexer, "index_codebase", delegated)

    result = await index_recon_output("acme", tmp_path / "root")

    assert result.success is True
    src_arg, out_arg = delegated.await_args.args[:2]
    assert src_arg == program_dir
    assert out_arg == tmp_path / "root" / "acme" / "graph"
    assert delegated.await_args.kwargs == {"output_format": "json"}


def test_export_submissions_json_maps_rows_to_graphify_shape(tmp_path: Path) -> None:
    out_path = tmp_path / "nested" / "dir" / "submissions.json"
    rows = [
        {
            "id": 7,
            "title": "XSS on search",
            "severity": "high",
            "status": "submitted",
            "program_id": 3,
            "finding_id": 11,
            "vuln_class": "xss",
            "asset_path": "/search",
        }
    ]

    returned = export_submissions_json(rows, out_path)

    assert returned == out_path
    records = json.loads(out_path.read_text())
    assert len(records) == 1
    rec = records[0]
    assert rec["id"] == "7"
    assert rec["type"] == "submission"
    assert rec["attrs"] == {
        "title": "XSS on search",
        "severity": "high",
        "status": "submitted",
        "program_id": "3",
        "vuln_class": "xss",
        "asset_path": "/search",
    }
    assert {"to": "3", "rel": "for_program"} in rec["edges"]
    assert {"to": "11", "rel": "from_finding"} in rec["edges"]


def test_export_submissions_json_empty_list_writes_empty_array(tmp_path: Path) -> None:
    out_path = tmp_path / "empty.json"
    export_submissions_json([], out_path)
    assert json.loads(out_path.read_text()) == []


# ---------------------------------------------------------------------------
# triage/deduper
# ---------------------------------------------------------------------------


def test_normalise_path_collapses_ids_and_uuids() -> None:
    assert normalise_path("/users/12345/orders") == "/users/{id}/orders"
    assert normalise_path("/a/3fa85f64-5717-4562-b3fc-2c963f66afa6") == "/a/{uuid}"
    assert normalise_path("  /Users/9/Profile  ") == "/users/{id}/profile"


def test_normalise_path_empty_defaults_to_root() -> None:
    assert normalise_path("") == "/"
    assert normalise_path(None) == "/"  # type: ignore[arg-type]


def test_normalise_path_keeps_non_numeric_segments() -> None:
    assert normalise_path("/v2/items") == "/v2/items"


def test_fingerprint_normalises_inputs() -> None:
    fp = fingerprint("  XSS ", "/Search/42", " Q ")
    assert fp == DedupFingerprint(vuln_class="xss", normalised_path="/search/{id}", param_name="q")


def test_fingerprint_param_name_defaults_to_empty() -> None:
    fp = fingerprint("idor", "/x/1")
    assert fp.param_name == ""


def test_fingerprint_hash_is_deterministic_and_case_insensitive() -> None:
    a = fingerprint("XSS", "/a/1", "q")
    b = fingerprint("xss", "/A/2", "Q")
    assert a.hash() == b.hash()
    assert len(a.hash()) == 64


def test_fingerprint_hash_differs_when_any_component_differs() -> None:
    base = fingerprint("xss", "/a", "q").hash()
    assert fingerprint("sqli", "/a", "q").hash() != base
    assert fingerprint("xss", "/b", "q").hash() != base
    assert fingerprint("xss", "/a", "r").hash() != base


@pytest.mark.asyncio
async def test_is_duplicate_returns_prior_signature() -> None:
    prior = SimpleNamespace(signature_hash="abc")
    result = SimpleNamespace(scalar_one_or_none=lambda: prior)
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)

    found = await is_duplicate(session, "prog-1", fingerprint("xss", "/a", "q"))

    assert found is prior
    session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_duplicate_returns_none_when_unseen() -> None:
    result = SimpleNamespace(scalar_one_or_none=lambda: None)
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)

    assert await is_duplicate(session, "prog-1", fingerprint("xss", "/a", "q")) is None


@pytest.mark.asyncio
async def test_record_signature_persists_truncated_fields() -> None:
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    finding_id = uuid.uuid4()
    program_id = uuid.uuid4()
    fp = fingerprint("A" * 100, "/p", "q")

    sig = await record_signature(
        session,
        finding_id,
        program_id,
        fp,
        asset_path="/" + "x" * 1500,
        signal_type="s" * 60,
    )

    assert isinstance(sig, BBDedupSignature)
    session.add.assert_called_once_with(sig)
    session.flush.assert_awaited_once()
    assert sig.signature_hash == fp.hash()
    assert len(sig.asset_path) == 1024
    assert len(sig.signal_type) == 40
    assert len(sig.vuln_class) == 80
    assert sig.finding_id == finding_id
    assert sig.program_id == program_id


def _write_export(path: Path, records) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records))
    return path


def test_find_graph_similar_no_export_degrades_to_empty(tmp_path: Path) -> None:
    assert find_graph_similar("p1", "/a", "xss", export_path=tmp_path / "missing.json") == []


def test_find_graph_similar_corrupt_export_degrades_to_empty(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert find_graph_similar("p1", "/a", "xss", export_path=bad) == []


def test_find_graph_similar_directory_instead_of_file_degrades_to_empty(tmp_path: Path) -> None:
    # read_text on a directory raises IsADirectoryError (an OSError); must not propagate.
    assert find_graph_similar("p1", "/a", "xss", export_path=tmp_path) == []


def test_find_graph_similar_non_list_payload_returns_empty(tmp_path: Path) -> None:
    path = _write_export(tmp_path / "obj.json", {"attrs": {}})
    assert find_graph_similar("p1", "/a", "xss", export_path=path) == []


def test_find_graph_similar_matches_same_and_neighbouring_paths(tmp_path: Path) -> None:
    path = _write_export(
        tmp_path / "s.json",
        [
            {"id": "r1", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": "/shop/cart", "title": "same"}},
            {"id": "r2", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": "/shop/checkout", "title": "neighbour"}},
            {"id": "r3", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": "/shop/a/deep", "title": "too deep"}},
        ],
    )

    hints = find_graph_similar("p1", "/shop/cart", "xss", export_path=path)

    ids = [h["id"] for h in hints]
    assert ids == ["r1", "r2"]
    assert hints[0]["reason"] == "same vuln class on same or neighbouring asset path"
    assert hints[0]["title"] == "same"


def test_find_graph_similar_filters_by_program_and_vuln_class(tmp_path: Path) -> None:
    path = _write_export(
        tmp_path / "s.json",
        [
            {"id": "other-program", "attrs": {"program_id": "p2", "vuln_class": "xss", "asset_path": "/a/b"}},
            {"id": "other-class", "attrs": {"program_id": "p1", "vuln_class": "sqli", "asset_path": "/a/b"}},
            {"id": "match", "attrs": {"program_id": "p1", "vuln_class": "XSS", "asset_path": "/a/b"}},
        ],
    )

    hints = find_graph_similar("p1", "/a/b", "xss", export_path=path)

    assert [h["id"] for h in hints] == ["match"]


def test_find_graph_similar_caps_hints_at_five(tmp_path: Path) -> None:
    records = [
        {"id": f"r{i}", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": "/a/b"}}
        for i in range(9)
    ]
    path = _write_export(tmp_path / "s.json", records)
    assert len(find_graph_similar("p1", "/a/b", "xss", export_path=path)) == 5


def test_find_graph_similar_program_id_compared_as_string(tmp_path: Path) -> None:
    path = _write_export(
        tmp_path / "s.json",
        [{"id": "r", "attrs": {"program_id": 5, "vuln_class": "xss", "asset_path": "/a"}}],
    )
    assert [h["id"] for h in find_graph_similar(5, "/a", "xss", export_path=path)] == ["r"]  # type: ignore[arg-type]


def test_find_graph_similar_round_trips_export_submissions_json(tmp_path: Path) -> None:
    export = tmp_path / "submissions.json"
    export_submissions_json(
        [
            {
                "id": 1,
                "title": "Stored XSS",
                "severity": "high",
                "status": "submitted",
                "program_id": "p1",
                "finding_id": 9,
                "vuln_class": "xss",
                "asset_path": "/profile/edit",
            }
        ],
        export,
    )

    hints = find_graph_similar("p1", "/profile/view", "xss", export_path=export)

    assert [h["id"] for h in hints] == ["1"]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect: deduper.py:108-112 normalises a missing asset_path to '/', so a "
        "record with no asset_path matches every top-level asset as a 'neighbour'."
    ),
)
def test_find_graph_similar_ignores_records_without_asset_path(tmp_path: Path) -> None:
    path = _write_export(
        tmp_path / "s.json",
        [{"id": "no-path", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": None}}],
    )
    assert find_graph_similar("p1", "/login", "xss", export_path=path) == []


def test_find_graph_similar_missing_asset_path_currently_matches_top_level(tmp_path: Path) -> None:
    """Documents current behaviour behind the xfail above."""
    path = _write_export(
        tmp_path / "s.json",
        [{"id": "no-path", "attrs": {"program_id": "p1", "vuln_class": "xss", "asset_path": None}}],
    )
    assert [h["id"] for h in find_graph_similar("p1", "/login", "xss", export_path=path)] == ["no-path"]


def test_deduper_module_exports_expected_surface() -> None:
    for name in ("fingerprint", "is_duplicate", "record_signature", "find_graph_similar"):
        assert hasattr(deduper, name)


# ---------------------------------------------------------------------------
# triage/bounty_persona
# ---------------------------------------------------------------------------


def test_composite_uses_documented_weights() -> None:
    score = BountyScore(impact=10, novelty=0, payout=0, rationale="")
    assert score.composite == pytest.approx(5.0)
    score = BountyScore(impact=0, novelty=10, payout=0, rationale="")
    assert score.composite == pytest.approx(3.0)
    score = BountyScore(impact=0, novelty=0, payout=10, rationale="")
    assert score.composite == pytest.approx(2.0)


def test_composite_full_marks_is_ten() -> None:
    assert BountyScore(10, 10, 10, "").composite == pytest.approx(10.0)


@pytest.mark.parametrize(
    ("impact", "novelty", "payout", "expected_tier"),
    [
        (10, 10, 10, "must_submit"),  # 10.0
        (8, 8, 8, "must_submit"),  # 8.0 exactly on the boundary
        (6, 6, 6, "submit"),  # 6.0 exactly on the boundary
        (4, 4, 4, "consider"),  # 4.0 exactly on the boundary
        (1, 1, 1, "skip"),
    ],
)
def test_tier_buckets(impact: int, novelty: int, payout: int, expected_tier: str) -> None:
    assert BountyScore(impact, novelty, payout, "").tier == expected_tier


def test_tier_just_below_thresholds() -> None:
    # impact 8, novelty 7, payout 7 -> 4 + 2.1 + 1.4 = 7.5 -> submit (below must_submit)
    assert BountyScore(8, 7, 7, "").tier == "submit"
    # impact 4, novelty 3, payout 3 -> 2 + 0.9 + 0.6 = 3.5 -> skip (below consider)
    assert BountyScore(4, 3, 3, "").tier == "skip"


def test_bountyscore_is_frozen() -> None:
    score = BountyScore(1, 2, 3, "r")
    with pytest.raises(AttributeError):
        score.impact = 9  # type: ignore[misc]


def test_parse_response_plain_json() -> None:
    raw = json.dumps({"impact": 9, "novelty": 7, "payout": 5, "rationale_short": "Solid IDOR"})
    score = parse_response(raw)
    assert score == BountyScore(impact=9, novelty=7, payout=5, rationale="Solid IDOR")
    assert score.tier == "submit"  # 9*0.5 + 7*0.3 + 5*0.2 = 7.6


def test_parse_response_strips_code_fences_and_whitespace() -> None:
    raw = '  ```json\n{"impact": 5, "novelty": 5, "payout": 5, "rationale_short": "ok"}\n```  \n'
    assert parse_response(raw).impact == 5


def test_parse_response_tolerates_leading_prose() -> None:
    raw = 'Sure! Here is my scoring:\n{"impact": 3, "novelty": 4, "payout": 2, "rationale_short": "meh"}'
    score = parse_response(raw)
    assert (score.impact, score.novelty, score.payout) == (3, 4, 2)


def test_parse_response_coerces_numeric_strings() -> None:
    raw = '{"impact": "7", "novelty": "6", "payout": "5"}'
    score = parse_response(raw)
    assert (score.impact, score.novelty, score.payout) == (7, 6, 5)
    assert score.rationale == ""


def test_parse_response_truncates_rationale_to_280() -> None:
    raw = json.dumps({"impact": 1, "novelty": 1, "payout": 1, "rationale_short": "x" * 500})
    assert len(parse_response(raw).rationale) == 280


def test_parse_response_invalid_json_raises_value_error() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_response("definitely not json")


@pytest.mark.parametrize(
    "raw",
    [
        '{"impact": 5, "novelty": 5}',  # missing payout
        '{"impact": "high", "novelty": 5, "payout": 5}',  # non-numeric
        "[1, 2, 3]",  # list, not object
        '"just a string"',
        "null",
    ],
)
def test_parse_response_invalid_shapes_raise_value_error(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_response(raw)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect: bounty_persona.py:102-108 does not range-check scores, so values "
        "outside 1-10 pass through and push composite outside its documented 1.0-10.0 range."
    ),
)
def test_parse_response_rejects_out_of_range_scores() -> None:
    with pytest.raises(ValueError):
        parse_response('{"impact": 42, "novelty": 42, "payout": 42}')


def test_parse_response_currently_accepts_out_of_range_scores() -> None:
    """Documents current behaviour behind the xfail above."""
    score = parse_response('{"impact": 42, "novelty": 42, "payout": 42}')
    assert score.composite == pytest.approx(42.0)


def test_prompt_template_formats_with_all_placeholders() -> None:
    rendered = BOUNTY_HUNTER_PROMPT.format(
        finding_context="F",
        program_context="P",
        comparable_reports="C",
    )
    assert "Finding under review:\nF" in rendered
    assert "Program info:\nP" in rendered
    assert "Comparable disclosed reports and prior art:\nC" in rendered
