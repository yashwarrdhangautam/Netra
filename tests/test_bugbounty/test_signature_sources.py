"""Tests for the public signature sources (chaos index, repo heads). Mock transport only."""

import json

import httpx
import pytest
from sqlalchemy import select

from netra.bugbounty.learning.sources import signatures
from netra.db.models.bb_corpus_signature import BBCorpusSignature


def _client(routes: dict[str, tuple[int, object]]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        key = str(request.url)
        if key in routes:
            status, body = routes[key]
            if isinstance(body, dict | list):
                return httpx.Response(status, json=body)
            return httpx.Response(status, text=str(body))
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_parse_chaos_index_keeps_well_formed_entries_only() -> None:
    rows = signatures.parse_chaos_index(
        [
            {
                "name": "acme",
                "platform": "hackerone",
                "count": 3,
                "bounty": True,
                "last_updated": "2026-11-12T00:10:54Z",
                "program_url": "https://h1.example/acme",
            },
            {"platform": "no-name"},
            "not-a-dict",
            {"name": 42},
        ]
    )
    assert [r["name"] for r in rows] == ["acme"]
    assert rows[0]["count"] == 3
    assert rows[0]["last_updated"] is not None


def test_parse_chaos_index_ignores_non_list_payload() -> None:
    assert signatures.parse_chaos_index({"error": "nope"}) == []


def test_parse_commit_head_reads_sha_and_date() -> None:
    head = signatures.parse_commit_head(
        {"sha": "abc123", "commit": {"committer": {"date": "2026-11-12T07:44:15Z"}}}
    )
    assert head is not None and head["sha"] == "abc123"
    assert head["committed_at"] is not None
    assert signatures.parse_commit_head({"message": "rate limited"}) is None


async def test_chaos_ingest_creates_then_updates(db_session) -> None:
    index_url = signatures.CHAOS_INDEX_URL
    payload = [
        {
            "name": "alpha",
            "platform": "hackerone",
            "count": 1,
            "bounty": True,
            "last_updated": "2026-11-12T00:00:00Z",
            "program_url": "https://h1.example/alpha",
        },
        {
            "name": "beta",
            "platform": "bugcrowd",
            "count": 2,
            "bounty": False,
            "last_updated": None,
            "program_url": "",
        },
    ]
    async with _client({index_url: (200, payload)}) as client:
        first = await signatures.ingest_chaos_index(db_session, client=client)
    assert first == {"added": 2, "updated": 0}

    payload[0]["count"] = 9
    async with _client({index_url: (200, payload)}) as client:
        second = await signatures.ingest_chaos_index(db_session, client=client)
    assert second == {"added": 0, "updated": 2}

    rows = (
        (
            await db_session.execute(
                select(BBCorpusSignature).where(BBCorpusSignature.source_repo == "chaos")
            )
        )
        .scalars()
        .all()
    )
    by_tag = {r.tag: r for r in rows}
    assert set(by_tag) == {"alpha", "beta"}
    assert json.loads(by_tag["alpha"].signature_blob)["count"] == 9


async def test_repo_heads_store_head_and_survive_one_failure(db_session) -> None:
    ok_url = signatures.GITHUB_COMMIT_URL.format(
        repo="projectdiscovery/nuclei-templates", branch="main"
    )
    bad_url = signatures.GITHUB_COMMIT_URL.format(repo="enthec/webappanalyzer", branch="main")
    routes = {
        ok_url: (
            200,
            {"sha": "f99ca476bb7e", "commit": {"committer": {"date": "2026-11-12T07:44:15Z"}}},
        ),
        bad_url: (403, {"message": "rate limit exceeded"}),
    }
    async with _client(routes) as client:
        result = await signatures.ingest_repo_heads(db_session, client=client)
    assert result["added"] == 1
    assert result["errors"] == 1

    row = (
        await db_session.execute(
            select(BBCorpusSignature).where(BBCorpusSignature.source_repo == "nuclei-templates")
        )
    ).scalar_one()
    assert row.tag == "head"
    assert row.signature_blob == "f99ca476bb7e"


@pytest.mark.parametrize("flag", ["corpus_source_chaos"])
async def test_chaos_respects_disable_flag(db_session, monkeypatch, flag) -> None:
    monkeypatch.setattr(signatures.settings, flag, False)
    async with _client({}) as client:
        result = await signatures.ingest_chaos_index(db_session, client=client)
    assert result == {"added": 0, "updated": 0}
