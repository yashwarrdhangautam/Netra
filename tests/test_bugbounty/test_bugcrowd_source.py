"""Tests for the Bugcrowd disclosure source. Mock transport only, no live network.

Row shape follows the live crowdstream feed, checked 2026-11-12: a top-level ``results`` list,
a relative ``disclosure_report_url``, and ``disclosed_at`` as "6 Nov 2026".
"""

import httpx
from sqlalchemy import select

from netra.bugbounty.learning.sources import bugcrowd
from netra.db.models.bb_corpus_report import BBCorpusReport


def _client(pages: dict[str, object]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        page = request.url.params.get("page", "1")
        if request.url.path == "/crowdstream.json" and page in pages:
            return httpx.Response(200, json=pages[page])
        if request.url.path == "/crowdstream.json":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _row(report_path: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": report_path,
        "engagement_name": "ExampleCo",
        "engagement_code": "exampleco",
        "researcher_username": "alice",
        "priority": 2,
        "target": "app.example.test",
        "title": "Stored XSS in profile bio",
        "disclosed": True,
        "disclosed_at": "6 Nov 2026",
        "disclosure_report_url": report_path,
    }
    row.update(overrides)
    return row


def test_extract_rows_resolves_relative_links_and_keeps_disclosed_rows() -> None:
    rows = bugcrowd.extract_rows(
        {
            "results": [
                _row("/disclosures/aaa/one"),
                _row("/disclosures/bbb/two", priority=99),
                _row("/disclosures/ccc/three", disclosed=False),
                _row("", disclosure_report_url=None),
                "not-a-dict",
            ]
        }
    )
    assert [r["source_url"] for r in rows] == [
        "https://bugcrowd.com/disclosures/aaa/one",
        "https://bugcrowd.com/disclosures/bbb/two",
    ]
    assert rows[0]["severity"] == "P2"
    assert rows[1]["severity"] is None
    assert rows[0]["program"] == "ExampleCo"
    assert rows[0]["author"] == "alice"
    assert rows[0]["disclosed_at"] is not None


def test_extract_rows_rejects_links_off_bugcrowd() -> None:
    rows = bugcrowd.extract_rows(
        {
            "results": [
                _row("https://evil.example/disclosures/x"),
                _row("http://bugcrowd.com/disclosures/y"),
            ]
        }
    )
    assert rows == []


def test_extract_rows_ignores_unknown_payload_shape() -> None:
    assert bugcrowd.extract_rows({"error": "nope"}) == []
    assert bugcrowd.extract_rows("text") == []


async def test_ingest_stores_metadata_and_is_idempotent(db_session) -> None:
    path = "/disclosures/abc/xss"
    pages = {"1": {"results": [_row(path)]}}
    async with _client(pages) as client:
        first = await bugcrowd.ingest_bugcrowd_disclosures(db_session, max_pages=2, client=client)
    assert first == {"added": 1, "updated": 0}

    async with _client(pages) as client:
        second = await bugcrowd.ingest_bugcrowd_disclosures(db_session, max_pages=2, client=client)
    assert second == {"added": 0, "updated": 1}

    row = (
        await db_session.execute(
            select(BBCorpusReport).where(BBCorpusReport.source_url == "https://bugcrowd.com" + path)
        )
    ).scalar_one()
    assert row.source_platform == "bugcrowd"
    assert row.title == "Stored XSS in profile bio"
    assert row.severity == "P2"


async def test_ingest_stops_on_page_error(db_session) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(500)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with client:
        result = await bugcrowd.ingest_bugcrowd_disclosures(db_session, max_pages=3, client=client)
    assert result == {"added": 0, "updated": 0}


async def test_disable_flag_skips_fetch(db_session, monkeypatch) -> None:
    monkeypatch.setattr(bugcrowd.settings, "corpus_source_bugcrowd", False)
    async with _client({"1": {"results": [_row("/disclosures/x")]}}) as client:
        result = await bugcrowd.ingest_bugcrowd_disclosures(db_session, client=client)
    assert result == {"added": 0, "updated": 0}
