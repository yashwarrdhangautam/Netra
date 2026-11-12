"""Coverage-focused tests for learning source adapters, fetcher and pgvector helpers.

All HTTP goes through httpx.MockTransport and all DB access is replaced with mocks, so
no network or database is touched.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from netra.bugbounty.learning import fetcher as fetcher_mod
from netra.bugbounty.learning import pgvector as pgvector_mod
from netra.bugbounty.learning.fetcher import LearningFetcher, RobotsDeniedError
from netra.bugbounty.learning.sources import advisories as advisories_source
from netra.bugbounty.learning.sources import hackerone as h1_source
from netra.bugbounty.learning.sources import rss as rss_source
from netra.core.config import settings as app_settings
from netra.integrations.hackerone import H1HacktivityItem


# ── shared helpers ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch):
    """Disable robots checks and throttling for every test; restored automatically."""
    monkeypatch.setattr(app_settings, "corpus_obey_robots", False)
    monkeypatch.setattr(app_settings, "corpus_default_rps", 0.0)
    monkeypatch.setattr(app_settings, "corpus_source_hackerone", True)
    monkeypatch.setattr(app_settings, "corpus_source_advisories", True)
    monkeypatch.setattr(app_settings, "corpus_source_writeups", True)


def _mock_session() -> MagicMock:
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.add = MagicMock()
    return session


def _patch_async_client(monkeypatch, handler, created: list | None = None) -> None:
    """Make any httpx.AsyncClient constructed without an explicit client use MockTransport."""
    original = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003
        kwargs.pop("timeout", None)
        client = original(transport=httpx.MockTransport(handler), **kwargs)
        if created is not None:
            created.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", factory)


class FakeHacktivityClient:
    items: list[H1HacktivityItem] = []
    configured = True
    init_kwargs: dict = {}
    calls: list[dict] = []

    def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        FakeHacktivityClient.init_kwargs = kwargs

    def is_configured(self) -> bool:
        return FakeHacktivityClient.configured

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get_hacktivity(self, **kwargs):  # noqa: ANN003
        FakeHacktivityClient.calls.append(kwargs)
        return list(FakeHacktivityClient.items)


@pytest.fixture
def fake_h1(monkeypatch):
    FakeHacktivityClient.items = []
    FakeHacktivityClient.configured = True
    FakeHacktivityClient.init_kwargs = {}
    FakeHacktivityClient.calls = []
    return FakeHacktivityClient


def _h1_item(**overrides) -> H1HacktivityItem:
    base = dict(
        source_url="https://hackerone.com/reports/1",
        title="Report",
        body="body",
        severity="high",
        program_handle="Shopify",
        author_handle="alice",
        weakness="Cross-Site Scripting (XSS)",
        disclosed_at=None,
        raw={},
    )
    base.update(overrides)
    return H1HacktivityItem(**base)


# ── hackerone.py ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("weakness", "expected"),
    [
        ("Cross-Site Scripting (XSS) - Stored", "xss"),
        ("Insecure Direct Object Reference (IDOR)", "idor"),
        ("SQL Injection", "sqli"),
        ("Server-Side Request Forgery (SSRF)", "ssrf"),
        ("Cross-Site Request Forgery (CSRF)", "csrf"),
        ("Information Disclosure", "information disclosure"),
        ("", None),
        (None, None),
    ],
)
def test_h1_infer_vuln_class(weakness, expected) -> None:
    assert h1_source._infer_vuln_class(_h1_item(weakness=weakness)) == expected


async def test_h1_ingest_disabled_by_config_logs_and_skips(monkeypatch, fake_h1) -> None:
    monkeypatch.setattr(app_settings, "corpus_source_hackerone", False)
    log = AsyncMock()
    monkeypatch.setattr(h1_source, "log_ingest", log)
    session = _mock_session()

    result = await h1_source.ingest_hacktivity(session, client_cls=fake_h1)

    assert result == {"added": 0, "updated": 0}
    assert log.await_args.kwargs["notes"] == "disabled_by_config"
    assert fake_h1.calls == []
    session.commit.assert_awaited_once()


async def test_h1_ingest_credentials_missing_logs_error(monkeypatch, fake_h1) -> None:
    fake_h1.configured = False
    log = AsyncMock()
    monkeypatch.setattr(h1_source, "log_ingest", log)
    session = _mock_session()

    result = await h1_source.ingest_hacktivity(session, client_cls=fake_h1)

    assert result == {"added": 0, "updated": 0}
    assert log.await_args.kwargs["errors"] == ["credentials_missing"]
    assert fake_h1.calls == []
    session.commit.assert_awaited_once()


async def test_h1_ingest_counts_added_and_updated(monkeypatch, fake_h1) -> None:
    disclosed = datetime(2026, 5, 1, tzinfo=UTC)
    fake_h1.items = [
        _h1_item(source_url="https://hackerone.com/reports/1", disclosed_at=disclosed),
        _h1_item(source_url="https://hackerone.com/reports/2", disclosed_at=None),
    ]
    upsert = AsyncMock(side_effect=[(MagicMock(), True), (MagicMock(), False)])
    log = AsyncMock()
    monkeypatch.setattr(h1_source, "upsert_report", upsert)
    monkeypatch.setattr(h1_source, "log_ingest", log)
    session = _mock_session()

    result = await h1_source.ingest_hacktivity(session, since_days=2, client_cls=fake_h1)

    assert result == {"added": 1, "updated": 1}
    first = upsert.await_args_list[0].kwargs
    assert first["source_platform"] == "hackerone"
    assert first["vuln_class"] == "xss"
    assert first["tech_stack"] == []
    assert first["metadata"] == {"weakness": "Cross-Site Scripting (XSS)"}
    assert first["ingested_at"] == disclosed
    # Item without disclosed_at falls back to the run's start time.
    second = upsert.await_args_list[1].kwargs
    assert second["ingested_at"] <= datetime.now(UTC)
    assert second["ingested_at"].tzinfo is not None
    log.await_args.kwargs["items_added"] == 1
    assert log.await_args.kwargs["items_updated"] == 1
    session.commit.assert_awaited_once()


async def test_h1_ingest_passes_since_window_and_fetcher_hooks(monkeypatch, fake_h1) -> None:
    monkeypatch.setattr(h1_source, "upsert_report", AsyncMock(return_value=(MagicMock(), True)))
    monkeypatch.setattr(h1_source, "log_ingest", AsyncMock())

    await h1_source.ingest_hacktivity(_mock_session(), since_days=3, client_cls=fake_h1)

    since_value = fake_h1.calls[0]["since"]
    since_dt = datetime.fromisoformat(since_value)
    delta = datetime.now(UTC) - since_dt
    assert timedelta(days=2, hours=23) < delta < timedelta(days=3, minutes=1)
    assert fake_h1.calls[0]["disclosed"] is True
    assert callable(fake_h1.init_kwargs["before_request"])
    assert callable(fake_h1.init_kwargs["after_response"])


async def test_h1_bootstrap_disabled_returns_zero(monkeypatch, fake_h1) -> None:
    monkeypatch.setattr(app_settings, "corpus_source_hackerone", False)
    session = _mock_session()
    assert await h1_source.bootstrap_program(session, handle="shopify", client_cls=fake_h1) == {
        "added": 0,
        "updated": 0,
    }
    assert fake_h1.calls == []


async def test_h1_bootstrap_credentials_missing_returns_zero(monkeypatch, fake_h1) -> None:
    fake_h1.configured = False
    session = _mock_session()
    result = await h1_source.bootstrap_program(session, handle="shopify", client_cls=fake_h1)
    assert result == {"added": 0, "updated": 0}
    session.commit.assert_not_awaited()


async def test_h1_bootstrap_filters_program_case_insensitively(monkeypatch, fake_h1) -> None:
    fake_h1.items = [
        _h1_item(source_url="https://hackerone.com/reports/10", program_handle="Shopify"),
        _h1_item(source_url="https://hackerone.com/reports/11", program_handle="github"),
        _h1_item(source_url="https://hackerone.com/reports/12", program_handle=None),
    ]
    upsert = AsyncMock(side_effect=[(MagicMock(), True)])
    monkeypatch.setattr(h1_source, "upsert_report", upsert)
    session = _mock_session()

    result = await h1_source.bootstrap_program(
        session, handle="SHOPIFY", since_days=30, client_cls=fake_h1
    )

    assert result == {"added": 1, "updated": 0}
    assert upsert.await_count == 1
    kwargs = upsert.await_args.kwargs
    assert kwargs["source_url"] == "https://hackerone.com/reports/10"
    assert kwargs["metadata"]["bootstrap"] is True
    session.commit.assert_awaited_once()


async def test_h1_bootstrap_counts_updates(monkeypatch, fake_h1) -> None:
    fake_h1.items = [_h1_item(program_handle="shopify")]
    monkeypatch.setattr(h1_source, "upsert_report", AsyncMock(return_value=(MagicMock(), False)))
    result = await h1_source.bootstrap_program(_mock_session(), handle="shopify", client_cls=fake_h1)
    assert result == {"added": 0, "updated": 1}


# ── rss.py ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Stored SSRF in webhooks", "ssrf"),
        ("IDOR on invoices", "idor"),
        ("reflected XSS", "xss"),
        ("SQL injection in search", "sqli"),
        ("CSRF on settings", "csrf"),
        ("Public S3 bucket leak", "exposure"),
        ("Nothing interesting", None),
    ],
)
def test_rss_infer_vuln_class(text, expected) -> None:
    assert rss_source._infer_vuln_class(text) == expected


def test_rss_parse_feed_extracts_fields_and_fallbacks() -> None:
    xml = """<rss xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>
      <item>
        <title> Shopify IDOR </title>
        <link>https://example.com/a</link>
        <description>IDOR in orders</description>
        <dc:creator>Bob</dc:creator>
        <pubDate>Fri, 09 May 2026 10:00:00 GMT</pubDate>
      </item>
      <item>
        <title>Bad date</title>
        <link>https://example.com/b</link>
        <author>Carol</author>
        <pubDate>not a date</pubDate>
      </item>
      <item>
        <title>No extras</title>
        <link>https://example.com/c</link>
      </item>
    </channel></rss>"""

    items = rss_source._parse_feed(xml)

    assert len(items) == 3
    assert items[0]["title"] == "Shopify IDOR"
    assert items[0]["author"] == "Bob"
    assert items[0]["vuln_class"] == "idor"
    assert items[0]["published_at"] == datetime(2026, 5, 9, 10, 0, tzinfo=UTC)
    assert items[1]["author"] == "Carol"
    assert items[1]["published_at"] is None
    assert items[2]["author"] is None
    assert items[2]["body_summary"] == ""
    assert items[2]["published_at"] is None


async def test_rss_ingest_disabled_by_config(monkeypatch) -> None:
    monkeypatch.setattr(app_settings, "corpus_source_writeups", False)
    log = AsyncMock()
    monkeypatch.setattr(rss_source, "log_ingest", log)
    session = _mock_session()

    result = await rss_source.ingest_public_writeups(session, feeds=["https://x.test/f"])

    assert result == {"added": 0, "updated": 0}
    assert log.await_args.kwargs["notes"] == "disabled_by_config"
    session.commit.assert_awaited_once()


async def test_rss_ingest_skips_incomplete_items_and_uses_published_date(monkeypatch) -> None:
    xml = """<rss><channel>
      <item><title></title><link>https://example.com/no-title</link></item>
      <item><title>No link</title></item>
      <item>
        <title>Good</title><link>https://example.com/good</link>
        <pubDate>Fri, 09 May 2026 10:00:00 GMT</pubDate>
      </item>
      <item><title>Undated</title><link>https://example.com/undated</link></item>
    </channel></rss>"""
    handler = lambda request: httpx.Response(200, text=xml)  # noqa: E731
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upsert = AsyncMock(side_effect=[(MagicMock(), True), (MagicMock(), False)])
    log = AsyncMock()
    monkeypatch.setattr(rss_source, "upsert_writeup", upsert)
    monkeypatch.setattr(rss_source, "log_ingest", log)
    session = _mock_session()
    try:
        result = await rss_source.ingest_public_writeups(
            session, feeds=["https://feed.test/rss"], client=client
        )
    finally:
        await client.aclose()

    assert result == {"added": 1, "updated": 1}
    assert upsert.await_count == 2
    good = upsert.await_args_list[0].kwargs
    assert good["source_url"] == "https://example.com/good"
    assert good["ingested_at"] == datetime(2026, 5, 9, 10, 0, tzinfo=UTC)
    assert good["metadata"] == {"feed": "https://feed.test/rss"}
    undated = upsert.await_args_list[1].kwargs
    assert undated["ingested_at"].tzinfo is not None
    assert log.await_args.kwargs["items_added"] == 1
    session.commit.assert_awaited_once()


async def test_rss_ingest_defaults_to_default_feeds_and_owns_client(monkeypatch) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(404)
        return httpx.Response(200, text="<rss><channel></channel></rss>")

    created: list[httpx.AsyncClient] = []
    _patch_async_client(monkeypatch, handler, created)
    monkeypatch.setattr(rss_source, "log_ingest", AsyncMock())

    result = await rss_source.ingest_public_writeups(_mock_session())

    assert result == {"added": 0, "updated": 0}
    for feed in rss_source.DEFAULT_FEEDS:
        assert feed in requested
    assert len(created) == 1
    assert created[0].is_closed


async def test_rss_ingest_propagates_feed_http_error(monkeypatch) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    log = AsyncMock()
    monkeypatch.setattr(rss_source, "log_ingest", log)
    session = _mock_session()
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await rss_source.ingest_public_writeups(
                session, feeds=["https://feed.test/rss"], client=client
            )
    finally:
        await client.aclose()
    log.assert_not_awaited()
    session.commit.assert_not_awaited()


# ── advisories.py ────────────────────────────────────────────────────────────────


def _nvd_entry(**cve_overrides) -> dict:
    cve = {
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "en", "value": "English summary"}],
        "metrics": {},
        "references": [{"url": "https://nvd.test/CVE-2026-0001"}],
        "configurations": [],
    }
    cve.update(cve_overrides)
    return {"cve": cve}


def test_nvd_prefers_v31_then_v30_then_v2_metrics() -> None:
    def item_with(metrics: dict) -> dict:
        payload = {"vulnerabilities": [_nvd_entry(metrics=metrics)]}
        return advisories_source._extract_nvd_items(payload)[0]

    v31 = item_with(
        {
            "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "vectorString": "V31"}}],
            "cvssMetricV30": [{"cvssData": {"baseSeverity": "LOW", "vectorString": "V30"}}],
        }
    )
    assert (v31["severity"], v31["cvss_vector"]) == ("HIGH", "V31")

    v30 = item_with({"cvssMetricV30": [{"cvssData": {"baseSeverity": "MEDIUM", "vectorString": "V30"}}]})
    assert (v30["severity"], v30["cvss_vector"]) == ("MEDIUM", "V30")

    v2 = item_with({"cvssMetricV2": [{"cvssData": {"baseSeverity": "LOW", "vectorString": "V2"}}]})
    assert (v2["severity"], v2["cvss_vector"]) == ("LOW", "V2")

    none = item_with({})
    assert none["severity"] is None
    assert none["cvss_vector"] is None


def test_nvd_summary_affected_packages_and_missing_fields() -> None:
    cpe_matches = [{"criteria": f"cpe:2.3:a:vendor:pkg{i}"} for i in range(25)]
    cpe_matches.append({"criteria": None})
    payload = {
        "vulnerabilities": [
            _nvd_entry(
                descriptions=[{"lang": "fr", "value": "Bonjour"}],
                references=[],
                configurations=[{"nodes": [{"cpeMatch": cpe_matches}]}],
            ),
            {"cve": None},
        ]
    }

    items = advisories_source._extract_nvd_items(payload)

    assert len(items) == 2
    first, second = items
    assert first["summary"] == ""
    assert first["source_url"] is None
    assert len(first["affected_packages"]) == 20
    assert first["affected_packages"][0] == "cpe:2.3:a:vendor:pkg0"
    assert second["cve_id"] is None
    assert second["source_url"] is None
    assert second["affected_packages"] == []
    assert second["metadata"] == {"source": "nvd"}


def test_nvd_empty_payload_returns_no_items() -> None:
    assert advisories_source._extract_nvd_items({}) == []
    assert advisories_source._extract_nvd_items({"vulnerabilities": None}) == []


def test_ghsa_extracts_fields_with_description_fallback() -> None:
    payload = [
        {
            "ghsa_id": "GHSA-1111-2222-3333",
            "cve_id": None,
            "severity": "critical",
            "summary": "",
            "description": "Long description",
            "html_url": "https://github.test/advisories/GHSA-1111",
            "vulnerabilities": [
                {"package": {"name": "lodash"}},
                {"package": {"name": None}},
                {"package": {}},
            ],
            "cvss": None,
        },
        {
            "ghsa_id": "GHSA-4444-5555-6666",
            "summary": "",
            "description": None,
            "cvss": {"vector_string": "CVSS:3.1/AV:N"},
        },
    ]

    first, second = advisories_source._extract_ghsa_items(payload)

    assert first["summary"] == "Long description"
    assert first["affected_packages"] == ["lodash"]
    assert first["cvss_vector"] is None
    assert first["metadata"] == {"source": "ghsa"}
    assert second["summary"] == ""
    assert second["affected_packages"] == []
    assert second["cvss_vector"] == "CVSS:3.1/AV:N"
    assert second["source_url"] is None


async def test_advisories_disabled_by_config(monkeypatch) -> None:
    monkeypatch.setattr(app_settings, "corpus_source_advisories", False)
    log = AsyncMock()
    monkeypatch.setattr(advisories_source, "log_ingest", log)
    session = _mock_session()

    result = await advisories_source.ingest_advisories(session)

    assert result == {"added": 0, "updated": 0}
    assert log.await_args.kwargs["notes"] == "disabled_by_config"
    session.commit.assert_awaited_once()


async def test_advisories_creates_and_closes_own_client(monkeypatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(404)
        if "api.github.com" in str(request.url):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"vulnerabilities": []})

    created: list[httpx.AsyncClient] = []
    _patch_async_client(monkeypatch, handler, created)
    monkeypatch.setattr(advisories_source, "log_ingest", AsyncMock())
    upsert = AsyncMock(return_value=(MagicMock(), True))
    monkeypatch.setattr(advisories_source, "upsert_advisory", upsert)

    result = await advisories_source.ingest_advisories(_mock_session())

    assert result == {"added": 0, "updated": 0}
    assert advisories_source.GHSA_URL in seen
    assert advisories_source.NVD_URL in seen
    upsert.assert_not_awaited()
    assert len(created) == 1
    assert created[0].is_closed


async def test_advisories_upserts_counts_and_metadata(monkeypatch) -> None:
    ghsa_payload = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2026-2222",
            "severity": "high",
            "summary": "GHSA summary",
            "html_url": "https://github.test/a",
            "vulnerabilities": [{"package": {"name": "next"}}],
            "cvss": {"vector_string": "V"},
        }
    ]
    nvd_payload = {"vulnerabilities": [_nvd_entry()]}

    def handler(request: httpx.Request) -> httpx.Response:
        if "api.github.com" in str(request.url):
            return httpx.Response(200, json=ghsa_payload)
        return httpx.Response(200, json=nvd_payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upsert = AsyncMock(side_effect=[(MagicMock(), True), (MagicMock(), False)])
    log = AsyncMock()
    monkeypatch.setattr(advisories_source, "upsert_advisory", upsert)
    monkeypatch.setattr(advisories_source, "log_ingest", log)
    session = _mock_session()
    try:
        result = await advisories_source.ingest_advisories(session, client=client)
    finally:
        await client.aclose()

    assert result == {"added": 1, "updated": 1}
    ghsa_kwargs = upsert.await_args_list[0].kwargs
    assert ghsa_kwargs["ghsa_id"] == "GHSA-aaaa-bbbb-cccc"
    assert ghsa_kwargs["metadata"] == {"source": "ghsa"}
    assert ghsa_kwargs["affected_packages"] == ["next"]
    nvd_kwargs = upsert.await_args_list[1].kwargs
    assert nvd_kwargs["cve_id"] == "CVE-2026-0001"
    assert nvd_kwargs["source_url"] == "https://nvd.test/CVE-2026-0001"
    assert log.await_args.kwargs["items_added"] == 1
    session.commit.assert_awaited_once()


async def test_advisories_ghsa_failure_propagates(monkeypatch) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    log = AsyncMock()
    monkeypatch.setattr(advisories_source, "log_ingest", log)
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await advisories_source.ingest_advisories(_mock_session(), client=client)
    finally:
        await client.aclose()
    log.assert_not_awaited()


# ── fetcher.py ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 0.0), ("", 0.0), ("2", 2.0), ("-5", 0.0), ("soon", 0.0)],
)
def test_retry_after_numeric_and_invalid(value, expected) -> None:
    assert LearningFetcher._retry_after_seconds(value) == expected


def test_retry_after_http_date_in_future_and_past() -> None:
    future = format_datetime(datetime.now(UTC) + timedelta(seconds=120), usegmt=True)
    past = format_datetime(datetime.now(UTC) - timedelta(seconds=120), usegmt=True)
    assert 60 < LearningFetcher._retry_after_seconds(future) <= 121
    assert LearningFetcher._retry_after_seconds(past) == 0.0


async def test_fetcher_skips_robots_when_disabled() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=False, default_rps=0)
        assert await fetcher.get_text("https://robots-off.test/page") == "ok"
    finally:
        await client.aclose()
    assert calls == ["https://robots-off.test/page"]


async def test_fetcher_robots_missing_allows_and_is_cached() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(404)
        return httpx.Response(200, json={"n": 1})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=True, default_rps=0)
        assert await fetcher.get_json("https://robots-missing.test/a") == {"n": 1}
        assert await fetcher.get_json("https://robots-missing.test/b") == {"n": 1}
    finally:
        await client.aclose()
    assert calls.count("https://robots-missing.test/robots.txt") == 1


async def test_fetcher_robots_fetch_error_fails_open() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            raise httpx.ConnectError("boom")
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=True, default_rps=0)
        assert await fetcher.get_text("https://robots-error.test/x") == "ok"
    finally:
        await client.aclose()


async def test_fetcher_robots_allows_matching_path_and_uses_fresh_client(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(200, text="User-agent: *\nDisallow: /private\n")
        return httpx.Response(200, text="public")

    created: list[httpx.AsyncClient] = []
    _patch_async_client(monkeypatch, handler, created)

    fetcher = LearningFetcher(obey_robots=True, default_rps=0)
    assert await fetcher.get_text("https://robots-fresh.test/public/page") == "public"
    assert len(created) >= 1
    assert all(client.is_closed for client in created)


async def test_fetcher_robots_parser_fetch_failure_builds_own_client(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    created: list[httpx.AsyncClient] = []
    _patch_async_client(monkeypatch, handler, created)

    parser = await LearningFetcher(obey_robots=True, default_rps=0)._robots_parser(
        "https://robots-offline.test/x"
    )
    assert parser is None
    assert created and created[0].is_closed


async def test_fetcher_before_request_checks_robots_and_rate_limit(monkeypatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    host = "https://rate-limit-host.test/"
    fetcher_mod.LearningFetcher._host_last_request["rate-limit-host.test"] = fetcher_mod.time.monotonic()

    fetcher = LearningFetcher(obey_robots=False, default_rps=2.0)
    await fetcher.before_request(host + "a")

    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 0.5


async def test_fetcher_rate_limit_skipped_when_rps_disabled(monkeypatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    fetcher_mod.LearningFetcher._host_last_request["no-throttle.test"] = fetcher_mod.time.monotonic()

    await LearningFetcher(obey_robots=False, default_rps=0).before_request("https://no-throttle.test/")
    assert sleeps == []


async def test_fetcher_retries_after_429_and_honours_retry_after(monkeypatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    responses = iter([httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200, text="done")])
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: next(responses)))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=False, default_rps=0, max_retries=2)
        assert await fetcher.get_text("https://retry-ok.test/feed", headers={"X-Extra": "1"}) == "done"
    finally:
        await client.aclose()
    assert 3.0 in sleeps


async def test_fetcher_raises_when_rate_limit_persists(monkeypatch) -> None:
    async def fake_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=False, default_rps=0, max_retries=1)
        with pytest.raises(RuntimeError, match="rate limited by persist-429.test"):
            await fetcher.get_text("https://persist-429.test/feed")
    finally:
        await client.aclose()


async def test_fetcher_no_sleep_when_interval_already_elapsed(monkeypatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    fetcher_mod.LearningFetcher._host_last_request["old-request.test"] = 0.0
    await LearningFetcher(obey_robots=False, default_rps=5.0).before_request(
        "https://old-request.test/"
    )
    assert sleeps == []


@pytest.mark.xfail(
    strict=True,
    reason="BUG: robots.txt 5xx is treated as allow-all instead of fail-closed (fetcher.py:107-108)",
)
async def test_fetcher_robots_server_error_should_fail_closed() -> None:
    """RFC 9309 section 2.3.1.4: a 5xx robots.txt means the crawler must assume disallow."""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(503)
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=True, default_rps=0)
        with pytest.raises(RobotsDeniedError):
            await fetcher.get_text("https://robots-503.test/page")
    finally:
        await client.aclose()


@pytest.mark.xfail(
    strict=True,
    reason="BUG: transient robots.txt fetch error is cached as allow-all for the process lifetime (fetcher.py:114-115)",
)
async def test_fetcher_robots_transient_error_is_not_cached_forever() -> None:
    state = {"robots_up": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            if not state["robots_up"]:
                raise httpx.ConnectError("temporarily unreachable")
            return httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=True, default_rps=0)
        assert await fetcher.get_text("https://robots-transient.test/page") == "ok"
        state["robots_up"] = True
        with pytest.raises(RobotsDeniedError):
            await fetcher.get_text("https://robots-transient.test/page")
    finally:
        await client.aclose()


async def test_fetcher_non_429_error_raises_without_retry() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=False, default_rps=0, max_retries=3)
        with pytest.raises(httpx.HTTPStatusError):
            await fetcher.get_text("https://no-retry.test/missing")
    finally:
        await client.aclose()
    assert len(calls) == 1


async def test_fetcher_owns_client_when_none_given(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["User-Agent"] == "NETRA-TEST/9"
        return httpx.Response(200, json=[1, 2])

    created: list[httpx.AsyncClient] = []
    _patch_async_client(monkeypatch, handler, created)

    fetcher = LearningFetcher(obey_robots=False, default_rps=0, user_agent="NETRA-TEST/9")
    assert await fetcher.get_json("https://own-client.test/data") == [1, 2]
    assert created and created[0].is_closed


async def test_fetcher_after_response_ignores_non_429() -> None:
    fetcher = LearningFetcher(obey_robots=False, default_rps=0)
    await fetcher.after_response("https://x.test", httpx.Response(200))


async def test_fetcher_after_response_zero_delay_does_not_sleep(monkeypatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(fetcher_mod.asyncio, "sleep", fake_sleep)
    fetcher = LearningFetcher(obey_robots=False, default_rps=0)
    await fetcher.after_response("https://x.test", httpx.Response(429, headers={"Retry-After": "0"}))
    assert sleeps == []


async def test_fetcher_robots_denied_raises_from_before_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        return httpx.Response(200, text="x")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, obey_robots=True, default_rps=0)
        with pytest.raises(RobotsDeniedError):
            await fetcher.before_request("https://robots-all.test/anything")
    finally:
        await client.aclose()


# ── pgvector.py ──────────────────────────────────────────────────────────────────


def test_pgvector_literal_formats_values() -> None:
    assert pgvector_mod.pgvector_literal([1.0, 0.25]) == "[1,0.25]"
    assert pgvector_mod.pgvector_literal([]) == "[]"


async def test_sync_embedding_vector_skips_when_no_bind() -> None:
    session = _mock_session()
    session.get_bind = MagicMock(return_value=None)

    await pgvector_mod.sync_embedding_vector(
        session, table_name="bb_corpus_reports", row_id=1, embedding=[0.1]
    )
    session.execute.assert_not_awaited()


async def test_sync_embedding_vector_skips_non_postgres() -> None:
    session = _mock_session()
    bind = MagicMock()
    bind.dialect.name = "sqlite"
    session.get_bind = MagicMock(return_value=bind)

    await pgvector_mod.sync_embedding_vector(
        session, table_name="bb_corpus_reports", row_id=1, embedding=[0.1]
    )
    session.execute.assert_not_awaited()


async def test_sync_embedding_vector_updates_postgres_column() -> None:
    session = _mock_session()
    bind = MagicMock()
    bind.dialect.name = "postgresql"
    session.get_bind = MagicMock(return_value=bind)

    await pgvector_mod.sync_embedding_vector(
        session, table_name="bb_corpus_writeups", row_id=42, embedding=[0.5, -1.0]
    )

    session.execute.assert_awaited_once()
    statement, params = session.execute.await_args.args
    sql = str(statement)
    assert "UPDATE bb_corpus_writeups SET embedding_vector" in sql
    assert "CAST(:embedding AS vector)" in sql
    assert params == {"embedding": "[0.5,-1]", "row_id": 42}
