"""Tests for learning-source fetch guardrails."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from netra.bugbounty.learning.fetcher import LearningFetcher, RobotsDeniedError


@pytest.mark.asyncio
async def test_fetcher_blocks_disallowed_robots_path() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(200, text="User-agent: *\nDisallow: /private\n")
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client)
        with pytest.raises(RobotsDeniedError):
            await fetcher.get_text("https://example.com/private/report")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_fetcher_respects_retry_after_header() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url).endswith("/robots.txt"):
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        return httpx.Response(429, headers={"Retry-After": "0"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        fetcher = LearningFetcher(client=client, max_retries=1)
        with pytest.raises(RuntimeError):
            await fetcher.get_text("https://example.com/feed")
        assert calls.count("https://example.com/feed") == 2
    finally:
        await client.aclose()
