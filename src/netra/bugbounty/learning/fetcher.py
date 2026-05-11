"""Shared fetch guardrails for NETRA-BB learning sources."""
from __future__ import annotations

import asyncio
import time
from email.utils import parsedate_to_datetime
from typing import Any
from urllib import robotparser
from urllib.parse import urlparse

import httpx

from netra.core.config import settings


class RobotsDeniedError(RuntimeError):
    """Raised when robots.txt denies access to a URL."""


class LearningFetcher:
    """Fetch helper with robots checks and simple per-host rate limiting."""

    _host_locks: dict[str, asyncio.Lock] = {}
    _host_last_request: dict[str, float] = {}
    _robots_cache: dict[str, robotparser.RobotFileParser | None] = {}

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        user_agent: str = "NETRA-BB/1.0",
        obey_robots: bool | None = None,
        default_rps: float | None = None,
        max_retries: int = 2,
    ) -> None:
        self.client = client
        self.user_agent = user_agent
        self.obey_robots = settings.corpus_obey_robots if obey_robots is None else obey_robots
        self.default_rps = settings.corpus_default_rps if default_rps is None else default_rps
        self.max_retries = max_retries

    async def before_request(self, url: str) -> None:
        """Check robots and rate-limit before a source HTTP call."""
        await self._ensure_allowed(url)
        await self._respect_rate_limit(url)

    async def after_response(self, _url: str, response: httpx.Response) -> None:
        """Honor server-provided backoff hints when possible."""
        if response.status_code != 429:
            return
        delay = self._retry_after_seconds(response.headers.get("Retry-After"))
        if delay > 0:
            await asyncio.sleep(delay)

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        response = await self._request("GET", url, **kwargs)
        return response.json()

    async def get_text(self, url: str, **kwargs: Any) -> str:
        response = await self._request("GET", url, **kwargs)
        return response.text

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        close_client = False
        client = self.client
        if client is None:
            client = httpx.AsyncClient(timeout=60, headers={"User-Agent": self.user_agent})
            close_client = True
        try:
            headers = {"User-Agent": self.user_agent, **kwargs.pop("headers", {})}
            last_exc: Exception | None = None
            for _attempt in range(self.max_retries + 1):
                await self.before_request(url)
                response = await client.request(method, url, headers=headers, **kwargs)
                await self.after_response(url, response)
                if response.status_code != 429:
                    response.raise_for_status()
                    return response
                last_exc = RuntimeError(f"rate limited by {urlparse(url).hostname}")
            raise last_exc or RuntimeError(f"request failed: {url}")
        finally:
            if close_client:
                await client.aclose()

    async def _ensure_allowed(self, url: str) -> None:
        if not self.obey_robots:
            return
        parser = await self._robots_parser(url)
        if parser is None:
            return
        if not parser.can_fetch(self.user_agent, url):
            raise RobotsDeniedError(f"robots.txt disallows {url}")

    async def _robots_parser(self, url: str) -> robotparser.RobotFileParser | None:
        parsed = urlparse(url)
        host = parsed.netloc
        if host in self._robots_cache:
            return self._robots_cache[host]
        robots_url = f"{parsed.scheme or 'https'}://{host}/robots.txt"
        client = self.client or httpx.AsyncClient(timeout=20, headers={"User-Agent": self.user_agent})
        created_client = self.client is None
        try:
            response = await client.get(robots_url)
            if response.status_code >= 400:
                self._robots_cache[host] = None
                return None
            parser = robotparser.RobotFileParser()
            parser.parse(response.text.splitlines())
            self._robots_cache[host] = parser
            return parser
        except Exception:
            self._robots_cache[host] = None
            return None
        finally:
            if created_client:
                await client.aclose()

    async def _respect_rate_limit(self, url: str) -> None:
        if self.default_rps <= 0:
            return
        host = urlparse(url).netloc
        lock = self._host_locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            min_interval = 1.0 / float(self.default_rps)
            last = self._host_last_request.get(host, 0.0)
            wait = min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._host_last_request[host] = time.monotonic()

    @staticmethod
    def _retry_after_seconds(value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                target = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return 0.0
            return max(0.0, target.timestamp() - time.time())
