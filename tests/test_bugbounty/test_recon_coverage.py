"""Coverage tests for bug bounty active and passive recon.

Every network call (httpx) and every subprocess is replaced with a fake. An autouse
guard makes any unfaked subprocess or HTTP client construction fail the test.

SAFETY findings are documented as tests that pin current behaviour; they do not
assert that the behaviour is correct.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from netra.bugbounty.recon import active, passive
from netra.bugbounty.scope import (
    AssetType,
    RuleType,
    ScopeDecision,
    ScopeRule,
    ScopeValidator,
    ScopeViolation,
)
from netra.scanner.tools.base import ToolResult

# ── Guards and helpers ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _forbid_real_io(monkeypatch):
    """Fail loudly if any test reaches a real subprocess or HTTP client."""

    async def _no_subprocess(*args, **kwargs):
        raise AssertionError(f"real subprocess attempted: {args[:1]}")

    class _NoClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("real httpx.AsyncClient constructed")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _no_subprocess)
    monkeypatch.setattr(httpx, "AsyncClient", _NoClient)


@pytest.fixture(autouse=True)
def _reset_passive_state(monkeypatch):
    passive._GITHUB_CACHE.clear()
    monkeypatch.setattr(passive, "_GITHUB_MISSING_TOKEN_LOGGED", False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    passive._GITHUB_CACHE.clear()


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple] = []


def _stub_tool(monkeypatch, module, cls_name: str, recorder: _Recorder, result):
    """Replace a tool class on a module with a fake whose run() returns `result`.

    `result` may be a ToolResult or a callable(target, kwargs) -> ToolResult.
    """

    class _FakeTool:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def run(self, target, **kwargs):
            recorder.calls.append((target, kwargs))
            return result(target, kwargs) if callable(result) else result

    monkeypatch.setattr(module, cls_name, _FakeTool)


def _ok(tool: str, findings: list[dict]) -> ToolResult:
    return ToolResult(tool_name=tool, success=True, findings=findings)


def _fail(tool: str, error: str) -> ToolResult:
    return ToolResult(tool_name=tool, success=False, error=error)


class _FakeResponse:
    def __init__(self, payload=None, status_code: int = 200, json_error: bool = False):
        self._payload = payload
        self.status_code = status_code
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("not json")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _install_fake_client(monkeypatch, response: _FakeResponse) -> list[dict]:
    """Install a fake httpx.AsyncClient; returns the list that records every call."""
    calls: list[dict] = []

    class _FakeClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            calls.append({"init": kwargs})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> bool:
            return False

        async def get(self, url, params=None):
            calls.append({"url": url, "params": params, "headers": self.kwargs.get("headers")})
            return response

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    return calls


def _example_validator() -> ScopeValidator:
    return ScopeValidator(
        [
            ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com"),
            ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.com"),
        ]
    )


# ── passive: normalisation helpers ──────────────────────────────────────────────


def test_normalise_hostname_rejects_empty_and_dotless() -> None:
    assert passive._normalise_hostname("") is None
    assert passive._normalise_hostname("localhost") is None


def test_normalise_hostname_strips_wildcard_case_and_url() -> None:
    assert passive._normalise_hostname("*.Api.Example.com.") == "api.example.com"
    assert passive._normalise_hostname("https://sub.example.com:8443/x") == "sub.example.com"


def test_normalise_hostname_seed_filter() -> None:
    assert passive._normalise_hostname("example.com", "example.com") == "example.com"
    assert passive._normalise_hostname("evil.com", "example.com") is None
    # Suffix match must be on a label boundary.
    assert passive._normalise_hostname("notexample.com", "example.com") is None


def test_hosts_from_findings_reads_all_candidate_keys() -> None:
    findings = [
        {"hostname": "a.example.com"},
        {"host": "b.example.com"},
        {"url": "https://c.example.com/path"},
        {"matched_at": "d.example.com:443"},
        {"matched-at": "e.example.com"},
        {"input": "f.example.com"},
        {"url": "https://evil.net/"},
        {},
    ]
    assert passive._hosts_from_findings(findings, "example.com") == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "d.example.com",
        "e.example.com",
        "f.example.com",
    ]


# ── passive: crt.sh ─────────────────────────────────────────────────────────────


async def test_crtsh_parses_multiline_names_and_common_name_fallback(monkeypatch) -> None:
    rows = [
        {"name_value": "api.example.com\n*.dev.example.com"},
        {"name_value": "", "common_name": "www.example.com"},
        {"name_value": "evil.net"},
        {"name_value": "example.com"},
    ]
    calls = _install_fake_client(monkeypatch, _FakeResponse(payload=rows))

    hosts = await passive._run_crtsh("example.com")

    assert hosts == ["api.example.com", "dev.example.com", "example.com", "www.example.com"]
    request = calls[1]
    assert request["url"] == "https://crt.sh/"
    assert request["params"] == {"q": "%.example.com", "output": "json"}


async def test_crtsh_non_json_and_non_list_payloads_yield_nothing(monkeypatch) -> None:
    _install_fake_client(monkeypatch, _FakeResponse(json_error=True))
    assert await passive._run_crtsh("example.com") == []

    _install_fake_client(monkeypatch, _FakeResponse(payload={"unexpected": "dict"}))
    assert await passive._run_crtsh("example.com") == []


async def test_crtsh_http_error_surfaces_as_run_error(monkeypatch) -> None:
    _install_fake_client(monkeypatch, _FakeResponse(status_code=500))

    result = await passive.run_passive_recon(
        ["example.com"], _example_validator(), "example", sources=["crtsh"]
    )

    assert result.in_scope_hosts == []
    assert result.errors == ["crtsh:HTTP 500"]


# ── passive: subfinder and amass ────────────────────────────────────────────────


async def test_subfinder_success_uses_passive_mode_and_filters(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(
        monkeypatch,
        passive,
        "SubfinderTool",
        recorder,
        _ok("subfinder", [{"hostname": "a.example.com"}, {"hostname": "other.net"}]),
    )

    hosts = await passive._run_subfinder("example.com")

    assert hosts == ["a.example.com"]
    assert recorder.calls == [("example.com", {"passive_only": True})]


async def test_subfinder_failure_returns_empty(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, passive, "SubfinderTool", recorder, _fail("subfinder", "boom"))
    assert await passive._run_subfinder("example.com") == []


async def test_amass_success_uses_passive_mode(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(
        monkeypatch,
        passive,
        "AmassTool",
        recorder,
        _ok("amass", [{"url": "https://b.example.com/"}]),
    )

    hosts = await passive._run_amass_passive("example.com")

    assert hosts == ["b.example.com"]
    assert recorder.calls == [("example.com", {"passive": True})]


async def test_amass_failure_returns_empty(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, passive, "AmassTool", recorder, _fail("amass", "boom"))
    assert await passive._run_amass_passive("example.com") == []


# ── passive: GitHub dorks ───────────────────────────────────────────────────────


async def test_github_dorks_without_token_skips_and_logs_once(monkeypatch) -> None:
    # No client is installed here: the autouse guard fails the test if one is built.
    assert await passive._run_github_dorks("example.com") == []
    assert await passive._run_github_dorks("example.com") == []

    assert passive._GITHUB_MISSING_TOKEN_LOGGED is True


async def test_out_of_scope_hosts_are_partitioned(monkeypatch) -> None:
    async def source(seed: str) -> list[str]:
        return ["api.example.com", "evil.net"]

    monkeypatch.setitem(passive.SOURCES, "unit", source)

    result = await passive.run_passive_recon(
        ["example.com"], _example_validator(), "example", sources=["unit"]
    )

    assert result.in_scope_hosts == ["api.example.com"]
    assert result.out_of_scope_hosts == ["evil.net"]


async def test_github_dorks_extracts_hosts_and_caches(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok-test")
    payload = {
        "items": [
            {
                "name": "config.yml",
                "path": "deploy/config.yml",
                "text_matches": [
                    {"fragment": "url: https://api.example.com/v1, see dev.example.com"},
                    {"fragment": "other: evil.org"},
                ],
            },
            {"name": "README.md", "path": "README.md", "text_matches": None},
        ]
    }
    calls = _install_fake_client(monkeypatch, _FakeResponse(payload=payload))

    first = await passive._run_github_dorks("example.com")
    second = await passive._run_github_dorks("example.com")

    assert first == ["api.example.com", "dev.example.com"]
    assert second == first
    requests = [c for c in calls if "url" in c]
    assert len(requests) == 1, "second call must be served from the cache"
    assert requests[0]["url"] == "https://api.github.com/search/code"
    assert requests[0]["params"] == {"q": '"example.com"', "per_page": 50}
    assert requests[0]["headers"]["Authorization"] == "Bearer tok-test"


async def test_github_dorks_cache_expires(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok-test")
    passive._GITHUB_CACHE["example.com"] = (
        time.time() - 7200,
        ["stale.example.com"],
    )
    calls = _install_fake_client(
        monkeypatch,
        _FakeResponse(payload={"items": [{"name": "x", "path": "y.example.com"}]}),
    )

    hosts = await passive._run_github_dorks("example.com")

    assert hosts == ["y.example.com"]
    assert any("url" in c for c in calls)


@pytest.mark.parametrize("status", [403, 429])
async def test_github_dorks_rate_limit_returns_empty_and_is_not_cached(monkeypatch, status) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok-test")
    calls = _install_fake_client(monkeypatch, _FakeResponse(status_code=status))

    assert await passive._run_github_dorks("example.com") == []
    assert "example.com" not in passive._GITHUB_CACHE

    await passive._run_github_dorks("example.com")
    assert len([c for c in calls if "url" in c]) == 2


async def test_github_dorks_server_error_is_raised_to_caller(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok-test")
    _install_fake_client(monkeypatch, _FakeResponse(status_code=500))

    with pytest.raises(RuntimeError, match="HTTP 500"):
        await passive._run_github_dorks("example.com")

    result = await passive.run_passive_recon(
        ["example.com"], _example_validator(), "example", sources=["github_dorks"]
    )
    assert result.errors == ["github_dorks:HTTP 500"]


# ── passive: orchestration ──────────────────────────────────────────────────────


async def test_unknown_source_is_recorded_not_raised() -> None:
    result = await passive.run_passive_recon(
        ["example.com"], _example_validator(), "example", sources=["nope"]
    )
    assert result.errors == ["unknown_source:nope"]
    assert result.in_scope_hosts == []


async def test_source_exception_is_recorded_and_other_sources_still_run(monkeypatch) -> None:
    async def broken(seed: str) -> list[str]:
        raise OSError("socket closed")

    async def healthy(seed: str) -> list[str]:
        return ["ok.example.com"]

    monkeypatch.setitem(passive.SOURCES, "broken", broken)
    monkeypatch.setitem(passive.SOURCES, "healthy", healthy)

    result = await passive.run_passive_recon(
        ["example.com"], _example_validator(), "example", sources=["broken", "healthy"]
    )

    assert result.errors == ["broken:socket closed"]
    assert result.in_scope_hosts == ["ok.example.com"]
    assert result.sources == {"healthy": 1}


async def test_default_sources_runs_every_registered_source(monkeypatch) -> None:
    seen: list[str] = []

    def _make(name: str):
        async def _src(seed: str) -> list[str]:
            seen.append(name)
            return []

        return _src

    for name in list(passive.SOURCES):
        monkeypatch.setitem(passive.SOURCES, name, _make(name))

    await passive.run_passive_recon(["example.com"], _example_validator(), "example")

    assert sorted(seen) == sorted(passive.SOURCES)


async def test_counts_accumulate_across_seeds_and_dedupe_hosts(monkeypatch) -> None:
    async def source(seed: str) -> list[str]:
        return ["shared.example.com"]

    monkeypatch.setitem(passive.SOURCES, "unit", source)

    result = await passive.run_passive_recon(
        ["example.com", "a.example.com"],
        ScopeValidator(
            [
                ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com"),
                ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.com"),
            ]
        ),
        "example",
        sources=["unit"],
    )

    assert result.in_scope_hosts == ["shared.example.com"]
    # Per-source counts are summed per seed, so duplicates across seeds are counted twice.
    assert result.sources["unit"] == 2


async def test_out_of_scope_seed_is_never_sent_to_sources(monkeypatch) -> None:
    """Regression for the safety fix: an out-of-scope seed is refused before any source runs."""
    received: list[str] = []

    async def recording(seed: str) -> list[str]:
        received.append(seed)
        return []

    monkeypatch.setitem(passive.SOURCES, "recording", recording)

    result = await passive.run_passive_recon(
        ["evil.net"], _example_validator(), "example", sources=["recording"]
    )

    assert received == []
    assert result.in_scope_hosts == []
    assert "seed_out_of_scope:evil.net" in result.errors


# ── active: liveness, ffuf, nuclei wrappers ─────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, True),
        (204, True),
        (301, True),
        (399, True),
        (400, False),
        (404, False),
        (500, False),
        (None, False),
    ],
)
async def test_httpx_alive_status_window(monkeypatch, status, expected) -> None:
    recorder = _Recorder()
    _stub_tool(
        monkeypatch,
        active,
        "HttpxTool",
        recorder,
        _ok("httpx", [{"url": "https://a.example.com", "status_code": status}]),
    )

    assert (
        await active.httpx_alive("https://a.example.com", validator=_example_validator())
        is expected
    )


async def test_httpx_alive_passes_head_and_no_redirect_flags(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "HttpxTool", recorder, _ok("httpx", []))

    assert (
        await active.httpx_alive("https://a.example.com", validator=_example_validator()) is False
    )
    target, kwargs = recorder.calls[0]
    assert target == "https://a.example.com"
    assert kwargs == {"follow_redirects": False, "tech_detect": True, "head": True}


async def test_httpx_alive_tool_failure_returns_false(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "HttpxTool", recorder, _fail("httpx", "timeout"))
    assert (
        await active.httpx_alive("https://a.example.com", validator=_example_validator()) is False
    )


async def test_ffuf_paths_normalises_dedupes_and_sorts(monkeypatch) -> None:
    recorder = _Recorder()
    findings = [
        {"path": "admin"},
        {"path": "/admin"},
        {"url": "https://a.example.com/api/v1"},
        {"url": "https://a.example.com/"},
        {"path": ""},
    ]
    _stub_tool(monkeypatch, active, "FfufTool", recorder, _ok("ffuf", findings))

    paths = await active.ffuf_paths(
        "https://a.example.com/", wordlist="dirs.txt", rate_limit=10, validator=_example_validator()
    )

    assert paths == ["/", "/admin", "/api/v1"]
    target, kwargs = recorder.calls[0]
    assert target == "https://a.example.com/FUZZ"
    assert kwargs == {"wordlist": "dirs.txt", "rate_limit": 10}


async def test_ffuf_paths_failure_returns_empty(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "FfufTool", recorder, _fail("ffuf", "bad wordlist"))
    assert await active.ffuf_paths("https://a.example.com", validator=_example_validator()) == []


async def test_nuclei_safe_normalises_both_key_styles(monkeypatch) -> None:
    recorder = _Recorder()
    findings = [
        {
            "template_id": "tpl-a",
            "matched_at": "https://a.example.com/x",
            "severity": "high",
            "title": "Exposed thing",
            "evidence": {"raw": 1},
        },
        {
            "template-id": "tpl-b",
            "matched-at": "https://a.example.com/y",
        },
        {"url": "https://a.example.com/z"},
    ]
    _stub_tool(monkeypatch, active, "NucleiTool", recorder, _ok("nuclei", findings))

    out = await active.nuclei_safe(
        "https://a.example.com", severity_cap="high", validator=_example_validator()
    )

    assert out[0] == {
        "template_id": "tpl-a",
        "matched_at": "https://a.example.com/x",
        "severity": "high",
        "title": "Exposed thing",
        "evidence": {"raw": 1},
    }
    assert out[1]["template_id"] == "tpl-b"
    assert out[1]["matched_at"] == "https://a.example.com/y"
    assert out[1]["severity"] == "info"
    assert out[1]["title"] == "Nuclei finding"
    assert out[1]["evidence"] == findings[1]
    assert out[2]["matched_at"] == "https://a.example.com/z"

    target, kwargs = recorder.calls[0]
    assert target == "https://a.example.com"
    assert kwargs == {"tags": "cve,exposure,misconfig", "severity": "high", "rate_limit": 25}


async def test_nuclei_safe_defaults_to_medium_cap(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "NucleiTool", recorder, _ok("nuclei", []))

    assert await active.nuclei_safe("https://a.example.com", validator=_example_validator()) == []
    assert recorder.calls[0][1]["severity"] == "medium"


async def test_nuclei_safe_failure_returns_empty(monkeypatch) -> None:
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "NucleiTool", recorder, _fail("nuclei", "crash"))
    assert await active.nuclei_safe("https://a.example.com", validator=_example_validator()) == []


# ── active: run_active_recon orchestration ──────────────────────────────────────


def _active_validator() -> ScopeValidator:
    return ScopeValidator(
        [
            ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.com", severity_cap="high"),
            ScopeRule(RuleType.OUT, AssetType.DOMAIN, "admin.example.com"),
        ]
    )


async def test_run_active_recon_blocks_out_of_scope_before_any_tool(monkeypatch) -> None:
    httpx_rec, ffuf_rec, nuclei_rec = _Recorder(), _Recorder(), _Recorder()
    _stub_tool(monkeypatch, active, "HttpxTool", httpx_rec, _ok("httpx", []))
    _stub_tool(monkeypatch, active, "FfufTool", ffuf_rec, _ok("ffuf", []))
    _stub_tool(monkeypatch, active, "NucleiTool", nuclei_rec, _ok("nuclei", []))

    result = await active.run_active_recon(
        ["evil.net", "admin.example.com"],
        _active_validator(),
        enable_ffuf=True,
        enable_nuclei=True,
    )

    assert [host for host, _ in result.blocked_targets] == ["evil.net", "admin.example.com"]
    assert all(reason for _, reason in result.blocked_targets)
    assert httpx_rec.calls == [] and ffuf_rec.calls == [] and nuclei_rec.calls == []


async def test_run_active_recon_full_in_scope_flow(monkeypatch) -> None:
    httpx_rec, ffuf_rec, nuclei_rec = _Recorder(), _Recorder(), _Recorder()
    _stub_tool(
        monkeypatch,
        active,
        "HttpxTool",
        httpx_rec,
        _ok("httpx", [{"url": "https://a.example.com", "status_code": 200}]),
    )
    _stub_tool(
        monkeypatch,
        active,
        "FfufTool",
        ffuf_rec,
        _ok("ffuf", [{"path": "/robots.txt"}, {"path": "/admin/login"}]),
    )
    _stub_tool(
        monkeypatch,
        active,
        "NucleiTool",
        nuclei_rec,
        _ok("nuclei", [{"template_id": "exp-1", "matched_at": "https://a.example.com/"}]),
    )

    result = await active.run_active_recon(
        ["a.example.com"],
        _active_validator(),
        enable_ffuf=True,
        enable_nuclei=True,
        wordlist="w.txt",
        rate_limit=5,
    )

    assert result.alive_hosts == ["a.example.com"]
    assert result.discovered_paths == [
        "a.example.com/admin/login",
        "a.example.com/robots.txt",
    ]
    assert result.nuclei_findings[0]["template_id"] == "exp-1"
    assert result.errors == []
    assert result.blocked_targets == []
    # The severity cap from the matched scope rule is forwarded to nuclei.
    assert nuclei_rec.calls[0][1]["severity"] == "high"
    assert ffuf_rec.calls[0] == ("a.example.com/FUZZ", {"wordlist": "w.txt", "rate_limit": 5})


async def test_run_active_recon_disabled_phases_do_not_run_tools(monkeypatch) -> None:
    httpx_rec, ffuf_rec, nuclei_rec = _Recorder(), _Recorder(), _Recorder()
    _stub_tool(monkeypatch, active, "HttpxTool", httpx_rec, _ok("httpx", []))
    _stub_tool(monkeypatch, active, "FfufTool", ffuf_rec, _ok("ffuf", []))
    _stub_tool(monkeypatch, active, "NucleiTool", nuclei_rec, _ok("nuclei", []))

    result = await active.run_active_recon(
        ["a.example.com"],
        _active_validator(),
        enable_alive=False,
    )

    assert result == active.ActiveReconResult()
    assert httpx_rec.calls == [] and ffuf_rec.calls == [] and nuclei_rec.calls == []


async def test_run_active_recon_tool_exception_is_recorded_per_host(monkeypatch) -> None:
    class _ExplodingHttpx:
        def __init__(self, *a, **k) -> None:
            pass

        async def run(self, target, **kwargs):
            raise ConnectionError("reset by peer")

    monkeypatch.setattr(active, "HttpxTool", _ExplodingHttpx)

    result = await active.run_active_recon(["a.example.com"], _active_validator())

    assert result.errors == ["a.example.com:reset by peer"]
    assert result.alive_hosts == []


async def test_run_active_recon_path_violation_is_recorded_as_error(monkeypatch) -> None:
    """A ffuf path rejected by the validator is recorded as a generic host error.

    The ScopeViolation is caught by the broad handler (active.py:118), not by the
    blocked-target branch, and the remaining phases for that host are skipped.
    """

    class _PathBlockingValidator:
        def __init__(self, inner: ScopeValidator) -> None:
            self._inner = inner

        def require(self, target: str) -> ScopeDecision:
            if "/secret" in target:
                raise ScopeViolation(ScopeDecision(allowed=False, reason="path denied"))
            return self._inner.require(target)

    recorder, nuclei_rec = _Recorder(), _Recorder()
    _stub_tool(
        monkeypatch,
        active,
        "HttpxTool",
        _Recorder(),
        _ok("httpx", [{"status_code": 200}]),
    )
    _stub_tool(
        monkeypatch,
        active,
        "FfufTool",
        recorder,
        _ok("ffuf", [{"path": "/ok"}, {"path": "/secret"}]),
    )
    _stub_tool(monkeypatch, active, "NucleiTool", nuclei_rec, _ok("nuclei", []))

    result = await active.run_active_recon(
        ["a.example.com"],
        _PathBlockingValidator(_active_validator()),
        enable_ffuf=True,
        enable_nuclei=True,
    )

    assert result.discovered_paths == ["a.example.com/ok"]
    assert result.errors == ["a.example.com:Out of scope: path denied"]
    assert nuclei_rec.calls == []
    assert result.blocked_targets == []


async def test_safety_ffuf_paths_refuses_out_of_scope_host(monkeypatch) -> None:
    """Regression for the safety fix: ffuf_paths checks scope itself before any tool runs."""
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "FfufTool", recorder, _ok("ffuf", []))

    with pytest.raises(ScopeViolation):
        await active.ffuf_paths("https://evil.net", validator=_example_validator())
    assert recorder.calls == []


async def test_safety_ffuf_paths_requires_a_validator(monkeypatch) -> None:
    """Regression: calling ffuf_paths without a validator is refused, not run ungated."""
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "FfufTool", recorder, _ok("ffuf", []))

    with pytest.raises(ValueError, match="ScopeValidator is required"):
        await active.ffuf_paths("https://a.example.com")
    assert recorder.calls == []


async def test_safety_nuclei_safe_refuses_out_of_scope_host(monkeypatch) -> None:
    """Regression for the safety fix: nuclei_safe checks scope itself before any tool runs."""
    recorder = _Recorder()
    _stub_tool(monkeypatch, active, "NucleiTool", recorder, _ok("nuclei", []))

    with pytest.raises(ScopeViolation):
        await active.nuclei_safe("https://evil.net", validator=_example_validator())
    assert recorder.calls == []
