"""Coverage tests for the verifier allowlist loader and read-only replay runner.

SAFETY findings are documented as tests that pin the *current* behaviour. They are
marked with "SAFETY FINDING" comments; the source under src/ is intentionally not
modified by this test module.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator, ScopeViolation
from netra.bugbounty.verifiers import loader, runner
from netra.bugbounty.verifiers.loader import (
    VerifierConfigError,
    VerifierSpec,
    find_verifier,
    load_verifiers,
    reload_verifiers,
    verifiers_as_dicts,
)
from netra.db.models.bb_evidence import BBEvidence

# ── Helpers ─────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_loader_cache():
    load_verifiers.cache_clear()
    yield
    load_verifiers.cache_clear()


def _write_yaml(tmp_path, payload: Any, name: str = "allowlist.yaml"):
    path = tmp_path / name
    text = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _fixture_allowlist(monkeypatch):
    """Runner refuses specs not on the allowlist. Only the fixture spec (fixture_get / idor) is allowlisted."""
    from netra.bugbounty.verifiers import runner

    def _lookup(verifier_id, vuln_class):
        return _spec() if (verifier_id, vuln_class) == ("fixture_get", "idor") else None

    monkeypatch.setattr(runner, "find_verifier", _lookup)


def _spec(**overrides: Any) -> VerifierSpec:
    base: dict[str, Any] = dict(
        id="fixture_get",
        vuln_class="idor",
        description="fixture",
        methods=("GET", "HEAD"),
        will_do=(),
        will_not_do=(),
        requires=("scope_check",),
    )
    base.update(overrides)
    return VerifierSpec(**base)


def _allow_validator(host: str = "app.test") -> ScopeValidator:
    return ScopeValidator(
        [ScopeRule(rule_type=RuleType.IN, asset_type=AssetType.DOMAIN, pattern=host)]
    )


def _evidence(tmp_path, content: str | bytes, metadata: dict | None = None) -> BBEvidence:
    blob = tmp_path / "evidence.json"
    if isinstance(content, bytes):
        blob.write_bytes(content)
    else:
        blob.write_text(content, encoding="utf-8")
    return BBEvidence(
        filename="evidence.json",
        mime_type="application/json",
        storage_path=str(blob),
        sha256="0" * 64,
        size_bytes=blob.stat().st_size,
        encrypted=False,
        metadata_=metadata,
    )


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "application/json"}


class _FakeClient:
    """Stand-in for httpx.AsyncClient. Records requests; never touches the network."""

    created: list[_FakeClient] = []
    response: _FakeResponse = _FakeResponse()
    raise_on_request: Exception | None = None

    def __init__(self, **kwargs: Any):
        self.kwargs = kwargs
        self.requests: list[tuple[str, str, dict]] = []
        _FakeClient.created.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method: str, url: str, headers: dict | None = None):
        self.requests.append((method, url, headers or {}))
        if _FakeClient.raise_on_request is not None:
            raise _FakeClient.raise_on_request
        return _FakeClient.response


@pytest.fixture
def fake_httpx(monkeypatch):
    _FakeClient.created = []
    _FakeClient.response = _FakeResponse(200, "hello world")
    _FakeClient.raise_on_request = None
    monkeypatch.setattr(runner, "httpx", SimpleNamespace(AsyncClient=_FakeClient))
    return _FakeClient


# ── loader.py ───────────────────────────────────────────────────────────────────


def test_repo_allowlist_loads_and_is_read_only():
    """The shipped verifier_allowlist.yaml parses and every verifier is GET/HEAD only."""
    specs = load_verifiers()
    ids = {s.id for s in specs}
    assert {"xss_reflected_passive", "ssrf_head_probe", "idor_read_only"} <= ids
    for spec in specs:
        assert set(spec.methods) <= {"GET", "HEAD"}, spec.id
        assert "scope_check" in spec.requires, spec.id


def test_load_valid_fixture_normalises_fields(tmp_path):
    path = _write_yaml(
        tmp_path,
        {
            "verifiers": [
                {
                    "id": "v1",
                    "vuln_class": "IDOR",
                    "description": "d",
                    "methods": ["get", "head"],
                    "will_do": ["a"],
                    "will_not_do": ["b"],
                    "requires": ["scope_check"],
                }
            ]
        },
    )
    (spec,) = load_verifiers(path)
    assert spec.id == "v1"
    assert spec.vuln_class == "idor"  # lowercased
    assert spec.methods == ("GET", "HEAD")  # uppercased
    assert spec.will_do == ("a",)
    assert spec.will_not_do == ("b",)
    assert spec.requires == ("scope_check",)


def test_optional_keys_take_defaults(tmp_path):
    path = _write_yaml(tmp_path, {"verifiers": [{"id": "bare", "vuln_class": "xss"}]})
    (spec,) = load_verifiers(path)
    assert spec.vuln_class == "xss"
    assert spec.description == ""
    assert spec.methods == ("GET",)
    assert spec.will_do == () and spec.will_not_do == () and spec.requires == ()


def test_missing_verifiers_key_yields_empty_list(tmp_path):
    path = _write_yaml(tmp_path, {"other": 1})
    assert load_verifiers(path) == []


def test_missing_file_fails_closed(tmp_path):
    with pytest.raises(VerifierConfigError, match="Could not parse"):
        load_verifiers(tmp_path / "does_not_exist.yaml")


def test_invalid_json_fails_closed(tmp_path):
    path = _write_yaml(tmp_path, "{ not json", name="bad.yaml")
    with pytest.raises(VerifierConfigError, match="Could not parse"):
        load_verifiers(path)


def test_yaml_only_syntax_fails_closed(tmp_path):
    """v1 accepts JSON-compatible YAML only; block-style YAML is rejected, not guessed at."""
    path = _write_yaml(tmp_path, "verifiers:\n  - id: x\n", name="block.yaml")
    with pytest.raises(VerifierConfigError):
        load_verifiers(path)


def test_entry_missing_id_raises_config_error(tmp_path):
    path = _write_yaml(tmp_path, {"verifiers": [{"vuln_class": "xss"}]})
    with pytest.raises(VerifierConfigError, match="missing required key"):
        load_verifiers(path)


def test_non_object_entry_raises_config_error(tmp_path):
    path = _write_yaml(tmp_path, {"verifiers": ["not-an-object"]})
    with pytest.raises(VerifierConfigError, match="must be an object"):
        load_verifiers(path)


def test_top_level_list_raises_config_error(tmp_path):
    path = _write_yaml(tmp_path, [{"id": "x", "vuln_class": "xss"}])
    with pytest.raises(VerifierConfigError, match="must be an object"):
        load_verifiers(path)


def test_verifiers_must_be_a_list(tmp_path):
    path = _write_yaml(tmp_path, {"verifiers": {"id": "x", "vuln_class": "xss"}})
    with pytest.raises(VerifierConfigError, match="must be a list"):
        load_verifiers(path)


def test_string_methods_are_one_method(tmp_path):
    """A bare string is a single method, not a sequence of characters."""
    path = _write_yaml(tmp_path, {"verifiers": [{"id": "s", "vuln_class": "xss", "methods": "get"}]})
    (spec,) = load_verifiers(path)
    assert spec.methods == ("GET",)


def test_list_methods_are_uppercased(tmp_path):
    path = _write_yaml(
        tmp_path, {"verifiers": [{"id": "s", "vuln_class": "xss", "methods": ["get", "HEAD"]}]}
    )
    (spec,) = load_verifiers(path)
    assert spec.methods == ("GET", "HEAD")


@pytest.mark.parametrize("methods", [5, None, {"GET": 1}, ["GET", 1], [["GET"]]])
def test_invalid_methods_raise_config_error(tmp_path, methods):
    path = _write_yaml(
        tmp_path, {"verifiers": [{"id": "s", "vuln_class": "xss", "methods": methods}]}
    )
    with pytest.raises(VerifierConfigError, match="methods"):
        load_verifiers(path)


def test_missing_vuln_class_is_rejected_not_wildcarded(tmp_path):
    """Regression for the safety fix: a missing vuln_class must fail closed. It must not
    default to "*", which would make the verifier allowed for every vuln class (PRD 9.1)."""
    path = _write_yaml(tmp_path, {"verifiers": [{"id": "oops_no_class", "methods": ["GET"]}]})
    with pytest.raises(VerifierConfigError, match="vuln_class"):
        load_verifiers(path)


def test_load_verifiers_is_cached_per_path(tmp_path):
    path = _write_yaml(tmp_path, {"verifiers": [{"id": "a", "vuln_class": "xss"}]})
    first = load_verifiers(path)
    path.write_text(json.dumps({"verifiers": [{"id": "b", "vuln_class": "xss"}]}), encoding="utf-8")
    assert load_verifiers(path) is first  # served from cache until cleared
    load_verifiers.cache_clear()
    assert load_verifiers(path)[0].id == "b"


def test_find_verifier_matches_exact_class_and_wildcard(monkeypatch):
    specs = [
        _spec(id="idor_only", vuln_class="idor"),
        _spec(id="any", vuln_class="*"),
    ]
    monkeypatch.setattr(loader, "load_verifiers", lambda: specs)
    assert find_verifier("idor_only", "IDOR").id == "idor_only"  # case-insensitive
    assert find_verifier("idor_only", "xss") is None  # allowlist miss is refused
    assert find_verifier("any", "xss").id == "any"
    assert find_verifier("missing", "idor") is None


def test_find_verifier_unknown_id_returns_none():
    assert find_verifier("definitely_not_on_allowlist", "xss") is None


def test_verifiers_as_dicts_serialises_all_fields(monkeypatch):
    monkeypatch.setattr(loader, "load_verifiers", lambda: [_spec(will_do=("x",))])
    (d,) = verifiers_as_dicts()
    assert d["methods"] == ["GET", "HEAD"]
    assert d["will_do"] == ["x"]
    assert d["requires"] == ["scope_check"]
    assert set(d) == {
        "id",
        "vuln_class",
        "description",
        "methods",
        "will_do",
        "will_not_do",
        "requires",
    }


def test_reload_verifiers_clears_cache_and_reports(monkeypatch):
    calls = {"n": 0}
    real_cache_clear = load_verifiers.cache_clear

    def _spy_clear():
        calls["n"] += 1
        real_cache_clear()

    monkeypatch.setattr(load_verifiers, "cache_clear", _spy_clear)
    result = reload_verifiers()
    assert calls["n"] == 1
    assert any(item["id"] == "idor_read_only" for item in result)


# ── runner.py: parsing ─────────────────────────────────────────────────────────


def test_parse_nested_request_envelope(tmp_path):
    ev = _evidence(
        tmp_path,
        json.dumps(
            {
                "request": {
                    "method": "get",
                    "url": "https://app.test/a",
                    "headers": {"X-A": "1"},
                    "status_code": 200,
                    "body": "orig",
                }
            }
        ),
    )
    parsed = runner.parse_captured_request(ev)
    assert parsed == {
        "method": "GET",
        "url": "https://app.test/a",
        "headers": {"X-A": "1"},
        "original_status": 200,
        "original_body": "orig",
    }


def test_parse_flat_envelope_and_defaults(tmp_path):
    ev = _evidence(tmp_path, json.dumps({"target": "https://app.test/b", "headers": "bad"}))
    parsed = runner.parse_captured_request(ev)
    assert parsed["method"] == "GET"
    assert parsed["url"] == "https://app.test/b"
    assert parsed["headers"] == {}  # non-dict headers are discarded
    assert parsed["original_body"] == ""


def test_parse_non_json_falls_back_to_metadata(tmp_path):
    ev = _evidence(tmp_path, "GET raw text", metadata={"url": "https://app.test/c"})
    parsed = runner.parse_captured_request(ev)
    assert parsed["url"] == "https://app.test/c"
    assert parsed["method"] == "GET"


def test_parse_non_json_mutates_evidence_metadata(tmp_path):
    """Observation: runner.py:25 writes "raw" into evidence.metadata_ in place, so
    parsing mutates the ORM object the caller holds. Pinned as current behaviour."""
    meta: dict = {"url": "https://app.test/c"}
    ev = _evidence(tmp_path, "plain", metadata=meta)
    runner.parse_captured_request(ev)
    assert meta.get("raw") == "plain"


def test_parse_json_scalar_is_treated_as_raw_text(tmp_path):
    """A JSON scalar such as 123 is handled like non-JSON text: metadata is used and the
    scalar is kept under "raw"."""
    ev = _evidence(tmp_path, "123", metadata={"url": "https://app.test/s"})
    parsed = runner.parse_captured_request(ev)
    assert parsed["method"] == "GET"
    assert parsed["url"] == "https://app.test/s"
    assert ev.metadata_["raw"] == "123"


def test_parse_json_array_is_treated_as_raw_text(tmp_path):
    ev = _evidence(tmp_path, '[{"url": "https://app.test/a"}]', metadata={"target": "https://app.test/t"})
    parsed = runner.parse_captured_request(ev)
    assert parsed["url"] == "https://app.test/t"


# ── runner.py: run_replay ──────────────────────────────────────────────────────


async def test_replay_completes_and_reports_diff(tmp_path, fake_httpx):
    fake_httpx.response = _FakeResponse(404, "nope!", {"x-h": "1"})
    ev = _evidence(
        tmp_path,
        json.dumps(
            {
                "request": {
                    "method": "GET",
                    "url": "https://app.test/api/1",
                    "headers": {"Authorization": "redacted"},
                    "status_code": 200,
                    "body": "original-body",
                }
            }
        ),
    )
    result = await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert result["status"] == "completed"
    assert result["status_code"] == 404
    assert result["scope"].startswith("Matched in-scope rule")
    diff = result["diff"]
    assert diff["status_changed"] is True
    assert diff["original_status"] == 200
    assert diff["current_status"] == 404
    assert diff["body_length_delta"] == len("nope!") - len("original-body")
    assert diff["headers"]["x-h"] == "1"

    (client,) = fake_httpx.created
    assert client.kwargs["follow_redirects"] is False  # redirects never followed
    assert client.requests == [
        ("GET", "https://app.test/api/1", {"Authorization": "redacted"})
    ]


async def test_head_replay_sends_no_body_comparison(tmp_path, fake_httpx):
    fake_httpx.response = _FakeResponse(200, "ignored")
    ev = _evidence(
        tmp_path,
        json.dumps({"method": "HEAD", "url": "https://app.test/h", "body": "abc"}),
    )
    result = await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert result["status"] == "completed"
    assert result["diff"]["body_length_delta"] == -3  # HEAD never reads body
    assert result["diff"]["status_changed"] is False


async def test_missing_url_fails_without_request(tmp_path, fake_httpx):
    ev = _evidence(tmp_path, json.dumps({"method": "GET"}))
    result = await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert result["status"] == "failed"
    assert fake_httpx.created == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_mutating_method_is_blocked_before_any_request(tmp_path, fake_httpx, method):
    ev = _evidence(tmp_path, json.dumps({"method": method, "url": "https://app.test/x"}))
    # Even if a verifier lists the mutating method, the runner's GET/HEAD gate refuses.
    spec = _spec(methods=("GET", "HEAD", method))
    result = await runner.run_replay(ev, spec, _allow_validator(), vuln_class="idor")
    assert result["status"] == "blocked"
    assert method in result["error"]
    assert fake_httpx.created == []


async def test_method_not_on_verifier_is_blocked(tmp_path, fake_httpx):
    ev = _evidence(tmp_path, json.dumps({"method": "HEAD", "url": "https://app.test/x"}))
    spec = _spec(methods=("GET",))
    result = await runner.run_replay(ev, spec, _allow_validator(), vuln_class="idor")
    assert result["status"] == "blocked"
    assert fake_httpx.created == []


async def test_out_of_scope_url_is_refused_without_request(tmp_path, fake_httpx):
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://evil.test/x"}))
    with pytest.raises(ScopeViolation):
        await runner.run_replay(ev, _spec(), _allow_validator("app.test"), vuln_class="idor")
    assert fake_httpx.created == []


async def test_empty_scope_denies_everything(tmp_path, fake_httpx):
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://app.test/x"}))
    with pytest.raises(ScopeViolation):
        await runner.run_replay(ev, _spec(), ScopeValidator([]), vuln_class="idor")
    assert fake_httpx.created == []


async def test_scope_is_checked_before_network(tmp_path, fake_httpx):
    """Every replay that reaches the client must have passed validator.require first."""
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://app.test/x"}))
    seen: list[str] = []

    class _Recording(ScopeValidator):
        def require(self, target: str):
            seen.append(("require", target, len(fake_httpx.created)))
            return super().require(target)

    validator = _Recording(
        [ScopeRule(rule_type=RuleType.IN, asset_type=AssetType.DOMAIN, pattern="app.test")]
    )
    await runner.run_replay(ev, _spec(), validator, vuln_class="idor")
    # require() ran while no client existed yet, i.e. before any network activity.
    assert seen == [("require", "https://app.test/x", 0)]


async def test_transport_exception_is_reported_as_failed(tmp_path, fake_httpx):
    fake_httpx.raise_on_request = RuntimeError("connection reset")
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://app.test/x"}))
    result = await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert result["status"] == "failed"
    assert "connection reset" in result["error"]
    assert result["scope"].startswith("Matched in-scope rule")


async def test_status_unchanged_when_original_missing(tmp_path, fake_httpx):
    fake_httpx.response = _FakeResponse(500, "")
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://app.test/x"}))
    result = await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert result["diff"]["status_changed"] is False
    assert result["diff"]["original_status"] is None


# ── SAFETY FINDING: runner does not enforce the allowlist itself ───────────────


async def test_safety_runner_runs_unallowlisted_spec_for_mismatched_class(
    tmp_path, fake_httpx
):
    """Regression for the safety fix: run_replay() refuses a spec that is not on the
    allowlist for the finding's vuln_class, even when scope and method checks pass."""
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://app.test/x"}))
    rogue = _spec(id="never_allowlisted", vuln_class="xss")
    result = await runner.run_replay(ev, rogue, _allow_validator(), vuln_class="idor")
    assert result["status"] == "blocked"
    assert fake_httpx.created == []


async def test_safety_scope_still_required_for_any_spec(tmp_path, fake_httpx):
    """Scope recheck still applies to an allowlisted spec whose URL is out of scope."""
    ev = _evidence(tmp_path, json.dumps({"method": "GET", "url": "https://evil.test/x"}))
    with pytest.raises(ScopeViolation):
        await runner.run_replay(ev, _spec(), _allow_validator(), vuln_class="idor")
    assert fake_httpx.created == []
