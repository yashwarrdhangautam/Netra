"""Coverage closure for bugbounty programs, scope, submission draft and recon enrich.

Targets the lines left uncovered by the existing suites (test_scope.py,
test_scope_add.py, test_enrich.py, test_cli_scope_sync.py, ...). No real HTTP and no
real database: DB access goes through an in-memory fake session and the gitleaks
CLI wrapper is replaced with a stub.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from netra.bugbounty import programs as programs_mod
from netra.bugbounty.programs import (
    ProgramInput,
    ScopeRuleInput,
    add_scope_rule,
    apply_scope_diff,
    create_program,
    diff_scope,
    get_program,
    list_active_programs,
    replace_scope_rules,
)
from netra.bugbounty.recon import enrich as enrich_mod
from netra.bugbounty.recon.enrich import extract_js_endpoints, hunt_secrets, hunt_secrets_async
from netra.bugbounty.scope import (
    AssetType,
    RuleType,
    ScopeRule,
    ScopeValidator,
    ScopeViolation,
    _match_cidr,
    _match_ip,
    _match_mobile,
    _match_repo,
    _match_wildcard,
    _normalise_host,
    parse_target,
)
from netra.bugbounty.submission.draft import (
    DraftSections,
    _ngrams,
    detect_verbatim_overlap,
    render_markdown,
    title_from_class,
)
from netra.db.models.bb_program import BBPlatform, BBProgram
from netra.db.models.bb_scope_rule import BBScopeRule, ScopeAssetType, ScopeRuleType


# ── Fakes ───────────────────────────────────────────────────────────────────────
class _FakeResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    """Minimal AsyncSession stand-in. Each execute() pops the next queued row list."""

    def __init__(self, results=()):
        self._results = list(results)
        self.statements: list = []
        self.added: list = []
        self.flushes = 0

    async def execute(self, stmt):
        self.statements.append(stmt)
        rows = self._results.pop(0) if self._results else []
        return _FakeResult(rows)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flushes += 1


def _program(handle: str = "acme") -> BBProgram:
    return BBProgram(
        id=uuid.uuid4(),
        platform=BBPlatform.HACKERONE,
        handle=handle,
        name="Acme",
        currency="USD",
        active=True,
    )


def _db_rule(
    pattern: str,
    *,
    rule_type: ScopeRuleType = ScopeRuleType.IN,
    asset_type: ScopeAssetType = ScopeAssetType.DOMAIN,
    synced: bool = True,
    active: bool = True,
) -> BBScopeRule:
    return BBScopeRule(
        program_id=uuid.uuid4(),
        rule_type=rule_type,
        asset_type=asset_type,
        pattern=pattern,
        active=active,
        synced_from_platform=synced,
    )


# ── programs.py ─────────────────────────────────────────────────────────────────
async def test_get_program_returns_match_and_filters_by_platform_and_handle():
    prog = _program("acme")
    session = _FakeSession(results=[[prog]])

    found = await get_program(session, BBPlatform.HACKERONE, "acme")

    assert found is prog
    sql = str(session.statements[0])
    assert "bb_programs.platform" in sql
    assert "bb_programs.handle" in sql


async def test_get_program_returns_none_when_absent():
    session = _FakeSession(results=[[]])
    assert await get_program(session, BBPlatform.BUGCROWD, "missing") is None


async def test_create_program_inserts_active_program_and_flushes():
    session = _FakeSession()
    data = ProgramInput(
        platform=BBPlatform.BUGCROWD,
        handle="widgets",
        name="Widgets",
        policy_url="https://example.com/policy",
        payout_min=100,
        payout_max=5000,
    )

    program = await create_program(session, data)

    assert program.platform == BBPlatform.BUGCROWD
    assert program.handle == "widgets"
    assert program.policy_url == "https://example.com/policy"
    assert program.payout_min == 100
    assert program.payout_max == 5000
    assert program.currency == "USD"
    assert program.active is True
    assert session.added == [program]
    assert session.flushes == 1


async def test_list_active_programs_excludes_soft_deleted_rows():
    progs = [_program("a"), _program("b")]
    session = _FakeSession(results=[progs])

    result = await list_active_programs(session)

    assert result == progs
    assert "deleted_at IS NULL" in str(session.statements[0])


def test_diff_scope_matches_case_and_whitespace_insensitively():
    existing = [
        _db_rule("A.example.com"),
        _db_rule("b.example.com"),
    ]
    fresh = [
        ScopeRuleInput(
            rule_type=ScopeRuleType.IN,
            asset_type=ScopeAssetType.DOMAIN,
            pattern="  a.example.com ",
        ),
        ScopeRuleInput(
            rule_type=ScopeRuleType.IN,
            asset_type=ScopeAssetType.DOMAIN,
            pattern="c.example.com",
        ),
    ]

    diff = diff_scope(existing, fresh)

    assert [r.pattern for r in diff.added] == ["c.example.com"]
    assert [r.pattern for r in diff.removed] == ["b.example.com"]
    assert diff.unchanged_count == 1
    assert diff.has_changes is True


async def test_apply_scope_diff_deactivates_removed_and_inserts_added():
    program = _program()
    stale = _db_rule("old.example.com")
    diff = programs_mod.ScopeDiff(
        added=[
            ScopeRuleInput(
                rule_type=ScopeRuleType.IN,
                asset_type=ScopeAssetType.WILDCARD,
                pattern="*.example.com",
                severity_cap="high",
                notes="from H1",
            )
        ],
        removed=[stale],
        unchanged_count=0,
    )
    session = _FakeSession()

    await apply_scope_diff(session, program, diff)

    assert stale.active is False
    assert len(session.added) == 1
    new_rule = session.added[0]
    assert isinstance(new_rule, BBScopeRule)
    assert new_rule.pattern == "*.example.com"
    assert new_rule.severity_cap == "high"
    assert new_rule.notes == "from H1"
    assert new_rule.active is True
    assert new_rule.synced_from_platform is True
    assert program.scope_synced_at is not None
    assert session.flushes == 1


async def test_replace_scope_rules_without_changes_only_stamps_sync_time():
    program = _program()
    existing = _db_rule("a.example.com")
    session = _FakeSession(results=[[existing]])
    fresh = [
        ScopeRuleInput(
            rule_type=ScopeRuleType.IN,
            asset_type=ScopeAssetType.DOMAIN,
            pattern="A.EXAMPLE.COM",
        )
    ]

    diff = await replace_scope_rules(session, program, fresh)

    assert diff.has_changes is False
    assert session.added == []
    assert existing.active is True
    assert program.scope_synced_at is not None
    assert session.flushes == 1


async def test_add_scope_rule_records_manual_rule_as_not_platform_synced():
    program = _program()
    session = _FakeSession()

    rule = await add_scope_rule(
        session,
        program,
        pattern="  lab.example.com  ",
        asset_type="domain",
        rule_type="out",
        severity_cap="low",
        notes="lab only",
    )

    assert rule.pattern == "lab.example.com"
    assert rule.rule_type == ScopeRuleType.OUT
    assert rule.asset_type == ScopeAssetType.DOMAIN
    assert rule.synced_from_platform is False
    assert rule.active is True
    assert session.added == [rule]
    assert session.flushes == 1


async def test_replace_scope_rules_applies_added_rules():
    program = _program()
    session = _FakeSession(results=[[]])
    fresh = [
        ScopeRuleInput(
            rule_type=ScopeRuleType.IN,
            asset_type=ScopeAssetType.DOMAIN,
            pattern="new.example.com",
        )
    ]

    diff = await replace_scope_rules(session, program, fresh)

    assert [r.pattern for r in diff.added] == ["new.example.com"]
    assert len(session.added) == 1
    assert session.added[0].pattern == "new.example.com"
    assert program.scope_synced_at is not None


async def test_replace_scope_rules_preserves_operator_authored_out_rule():
    program = _program()
    manual_out = _db_rule(
        "internal.example.com",
        rule_type=ScopeRuleType.OUT,
        synced=False,
    )
    session = _FakeSession(results=[[manual_out]])
    fresh = [
        ScopeRuleInput(
            rule_type=ScopeRuleType.IN,
            asset_type=ScopeAssetType.DOMAIN,
            pattern="app.example.com",
        )
    ]

    await replace_scope_rules(session, program, fresh)

    assert manual_out.active is True


# ── scope.py ────────────────────────────────────────────────────────────────────
def test_normalise_host_blank_inputs_return_empty():
    assert _normalise_host("") == ""
    assert _normalise_host("   ") == ""
    assert _normalise_host("...") == ""


def test_parse_target_none_is_treated_as_empty():
    parsed = parse_target(None)  # type: ignore[arg-type]

    assert parsed.host is None
    assert parsed.path == "/"
    assert parsed.asset_kind_hint == AssetType.OTHER


def test_parse_target_non_numeric_port_keeps_host_and_drops_port():
    parsed = parse_target("example.com:abc")

    assert parsed.port is None
    assert parsed.host == "example.com:abc"


def test_parse_target_malformed_url_falls_back_and_is_denied():
    # urlparse rejects the unclosed IPv6 bracket; the fallback splitter must not
    # produce a host that matches a legitimate in-scope domain.
    parsed = parse_target("http://[::1")
    assert parsed.is_ip is False

    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com")])
    assert validator.check("http://[::1").allowed is False


def test_match_wildcard_ignores_non_wildcard_pattern():
    assert _match_wildcard("example.com", parse_target("a.example.com")) is False


def test_match_wildcard_with_degenerate_root_matches_nothing():
    # "a..com" normalises to an empty IDNA host, so the rule can never match.
    assert _match_wildcard("*.a..com", parse_target("x.example.com")) is False


def test_match_ip_exact_address_only():
    assert _match_ip("203.0.113.5", parse_target("203.0.113.5")) is True
    assert _match_ip("203.0.113.5", parse_target("203.0.113.6")) is False
    assert _match_ip("203.0.113.5", parse_target("app.example.com")) is False
    assert _match_ip("not-an-ip", parse_target("203.0.113.5")) is False


def test_ip_rule_via_validator():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.IP, "198.51.100.7")])

    assert validator.check("198.51.100.7").allowed is True
    assert validator.check("198.51.100.8").allowed is False


def test_match_cidr_rejects_invalid_network_pattern():
    assert _match_cidr("not/a/cidr", parse_target("10.0.0.1")) is False


def test_match_cidr_rejects_ipv4_address_against_ipv6_network():
    assert _match_cidr("2001:db8::/32", parse_target("10.0.0.1")) is False


def test_match_cidr_membership_for_ipv4_and_ipv6():
    assert _match_cidr("10.0.0.0/8", parse_target("10.20.30.40")) is True
    assert _match_cidr("2001:db8::/32", parse_target("[2001:db8::1]")) is True


def test_match_mobile_requires_host_and_exact_package_id():
    assert _match_mobile("com.example.app", parse_target("/just/a/path")) is False
    assert _match_mobile("com.example.app", parse_target("com.example.app")) is True


def test_match_repo_root_path_matches_any_repository_on_host():
    assert _match_repo("github.com", parse_target("https://github.com/acme/tool")) is True
    assert _match_repo("github.com", parse_target("https://gitlab.com/acme/tool")) is False


def test_unknown_asset_type_is_skipped_in_both_rule_loops():
    # Unknown asset types have no matcher: they must never allow or deny anything.
    validator = ScopeValidator(
        [
            ScopeRule(RuleType.OUT, "bogus", "example.com"),  # type: ignore[arg-type]
            ScopeRule(RuleType.IN, "bogus", "example.com"),  # type: ignore[arg-type]
        ]
    )
    decision = validator.check("example.com")
    assert decision.allowed is False
    assert "deny by default" in decision.reason

    validator_with_domain = ScopeValidator(
        [
            ScopeRule(RuleType.OUT, "bogus", "example.com"),  # type: ignore[arg-type]
            ScopeRule(RuleType.IN, "bogus", "example.com"),  # type: ignore[arg-type]
            ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com"),
        ]
    )
    assert validator_with_domain.check("example.com").allowed is True


def test_url_rule_rejects_dot_segment_traversal():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.URL, "example.com/admin")])

    assert validator.check("https://example.com/admin/../secret").allowed is False
    assert validator.check("https://example.com/admin/%2e%2e/secret").allowed is False


def test_repo_rule_rejects_dot_segment_traversal():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.REPO, "github.com/org")])

    assert validator.check("https://github.com/org/../other/x").allowed is False


def test_ipv4_mapped_ipv6_cannot_bypass_ipv4_deny_cidr():
    validator = ScopeValidator(
        [
            ScopeRule(RuleType.OUT, AssetType.CIDR, "10.0.0.0/8"),
            ScopeRule(RuleType.IN, AssetType.CIDR, "::/0"),
        ]
    )

    assert validator.check("[::ffff:10.0.0.5]").allowed is False


# ── submission/draft.py ─────────────────────────────────────────────────────────
def test_render_markdown_includes_all_optional_sections_in_order():
    sections = DraftSections(
        title="  Reflected XSS in search  ",
        summary=" Search reflects input. ",
        steps_to_reproduce=["Open /search?q=<svg>", "Observe alert"],
        impact="Session theft.",
        suggested_fix="Encode output.",
        references=["https://example.com/ref1", "https://example.com/ref2"],
        proof_of_concept="curl 'https://example.com/search?q=1'\n\n",
    )

    md = render_markdown(sections)

    assert md.startswith("# Reflected XSS in search\n")
    assert "1. Open /search?q=<svg>" in md
    assert "2. Observe alert" in md
    assert "## Suggested Fix\nEncode output." in md
    assert "## References\n- https://example.com/ref1\n- https://example.com/ref2" in md
    assert "## Proof of Concept\ncurl 'https://example.com/search?q=1'" in md
    assert md.index("## Impact") < md.index("## Suggested Fix")
    assert md.index("## Suggested Fix") < md.index("## References")
    assert md.index("## References") < md.index("## Proof of Concept")
    assert md.endswith("\n") and not md.endswith("\n\n")


def test_render_markdown_omits_optional_sections_when_empty():
    md = render_markdown(
        DraftSections(
            title="Minimal",
            summary="s",
            steps_to_reproduce=["one"],
            impact="i",
        )
    )

    assert "## Suggested Fix" not in md
    assert "## References" not in md
    assert "## Proof of Concept" not in md


def test_title_from_class_maps_known_and_unknown_classes():
    assert title_from_class("stored_xss", "x.example.com") == "Stored XSS in x.example.com"
    assert title_from_class("  XSS ", "x") == "Reflected XSS in x"
    assert title_from_class("path_traversal", "x") == "Path Traversal in x"


def test_detect_verbatim_overlap_flags_copied_reference():
    candidate = "the quick brown fox jumps over the lazy dog"
    references = [
        "short",  # too few tokens for the n-gram window: skipped
        "the quick brown fox jumps over the lazy dog today",
    ]

    hit = detect_verbatim_overlap(candidate, references, ngram_size=3)

    assert hit == references[1]


def test_detect_verbatim_overlap_none_for_unrelated_text():
    hit = detect_verbatim_overlap(
        "the quick brown fox jumps over the lazy dog",
        ["completely different sentence about cats and kittens"],
        ngram_size=3,
    )
    assert hit is None


def test_detect_verbatim_overlap_empty_candidate_returns_none():
    assert detect_verbatim_overlap("", ["anything at all here"], ngram_size=3) is None
    assert detect_verbatim_overlap("ab", ["anything at all here"], ngram_size=3) is None


def test_ngrams_shorter_than_window_is_empty():
    assert _ngrams(["a", "b"], 3) == set()


# ── recon/enrich.py ─────────────────────────────────────────────────────────────
def test_extract_js_endpoints_drops_non_http_and_relative_urls():
    js = "fetch('ftp://files.example.com/x') axios.get('api/users') fetch('/api/v1/items')"

    assert extract_js_endpoints(js) == ["/api/v1/items"]


_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


async def test_hunt_secrets_async_falls_back_to_regex_when_gitleaks_missing(monkeypatch):
    class _Missing:
        def is_installed(self):
            return False

    monkeypatch.setattr(enrich_mod, "GitleaksTool", _Missing)

    hits = await hunt_secrets_async(f"key={_AWS_KEY}")

    assert hits == hunt_secrets(f"key={_AWS_KEY}")
    assert hits[0]["rule"] == "aws_access_key"


async def test_hunt_secrets_async_returns_gitleaks_findings_when_successful(monkeypatch):
    findings = [{"rule": "gitleaks-generic", "secret": "xyz"}]

    class _Installed:
        def is_installed(self):
            return True

        async def scan_text(self, text):
            return SimpleNamespace(success=True, findings=findings)

    monkeypatch.setattr(enrich_mod, "GitleaksTool", _Installed)

    assert await hunt_secrets_async("anything") == findings


async def test_hunt_secrets_async_falls_back_when_gitleaks_scan_fails(monkeypatch):
    class _Broken:
        def is_installed(self):
            return True

        async def scan_text(self, text):
            return SimpleNamespace(success=False, findings=[])

    monkeypatch.setattr(enrich_mod, "GitleaksTool", _Broken)

    hits = await hunt_secrets_async(f"key={_AWS_KEY}")

    assert [h["rule"] for h in hits] == ["aws_access_key"]


def test_fingerprint_tech_matches_header_names_case_insensitively():
    headers = {"Server": "nginx/1.25", "X-Powered-By": "Express", "CF-Ray": "abc-LHR"}

    tech = enrich_mod.fingerprint_tech(headers, body_snippet="")

    assert "nginx" in tech
    assert "express" in tech
    assert "cloudflare" in tech


def test_fingerprint_tech_ignores_headers_with_no_matching_value():
    assert enrich_mod.fingerprint_tech({"Server": "mystery-box"}) == []
    assert enrich_mod.fingerprint_tech({}, body_snippet="") == []


def test_fingerprint_tech_body_rules_are_case_insensitive():
    tech = enrich_mod.fingerprint_tech({}, body_snippet="<SCRIPT src='/WP-CONTENT/x.js'>")

    assert tech == ["wordpress"]


def test_extract_js_endpoints_handles_xhr_and_open_patterns():
    js = (
        "xhr.open('POST', '/api/submit');"
        "XMLHttpRequest().open('GET', 'https://api.example.com/v2/me');"
        "axios.delete('/api/items/1')"
    )

    endpoints = extract_js_endpoints(js)

    assert endpoints == [
        "/api/items/1",
        "/api/submit",
        "https://api.example.com/v2/me",
    ]


# ── scope.py: validator API, ports, IPv6 and prefix boundaries ─────────────────
def test_require_returns_decision_when_allowed_and_raises_when_denied():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com")])

    decision = validator.require("example.com")
    assert decision.allowed is True

    with pytest.raises(ScopeViolation) as exc_info:
        validator.require("evil.com")

    assert exc_info.value.decision.allowed is False
    assert str(exc_info.value).startswith("Out of scope:")


def test_from_db_rules_maps_rows_and_drops_inactive():
    rows = [
        _db_rule("example.com"),
        _db_rule("*.example.com", asset_type=ScopeAssetType.WILDCARD),
        _db_rule("legacy.test", active=False),
        _db_rule("bad.example.com", rule_type=ScopeRuleType.OUT),
    ]

    validator = ScopeValidator.from_db_rules(rows)

    assert validator.rule_count == 3
    assert validator.check("api.example.com").allowed is True
    assert validator.check("legacy.test").allowed is False
    assert validator.check("bad.example.com").allowed is False


def test_out_of_scope_rule_wins_over_broader_in_scope_rule():
    validator = ScopeValidator(
        [
            ScopeRule(RuleType.IN, AssetType.WILDCARD, "*.example.com"),
            ScopeRule(RuleType.OUT, AssetType.DOMAIN, "admin.example.com"),
        ]
    )

    decision = validator.check("admin.example.com")
    assert decision.allowed is False
    assert "out-of-scope" in decision.reason
    assert validator.check("shop.example.com").allowed is True


def test_url_rule_port_and_path_boundaries():
    validator = ScopeValidator(
        [ScopeRule(RuleType.IN, AssetType.URL, "api.example.com:8443/v1")]
    )

    assert validator.check("https://api.example.com:8443/v1/orders").allowed is True
    assert validator.check("https://api.example.com:9443/v1/orders").allowed is False
    assert validator.check("https://api.example.com:8443/v10/orders").allowed is False


def test_url_rule_root_path_allows_any_path_on_host():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.URL, "example.com/")])

    assert validator.check("https://example.com/anything/here").allowed is True


def test_domain_rule_does_not_match_ip_target_or_suffix_host():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com")])

    assert validator.check("203.0.113.9").allowed is False
    assert validator.check("notexample.com").allowed is False


def test_parse_target_bracketed_ipv6_with_port():
    parsed = parse_target("[2001:db8::1]:8080")

    assert parsed.is_ip is True
    assert parsed.port == 8080
    assert parsed.asset_kind_hint == AssetType.IP


def test_parse_target_host_with_port_and_path():
    parsed = parse_target("https://Example.COM:8443//a//b/")

    assert parsed.host == "example.com"
    assert parsed.port == 8443
    assert parsed.path == "/a/b"
    assert parsed.scheme == "https"


def test_empty_and_blank_targets_are_denied_as_unparseable():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com")])

    for target in ("", "   "):
        decision = validator.check(target)
        assert decision.allowed is False
        assert decision.reason == "Empty or unparseable target"


def test_matchers_reject_targets_of_the_wrong_kind():
    ip_target = parse_target("203.0.113.9")
    host_target = parse_target("app.example.com")
    path_only = parse_target("/just/path")

    assert _match_wildcard("*.example.com", ip_target) is False
    assert _match_cidr("203.0.113.0/24", host_target) is False
    assert _match_repo("github.com", path_only) is False
    assert _match_repo("", parse_target("https://github.com/acme/tool")) is False

    validator = ScopeValidator(
        [
            ScopeRule(RuleType.IN, AssetType.URL, "example.com/admin"),
            ScopeRule(RuleType.IN, AssetType.URL, "example.com/admin"),
        ]
    )
    assert validator.check("https://other.com/admin").allowed is False
    assert validator.check("/admin").allowed is False


def test_parse_target_path_only_without_host_is_denied():
    validator = ScopeValidator([ScopeRule(RuleType.IN, AssetType.DOMAIN, "example.com")])

    decision = validator.check("/only/a/path")
    assert decision.allowed is False
    assert decision.parsed is not None
    assert decision.parsed.host is None
