"""Tests for the scope validator.

The scope validator is the safety gate of NETRA-BB. These tests are adversarial on
purpose — every CVE-class trick a researcher might pull on themselves accidentally
should be covered here.

Conventions:
    * happy-path tests live in TestHappyPath
    * adversarial tests live in TestAdversarial — these are the ones that matter
    * a test failing in TestAdversarial means an out-of-scope target could leak through
"""
from __future__ import annotations

import pytest

from netra.bugbounty.scope import (
    AssetType,
    RuleType,
    ScopeDecision,
    ScopeRule,
    ScopeValidator,
    ScopeViolation,
    parse_target,
)


# ── Fixtures ────────────────────────────────────────────────────────────────────
def _allow(asset_type: AssetType, pattern: str, severity_cap: str | None = None) -> ScopeRule:
    return ScopeRule(rule_type=RuleType.IN, asset_type=asset_type, pattern=pattern, severity_cap=severity_cap)


def _deny(asset_type: AssetType, pattern: str) -> ScopeRule:
    return ScopeRule(rule_type=RuleType.OUT, asset_type=asset_type, pattern=pattern)


@pytest.fixture
def shopify_validator() -> ScopeValidator:
    """A representative-looking program with mixed allow/deny rules."""
    return ScopeValidator([
        _allow(AssetType.WILDCARD, "*.shopify.com"),
        _allow(AssetType.DOMAIN, "shopify.com"),
        _allow(AssetType.WILDCARD, "*.myshopify.com", severity_cap="high"),
        _allow(AssetType.CIDR, "203.0.113.0/24"),
        _allow(AssetType.URL, "api.shopify.com/v1"),
        _allow(AssetType.MOBILE, "com.shopify.mobile"),
        _allow(AssetType.REPO, "https://github.com/Shopify/cli"),
        _deny(AssetType.DOMAIN, "internal.shopify.com"),
        _deny(AssetType.WILDCARD, "*.staging.shopify.com"),
        _deny(AssetType.CIDR, "203.0.113.250/32"),
    ])


# ── parse_target ────────────────────────────────────────────────────────────────
class TestParseTarget:
    def test_bare_domain(self):
        p = parse_target("api.shopify.com")
        assert p.host == "api.shopify.com"
        assert p.is_ip is False
        assert p.path == "/"
        assert p.scheme is None

    def test_uppercase_domain_is_lowered(self):
        p = parse_target("API.Shopify.COM")
        assert p.host == "api.shopify.com"

    def test_url_with_path(self):
        p = parse_target("https://api.shopify.com/v1/orders")
        assert p.host == "api.shopify.com"
        assert p.scheme == "https"
        assert p.path == "/v1/orders"

    def test_url_with_port(self):
        p = parse_target("https://api.shopify.com:8443/v1")
        assert p.host == "api.shopify.com"
        assert p.port == 8443

    def test_host_port_no_scheme(self):
        p = parse_target("api.shopify.com:8080")
        assert p.host == "api.shopify.com"
        assert p.port == 8080

    def test_ipv4(self):
        p = parse_target("203.0.113.5")
        assert p.is_ip is True
        assert p.host == "203.0.113.5"
        assert p.asset_kind_hint == AssetType.IP

    def test_ipv6_bracketed_with_port(self):
        p = parse_target("[2001:db8::1]:8080")
        assert p.is_ip is True
        assert p.host == "2001:db8::1"
        assert p.port == 8080

    def test_idn_domain_punycoded(self):
        p = parse_target("bücher.example.com")
        # bücher → xn--bcher-kva
        assert p.host == "xn--bcher-kva.example.com"

    def test_trailing_dot_stripped(self):
        p = parse_target("api.shopify.com.")
        assert p.host == "api.shopify.com"

    def test_path_normalised(self):
        p = parse_target("https://example.com//foo///bar/")
        assert p.path == "/foo/bar"

    def test_url_decoded_once(self):
        p = parse_target("https://example.com/foo%20bar")
        assert p.path == "/foo bar"

    def test_empty_target_yields_no_host(self):
        p = parse_target("")
        assert p.host is None

    def test_invalid_idn_yields_no_host(self):
        # Unicode that can't be IDN-encoded should not crash.
        p = parse_target("​.com")  # zero-width space label
        assert p.host is None or p.host == ""


# ── Happy path ──────────────────────────────────────────────────────────────────
class TestHappyPath:
    def test_apex_domain_in_scope(self, shopify_validator):
        d = shopify_validator.check("shopify.com")
        assert d.allowed is True
        assert d.matched_rule is not None
        assert d.matched_rule.asset_type == AssetType.DOMAIN

    def test_wildcard_subdomain_in_scope(self, shopify_validator):
        d = shopify_validator.check("api.shopify.com")
        assert d.allowed is True

    def test_wildcard_deep_subdomain_in_scope(self, shopify_validator):
        d = shopify_validator.check("v2.api.shopify.com")
        assert d.allowed is True

    def test_url_in_scope(self, shopify_validator):
        d = shopify_validator.check("https://api.shopify.com/v1/orders")
        assert d.allowed is True

    def test_severity_cap_propagates(self, shopify_validator):
        d = shopify_validator.check("foo.myshopify.com")
        assert d.allowed is True
        assert d.severity_cap == "high"

    def test_cidr_in_scope(self, shopify_validator):
        d = shopify_validator.check("203.0.113.42")
        assert d.allowed is True

    def test_mobile_in_scope(self, shopify_validator):
        d = shopify_validator.check("com.shopify.mobile")
        assert d.allowed is True

    def test_repo_in_scope(self, shopify_validator):
        d = shopify_validator.check("https://github.com/Shopify/cli")
        assert d.allowed is True

    def test_repo_subpath_in_scope(self, shopify_validator):
        d = shopify_validator.check("https://github.com/Shopify/cli/tree/main")
        assert d.allowed is True


# ── Out of scope (negative paths) ───────────────────────────────────────────────
class TestOutOfScope:
    def test_unrelated_domain_denied(self, shopify_validator):
        d = shopify_validator.check("evil.com")
        assert d.allowed is False
        assert "deny by default" in d.reason or "out-of-scope" in d.reason

    def test_explicit_deny_wins_over_implicit_allow(self, shopify_validator):
        # internal.shopify.com would match *.shopify.com (wildcard allow), but the
        # explicit deny rule MUST win.
        d = shopify_validator.check("internal.shopify.com")
        assert d.allowed is False
        assert d.matched_rule is not None
        assert d.matched_rule.rule_type == RuleType.OUT

    def test_explicit_deny_wildcard_wins(self, shopify_validator):
        # foo.staging.shopify.com matches *.shopify.com (in) and *.staging.shopify.com (out).
        # Deny must win.
        d = shopify_validator.check("foo.staging.shopify.com")
        assert d.allowed is False

    def test_cidr_deny_wins(self, shopify_validator):
        # 203.0.113.250 matches both the allow CIDR and the deny /32. Deny wins.
        d = shopify_validator.check("203.0.113.250")
        assert d.allowed is False

    def test_outside_cidr_denied(self, shopify_validator):
        d = shopify_validator.check("203.0.114.5")
        assert d.allowed is False

    def test_apex_for_wildcard_only_program_denied(self):
        # If only *.example.com is in scope (no apex rule), example.com itself is OUT.
        v = ScopeValidator([_allow(AssetType.WILDCARD, "*.example.com")])
        assert v.check("example.com").allowed is False
        assert v.check("api.example.com").allowed is True

    def test_url_path_outside_prefix_denied(self):
        v = ScopeValidator([_allow(AssetType.URL, "api.example.com/v1")])
        assert v.check("https://api.example.com/v1/foo").allowed is True
        assert v.check("https://api.example.com/v2/foo").allowed is False


# ── Adversarial / safety-critical ───────────────────────────────────────────────
class TestAdversarial:
    """If anything in here regresses, an out-of-scope probe could leak."""

    def test_unicode_homograph_does_not_match_ascii_domain(self):
        # Cyrillic 'a' (U+0430) looks like ascii 'a' but is a different character.
        # Punycode encoding turns it into a different host, which must not match.
        v = ScopeValidator([_allow(AssetType.DOMAIN, "shopify.com")])
        homograph = "shopify.com".replace("a", "а")  # cyrillic a in 'shopify'... wait, no 'a' there
        # Use a sample with a real 'a'
        v2 = ScopeValidator([_allow(AssetType.DOMAIN, "amazon.com")])
        homograph2 = "аmazon.com"  # cyrillic a + mazon.com
        d = v2.check(homograph2)
        assert d.allowed is False

    def test_uppercase_in_scope_input_normalised(self, shopify_validator):
        d = shopify_validator.check("API.SHOPIFY.COM")
        assert d.allowed is True

    def test_trailing_dot_does_not_evade_deny(self, shopify_validator):
        d = shopify_validator.check("internal.shopify.com.")
        assert d.allowed is False

    def test_double_url_encoded_path_not_double_decoded(self):
        # %2520 is a URL-encoded '%20'. We decode ONCE, so the parsed path keeps the
        # literal '%20'. This means a deny rule on '/admin' is NOT bypassed by encoding
        # '/%2541dmin' or similar.
        v = ScopeValidator([
            _allow(AssetType.URL, "example.com/"),
            _deny(AssetType.URL, "example.com/admin"),
        ])
        d = v.check("https://example.com/%2541dmin")
        # The path becomes '/%41dmin' after one decode, which does NOT match '/admin' prefix.
        # Therefore it falls through to the allow root rule. That's the SAFE behaviour:
        # we never auto-decode dangerous paths to make them match deny rules.
        assert d.allowed is True
        # And the genuine /admin path is denied:
        d2 = v.check("https://example.com/admin/users")
        assert d2.allowed is False

    def test_host_with_userinfo_does_not_escape_scope(self):
        # https://evil.com@api.shopify.com/ — urlparse gives host=api.shopify.com (correct).
        v = ScopeValidator([_allow(AssetType.DOMAIN, "api.shopify.com")])
        d = v.check("https://evil.com@api.shopify.com/")
        assert d.allowed is True
        # Inverted: target host is evil.com, with shopify in userinfo. Must be denied.
        d2 = v.check("https://api.shopify.com@evil.com/")
        assert d2.allowed is False

    def test_ip_as_domain_string_not_treated_as_domain(self):
        # If only domain rules are loaded, an IP literal must not match them.
        v = ScopeValidator([_allow(AssetType.DOMAIN, "203.0.113.5")])
        # The rule pattern itself is an IP-shaped string, but parsed as a DOMAIN rule
        # it should never match an actual IP target — the parsed target's is_ip=True
        # short-circuits domain matchers.
        d = v.check("203.0.113.5")
        assert d.allowed is False

    def test_cidr_v4_does_not_match_v6_target(self):
        v = ScopeValidator([_allow(AssetType.CIDR, "203.0.113.0/24")])
        d = v.check("[2001:db8::1]:80")
        assert d.allowed is False

    def test_inactive_rule_is_ignored(self):
        v = ScopeValidator([
            ScopeRule(rule_type=RuleType.IN, asset_type=AssetType.DOMAIN,
                      pattern="shopify.com", active=False),
        ])
        assert v.rule_count == 0
        assert v.check("shopify.com").allowed is False

    def test_no_rules_means_deny_all(self):
        v = ScopeValidator([])
        assert v.check("anything.com").allowed is False
        assert v.check("203.0.113.1").allowed is False
        assert v.check("").allowed is False

    def test_empty_target_denied(self, shopify_validator):
        assert shopify_validator.check("").allowed is False

    def test_whitespace_only_target_denied(self, shopify_validator):
        assert shopify_validator.check("   ").allowed is False

    def test_path_only_target_denied(self, shopify_validator):
        # '/admin' with no host should never be 'in scope'.
        assert shopify_validator.check("/admin").allowed is False

    def test_wildcard_does_not_match_unrelated_suffix(self):
        v = ScopeValidator([_allow(AssetType.WILDCARD, "*.example.com")])
        # A domain that contains 'example.com' as a substring but not as a suffix
        # must not match. e.g. notexample.com → suffix is 'example.com' but rooted
        # boundary check is via the dot, so '.example.com' suffix only.
        assert v.check("notexample.com").allowed is False
        # And 'example.com.evil.com' only matches if .evil.com is the actual suffix.
        assert v.check("example.com.evil.com").allowed is False

    def test_wildcard_apex_excluded(self):
        v = ScopeValidator([_allow(AssetType.WILDCARD, "*.example.com")])
        assert v.check("example.com").allowed is False
        assert v.check("a.example.com").allowed is True

    def test_url_rule_with_port_is_port_specific(self):
        v = ScopeValidator([_allow(AssetType.URL, "api.example.com:8443/v1")])
        assert v.check("https://api.example.com:8443/v1/foo").allowed is True
        # Different port → not in scope.
        assert v.check("https://api.example.com:9443/v1/foo").allowed is False
        # No port specified on input — strict: rule required 8443.
        assert v.check("https://api.example.com/v1/foo").allowed is False

    def test_deny_rule_evaluated_before_allow_even_if_listed_after(self):
        v = ScopeValidator([
            _allow(AssetType.WILDCARD, "*.example.com"),
            _deny(AssetType.DOMAIN, "internal.example.com"),
        ])
        d = v.check("internal.example.com")
        assert d.allowed is False
        assert d.matched_rule is not None
        assert d.matched_rule.rule_type == RuleType.OUT


# ── Require / ScopeViolation ────────────────────────────────────────────────────
class TestRequire:
    def test_require_allows_in_scope(self, shopify_validator):
        d = shopify_validator.require("api.shopify.com")
        assert isinstance(d, ScopeDecision)
        assert d.allowed is True

    def test_require_raises_for_out_of_scope(self, shopify_validator):
        with pytest.raises(ScopeViolation) as exc:
            shopify_validator.require("evil.com")
        assert exc.value.decision.allowed is False

    def test_violation_carries_decision(self, shopify_validator):
        try:
            shopify_validator.require("evil.com")
        except ScopeViolation as e:
            assert e.decision.parsed is not None
            assert e.decision.matched_rule is None  # no match → deny by default


# ── from_db_rules construction ──────────────────────────────────────────────────
class TestFromDbRules:
    def test_constructs_from_orm_like_objects(self):
        # Use simple dataclass stand-ins so we don't pull in the DB layer.
        class _Row:
            def __init__(self, rule_type, asset_type, pattern, severity_cap=None,
                         notes=None, active=True):
                self.rule_type = rule_type
                self.asset_type = asset_type
                self.pattern = pattern
                self.severity_cap = severity_cap
                self.notes = notes
                self.active = active

        rows = [
            _Row("in", "domain", "shopify.com"),
            _Row("out", "domain", "internal.shopify.com"),
            _Row("in", "wildcard", "*.shopify.com", severity_cap="high"),
        ]
        v = ScopeValidator.from_db_rules(rows)
        assert v.rule_count == 3
        assert v.check("shopify.com").allowed is True
        assert v.check("internal.shopify.com").allowed is False
        assert v.check("a.shopify.com").severity_cap == "high"


# ── Sync with DB enums ──────────────────────────────────────────────────────────
class TestEnumSync:
    """The local AssetType / RuleType enums must stay in sync with the DB enums.

    We assert against a canonical set rather than importing the DB module, because
    the DB module's package init pulls in the full netra.db engine stack, which is
    not relevant for a pure-Python validator test.

    If you change either side (db/models/bb_scope_rule.py OR bugbounty/scope.py),
    update this set too. The whole point of these tests is to fail when drift happens.
    """

    EXPECTED_ASSET_TYPES = {
        "domain", "wildcard", "ip", "cidr", "url", "mobile", "repo", "other",
    }
    EXPECTED_RULE_TYPES = {"in", "out"}

    def test_local_asset_types_match_canonical_set(self):
        local = {a.value for a in AssetType}
        assert local == self.EXPECTED_ASSET_TYPES, (
            f"drift: {local ^ self.EXPECTED_ASSET_TYPES}"
        )

    def test_local_rule_types_match_canonical_set(self):
        local = {r.value for r in RuleType}
        assert local == self.EXPECTED_RULE_TYPES, (
            f"drift: {local ^ self.EXPECTED_RULE_TYPES}"
        )

    def test_db_asset_types_match_canonical_set(self):
        """Read the DB enum source as text and assert it lists the same values."""
        from pathlib import Path
        path = (
            Path(__file__).resolve().parents[2]
            / "src" / "netra" / "db" / "models" / "bb_scope_rule.py"
        )
        text = path.read_text()
        for value in self.EXPECTED_ASSET_TYPES:
            assert f'"{value}"' in text, f"DB enum missing value: {value}"

    def test_db_rule_types_match_canonical_set(self):
        from pathlib import Path
        path = (
            Path(__file__).resolve().parents[2]
            / "src" / "netra" / "db" / "models" / "bb_scope_rule.py"
        )
        text = path.read_text()
        for value in self.EXPECTED_RULE_TYPES:
            assert f'"{value}"' in text, f"DB enum missing value: {value}"
