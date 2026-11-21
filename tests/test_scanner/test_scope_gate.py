import pytest

from netra.db.models.target import Target
from netra.scanner.scope_gate import canonical_rule, compile_rules


@pytest.mark.parametrize(
    "value",
    [
        "--output=x",
        "https://u:p@example.org/",
        "https://example.org\n/",
        "*.bad.*.org",
        "https://example.org/%252e%252e/admin",
    ],
)
def test_invalid_rules_rejected(value):
    with pytest.raises(ValueError):
        canonical_rule(value, allow_wildcard=True)


def test_bad_exclusion_fails_closed():
    target = Target(name="fixture", target_type="domain", value="example.org", scope_excludes=[""])
    with pytest.raises(ValueError):
        compile_rules(target)


def test_wildcard_and_exclusion():
    target = Target(
        name="fixture",
        target_type="domain",
        value="example.org",
        scope_includes=["*.example.org"],
        scope_excludes=["blocked.example.org"],
    )
    scope = compile_rules(target)
    assert scope.check("https://a.b.example.org/").allowed
    assert not scope.check("blocked.example.org").allowed
    assert not scope.check("example.org.evil.test").allowed


@pytest.mark.parametrize(
    "value",
    [
        "*.127.0.0.1",
        "https://example.org/api%2fadmin",
        "https://example.org/api%252fadmin",
        "https://example.org:0/",
        "https://example.org/#fragment",
    ],
)
def test_ambiguous_rules_rejected(value):
    with pytest.raises(ValueError):
        canonical_rule(value, allow_wildcard=True)


@pytest.mark.parametrize("value", [{}, {"domain": "example.org"}, "example.org"])
def test_scope_list_shape_is_strict(value):
    target = Target(name="fixture", target_type="domain", value="example.org", scope_includes=value)
    with pytest.raises(ValueError):
        compile_rules(target)
