"""URL scope must preserve the authorized transport and port."""

import pytest

from netra.bugbounty.scope import AssetType, RuleType, ScopeRule, ScopeValidator


@pytest.mark.parametrize(
    "candidate, allowed",
    [
        ("https://api.example.org/api/users", True),
        ("https://api.example.org:443/api/users", True),
        ("http://api.example.org/api/users", False),
        ("https://api.example.org:8443/api/users", False),
        ("https://api.example.org/apix", False),
    ],
)
def test_url_scope_preserves_scheme_port_and_path(candidate, allowed):
    validator = ScopeValidator(
        [ScopeRule(RuleType.IN, AssetType.URL, "https://api.example.org/api")]
    )
    assert validator.check(candidate).allowed is allowed
