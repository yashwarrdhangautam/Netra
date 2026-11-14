"""Recon manifest: built from live-host rows, valid against schema 1.0, and rendered as an arsenal map."""

from datetime import UTC, datetime

from netra.intel.manifest import build_manifest, render_arsenal, validate_manifest, write_manifest

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
ROWS = [
    {
        "url": "https://app.example.org/login",
        "status_code": 200,
        "tech": ["nginx", "React"],
        "title": "Login",
        "protections": ["waf", "csp"],
    },
    {"url": "https://old.example.org", "status_code": 404, "tech": [], "protections": []},
    {"url": None, "hostname": "dead.example.org", "status_code": None},
]


def test_build_manifest_is_valid_and_complete():
    manifest = build_manifest("example.org", ROWS, now=NOW)
    assert validate_manifest(manifest) == []
    assert manifest["schema_version"] == "1.0"
    assert manifest["counts"] == {
        "hosts": 3,
        "live": 2,
    }  # the DNS-only host counts as a host, not live
    assert [a["host"] for a in manifest["assets"]] == [
        "app.example.org",
        "old.example.org",
        "dead.example.org",
    ]


def test_ranking_prefers_protected_and_drops_dead_hosts():
    manifest = build_manifest("example.org", ROWS, now=NOW)
    priorities = {r["host"]: r["priority"] for r in manifest["ranked_surface"]}
    assert priorities["app.example.org"] == "P2"  # protected behind a WAF
    assert priorities["old.example.org"] == "KILL"


def test_validator_reports_missing_and_bad_fields():
    manifest = build_manifest("example.org", ROWS, now=NOW)
    broken = dict(manifest)
    del broken["assets"]
    broken["ranked_surface"] = [{"priority": "P9"}]
    problems = validate_manifest(broken)
    assert "missing key: assets" in problems
    broken2 = build_manifest("example.org", ROWS, now=NOW)
    broken2["ranked_surface"][0]["priority"] = "P9"
    assert any("priority" in p for p in validate_manifest(broken2))


def test_write_manifest_refuses_invalid(tmp_path):
    bad = {"schema_version": "1.0"}
    try:
        write_manifest(bad, tmp_path)
    except ValueError as exc:
        assert "invalid manifest" in str(exc)
    else:
        raise AssertionError("invalid manifest was written")


def test_write_manifest_writes_under_target(tmp_path):
    manifest = build_manifest("example.org", ROWS, now=NOW)
    path = write_manifest(manifest, tmp_path)
    assert path == tmp_path / "example.org" / "manifest.json"
    assert path.read_text(encoding="utf-8").startswith("{")


def test_arsenal_map_lists_checks_for_protected_hosts():
    manifest = build_manifest("example.org", ROWS, now=NOW)
    text = render_arsenal(manifest)
    assert "# Arsenal map: example.org" in text
    assert "## P2 https://app.example.org/login" in text
    assert "[Web application firewall]" in text
    assert "[Content Security Policy]" in text
