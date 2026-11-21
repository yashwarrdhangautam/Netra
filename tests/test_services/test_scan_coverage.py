"""Assessment completion requires explicit expected tools and parsed run evidence."""

from types import SimpleNamespace

import pytest

from netra.services.scan_coverage import scan_coverage


def scan(status="completed", manifest=True):
    return SimpleNamespace(
        status=status,
        checkpoint_data={
            "coverage_manifest": {
                "version": 1,
                "required_tools": [{"phase": "scope", "tool": "subfinder"}],
                "optional_tools": [{"phase": "scope", "tool": "amass"}],
            }
        }
        if manifest
        else {},
    )


def phase(runs):
    return SimpleNamespace(phase_type="scope", tool_outputs={"runs": runs})


def test_legacy_zero_findings_is_not_complete():
    result = scan_coverage(scan(manifest=False), [phase([{"tool": "subfinder", "success": True}])])
    assert result.outcome == "incomplete"
    assert result.coverage_reason == "coverage_unknown"


@pytest.mark.parametrize("state", ["skipped", "unavailable", "failed", "parse_error"])
def test_required_noncompletion_is_incomplete(state):
    result = scan_coverage(
        scan(),
        [
            phase(
                [{"tool": "subfinder", "state": state, "required": True, "reason_code": "example"}]
            )
        ],
    )
    assert result.outcome == "incomplete"
    assert result.coverage[0].state == state


def test_completed_zero_and_optional_skip_are_complete():
    result = scan_coverage(
        scan(),
        [
            phase(
                [
                    {
                        "tool": "subfinder",
                        "state": "completed",
                        "findings_count": 0,
                        "required": True,
                    },
                    {
                        "tool": "amass",
                        "state": "skipped",
                        "required": False,
                        "reason_code": "not_applicable",
                    },
                ]
            )
        ],
    )
    assert result.outcome == "complete"
    assert len(result.coverage) == 2


@pytest.mark.parametrize("status", ["pending", "running", "paused", "failed", "cancelled"])
def test_lifecycle_must_be_completed(status):
    assert (
        scan_coverage(
            scan(status), [phase([{"tool": "subfinder", "state": "completed", "required": True}])]
        ).outcome
        == "incomplete"
    )


@pytest.mark.parametrize("status", ["pending", "running", "paused"])
def test_tool_not_reached_yet_is_pending_not_missing(status):
    entry = scan_coverage(scan(status), []).coverage[0]
    assert (entry.state, entry.reason_code, entry.required) == ("pending", "not_run_yet", True)
    assert scan_coverage(scan(status), []).outcome == "incomplete"


def test_optional_tool_run_stays_optional():
    result = scan_coverage(
        scan(),
        [
            phase(
                [
                    {"tool": "subfinder", "state": "completed"},
                    {"tool": "amass", "state": "completed"},
                ]
            )
        ],
    )
    assert {e.tool: e.required for e in result.coverage} == {"subfinder": True, "amass": False}


def test_missing_required_and_empty_manifest_are_incomplete():
    assert scan_coverage(scan(), []).coverage[0].reason_code == "run_missing"
    empty = scan()
    empty.checkpoint_data["coverage_manifest"]["required_tools"] = []
    assert scan_coverage(empty, []).outcome == "incomplete"


def test_truncated_or_duplicate_failed_run_cannot_look_clean():
    assert (
        scan_coverage(
            scan(),
            [
                phase(
                    [
                        {
                            "tool": "subfinder",
                            "state": "completed",
                            "required": True,
                            "truncated": True,
                        }
                    ]
                )
            ],
        ).outcome
        == "incomplete"
    )
    result = scan_coverage(
        scan(),
        [
            phase(
                [
                    {"tool": "subfinder", "state": "completed", "required": True},
                    {"tool": "subfinder", "state": "failed", "required": True},
                ]
            )
        ],
    )
    assert result.outcome == "incomplete"


# ── Manifest matches what the worker phases actually run ────────────────────────


def _declared(manifest):
    return {
        (item["phase"], item["tool"])
        for item in manifest["required_tools"] + manifest.get("optional_tools", [])
    }


def test_every_tool_the_worker_records_is_declared():
    """A recorded run that is not declared makes coverage invalid for every scan."""
    import re
    from pathlib import Path

    from netra.services.scan_coverage import build_coverage_manifest
    from netra.worker import tasks

    source = Path(tasks.__file__).read_text(encoding="utf-8")
    recorded = set(re.findall(r'_record_(?:run|unavailable)\(runs, "([a-z_]+)"', source))
    declared_tools = {tool for _, tool in _declared(build_coverage_manifest("deep", {}))}
    assert recorded, "pattern no longer finds recorded tools"
    assert recorded <= declared_tools, recorded - declared_tools


def test_standard_scan_without_active_grant_can_be_complete():
    from netra.services.scan_coverage import build_coverage_manifest

    manifest = build_coverage_manifest("standard", {"use_nikto": False}, active_test_allowed=False)
    required = {(i["phase"], i["tool"]) for i in manifest["required_tools"]}
    assert not any(phase == "pentest" for phase, _ in required)
    done = SimpleNamespace(status="completed", checkpoint_data={"coverage_manifest": manifest})
    phases = [
        SimpleNamespace(
            phase_type="scope",
            tool_outputs={
                "runs": [
                    {"tool": "recontool", "state": "completed"},
                    {"tool": "passive_posture", "state": "completed"},
                ]
            },
        ),
        SimpleNamespace(
            phase_type="recon_discovery",
            tool_outputs={
                "runs": [
                    {"tool": "httpx", "state": "completed"},
                    {"tool": "tls_probe", "state": "completed"},
                ]
            },
        ),
        SimpleNamespace(
            phase_type="vuln_scan",
            tool_outputs={"runs": [{"tool": "nuclei", "state": "completed"}]},
        ),
        SimpleNamespace(phase_type="pentest", tool_outputs={}),
    ]
    assert scan_coverage(done, phases).outcome == "complete"


def test_ip_target_needs_no_passive_discovery():
    from netra.services.scan_coverage import build_coverage_manifest

    manifest = build_coverage_manifest("standard", {}, passive_discovery=False)
    assert ("scope", "recontool") not in _declared(manifest)
    assert ("scope", "passive_posture") not in _declared(manifest)


def test_pentest_tools_required_only_with_an_active_grant():
    from netra.services.scan_coverage import build_coverage_manifest

    granted = build_coverage_manifest("deep", {}, active_test_allowed=True)
    assert {"phase": "pentest", "tool": "sqlmap"} in granted["required_tools"]
    denied = build_coverage_manifest("deep", {}, active_test_allowed=False)
    assert {"phase": "pentest", "tool": "sqlmap"} in denied["optional_tools"]


def test_tech_targeted_run_is_never_complete():
    run = {"tool": "subfinder", "state": "completed", "reason_code": "tech_targeted"}
    result = scan_coverage(scan(), [phase([run])])
    assert result.outcome == "incomplete"
    assert result.coverage_reason == "tech_targeted"
    assert result.coverage[0].reason_code == "tech_targeted"


def test_light_pass_on_4xx_host_still_counts_as_completed():
    run = {"tool": "subfinder", "state": "completed", "reason_code": "light_scan_4xx_root"}
    assert scan_coverage(scan(), [phase([run])]).outcome == "complete"
