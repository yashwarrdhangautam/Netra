"""Conservative coverage derived from a server-owned manifest and tool-run evidence."""

from typing import Any

from netra.schemas.scan import ScanCoverage, ToolCoverage

STATES = {"completed", "skipped", "unavailable", "failed", "parse_error"}


def build_coverage_manifest(
    profile: str,
    config: dict[str, Any] | None = None,
    *,
    passive_discovery: bool = True,
    active_test_allowed: bool = True,
) -> dict[str, Any]:
    """Declare expected standard-pipeline tools before dispatch, never from its results.

    The list must match the tools the worker phases record (worker/tasks.py). A run of a tool
    that is not declared here makes the manifest invalid, so a mismatch would mark every scan
    incomplete.

    passive_discovery: False for IP and range targets, whose scope phase runs no discovery.
    active_test_allowed: False when the signed grant has no active_test action. The pentest
    phase is then skipped by design, so its tools are not required.
    """
    from netra.scanner.profiles import PROFILES

    if profile not in {"quick", "standard", "deep", "api_only"}:
        return {"version": 1, "required_tools": []}
    selected = PROFILES[profile]
    overrides = config or {}
    required = []
    if passive_discovery:
        required += [
            {"phase": "scope", "tool": "recontool"},
            {"phase": "scope", "tool": "passive_posture"},
        ]
    required += [
        {"phase": "recon_discovery", "tool": "httpx"},
        {"phase": "vuln_scan", "tool": "nuclei"},
    ]
    # tls_probe runs only for https hosts that answered, so it cannot be declared required.
    optional = [{"phase": "recon_discovery", "tool": "tls_probe"}]
    for phase, tool, flag in [
        ("vuln_scan", "nikto", "use_nikto"),
        ("pentest", "sqlmap", "test_sqli"),
        ("pentest", "dalfox", "test_xss"),
        ("pentest", "ffuf", "test_dirs"),
    ]:
        entry = {"phase": phase, "tool": tool}
        wanted = bool(selected.get(flag)) and bool(overrides.get(flag, True))
        if phase == "pentest" and not active_test_allowed:
            wanted = False
        (required if wanted else optional).append(entry)
    return {"version": 1, "required_tools": required, "optional_tools": optional}


def scan_coverage(scan: Any, phases: list[Any]) -> ScanCoverage:
    """Missing or legacy evidence is unknown, never inferred clean from zero findings."""
    checkpoint = scan.checkpoint_data if isinstance(scan.checkpoint_data, dict) else {}
    manifest = checkpoint.get("coverage_manifest")
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        return ScanCoverage()
    required = manifest.get("required_tools")
    if not isinstance(required, list) or not required:
        return ScanCoverage(coverage_reason="required_tools_unknown")
    expected: dict[tuple[str, str], bool] = {}
    for group, required_flag in [(required, True), (manifest.get("optional_tools", []), False)]:
        if not isinstance(group, list):
            return ScanCoverage(coverage_reason="manifest_invalid")
        for item in group:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("phase"), str)
                or not isinstance(item.get("tool"), str)
            ):
                return ScanCoverage(coverage_reason="manifest_invalid")
            key = (item["phase"], item["tool"])
            if key in expected or not all(key):
                return ScanCoverage(coverage_reason="manifest_invalid")
            expected[key] = required_flag
    evidence: dict[tuple[str, str], list[dict[str, Any]]] = {}
    invalid = False
    denied = bool(checkpoint.get("policy_denial"))
    for phase in phases:
        outputs = phase.tool_outputs if isinstance(phase.tool_outputs, dict) else {}
        denied = denied or bool(outputs.get("policy_denials"))
        runs = outputs.get("runs", [])
        if not isinstance(runs, list):
            invalid = True
            continue
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("tool"), str):
                invalid = True
                continue
            evidence.setdefault((str(phase.phase_type), run["tool"]), []).append(run)
    coverage = []
    # While the scan is still going, a tool with no run yet has simply not reached its turn.
    in_progress = str(scan.status) in {"pending", "running", "paused"}
    for (phase, tool), required_flag in expected.items():
        runs = evidence.pop((phase, tool), [])
        if not runs:
            if in_progress:
                state, reason = "pending", "not_run_yet"
            elif required_flag:
                state, reason = "unavailable", "run_missing"
            else:
                state, reason = "skipped", "not_applicable"
            coverage.append(
                ToolCoverage(
                    phase=phase, tool=tool, required=required_flag, state=state, reason_code=reason
                )
            )
        for run in runs:
            state = run.get("state")
            reason = run.get("reason_code")
            if state not in STATES:
                state, reason = "unavailable", "coverage_unknown"
            if run.get("truncated") or run.get("output_truncated"):
                state, reason = "parse_error", "output_truncated"
            count = run.get("findings_count")
            coverage.append(
                ToolCoverage(
                    phase=phase,
                    tool=tool,
                    state=state,
                    # The manifest decides; a run can only raise a tool to required explicitly.
                    required=required_flag or run.get("required") is True,
                    reason_code=reason if isinstance(reason, str) else None,
                    findings_count=count if isinstance(count, int) and count >= 0 else None,
                )
            )
    if evidence:
        invalid = True  # An undeclared run cannot silently broaden the reviewed manifest.
    complete = (
        str(scan.status) == "completed"
        and not invalid
        and not denied
        and all(not entry.required or entry.state == "completed" for entry in coverage)
    )
    return ScanCoverage(
        outcome="complete" if complete else "incomplete",
        coverage_reason=None if complete else "policy_denied" if denied else "coverage_incomplete",
        coverage=coverage,
    )
