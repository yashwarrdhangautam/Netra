"""Nuclei must stay inside the signed grant, and must not report an untested host as clean."""

from netra.scanner.tools import nuclei as nuclei_mod
from netra.scanner.tools.base import ToolResult
from netra.scanner.tools.nuclei import NucleiTool, method_condition, parse_nuclei_output


def test_method_condition_drops_every_method_outside_the_grant() -> None:
    condition = method_condition(["GET", "HEAD"])
    assert condition is not None
    for denied in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"):
        assert f'!contains(http_method, "{denied}")' in condition
    assert '"GET"' not in condition
    assert '"HEAD"' not in condition


def test_method_condition_is_case_insensitive_and_none_when_all_allowed() -> None:
    assert '"POST"' not in (method_condition(["get", "post"]) or "")
    assert method_condition(list(nuclei_mod.HTTP_METHODS)) is None


async def test_run_passes_grant_filters_and_is_not_silent(monkeypatch) -> None:
    seen: list[list[str]] = []

    async def fake_exec(self, args, **kwargs):
        seen.append(args)
        return ToolResult(tool_name="nuclei", success=True, raw_output="", metadata={})

    monkeypatch.setattr(NucleiTool, "_exec", fake_exec)
    await NucleiTool().run(
        "https://a.example.org",
        rate_limit=1,
        allowed_methods=["GET", "HEAD"],
        protocol_types=["http", "dns", "ssl"],
        exclude_tags=["intrusive", "dos", "fuzz"],
    )
    args = seen[0]
    # -silent would hide the "host skipped as unresponsive" line.
    assert "-silent" not in args
    assert args[args.index("-rate-limit") + 1] == "1"
    assert args[args.index("-type") + 1] == "http,dns,ssl"
    assert args[args.index("-exclude-tags") + 1] == "intrusive,dos,fuzz"
    assert '!contains(http_method, "POST")' in args[args.index("-template-condition") + 1]


async def test_run_without_grant_filters_adds_none(monkeypatch) -> None:
    seen: list[list[str]] = []

    async def fake_exec(self, args, **kwargs):
        seen.append(args)
        return ToolResult(tool_name="nuclei", success=True, raw_output="", metadata={})

    monkeypatch.setattr(NucleiTool, "_exec", fake_exec)
    await NucleiTool().run("https://a.example.org")
    for flag in ("-type", "-exclude-tags", "-template-condition"):
        assert flag not in seen[0]


def test_skipped_host_is_a_failed_run_not_a_clean_one() -> None:
    row = '{"template-id": "x", "info": {"name": "X", "severity": "low"}, "matched-at": "u"}'
    result = ToolResult(
        tool_name="nuclei",
        success=True,
        raw_output=row + "\n",
        metadata={
            "stderr": "[INF] Skipped a.example.org:443 from target list as found unresponsive "
            'permanently: cause="port closed or filtered"'
        },
    )
    parsed = parse_nuclei_output(result)
    assert parsed.success is False
    assert parsed.metadata["state"] == "failed"
    assert parsed.metadata["reason_code"] == "host_unresponsive"
    # What was found before the skip is still kept.
    assert len(parsed.findings) == 1


def test_clean_run_without_skip_completes() -> None:
    result = ToolResult(tool_name="nuclei", success=True, raw_output="", metadata={"stderr": ""})
    parsed = parse_nuclei_output(result)
    assert parsed.success is True
    assert parsed.metadata["state"] == "completed"


def test_timeout_keeps_findings_made_before_the_limit() -> None:
    row = '{"template-id": "x", "info": {"name": "X", "severity": "low"}, "matched-at": "u"}'
    result = ToolResult(
        tool_name="nuclei",
        success=False,
        raw_output=row + "\n" + '{"template-id": "half',  # killed mid-write
        error="timeout",
        metadata={"state": "failed", "reason_code": "timeout", "stderr": ""},
    )
    parsed = parse_nuclei_output(result)
    assert parsed.success is False
    assert parsed.metadata["reason_code"] == "timeout"
    assert len(parsed.findings) == 1


async def test_run_passes_its_timeout_and_skips_update_check(monkeypatch) -> None:
    seen: dict = {}

    async def fake_exec(self, args, **kwargs):
        seen["args"], seen["kwargs"] = args, kwargs
        return ToolResult(tool_name="nuclei", success=True, raw_output="", metadata={})

    monkeypatch.setattr(NucleiTool, "_exec", fake_exec)
    await NucleiTool().run("https://a.example.org", timeout=17700)
    assert seen["kwargs"]["timeout"] == 17700
    assert "-disable-update-check" in seen["args"]


async def test_tags_filter_inside_the_pinned_template_set(monkeypatch):
    from netra.scanner.tools import nuclei as mod

    tool = mod.NucleiTool()
    seen = {}

    async def fake_exec(args, stdin=None, timeout=300):
        seen["args"] = args
        return mod.ToolResult(tool_name="nuclei", success=True, metadata={"state": "completed"})

    monkeypatch.setattr(mod, "template_args", lambda _: ["-templates", "/pinned"])
    monkeypatch.setattr(tool, "_exec", fake_exec)
    await tool.run("https://example.test", tags="misconfig,exposure,tech")
    args = seen["args"]
    assert args[args.index("-tags") + 1] == "misconfig,exposure,tech"
    assert args[args.index("-templates") + 1] == "/pinned"
