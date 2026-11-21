"""Nikto wrapper held to the scan grant, with a parsed JSON report.

Nikto has no option that limits the HTTP methods it sends, and several of its plugins and
database tests use POST, PUT, DELETE, OPTIONS or attack payloads. So each run gets its own
copy of the nikto database that holds only grant-allowed, non-exploit tests, a config that
points at that copy, and an explicit plugin list. The installed nikto is never changed.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from netra.scanner.tools.base import CliTool, ToolResult
from netra.scanner.tools.generic import mark_completed, mark_unreadable

# Plugins that only send GET requests and do not attack. Left out on purpose:
#   options, optionsbleed, put_del_test  - send OPTIONS / PUT / DELETE
#   auth          - guesses credentials        shellshock - sends injection payloads
#   ms10_070      - padding-oracle probe       apacheusers - enumerates user accounts
#   dictionary, siebel - standalone extras (brute-force style)
NIKTO_PLUGINS = (
    "tests",
    "headers",
    "cookies",
    "robots",
    "favicon",
    "msgs",
    "outdated",
    "paths",
    "ssl",
    "content_search",
    "cgi",
    "multiple_index",
    "negotiate",
    "sitefiles",
    "springboot",
)

# db_tests tuning classes kept: 1 interesting file, 2 misconfiguration / default file,
# 3 information disclosure, b software identification, d web service, e admin console.
# Dropped: 4 injection (XSS), 5/7 remote file retrieval, 6 denial of service,
# 8 command execution, 9 SQL injection, 0 file upload, a auth bypass, c remote inclusion.
NON_EXPLOIT_TUNING = frozenset("123bde")

# Test files nikto reads from DBDIR; every one is filtered (udb_ files are user additions).
_TEST_DBS = ("db_tests", "udb_tests")
_MAXTIME_MARKER = "Host maximum execution time"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_FIELDS = 9  # "ID","References","Tuning","URI","Method","DSL","Message","Data","Headers"


def filter_db_tests(text: str, allowed_methods: list[str] | tuple[str, ...]) -> str:
    """Keep comments and the tests whose method is granted and whose tuning is non-exploit.

    A line that cannot be read as a full test row is dropped, so it can never be sent.
    """
    allowed = {m.upper() for m in allowed_methods}
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        if not line.startswith('"'):
            kept.append(line)
            continue
        body = line.rstrip("\r\n")
        if len(body) < 2 or not body.endswith('"'):
            continue
        fields = body[1:-1].split('","')  # exactly one quote each end: fields may be ""
        if len(fields) != _FIELDS:
            continue
        tuning, method, data = fields[2], fields[4].upper(), fields[7]
        if method not in allowed or data:
            continue
        if not tuning or not set(tuning) <= NON_EXPLOIT_TUNING:
            continue
        kept.append(line)
    return "".join(kept)


def build_nikto_workspace(
    home: Path, work: Path, allowed_methods: list[str] | tuple[str, ...]
) -> Path:
    """Copy nikto's database with only allowed tests and write a config that uses it."""
    db = work / "nikto-db"
    if db.exists():
        shutil.rmtree(db)
    shutil.copytree(home / "databases", db)
    for name in _TEST_DBS:
        path = db / name
        if path.exists():
            path.write_text(
                filter_db_tests(
                    path.read_text(encoding="utf-8", errors="replace"), allowed_methods
                ),
                encoding="utf-8",
            )
    check = "GET" if "GET" in {m.upper() for m in allowed_methods} else "HEAD"
    conf = work / "nikto.conf"
    conf.write_text(
        "\n".join(
            [
                f"EXECDIR={home.as_posix()}",
                f"PLUGINDIR={(home / 'plugins').as_posix()}",
                f"TEMPLATEDIR={(home / 'templates').as_posix()}",
                f"DBDIR={db.as_posix()}",
                "NIKTODTD=templates/nikto.dtd",
                "DEFAULTHTTPVER=1.1",
                "UPDATES=no",  # never send version data to cirt.net
                "PROMPTS=no",
                f"CHECKMETHODS={check}",
                "LW_SSL_ENGINE=auto",
                "FAILURES=20",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return conf


def _severity(references: str) -> str:
    # Nikto has no severity. A known CVE raises it to low; everything else is informational.
    return "low" if _CVE.search(references or "") else "info"


def parse_nikto_report(result: ToolResult, report: Path) -> ToolResult:
    """Turn nikto's JSON report into findings. No readable report is never a clean result."""
    if not result.success or result.metadata.get("state") == "parse_error":
        return result
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return mark_unreadable(result, "nikto_report_missing_or_invalid")
    if not isinstance(data, list) or not all(isinstance(h, dict) for h in data):
        return mark_unreadable(result, "nikto_report_invalid")
    if not data:
        result.success = False
        result.error = "host_not_tested: nikto wrote no host to its report"
        result.metadata = {**result.metadata, "state": "failed", "reason_code": "host_not_tested"}
        return result

    findings: list[dict[str, Any]] = []
    for host in data:
        port = str(host.get("port") or "")
        scheme = "https" if port == "443" or host.get("ssl_info") else "http"
        base = f"{scheme}://{host.get('host') or host.get('ip')}:{port}" if port else ""
        for item in host.get("vulnerabilities") or []:
            if not isinstance(item, dict):
                return mark_unreadable(result, "nikto_report_invalid")
            refs = str(item.get("references") or "")
            msg = str(item.get("msg") or "Nikto finding")
            path = str(item.get("url") or "")
            findings.append(
                {
                    "title": msg[:200],
                    "description": msg,
                    "severity": _severity(refs),
                    "url": f"{base}{path}" if base else path,
                    "cve_ids": sorted({c.upper() for c in _CVE.findall(refs)}),
                    "tags": ["nikto", f"nikto-{item.get('id')}"],
                    "evidence": {
                        "nikto_id": item.get("id"),
                        "method": item.get("method"),
                        "references": refs,
                        "server_banner": host.get("server_banner"),
                    },
                }
            )
    result.findings = findings
    if _MAXTIME_MARKER in result.raw_output:
        # Findings found before the time limit are kept; the host was not fully covered.
        result.success = False
        result.error = "timeout: nikto reached its maximum time for the host"
        result.metadata = {**result.metadata, "state": "failed", "reason_code": "timeout"}
        return result
    return mark_completed(result)


class NiktoTool(CliTool):
    binary = "nikto"
    tool_name = "nikto"
    install_instructions = "Install nikto (sullo/nikto) and put program/nikto.pl on PATH."

    def _nikto_home(self) -> Path | None:
        """The nikto program directory (it holds databases/ and plugins/), or None."""
        found = self._resolve_binary()
        if not found:
            return None
        home = Path(found).resolve().parent
        return home if (home / "databases" / "db_tests").is_file() else None

    async def run(
        self,
        target: str,
        max_rps: float | None = None,
        allowed_methods: list[str] | tuple[str, ...] = ("GET", "HEAD"),
        timeout: int = 1800,
        **kwargs,
    ) -> ToolResult:
        home = self._nikto_home()
        if home is None:
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                target=target,
                error="nikto not installed or its databases/ directory was not found",
                metadata={
                    "state": "unavailable",
                    "reason_code": "not_installed",
                    "install": self.install_instructions,
                },
            )
        work = self.work_dir or Path(tempfile.mkdtemp(prefix="netra-nikto-"))
        work.mkdir(parents=True, exist_ok=True)
        conf = build_nikto_workspace(home, work, allowed_methods)
        report = work / "nikto-report.json"
        report.unlink(missing_ok=True)
        # Nikto stops by itself before the process timeout, so it still writes its report.
        maxtime = max(60, int(timeout) - 120)
        args = [
            "-h", target,
            "-config", str(conf),
            # -Plugins also selects report plugins: without report_json, no report is written.
            "-Plugins", ";".join((*NIKTO_PLUGINS, "report_json")),
            "-Tuning", "".join(sorted(NON_EXPLOIT_TUNING)),
            "-Format", "json",
            "-o", str(report),
            "-maxtime", f"{maxtime}s",
            "-timeout", "10",
            "-nointeractive",
            "-ask", "no",
            "-nocheck",
        ]  # fmt: skip
        if max_rps:
            # Seconds between requests; nikto sleeps with Time::HiRes, so fractions work.
            args += ["-Pause", f"{1 / float(max_rps):.3f}"]
        result = await self._exec(args, timeout=timeout)
        result.target = target
        return parse_nikto_report(result, report)
