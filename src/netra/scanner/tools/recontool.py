"""Recontool wrapper: passive and active recon chaining, run as an external CLI.

Recontool (github.com/MANISHIGAUTAM/Recontool) is not vendored into NETRA. It is called as the
``recontool`` command, so its code and dependencies stay separate. Its licence is not confirmed
(pyproject says MIT, but the repo has no LICENSE file), so install it only after the owner
confirms the terms.

Safety rules enforced here, on top of NETRA's own scope and SSRF checks:

- The target must be a plain hostname. URLs, IPs, paths and wildcards are refused.
- Passive is the default. Active phases run only when the caller passes ``authorize_active=True``,
  which the caller must set only for a target that passed NETRA's scope validation.
- Output is read from the JSON export file, not stdout.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from netra.scanner.tools.base import CliTool, ToolResult

_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def is_plain_hostname(value: str) -> bool:
    return bool(_HOSTNAME.match(value.strip().lower()))


def parse_export(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a Recontool export into NETRA finding-style dicts.

    Only the fields NETRA uses are kept. Evidence is passed through as Recontool redacted it.
    """
    rows: list[dict[str, Any]] = []
    for asset in data.get("assets") or []:
        if not isinstance(asset, dict) or not asset.get("value"):
            continue
        rows.append(
            {
                "kind": "asset",
                "type": str(asset.get("type") or ""),
                "value": str(asset["value"])[:500],
                "in_scope": bool(asset.get("in_scope")),
                "is_live": bool(asset.get("is_live")),
                "confidence": asset.get("confidence"),
                "sources": list(asset.get("sources") or [])[:20],
            }
        )
    for endpoint in data.get("endpoints") or []:
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            continue
        rows.append(
            {
                "kind": "endpoint",
                "url": str(endpoint["url"])[:1000],
                "status": endpoint.get("status"),
                "title": str(endpoint.get("title") or "")[:300],
                "risk_class": endpoint.get("risk_class"),
            }
        )
    for finding in data.get("findings") or []:
        if not isinstance(finding, dict) or not finding.get("title"):
            continue
        rows.append(
            {
                "kind": "finding",
                "title": str(finding["title"])[:300],
                "severity": str(finding.get("severity") or "info").lower(),
                "cve": finding.get("cve"),
                "detector": finding.get("detector"),
                "asset": finding.get("asset"),
                "evidence": finding.get("evidence"),
            }
        )
    return rows


class RecontoolTool(CliTool):
    binary = "recontool"
    tool_name = "recontool"
    install_instructions = (
        "Install recontool from a reviewed commit: pip install git+https://github.com/"
        "MANISHIGAUTAM/Recontool@<commit>. Confirm the licence with the owner first."
    )

    async def run(
        self,
        target: str,
        *,
        profile: str = "stealth",
        authorize_active: bool = False,
        timeout: int = 1800,
        **_: Any,
    ) -> ToolResult:
        host = target.strip().lower()
        if not is_plain_hostname(host):
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                target=target,
                error="refused: recontool accepts a plain hostname only",
            )
        if self.work_dir is None:
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                target=host,
                error="work_dir is required to write the export file",
            )
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", profile):
            return ToolResult(
                tool_name=self.tool_name, success=False, target=host, error="invalid profile name"
            )

        export_path = self.work_dir / f"recontool-{uuid.uuid4().hex}.json"
        args = ["scan", host, "--profile", profile, "--export", str(export_path)]
        if authorize_active:
            args.append("--authorize-active")

        result = await self._exec(args, timeout=timeout)
        result.target = host
        result.metadata["active_authorized"] = authorize_active
        if not export_path.exists():
            if result.success:
                result.success = False
                result.error = "recontool finished without writing an export"
            return result

        try:
            data = json.loads(export_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.success = False
            result.error = f"unreadable recontool export: {type(exc).__name__}"
            return result
        finally:
            export_path.unlink(missing_ok=True)

        result.findings = parse_export(data)
        result.metadata["scan_id"] = data.get("scan_id")
        return result
