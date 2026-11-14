"""Common subprocess-backed scanner tool helpers."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netra.scanner.tools.process_control import register_process, unregister_process


@dataclass
class ToolResult:
    """Normalized output from a scanner wrapper."""

    tool_name: str
    success: bool
    target: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: str | None = None


class CliTool:
    """Small async wrapper around a CLI security tool."""

    binary = ""
    tool_name = "tool"
    install_instructions = "Install the tool and ensure it is on PATH."

    def __init__(self, work_dir: str | Path | None = None) -> None:
        self.work_dir = Path(work_dir) if work_dir else None
        if self.work_dir:
            self.work_dir.mkdir(parents=True, exist_ok=True)

    def is_installed(self) -> bool:
        return bool(self._resolve_binary())

    def _resolve_binary(self) -> str | None:
        found = shutil.which(self.binary)
        if found:
            return found

        repo_root = Path(__file__).resolve().parents[4]
        candidate = (
            repo_root
            / "tools"
            / "bin"
            / (f"{self.binary}.exe" if not self.binary.endswith(".exe") else self.binary)
        )
        if candidate.exists():
            return str(candidate)
        return None

    async def _exec(
        self, args: list[str], stdin: str | None = None, timeout: int = 300
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool_name=self.tool_name,
                success=False,
                error=f"{self.binary} not installed",
                metadata={"install": self.install_instructions},
            )

        creation_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            creation_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            creation_kwargs["start_new_session"] = True

        proc = await asyncio.create_subprocess_exec(
            self._resolve_binary() or self.binary,
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.work_dir) if self.work_dir else None,
            **creation_kwargs,
        )
        register_process(proc.pid)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin is not None else None),
                timeout=timeout,
            )
        except TimeoutError:
            proc.kill()
            unregister_process(proc.pid)
            return ToolResult(self.tool_name, False, error=f"{self.tool_name} timed out")
        except asyncio.CancelledError:
            proc.kill()
            unregister_process(proc.pid)
            raise
        finally:
            if proc.returncode is not None:
                unregister_process(proc.pid)

        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        success = proc.returncode == 0
        return ToolResult(
            tool_name=self.tool_name,
            success=success,
            raw_output=out,
            error=None if success else err.strip() or f"exit {proc.returncode}",
            metadata={"stderr": err.strip(), "returncode": proc.returncode},
        )


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON, ignoring malformed lines."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def unique_findings(findings: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    """Deduplicate findings by the first populated key in keys."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in findings:
        sig = ""
        for key in keys:
            if item.get(key):
                sig = str(item[key]).lower()
                break
        if not sig:
            sig = json.dumps(item, sort_keys=True)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(item)
    return out
