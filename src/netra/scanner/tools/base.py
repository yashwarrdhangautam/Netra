"""Common subprocess-backed scanner tool helpers."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netra.scanner.tools.process_control import (
    close_process_job,
    create_process_job,
    kill_process_tree,
    register_process,
    unregister_process,
)

# Set by the worker while a phase runs. Returns True when the scan was cancelled or paused, so
# the running tool is stopped instead of finishing (spec: cancel must not leave processes).
RUN_GUARD: ContextVar[Callable[[], Awaitable[bool]] | None] = ContextVar(
    "netra_run_guard", default=None
)
GUARD_INTERVAL_SECONDS = 2


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

    max_output_bytes = 10 * 1024 * 1024
    tool_env_keys: tuple[str, ...] = ()
    accepted_exit_codes: tuple[int, ...] = (0,)

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
                metadata={
                    "install": self.install_instructions,
                    "state": "unavailable",
                    "reason_code": "not_installed",
                },
            )

        creation_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            creation_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            creation_kwargs["start_new_session"] = True

        cap = self.max_output_bytes
        if cap <= 0:
            return ToolResult(self.tool_name, False, error="invalid output limit")
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        truncated = False
        proc: asyncio.subprocess.Process | None = None
        job: int | None = None
        jobs: list[asyncio.Task[Any]] = []
        failure: str | None = None
        watcher: asyncio.Task[Any] | None = None

        class OutputLimitExceeded(Exception):
            pass

        async def read_stream(reader: asyncio.StreamReader, destination: bytearray) -> None:
            nonlocal truncated
            while True:
                chunk = await reader.read(min(65536, cap - len(destination) + 1))
                if not chunk:
                    return
                remaining = cap - len(destination)
                destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    raise OutputLimitExceeded

        async def terminate() -> None:
            nonlocal job
            if proc is None:
                return
            close_process_job(job)
            job = None
            await asyncio.to_thread(kill_process_tree, proc.pid)
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()

            # An overflowing reader exited early. Drain its remaining pipe without
            # retaining bytes so paused StreamReader transports can observe EOF.
            async def discard(reader: asyncio.StreamReader) -> None:
                while await reader.read(65536):
                    pass

            for index, reader in enumerate((proc.stdout, proc.stderr)):
                if reader is not None and (len(jobs) <= index or jobs[index].done()):
                    jobs.append(asyncio.create_task(discard(reader)))
            # Let readers consume EOF after termination so Proactor pipe transports
            # close cleanly. Cancellation is reserved for a stuck inherited pipe.
            if jobs:
                _, pending = await asyncio.wait(jobs, timeout=2)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
            await proc.wait()

        # A fresh home prevents tool configuration/credentials from being inherited.
        # Cleanup is best-effort: tools such as semgrep leave socket/pipe files (ocaml_sp_*)
        # that Windows cannot unlink (WinError 1920). A scratch-dir cleanup failure must not
        # turn a completed scan into an exception.
        with tempfile.TemporaryDirectory(
            prefix="netra-tool-", ignore_cleanup_errors=True
        ) as private_home:
            env_keys = ("PATH", "SystemRoot", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
            env = {key: os.environ[key] for key in env_keys if key in os.environ}
            env.update({key: os.environ[key] for key in self.tool_env_keys if key in os.environ})
            env.update(
                {
                    "HOME": private_home,
                    "USERPROFILE": private_home,
                    "TMP": private_home,
                    "TEMP": private_home,
                    "TMPDIR": private_home,
                    "APPDATA": private_home,
                    "LOCALAPPDATA": private_home,
                }
            )
            try:
                proc = await asyncio.create_subprocess_exec(
                    self._resolve_binary() or self.binary,
                    *args,
                    stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self.work_dir) if self.work_dir else private_home,
                    env=env,
                    **creation_kwargs,
                )
                register_process(proc.pid)
                job = create_process_job(proc.pid)
                assert proc.stdout is not None and proc.stderr is not None
                jobs = [
                    asyncio.create_task(read_stream(proc.stdout, stdout_buffer)),
                    asyncio.create_task(read_stream(proc.stderr, stderr_buffer)),
                ]

                async def write_input() -> None:
                    if proc is not None and proc.stdin is not None:
                        try:
                            proc.stdin.write((stdin or "").encode())
                            await proc.stdin.drain()
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        finally:
                            proc.stdin.close()
                            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                                await proc.stdin.wait_closed()

                async def wait_process() -> int:
                    nonlocal job
                    assert proc is not None
                    returncode = await proc.wait()
                    close_process_job(job)
                    job = None
                    if os.name != "nt":
                        await asyncio.to_thread(kill_process_tree, proc.pid)
                    return returncode

                jobs.append(asyncio.create_task(write_input()))
                jobs.append(asyncio.create_task(wait_process()))
                guard = RUN_GUARD.get()
                if guard is not None:

                    async def watch_for_cancel() -> None:
                        nonlocal failure
                        while proc is not None and proc.returncode is None:
                            await asyncio.sleep(GUARD_INTERVAL_SECONDS)
                            try:
                                stop = await guard()
                            except Exception:
                                # A failed status check must not kill a healthy tool run.
                                stop = False
                            if stop and proc.returncode is None:
                                failure = "cancelled"
                                await terminate()
                                return

                    # Kept out of `jobs`: terminate() waits on those tasks and would wait on itself.
                    watcher = asyncio.create_task(watch_for_cancel())
                execution = asyncio.gather(*jobs)
                # Timeout/cancellation must not abort readers before killed children
                # close their handles. terminate() drains them before returning.
                try:
                    await asyncio.wait_for(asyncio.shield(execution), timeout=timeout)
                finally:
                    if not execution.done():
                        execution.add_done_callback(
                            lambda result: result.exception() if not result.cancelled() else None
                        )
            except OutputLimitExceeded:
                failure = "output_truncated"
                await terminate()
            except TimeoutError:
                failure = "timeout"
                await terminate()
            except asyncio.CancelledError:
                await terminate()
                raise
            except (OSError, RuntimeError, NotImplementedError) as exc:
                failure = "execution_unavailable"
                await terminate()
                # Avoid exception text containing caller data or inherited secrets.
                stderr_buffer.extend(type(exc).__name__.encode()[: cap - len(stderr_buffer)])
            finally:
                if watcher is not None:
                    watcher.cancel()
                if proc is not None:
                    # Also clean descendants that outlive a normally exited parent.
                    close_process_job(job)
                    job = None
                    if os.name != "nt":
                        await asyncio.to_thread(kill_process_tree, proc.pid)
                    unregister_process(proc.pid)

        out = stdout_buffer.decode("utf-8", errors="replace")
        err = stderr_buffer.decode("utf-8", errors="replace")
        returncode = proc.returncode if proc is not None else None
        # Several tools exit non-zero when they find something; the wrapper declares which codes
        # mean "ran successfully".
        success = failure is None and returncode in self.accepted_exit_codes
        return ToolResult(
            tool_name=self.tool_name,
            success=success,
            raw_output=out,
            error=None if success else failure or err.strip() or f"exit {returncode}",
            metadata={
                "stderr": err.strip(),
                "returncode": returncode,
                "output_truncated": truncated,
                "state": "parse_error" if truncated else "completed" if success else "failed",
                "reason_code": failure,
            },
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
