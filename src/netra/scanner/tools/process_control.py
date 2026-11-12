"""Process tracking and cleanup for long-running CLI-backed tools."""
from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
from contextvars import ContextVar, Token
from pathlib import Path


_CURRENT_TASK_ID: ContextVar[str | None] = ContextVar("netra_current_task_id", default=None)


def set_current_task_id(task_id: str | None) -> Token:
    """Set the current task id for subprocess registration."""
    return _CURRENT_TASK_ID.set(task_id)


def reset_current_task_id(token: Token) -> None:
    """Restore the previous task id context."""
    _CURRENT_TASK_ID.reset(token)


def current_task_id() -> str | None:
    """Return the current task id, if one is active."""
    return _CURRENT_TASK_ID.get()


def _registry_dir() -> Path:
    path = Path.home() / ".netra" / "task_registry"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _registry_path(task_id: str) -> Path:
    return _registry_dir() / f"{task_id}.json"


def _load_registry(task_id: str) -> dict:
    path = _registry_path(task_id)
    if not path.exists():
        return {"task_id": task_id, "pids": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"task_id": task_id, "pids": []}


def _write_registry(task_id: str, payload: dict) -> None:
    _registry_path(task_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def register_process(pid: int, task_id: str | None = None) -> None:
    """Register a child process under the current task id."""
    resolved = task_id or current_task_id()
    if not resolved:
        return
    payload = _load_registry(resolved)
    pids = {int(item) for item in payload.get("pids", []) if str(item).isdigit()}
    pids.add(int(pid))
    payload["pids"] = sorted(pids)
    _write_registry(resolved, payload)


def unregister_process(pid: int, task_id: str | None = None) -> None:
    """Remove a child process from the current task registry."""
    resolved = task_id or current_task_id()
    if not resolved:
        return
    payload = _load_registry(resolved)
    payload["pids"] = [int(item) for item in payload.get("pids", []) if int(item) != int(pid)]
    _write_registry(resolved, payload)


def kill_process_tree(pid: int) -> None:
    """Terminate a process tree as hard as the platform allows."""
    with contextlib.suppress(Exception):
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return
        os.killpg(os.getpgid(pid), signal.SIGKILL)


def kill_registered_processes(task_id: str) -> list[int]:
    """Kill all tracked child processes for a task and clear the registry."""
    payload = _load_registry(task_id)
    killed: list[int] = []
    for pid in payload.get("pids", []):
        try:
            kill_process_tree(int(pid))
            killed.append(int(pid))
        except Exception:
            continue
    clear_task_registry(task_id)
    return killed


def clear_task_registry(task_id: str) -> None:
    """Remove the task registry file."""
    with contextlib.suppress(FileNotFoundError):
        _registry_path(task_id).unlink()
