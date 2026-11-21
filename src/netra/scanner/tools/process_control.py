"""Process tracking and cleanup for long-running CLI-backed tools."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
from contextvars import ContextVar, Token
from pathlib import Path

import structlog

logger = structlog.get_logger()

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
            subprocess.run(  # noqa: S603 - fixed argv, no shell, pid is an int
                ["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S607
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return
        # CliTool starts each child as its own session/group leader. The group
        # may outlive its leader, so do not resolve pgid through a dead PID.
        os.killpg(pid, signal.SIGKILL)


def kill_registered_processes(task_id: str) -> list[int]:
    """Kill all tracked child processes for a task and clear the registry."""
    payload = _load_registry(task_id)
    killed: list[int] = []
    for pid in payload.get("pids", []):
        try:
            kill_process_tree(int(pid))
            killed.append(int(pid))
        except Exception as exc:  # the process may already have exited
            logger.debug("kill_process_failed", pid=pid, error=str(exc))
            continue
    clear_task_registry(task_id)
    return killed


def clear_task_registry(task_id: str) -> None:
    """Remove the task registry file."""
    with contextlib.suppress(FileNotFoundError):
        _registry_path(task_id).unlink()


def create_process_job(pid: int) -> int | None:
    """Bind Windows descendants to a kill-on-close Job Object."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_int64),
            ("job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD),
            ("min_working_set", ctypes.c_size_t),
            ("max_working_set", ctypes.c_size_t),
            ("active_processes", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "read_ops",
                "write_ops",
                "other_ops",
                "read_bytes",
                "write_bytes",
                "other_bytes",
            )
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimits),
            ("io", IoCounters),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process = None
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = kernel.OpenProcess(0x0100 | 0x0001, False, pid)
        if not process or not kernel.AssignProcessToJobObject(job, process):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(job)
    except BaseException:
        kernel.CloseHandle(job)
        raise
    finally:
        if process:
            kernel.CloseHandle(process)


def close_process_job(handle: int | None) -> None:
    """Close the last owned job handle, terminating descendants on Windows."""
    if handle is not None and os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.CloseHandle(handle)
