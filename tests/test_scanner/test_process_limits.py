"""Real benign subprocess coverage for scanner boundaries."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from netra.scanner.tools.base import CliTool


@pytest.fixture(scope="module")
def event_loop_policy():
    # The shared Windows Selector policy cannot run asyncio subprocesses.
    if os.name == "nt":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


class PythonFixture(CliTool):
    binary = sys.executable
    tool_name = "python-fixture"
    max_output_bytes = 4096


async def test_subprocess_has_private_home_and_no_platform_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("NETRA_JWT_SECRET_KEY", "synthetic-platform-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://synthetic-proxy.invalid")
    script = "import os,json; print(json.dumps(dict(os.environ)))"
    result = await PythonFixture(tmp_path)._exec(["-c", script])
    env = json.loads(result.raw_output)
    assert result.success
    assert "NETRA_JWT_SECRET_KEY" not in env
    assert "HTTP_PROXY" not in env
    assert env["HOME"] != str(Path.home())
    assert env["USERPROFILE"] == env["HOME"]
    assert not Path(env["HOME"]).exists()


async def test_private_home_cleanup_failure_does_not_fail_the_run(tmp_path, monkeypatch):
    """Regression: semgrep's ocaml_sp_* files cannot be unlinked on Windows (WinError 1920)."""
    import shutil

    def failing_rmtree(path, *args, onexc=None, **kwargs):
        error = OSError(1920, "The file cannot be accessed by the system")
        if onexc is not None:
            onexc(os.unlink, os.path.join(str(path), "ocaml_sp_0000b070_00000001"), error)
        else:
            raise error

    monkeypatch.setattr(shutil, "rmtree", failing_rmtree)
    result = await PythonFixture(tmp_path)._exec(["-c", "print('ok')"])
    assert result.success
    assert result.raw_output.strip() == "ok"


async def test_stdout_is_capped_during_capture(tmp_path):
    result = await PythonFixture(tmp_path)._exec(
        ["-c", "import sys; sys.stdout.write('x'*1000000); sys.stdout.flush()"]
    )
    assert not result.success
    assert len(result.raw_output.encode()) <= 4096
    assert result.metadata["output_truncated"] is True
    assert result.metadata["state"] == "parse_error"


async def test_stderr_is_capped_during_capture(tmp_path):
    result = await PythonFixture(tmp_path)._exec(
        ["-c", "import sys; sys.stderr.write('x'*1000000); sys.stderr.flush()"]
    )
    assert not result.success
    assert len(result.metadata["stderr"].encode()) <= 4096
    assert result.metadata["output_truncated"] is True


async def test_timeout_kills_and_reaps_parent(tmp_path):
    result = await PythonFixture(tmp_path)._exec(["-c", "import time; time.sleep(30)"], timeout=0.2)
    assert not result.success
    assert result.metadata["reason_code"] == "timeout"
    assert result.metadata["returncode"] is not None


async def test_cancellation_stops_process_and_propagates(tmp_path):
    pidfile = tmp_path / "pid"
    task = asyncio.create_task(
        PythonFixture(tmp_path)._exec(
            [
                "-c",
                f"import os,pathlib,time; pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)",
            ]
        )
    )
    for _ in range(100):
        if pidfile.exists():
            break
        await asyncio.sleep(0.02)
    assert pidfile.exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not _alive(int(pidfile.read_text()))


def _alive(pid):
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


async def test_timeout_kills_descendant(tmp_path):
    pidfile = tmp_path / "child-pid"
    child = "import time; time.sleep(30)"
    script = (
        "import subprocess,sys,pathlib,time; "
        f"child=subprocess.Popen([sys.executable,'-c',{child!r}]); "
        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid)); time.sleep(30)"
    )
    result = await PythonFixture(tmp_path)._exec(["-c", script], timeout=1)
    assert not result.success
    assert pidfile.exists()
    for _ in range(50):
        if not _alive(int(pidfile.read_text())):
            break
        await asyncio.sleep(0.02)
    assert not _alive(int(pidfile.read_text()))
