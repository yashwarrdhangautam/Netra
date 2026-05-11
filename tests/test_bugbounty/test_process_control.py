"""Focused tests for subprocess tracking and cleanup."""

from __future__ import annotations

from pathlib import Path

from netra.scanner.tools import process_control


def test_process_registry_tracks_and_clears(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(process_control, "_registry_dir", lambda: Path(tmp_path))

    token = process_control.set_current_task_id("task-1")
    try:
        process_control.register_process(111)
        process_control.register_process(222)
        payload = process_control._load_registry("task-1")  # noqa: SLF001
        assert payload["pids"] == [111, 222]

        process_control.unregister_process(111)
        payload = process_control._load_registry("task-1")  # noqa: SLF001
        assert payload["pids"] == [222]

        process_control.clear_task_registry("task-1")
        assert not (Path(tmp_path) / "task-1.json").exists()
    finally:
        process_control.reset_current_task_id(token)


def test_kill_registered_processes_invokes_tree_kill_and_clears(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(process_control, "_registry_dir", lambda: Path(tmp_path))
    killed: list[int] = []
    monkeypatch.setattr(process_control, "kill_process_tree", lambda pid: killed.append(pid))

    process_control._write_registry("task-2", {"task_id": "task-2", "pids": [333, 444]})  # noqa: SLF001
    result = process_control.kill_registered_processes("task-2")

    assert result == [333, 444]
    assert killed == [333, 444]
    assert not (Path(tmp_path) / "task-2.json").exists()
