"""The scan WebSocket pushes snapshots until the scan finishes, instead of waiting for the client."""

import importlib

from starlette.testclient import TestClient

from netra.api.app import create_app

# The routes package re-exports its router under the same name, so import the module directly.
ws_module = importlib.import_module("netra.api.routes.websocket")


def _snap(status: str) -> dict:
    return {"scan_id": "abc", "status": status, "error_message": None, "phases": []}


def test_pushes_each_change_then_closes_on_completion(monkeypatch) -> None:
    snapshots = [_snap("running"), _snap("running"), _snap("completed")]

    async def fake_auth(_websocket):
        return object()

    async def fake_snapshot(_scan_id):
        return snapshots.pop(0) if snapshots else _snap("completed")

    monkeypatch.setattr(ws_module, "authenticate_websocket", fake_auth)
    monkeypatch.setattr(ws_module, "scan_snapshot", fake_snapshot)
    monkeypatch.setattr(ws_module, "SNAPSHOT_INTERVAL_SECONDS", 0)

    with TestClient(create_app()).websocket_connect("/ws/scans/abc") as conn:
        first = conn.receive_json()
        second = conn.receive_json()

    # The unchanged "running" snapshot is not sent twice.
    assert first["status"] == "running"
    assert second["status"] == "completed"


def test_unknown_scan_gets_an_error_and_closes(monkeypatch) -> None:
    async def fake_auth(_websocket):
        return object()

    async def missing(_scan_id):
        return None

    monkeypatch.setattr(ws_module, "authenticate_websocket", fake_auth)
    monkeypatch.setattr(ws_module, "scan_snapshot", missing)

    with TestClient(create_app()).websocket_connect("/ws/scans/nope") as conn:
        assert conn.receive_json() == {"error": "scan_not_found", "scan_id": "nope"}
