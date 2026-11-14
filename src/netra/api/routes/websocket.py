"""WebSocket endpoints for real-time scan updates."""

import asyncio
import json
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from netra.core.security import decode_access_token, token_blacklist
from netra.db.models.scan import Scan
from netra.db.models.scan_phase import ScanPhase
from netra.db.models.user import User
from netra.db.session import async_session_factory

logger = structlog.get_logger()

router = APIRouter()

WS_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION


async def authenticate_websocket(websocket: WebSocket) -> User | None:
    """Return the signed-in user for a WebSocket, or None after closing it.

    Browsers cannot set an Authorization header on a WebSocket, so the access
    token is passed as the ``token`` query parameter. The same checks as HTTP
    apply: valid signature, not expired, not blacklisted, active user.
    """
    token = websocket.query_params.get("token")
    payload = decode_access_token(token) if token else None
    if not payload or await token_blacklist.is_blacklisted(token):
        await websocket.close(code=WS_POLICY_VIOLATION)
        return None

    user_id = payload.get("sub")
    async with async_session_factory() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        await websocket.close(code=WS_POLICY_VIOLATION)
        return None
    return user


# Connection manager
class ConnectionManager:
    """Manage WebSocket connections."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str) -> None:
        """Accept and register a new connection."""
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        self.active_connections[channel].append(websocket)
        logger.info("websocket_connected", channel=channel)

    def disconnect(self, websocket: WebSocket, channel: str) -> None:
        """Remove a connection."""
        connections = self.active_connections.get(channel, [])
        if websocket in connections:
            connections.remove(websocket)
        logger.info("websocket_disconnected", channel=channel)

    async def broadcast(self, channel: str, data: dict[str, Any]) -> None:
        """Broadcast a message to all connections in a channel."""
        if channel in self.active_connections:
            message = json.dumps(data)
            disconnected = []
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_text(message)
                except Exception:
                    disconnected.append(connection)
            # Clean up disconnected clients
            for conn in disconnected:
                self.disconnect(conn, channel)


manager = ConnectionManager()


TERMINAL_SCAN_STATES = {"completed", "failed", "cancelled"}
SNAPSHOT_INTERVAL_SECONDS = 2


async def scan_snapshot(scan_id: str) -> dict[str, Any] | None:
    """Current status and phases for one scan, read in its own session. None if unknown."""
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        return None
    async with async_session_factory() as db:
        scan = await db.get(Scan, sid)
        if scan is None:
            return None
        phases = (
            (
                await db.execute(
                    select(ScanPhase).where(ScanPhase.scan_id == sid).order_by(ScanPhase.started_at)
                )
            )
            .scalars()
            .all()
        )
        return {
            "scan_id": scan_id,
            "status": str(scan.status),
            "error_message": scan.error_message,
            "phases": [
                {
                    "phase_type": str(p.phase_type),
                    "status": str(p.status),
                    "started_at": p.started_at.isoformat() if p.started_at else None,
                    "completed_at": p.completed_at.isoformat() if p.completed_at else None,
                    "findings_count": p.findings_count,
                    "error_message": p.error_message,
                }
                for p in phases
            ],
        }


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """Push the scan's status and phases every few seconds until it finishes.

    The server reads the database and sends a snapshot only when something changed. The
    client no longer has to poll, and the final snapshot tells it the scan is done.
    """
    if await authenticate_websocket(websocket) is None:
        return
    channel = f"scan:{scan_id}"
    await manager.connect(websocket, channel)
    try:
        last: dict[str, Any] | None = None
        while True:
            snapshot = await scan_snapshot(scan_id)
            if snapshot is None:
                await websocket.send_json({"error": "scan_not_found", "scan_id": scan_id})
                break
            if snapshot != last:
                await websocket.send_json(snapshot)
                last = snapshot
            if snapshot["status"] in TERMINAL_SCAN_STATES:
                break
            await asyncio.sleep(SNAPSHOT_INTERVAL_SECONDS)
    except WebSocketDisconnect:
        pass
    else:
        # The loop ends when the scan is finished or unknown. Close the socket here so the
        # client sees the end, instead of waiting for the connection to time out.
        try:
            await websocket.close()
        except RuntimeError:
            pass  # the client already went away
    finally:
        manager.disconnect(websocket, channel)


@router.websocket("/ws/findings")
async def finding_stream(websocket: WebSocket) -> None:
    """Real-time finding stream across all active scans."""
    if await authenticate_websocket(websocket) is None:
        return
    channel = "findings:all"
    await manager.connect(websocket, channel)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


@router.websocket("/ws/agent/{session_id}")
async def agent_conversation(websocket: WebSocket, session_id: str) -> None:
    """Real-time autonomous agent conversation stream."""
    if await authenticate_websocket(websocket) is None:
        return
    channel = f"agent:{session_id}"
    await manager.connect(websocket, channel)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


async def broadcast_scan_update(scan_id: str, data: dict[str, Any]) -> None:
    """Broadcast scan update to all connected clients."""
    await manager.broadcast(f"scan:{scan_id}", data)


async def broadcast_finding_new(finding_data: dict[str, Any]) -> None:
    """Broadcast new finding to all connected clients."""
    await manager.broadcast("findings:all", {"type": "new_finding", "finding": finding_data})
