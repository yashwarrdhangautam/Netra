"""WebSocket endpoints for real-time scan updates."""
import json
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = structlog.get_logger()

router = APIRouter()


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
        if channel in self.active_connections:
            self.active_connections[channel].remove(websocket)
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


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """Real-time scan progress updates."""
    channel = f"scan:{scan_id}"
    await manager.connect(websocket, channel)
    try:
        while True:
            # Keep connection alive, wait for disconnect
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


@router.websocket("/ws/findings")
async def finding_stream(websocket: WebSocket) -> None:
    """Real-time finding stream across all active scans."""
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
