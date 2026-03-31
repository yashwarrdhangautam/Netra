"""Autonomous pentest agent API endpoints."""
import structlog
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/agent", tags=["Agent"])


@router.post("/start")
async def start_agent(
    target: str,
    profile: str = "standard",
) -> dict:
    """Start a new autonomous pentest agent session."""
    from netra.ai.agent import create_agent_session

    try:
        agent = create_agent_session()
        result = await agent.start(target, profile)
        return result
    except Exception:
        # Log sanitized error internally — never expose exception details
        # to prevent information leakage (CWE-209, CodeQL py/stack-trace-exposure)
        logger.exception(
            "agent_session_creation_failed",
            target=target,
            profile=profile,
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to create agent session. Please check server logs.",
        ) from None


@router.get("/{session_id}/status")
async def agent_status(session_id: str) -> dict:
    """Get current agent session status."""
    from netra.ai.agent import get_agent_session

    agent = get_agent_session(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Session not found")
    return agent._get_status_response()


@router.post("/{session_id}/approve")
async def approve_action(session_id: str) -> dict:
    """Approve pending exploitation action."""
    from netra.ai.agent import get_agent_session

    agent = get_agent_session(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Session not found")
    return await agent.approve_action()


@router.post("/{session_id}/reject")
async def reject_action(session_id: str, reason: str = "") -> dict:
    """Reject pending exploitation action."""
    from netra.ai.agent import get_agent_session

    agent = get_agent_session(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Session not found")
    return await agent.reject_action(reason)


@router.websocket("/ws/{session_id}")
async def agent_websocket(websocket: WebSocket, session_id: str) -> None:
    """WebSocket endpoint for real-time agent conversation stream."""
    from netra.ai.agent import get_agent_session

    await websocket.accept()
    agent = get_agent_session(session_id)

    if not agent:
        await websocket.send_json({"error": "Session not found"})
        await websocket.close()
        return

    try:
        # Send initial status
        await websocket.send_json(agent._get_status_response())

        # Keep connection alive
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
