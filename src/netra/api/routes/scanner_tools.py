"""Scanner tool inventory: which external binaries the scan worker has installed."""

import asyncio

import structlog
from fastapi import APIRouter

from netra.scanner.tools.inventory import tool_inventory

router = APIRouter(prefix="/scanner", tags=["Scanner"])
logger = structlog.get_logger(__name__)

WORKER_TASK = "netra.scanner_tool_inventory"


def _worker_inventory() -> list[dict]:
    """Ask a worker, the process that actually runs scans, for its tool inventory."""
    from netra.worker.celery_app import celery_app

    return celery_app.send_task(WORKER_TASK).get(timeout=5)


@router.get("/tools")
async def list_scanner_tools() -> dict[str, object]:
    """Report installed and missing scanner tools.

    The worker answers, because the API image does not carry the scanner binaries. If no
    worker answers within 5 seconds, the API's own view is returned and marked as such.
    """
    try:
        rows = await asyncio.to_thread(_worker_inventory)
        source = "worker"
    except Exception as exc:  # no worker reachable, or the result timed out
        logger.warning("scanner_tools_worker_unavailable", error=str(exc))
        rows = tool_inventory()
        source = "api"
    missing = [r["binary"] for r in rows if not r["installed"] and not r["optional"]]
    return {
        "source": source,
        "tools": rows,
        "missing_required": missing,
        "missing_count": len(missing),
    }
