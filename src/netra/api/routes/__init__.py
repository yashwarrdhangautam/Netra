"""Re-export all route routers for convenient importing."""
from netra.api.routes.agent import router as agent
from netra.api.routes.auth import router as auth
from netra.api.routes.compliance import router as compliance
from netra.api.routes.findings import router as findings
from netra.api.routes.health import router as health
from netra.api.routes.reports import router as reports
from netra.api.routes.scans import router as scans
from netra.api.routes.targets import router as targets
from netra.api.routes.websocket import router as websocket

__all__ = [
    "agent",
    "auth",
    "compliance",
    "findings",
    "health",
    "reports",
    "scans",
    "targets",
    "websocket",
]
