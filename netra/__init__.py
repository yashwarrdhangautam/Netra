"""
NETRA नेत्र — The Third Eye of Security
========================================
Open-source, AI-augmented cybersecurity platform.

Author  : Yash Wardhan Gautam
License : AGPL-3.0
Python  : 3.11+

Sub-packages
------------
netra.core       — Config, DB, checkpoints, utils, notifications, deps
netra.modules    — VAPT scanning modules (recon + pentest)
netra.ai_brain   — Multi-persona AI consensus, attack chains, CVSS, narratives
netra.mcp        — FastMCP server + 17 tools for Claude Desktop
netra.reports    — Word, PDF, HTML, Excel, Compliance, Evidence-ZIP report engine
netra.tui        — Terminal UI (Rich-based progress and status panels)
"""

__version__  = "1.0.0"
__author__   = "Yash Wardhan Gautam"
__license__  = "AGPL-3.0"
__email__    = "yash@netra.security"
__homepage__ = "https://github.com/netra-security/netra"


def version() -> str:
    """Return the current NETRA version string."""
    return __version__
