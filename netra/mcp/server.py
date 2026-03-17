"""
netra/mcp/server.py
NETRA MCP server — exposes NETRA capabilities to Claude Desktop and other
MCP-compatible clients via stdio transport (with optional SSE upgrade).

Start via:
    python3 netra.py mcp
    python3 -m netra.mcp

Claude Desktop config (~/.config/claude-desktop/claude_desktop_config.json):
{
  "mcpServers": {
    "netra": {
      "command": "python3",
      "args": ["-m", "netra.mcp"],
      "cwd": "/path/to/netra"
    }
  }
}
"""

import sys
import logging
from pathlib import Path

# Ensure parent package is importable when run as __main__
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logger = logging.getLogger("netra.mcp")


def run_mcp_server() -> None:
    """
    Bootstrap and run the NETRA MCP server.
    Registers all tools then starts the stdio event loop.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("[netra-mcp] fastmcp not installed. Run: pip3 install fastmcp --break-system-packages")
        sys.exit(1)

    from netra.core.config import load_config
    load_config()

    from netra.mcp.tools import register_tools

    mcp = FastMCP(
        name="netra",
        version="1.0.0",
        description=(
            "NETRA नेत्र — AI-Augmented Cybersecurity Platform. "
            "Run vulnerability scans, query findings, generate reports, "
            "and chain attack paths — all from Claude Desktop."
        ),
    )

    register_tools(mcp)

    logger.info("NETRA MCP server starting (stdio transport)")
    mcp.run()


if __name__ == "__main__":
    run_mcp_server()
