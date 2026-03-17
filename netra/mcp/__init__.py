"""
netra/mcp
MCP server package for NETRA. Exposes NETRA capabilities to Claude Desktop
and other MCP-compatible clients via stdio transport.

Run with:
    python3 -m netra.mcp
"""

from netra.mcp.server import run_mcp_server

if __name__ == "__main__":
    run_mcp_server()
