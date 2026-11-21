"""Tests for MCP server."""

import pytest

from netra.mcp.server import mcp


@pytest.mark.asyncio
async def test_mcp_server_starts() -> None:
    """Test MCP server can be instantiated."""
    assert mcp is not None
    assert mcp.name == "netra"


@pytest.mark.asyncio
async def test_nuclei_scan_stub(monkeypatch) -> None:
    """Missing authorization is refused before binary availability is inspected."""
    from netra.scanner.tools.nuclei import NucleiTool

    monkeypatch.setattr(NucleiTool, "is_installed", lambda self: False)
    from unittest.mock import AsyncMock

    from netra.mcp import server
    from netra.mcp.server import nuclei_scan

    monkeypatch.setattr(
        server, "_authorize_mcp", AsyncMock(return_value=server._blocked("authorization_missing"))
    )
    result = await nuclei_scan("example.com")
    assert result["error"] == "authorization_missing"


@pytest.mark.asyncio
async def test_nmap_scan_stub(monkeypatch) -> None:
    """Missing authorization is refused before binary availability is inspected."""
    from netra.scanner.tools.nmap import NmapTool

    monkeypatch.setattr(NmapTool, "is_installed", lambda self: False)
    from unittest.mock import AsyncMock

    from netra.mcp import server
    from netra.mcp.server import nmap_scan

    monkeypatch.setattr(
        server, "_authorize_mcp", AsyncMock(return_value=server._blocked("authorization_missing"))
    )
    result = await nmap_scan("192.168.1.1")
    assert result["error"] == "authorization_missing"
