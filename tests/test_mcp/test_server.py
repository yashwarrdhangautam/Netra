"""Tests for MCP server."""
import pytest

from netra.mcp.server import mcp


@pytest.mark.asyncio
async def test_mcp_server_starts() -> None:
    """Test MCP server can be instantiated."""
    assert mcp is not None
    assert mcp.name == "netra"


@pytest.mark.asyncio
async def test_nuclei_scan_stub() -> None:
    """Test nuclei scan tool stub."""
    from netra.mcp.server import nuclei_scan

    result = await nuclei_scan("example.com")
    assert result["status"] == "mock"
    assert result["tool"] == "nuclei"


@pytest.mark.asyncio
async def test_nmap_scan_stub() -> None:
    """Test nmap scan tool stub."""
    from netra.mcp.server import nmap_scan

    result = await nmap_scan("192.168.1.1")
    assert result["status"] == "mock"
    assert result["tool"] == "nmap"
