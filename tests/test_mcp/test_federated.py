"""Tests for federated MCP client."""

import pytest

from netra.mcp.federated import FederatedMcpClient


@pytest.mark.asyncio
async def test_federated_pre_call_hook_blocks() -> None:
    calls = []

    def hook(name, args):
        calls.append((name, args))
        raise RuntimeError("blocked")

    client = FederatedMcpClient(["python", "-c", "print('unused')"], pre_call_hook=hook)
    with pytest.raises(RuntimeError, match="blocked"):
        await client.call_tool("bb_active_recon", {"target": "out.example"})

    assert calls == [("bb_active_recon", {"target": "out.example"})]
