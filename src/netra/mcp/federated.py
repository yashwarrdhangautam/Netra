"""Federated MCP client for proxying downstream stdio MCP servers."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netra.scanner.tools.process_control import register_process, unregister_process

PreCallHook = Callable[[str, dict[str, Any]], Awaitable[None] | None]


@dataclass
class FederatedTool:
    """A tool exposed by a downstream MCP server."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None


class FederatedMcpClient:
    """Tiny JSON-RPC stdio MCP client with an optional pre-call hook."""

    def __init__(self, command: list[str], pre_call_hook: PreCallHook | None = None) -> None:
        self.command = command
        self.pre_call_hook = pre_call_hook
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 1

    async def __aenter__(self) -> "FederatedMcpClient":
        creation_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            creation_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            creation_kwargs["start_new_session"] = True
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **creation_kwargs,
        )
        register_process(self._proc.pid)
        await self._request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "netra", "version": "1.0.0"}})
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except TimeoutError:
                self._proc.kill()
        if self._proc:
            unregister_process(self._proc.pid)

    async def list_tools(self) -> list[FederatedTool]:
        """Return downstream tools."""
        data = await self._request("tools/list", {})
        return [
            FederatedTool(
                name=t.get("name", ""),
                description=t.get("description"),
                input_schema=t.get("inputSchema"),
            )
            for t in data.get("tools", [])
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a downstream tool after running the optional pre-call hook."""
        if self.pre_call_hook is not None:
            result = self.pre_call_hook(name, arguments)
            if asyncio.iscoroutine(result):
                await result
        return await self._request("tools/call", {"name": name, "arguments": arguments})

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            raise RuntimeError("FederatedMcpClient is not connected")
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        self._proc.stdin.write((json.dumps(payload) + "\n").encode())
        await self._proc.stdin.drain()

        while True:
            line = await self._proc.stdout.readline()
            if not line:
                raise RuntimeError("downstream MCP closed stdout")
            data = json.loads(line.decode("utf-8"))
            if data.get("id") != request_id:
                continue
            if "error" in data:
                raise RuntimeError(str(data["error"]))
            return data.get("result", {})
