"""Generic wrappers for tools whose detailed parsers are not needed by BB yet."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class PassthroughTool(CliTool):
    async def run(self, target: str, **kwargs) -> ToolResult:
        return await self._exec([target])
