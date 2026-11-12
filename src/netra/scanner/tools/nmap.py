from netra.scanner.tools.base import CliTool, ToolResult


class NmapTool(CliTool):
    binary = "nmap"
    tool_name = "nmap"
    install_instructions = "Install nmap and put it on PATH."

    async def run(self, target: str, **kwargs) -> ToolResult:
        return await self._exec([target])

