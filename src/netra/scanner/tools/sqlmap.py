from netra.scanner.tools.generic import PassthroughTool


class SqlmapTool(PassthroughTool):
    binary = "sqlmap"
    tool_name = "sqlmap"
    install_instructions = "Install sqlmap and put it on PATH."

