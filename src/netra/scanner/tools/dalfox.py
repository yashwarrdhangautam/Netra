from netra.scanner.tools.generic import PassthroughTool


class DalfoxTool(PassthroughTool):
    binary = "dalfox"
    tool_name = "dalfox"
    install_instructions = "Install dalfox and put it on PATH."
