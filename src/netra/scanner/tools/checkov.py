from netra.scanner.tools.generic import PassthroughTool


class CheckovTool(PassthroughTool):
    binary = "checkov"
    tool_name = "checkov"
    install_instructions = "Install checkov and put it on PATH."
