from netra.scanner.tools.generic import PassthroughTool


class PipAuditTool(PassthroughTool):
    binary = "pip-audit"
    tool_name = "pip-audit"
    install_instructions = "Install pip-audit and put it on PATH."
