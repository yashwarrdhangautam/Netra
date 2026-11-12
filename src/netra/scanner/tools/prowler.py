from netra.scanner.tools.generic import PassthroughTool


class ProwlerTool(PassthroughTool):
    binary = "prowler"
    tool_name = "prowler"
    install_instructions = "Install prowler and put it on PATH."

