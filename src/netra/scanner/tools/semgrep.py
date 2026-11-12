from netra.scanner.tools.generic import PassthroughTool


class SemgrepTool(PassthroughTool):
    binary = "semgrep"
    tool_name = "semgrep"
    install_instructions = "Install semgrep and put it on PATH."

