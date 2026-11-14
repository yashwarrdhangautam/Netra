from netra.scanner.tools.generic import PassthroughTool


class TrivyTool(PassthroughTool):
    binary = "trivy"
    tool_name = "trivy"
    install_instructions = "Install trivy and put it on PATH."
