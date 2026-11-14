from netra.scanner.tools.generic import PassthroughTool


class NiktoTool(PassthroughTool):
    binary = "nikto"
    tool_name = "nikto"
    install_instructions = "Install nikto and put it on PATH."
