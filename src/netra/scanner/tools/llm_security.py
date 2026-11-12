from netra.scanner.tools.generic import PassthroughTool


class LLMSecurityTool(PassthroughTool):
    binary = "garak"
    tool_name = "llm_security"
    install_instructions = "Install garak or NETRA's configured LLM security scanner."

