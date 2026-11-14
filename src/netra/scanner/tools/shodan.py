from netra.scanner.tools.generic import PassthroughTool


class ShodanTool(PassthroughTool):
    binary = "shodan"
    tool_name = "shodan"
    install_instructions = "Install shodan CLI and configure SHODAN_API_KEY."
