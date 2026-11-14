"""dnsx wrapper: resolve hostnames and report A records."""

from __future__ import annotations

from netra.scanner.tools.base import CliTool, ToolResult


class DnsxTool(CliTool):
    binary = "dnsx"
    tool_name = "dnsx"
    install_instructions = "Install ProjectDiscovery dnsx and put it on PATH."

    async def run(self, hosts: list[str] | str, **kwargs) -> ToolResult:
        items = [hosts] if isinstance(hosts, str) else list(hosts)
        stdin = "\n".join(h.strip() for h in items if h and h.strip())
        result = await self._exec(["-silent", "-a", "-resp"], stdin=stdin)
        findings: list[dict] = []
        for line in result.raw_output.splitlines():
            # dnsx prints: host [ip] or host [ip1,ip2]
            if "[" not in line:
                continue
            host, _, rest = line.partition(" [")
            ips = [ip.strip() for ip in rest.rstrip("]").split(",") if ip.strip()]
            findings.append({"hostname": host.strip(), "url": host.strip(), "ips": ips})
        result.findings = findings
        return result
