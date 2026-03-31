"""Autonomous pentest agent — Claude Agent SDK orchestration."""
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from netra.core.config import settings

logger = structlog.get_logger()

# Hard limits for safety
MAX_TOOL_CALLS = 50
MAX_DURATION_MINUTES = 30
MAX_COST_USD = 5.0

AGENT_SYSTEM_PROMPT = """You are NETRA's autonomous penetration testing agent.
Your goal is to methodically discover and validate security vulnerabilities
in the target.

## Process
1. **Reconnaissance**: Start with passive recon (subdomains, OSINT, DNS).
   Analyze what you find before proceeding.
2. **Discovery**: Probe for live hosts, identify technologies, detect WAFs.
3. **Vulnerability Scanning**: Run targeted scans based on what you discovered.
   Choose the right tools for the tech stack.
4. **Active Testing**: Test for injection flaws, auth issues, misconfigs.
   ALWAYS require human approval before active exploitation.
5. **Analysis**: Connect findings into attack chains. Assess business impact.
6. **Reporting**: Generate a narrative of your findings with evidence.

## Rules
- ALWAYS explain your reasoning before choosing a tool
- NEVER exceed rate limits or cause denial of service
- STOP and ask for approval before any active exploitation (SQLi, XSS payloads, etc.)
- Log every decision for the audit trail
- If you find a critical vulnerability, flag it immediately — don't wait for the full scan
- Prioritize breadth first, then depth on interesting findings

## Available Tools
You have access to these NETRA tools via MCP:
- subfinder_enum, amass_enum: subdomain enumeration
- httpx_probe: live host detection + tech fingerprinting
- nmap_scan: port scanning + service detection
- nuclei_scan: template-based vulnerability scanning
- ffuf_fuzz: directory and file discovery
- sqlmap_test: SQL injection testing (REQUIRES APPROVAL)
- dalfox_xss: XSS testing (REQUIRES APPROVAL)
- nikto_scan: web server misconfiguration
- shodan_search: exposed services and CVEs
- semgrep_scan: source code analysis (if source available)
- trivy_scan: container vulnerabilities (if containers)
- prowler_audit: cloud posture (if cloud)
"""

# Tools that require human approval before execution
TOOLS_REQUIRING_APPROVAL = {"sqlmap_test", "dalfox_xss", "ffuf_fuzz"}


class PentestAgent:
    """Autonomous pentest agent with human-in-the-loop controls."""

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.tool_calls = 0
        self.conversation: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] = []  # Audit trail
        self.requires_approval = False
        self.pending_action: dict[str, Any] | None = None
        self.started_at = datetime.now(UTC)
        self.status = "initialized"

    def _log_decision(self, decision_type: str, data: Any) -> None:
        """Log agent decision for audit trail."""
        self.decisions.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "type": decision_type,
            "data": data,
        })
        logger.info("agent_decision", session_id=self.session_id, type=decision_type, data=data)

    async def start(self, target: str, profile: str = "standard") -> dict[str, Any]:
        """Start an autonomous pentest session."""
        try:
            import anthropic
        except ImportError:
            return {"error": "anthropic package not installed"}

        if not settings.anthropic_api_key:
            return {"error": "Anthropic API key not configured"}

        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        self.status = "running"

        # Initial message
        initial_message = f"""Target: {target}
Profile: {profile}
Session: {self.session_id}

Begin your reconnaissance. Explain your approach, then start scanning."""

        self.conversation.append({"role": "user", "content": initial_message})
        self._log_decision("session_started", {"target": target, "profile": profile})

        # Agent loop
        while self.tool_calls < MAX_TOOL_CALLS:
            # Check duration limit
            elapsed_minutes = (datetime.now(UTC) - self.started_at).total_seconds() / 60
            if elapsed_minutes > MAX_DURATION_MINUTES:
                self._log_decision("duration_limit_reached", {"elapsed_minutes": elapsed_minutes})
                break

            try:
                response = await client.messages.create(
                    model=settings.anthropic_model,
                    max_tokens=4000,
                    system=AGENT_SYSTEM_PROMPT,
                    messages=self.conversation,
                    tools=self._get_tool_definitions(),
                )
            except Exception as e:
                logger.error("agent_api_error", error=str(e))
                self.status = "error"
                return {"error": f"Anthropic API error: {str(e)}"}

            # Process response
            assistant_content = []
            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    self._log_decision("reasoning", block.text[:500])

                elif block.type == "tool_use":
                    self.tool_calls += 1
                    logger.info("agent_tool_call", tool=block.name, args=block.input)

                    # Check if this tool requires approval
                    if block.name in TOOLS_REQUIRING_APPROVAL:
                        self.requires_approval = True
                        self.pending_action = {
                            "tool": block.name,
                            "args": block.input,
                            "tool_use_id": block.id,
                        }
                        self._log_decision("approval_required", {
                            "tool": block.name,
                            "args": block.input,
                        })
                        self.status = "awaiting_approval"
                        # Return to caller — wait for human approval
                        return self._get_status_response()

                    # Execute tool
                    result = await self._execute_tool(block.name, block.input)
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

                    # Add tool result to conversation
                    self.conversation.append({"role": "assistant", "content": assistant_content})
                    self.conversation.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": str(result)[:3000],
                        }],
                    })
                    assistant_content = []

            if assistant_content:
                self.conversation.append({"role": "assistant", "content": assistant_content})

            # Check if agent is done
            if response.stop_reason == "end_turn":
                break

        self.status = "completed"
        return self._get_status_response()

    async def approve_action(self) -> dict[str, Any]:
        """Approve the pending action and continue the agent."""
        if not self.pending_action:
            return {"error": "No pending action"}

        logger.info("agent_action_approved", tool=self.pending_action["tool"])
        self._log_decision("action_approved", self.pending_action)

        result = await self._execute_tool(
            self.pending_action["tool"],
            self.pending_action["args"],
        )

        # Continue agent conversation with tool result
        self.conversation.append({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": self.pending_action["tool_use_id"],
                "content": str(result)[:3000],
            }],
        })

        self.pending_action = None
        self.requires_approval = False

        # Resume agent loop
        return await self.start("", "")

    async def reject_action(self, reason: str = "") -> dict[str, Any]:
        """Reject the pending action."""
        if not self.pending_action:
            return {"error": "No pending action"}

        logger.info("agent_action_rejected", tool=self.pending_action["tool"], reason=reason)
        self._log_decision("action_rejected", {
            "tool": self.pending_action["tool"],
            "reason": reason,
        })

        self.conversation.append({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": self.pending_action["tool_use_id"],
                "content": f"Action REJECTED by operator. Reason: {reason or 'Not approved'}. "
                           "Choose a different approach.",
                "is_error": True,
            }],
        })

        self.pending_action = None
        self.requires_approval = False

        return await self.start("", "")

    async def _execute_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute a NETRA tool and return results."""
        from netra.scanner.tools import (
            AmassTool,
            CheckovTool,
            DalfoxTool,
            FfufTool,
            GitleaksTool,
            HttpxTool,
            LLMSecurityTool,
            NiktoTool,
            NmapTool,
            NucleiTool,
            ProwlerTool,
            SemgrepTool,
            ShodanTool,
            SqlmapTool,
            SubfinderTool,
            TrivyTool,
        )

        tool_classes = {
            "nuclei_scan": NucleiTool,
            "nmap_scan": NmapTool,
            "subfinder_enum": SubfinderTool,
            "httpx_probe": HttpxTool,
            "ffuf_fuzz": FfufTool,
            "dalfox_xss": DalfoxTool,
            "nikto_scan": NiktoTool,
            "sqlmap_test": SqlmapTool,
            "amass_enum": AmassTool,
            "shodan_search": ShodanTool,
            "semgrep_scan": SemgrepTool,
            "trivy_scan": TrivyTool,
            "prowler_audit": ProwlerTool,
            "gitleaks_scan": GitleaksTool,
            "checkov_scan": CheckovTool,
            "llm_security_scan": LLMSecurityTool,
        }

        tool_class = tool_classes.get(tool_name)
        if not tool_class:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            tool = tool_class()
            target = args.pop("target", args.pop("url", args.pop("domain", "")))
            result = await tool.run(target, **args)

            self._log_decision("tool_execution", {
                "tool": tool_name,
                "target": target,
                "findings_count": len(result.findings),
                "success": result.success,
            })

            return {
                "success": result.success,
                "findings_count": len(result.findings),
                "findings_summary": [
                    {"title": f["title"], "severity": f.get("severity", "info")}
                    for f in result.findings[:10]
                ],
            }
        except Exception as e:
            logger.error("tool_execution_error", tool=tool_name, error=str(e))
            return {"error": str(e)}

    def _get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tool definitions for Claude Agent SDK."""
        return [
            {
                "name": "nuclei_scan",
                "description": "Run Nuclei vulnerability scanner with template-based detection",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or domain"},
                        "severity": {"type": "string", "default": "critical,high,medium"},
                        "rate_limit": {"type": "integer", "default": 150},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "subfinder_enum",
                "description": "Enumerate subdomains using subfinder",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Root domain to enumerate"},
                        "sources": {"type": "string", "default": "all"},
                        "recursive": {"type": "boolean", "default": False},
                    },
                    "required": ["domain"],
                },
            },
            {
                "name": "httpx_probe",
                "description": "Probe HTTP services for live hosts and technology detection",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"},
                                    "description": "List of domains/IPs to probe"},
                        "follow_redirects": {"type": "boolean", "default": True},
                        "tech_detect": {"type": "boolean", "default": True},
                    },
                    "required": ["targets"],
                },
            },
            {
                "name": "nmap_scan",
                "description": "Run Nmap port scanner with service/version detection",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                        "scan_type": {"type": "string", "default": "service_version"},
                        "ports": {"type": "string", "default": "top-1000"},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "sqlmap_test",
                "description": "Run sqlmap SQL injection testing (REQUIRES APPROVAL)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string",
                                "description": "Target URL with injectable parameter"},
                        "method": {"type": "string", "default": "GET"},
                        "parameter": {"type": "string", "default": ""},
                        "level": {"type": "integer", "default": 1},
                        "risk": {"type": "integer", "default": 1},
                        "safe_mode": {"type": "boolean", "default": True},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "dalfox_xss",
                "description": "XSS vulnerability scanning with Dalfox (REQUIRES APPROVAL)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameter": {"type": "string", "default": ""},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "shodan_search",
                "description": "Search Shodan for exposed services and vulnerabilities",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Shodan search query"},
                        "max_results": {"type": "integer", "default": 100},
                    },
                    "required": ["query"],
                },
            },
        ]

    def _get_status_response(self) -> dict[str, Any]:
        """Get current agent status response."""
        return {
            "status": self.status,
            "session_id": self.session_id,
            "pending_action": self.pending_action,
            "decisions": self.decisions[-20:],  # Last 20 decisions
            "tool_calls": self.tool_calls,
            "conversation_length": len(self.conversation),
            "elapsed_minutes": (datetime.now(UTC) - self.started_at).total_seconds() / 60,
        }


# In-memory agent sessions
AGENT_SESSIONS: dict[str, PentestAgent] = {}


def get_agent_session(session_id: str) -> PentestAgent | None:
    """Get an agent session by ID."""
    return AGENT_SESSIONS.get(session_id)


def create_agent_session() -> PentestAgent:
    """Create a new agent session.

    Returns:
        A new PentestAgent instance registered in AGENT_SESSIONS.
    """
    agent = PentestAgent()
    AGENT_SESSIONS[agent.session_id] = agent
    return agent
