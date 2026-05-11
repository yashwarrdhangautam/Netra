"""Role-aware model routing for the agentic hunt stack."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from netra.core.config import settings


class AgentRole(StrEnum):
    """Named specialist roles in the agentic orchestration layer."""

    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    SERVICE_ANALYST = "service_analyst"
    SECURITY_EXPERT = "security_expert"
    ATTACK_PATH = "attack_path"
    REPORT_SYNTH = "report_synth"


@dataclass(frozen=True)
class ModelRoute:
    """Provider/model pairing for a single role."""

    role: AgentRole
    provider: str
    model: str
    reason: str


class AgentModelRouter:
    """Resolve the best configured model route for a specialist role."""

    def route(self, role: AgentRole) -> ModelRoute:
        provider = settings.ai_provider
        if provider == "anthropic":
            return self._anthropic_route(role)
        return self._ollama_route(role)

    def _anthropic_route(self, role: AgentRole) -> ModelRoute:
        if role == AgentRole.REPORT_SYNTH:
            return ModelRoute(role, "anthropic", settings.anthropic_skeptic_model, "cheaper summarisation route")
        return ModelRoute(role, "anthropic", settings.anthropic_model, "default anthropic route")

    def _ollama_route(self, role: AgentRole) -> ModelRoute:
        role_model = {
            AgentRole.ORCHESTRATOR: settings.agentic_orchestrator_model,
            AgentRole.SERVICE_ANALYST: settings.agentic_service_analyst_model,
            AgentRole.SECURITY_EXPERT: settings.agentic_security_expert_model,
            AgentRole.ATTACK_PATH: settings.agentic_attack_path_model,
            AgentRole.REPORT_SYNTH: settings.agentic_report_synth_model,
        }.get(role, "")
        return ModelRoute(
            role=role,
            provider="ollama",
            model=role_model or settings.ollama_model,
            reason="role override" if role_model else "default ollama route",
        )
