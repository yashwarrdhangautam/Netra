"""Validate agentic LLM outputs before dispatch."""
from __future__ import annotations

from typing import Any

from netra.bugbounty.agentic.tool_registry import SafetyClass, get_tool_spec
from netra.bugbounty.scope import ScopeValidator


class SanitiserError(ValueError):
    """Raised when an agentic response is unsafe or invalid."""


def validate(response: dict[str, Any], validator: ScopeValidator) -> dict[str, Any]:
    tool_name = str(response.get("tool", "")).strip()
    target = str(response.get("target", "")).strip()
    flags = response.get("flags", {}) or {}

    spec = get_tool_spec(tool_name)
    if spec is None:
        raise SanitiserError(f"unknown tool: {tool_name}")
    if any(marker in str(response).lower() for marker in ("ignore previous", "rm -rf", "bash -c", "curl | sh")):
        raise SanitiserError("prompt-injection marker detected")
    validator.require(target)
    if spec.safety_class == SafetyClass.ACTIVE_INTRUSIVE:
        raise SanitiserError(f"tool is intrusive by default: {tool_name}")
    if not isinstance(flags, dict):
        raise SanitiserError("flags must be a mapping")
    return {"tool": tool_name, "target": target, "flags": flags}
