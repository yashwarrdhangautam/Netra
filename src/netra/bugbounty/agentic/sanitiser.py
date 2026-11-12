"""Validate agentic LLM outputs before dispatch."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from netra.bugbounty.agentic.tool_registry import SafetyClass, get_tool_spec
from netra.bugbounty.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Filesystem flags (for example a wordlist) may only point inside this directory.
APPROVED_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"

# Per-tool allowlist of flag names the model may set. Any other flag is dropped.
# Flags that the executor already sets (subfinder passive_only, httpx head/tech_detect,
# nuclei tags/severity) are deliberately absent so they cannot collide or be overridden.
TOOL_FLAG_ALLOWLIST: dict[str, frozenset[str]] = {
    "subfinder": frozenset({"recursive"}),
    "httpx": frozenset({"follow_redirects"}),
    "nuclei": frozenset({"rate_limit"}),
    "ffuf": frozenset({"rate_limit", "wordlist"}),
}

# Subset of allowed flags whose value is a filesystem path.
PATH_FLAG_NAMES: dict[str, frozenset[str]] = {
    "ffuf": frozenset({"wordlist"}),
}


class SanitiserError(ValueError):
    """Raised when an agentic response is unsafe or invalid."""


def validate(response: dict[str, Any], validator: ScopeValidator) -> dict[str, Any]:
    tool_name = str(response.get("tool", "")).strip()
    target = str(response.get("target", "")).strip()
    flags = response.get("flags", {}) or {}

    spec = get_tool_spec(tool_name)
    if spec is None:
        raise SanitiserError(f"unknown tool: {tool_name}")
    if any(
        marker in str(response).lower()
        for marker in ("ignore previous", "rm -rf", "bash -c", "curl | sh")
    ):
        raise SanitiserError("prompt-injection marker detected")
    validator.require(target)
    if spec.safety_class == SafetyClass.ACTIVE_INTRUSIVE:
        raise SanitiserError(f"tool is intrusive by default: {tool_name}")
    if not isinstance(flags, dict):
        raise SanitiserError("flags must be a mapping")
    return {"tool": tool_name, "target": target, "flags": _filter_flags(tool_name, flags)}


def _filter_flags(tool_name: str, flags: dict[str, Any]) -> dict[str, Any]:
    allowed = TOOL_FLAG_ALLOWLIST.get(tool_name, frozenset())
    path_flags = PATH_FLAG_NAMES.get(tool_name, frozenset())
    kept: dict[str, Any] = {}
    for name, value in flags.items():
        if not isinstance(name, str) or name not in allowed:
            logger.warning("sanitiser dropped flag %r for tool %s: not allowlisted", name, tool_name)
            continue
        if name in path_flags:
            resolved = _approved_path(value)
            if resolved is None:
                logger.warning(
                    "sanitiser dropped flag %r for tool %s: path outside approved wordlist directory",
                    name,
                    tool_name,
                )
                continue
            kept[name] = resolved
        else:
            kept[name] = value
    return kept


def _approved_path(value: Any) -> str | None:
    """Return the resolved path if it lies strictly under APPROVED_WORDLIST_DIR, else None."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    base = APPROVED_WORDLIST_DIR.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if resolved == base or not resolved.is_relative_to(base):
        return None
    return str(resolved)
