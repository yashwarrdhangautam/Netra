"""Verifier allowlist loader.

The file is named YAML for operator readability. To avoid adding a runtime dependency,
we accept JSON-compatible YAML in v1 and fail closed on parse errors.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VerifierSpec:
    """A single allowlisted verifier."""

    id: str
    vuln_class: str
    description: str
    methods: tuple[str, ...]
    will_do: tuple[str, ...]
    will_not_do: tuple[str, ...]
    requires: tuple[str, ...]


class VerifierConfigError(RuntimeError):
    """Raised when verifier config is invalid."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


@lru_cache(maxsize=1)
def load_verifiers(path: Path | None = None) -> list[VerifierSpec]:
    """Load verifier specs from the allowlist."""
    config_path = path or (_repo_root() / "verifier_allowlist.yaml")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VerifierConfigError(f"Could not parse verifier allowlist: {exc}") from exc

    verifiers: list[VerifierSpec] = []
    for item in data.get("verifiers", []):
        try:
            verifiers.append(
                VerifierSpec(
                    id=str(item["id"]),
                    vuln_class=str(item.get("vuln_class", "*")).lower(),
                    description=str(item.get("description", "")),
                    methods=tuple(str(m).upper() for m in item.get("methods", ["GET"])),
                    will_do=tuple(str(v) for v in item.get("will_do", [])),
                    will_not_do=tuple(str(v) for v in item.get("will_not_do", [])),
                    requires=tuple(str(v) for v in item.get("requires", [])),
                )
            )
        except KeyError as exc:
            raise VerifierConfigError(f"Verifier missing required key: {exc}") from exc
    return verifiers


def find_verifier(verifier_id: str, vuln_class: str) -> VerifierSpec | None:
    """Find an allowed verifier for a vuln class."""
    requested = vuln_class.lower()
    for spec in load_verifiers():
        if spec.id != verifier_id:
            continue
        if spec.vuln_class == "*" or spec.vuln_class == requested:
            return spec
    return None


def verifiers_as_dicts() -> list[dict[str, Any]]:
    """Return verifier specs for API display."""
    return [
        {
            "id": spec.id,
            "vuln_class": spec.vuln_class,
            "description": spec.description,
            "methods": list(spec.methods),
            "will_do": list(spec.will_do),
            "will_not_do": list(spec.will_not_do),
            "requires": list(spec.requires),
        }
        for spec in load_verifiers()
    ]


def reload_verifiers() -> list[dict[str, Any]]:
    """Clear cache and reload."""
    load_verifiers.cache_clear()
    return verifiers_as_dicts()

